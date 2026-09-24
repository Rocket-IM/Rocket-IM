"""真实 SQL/COMMIT 失败和下载、处理进程强杀窗口。"""

from download_support import (check_message, committed, download, downloaded, failure,
                              inspect, metrics, pending_blocked, process, processed,
                              received, record, saved, unchanged)
from support import require

DOWNLOAD_FAULTS = {"download_after_sql": ("after_sql", "database_error", 1, False),
                   "download_refuse_commit": ("refuse_commit", "commit_failed", 531, True)}
DOWNLOAD_KILLS = {"download_kill_before_commit": "before_commit", "download_kill_after_commit": "after_commit"}
PROCESS_FAULTS = {"process_reserve_refuse": ("reserve_refuse", "commit_failed", 531),
                  "process_after_sql": ("after_sql", "database_error", 1),
                  "process_refuse_commit": ("refuse_commit", "commit_failed", 531)}
PROCESS_KILLS = {"process_kill_after_reserve": ("pause_after_reserve", "after_reserve"),
                 "process_kill_after_crypto": ("pause_after_crypto", "after_crypto"),
                 "process_kill_before_commit": ("before_commit", "before_commit"),
                 "process_kill_after_commit": ("after_commit", "after_commit")}


class FaultCases:
    def download_failure(self, name):
        fault, code, sqlite_code, paused = DOWNLOAD_FAULTS[name]
        with self.peer() as peer:
            with self.probe(create=True) as alice:
                setup = self.setup(alice, peer, 2)
                before, records = setup["snapshot"], setup["records"]
                response = download(alice, records, fault)
                error = failure(response, code, sqlite_code, paused)
                metrics(response)
                if paused:
                    require(response["trace"][-2:] == ["COMMIT", "ROLLBACK_AUTOMATIC"], "没有真实下载 COMMIT 拒绝")
                else:
                    require("INSERT" in response["trace"] and response["trace"][-1] == "ROLLBACK",
                            "下载记录 SQL 失败没有真实写入和回滚")
                require(inspect(alice) == before, "下载失败遗留半批次、游标或预约")
                received(alice, 1)
                if paused:
                    refusal = download(alice, records)
                    failure(refusal, "crypto_paused", paused=True)
                    metrics(refusal)
            with self.probe() as reopened:
                require(inspect(reopened) == before, "下载失败重启后出现半批记录")
                saved(download(reopened, records), 2, 0, 2)
                after = inspect(reopened)
                downloaded(before, after, records)
                value = committed(process(reopened, 1), "receive")
                check_message(value, 1, records[0]["envelope"], setup["texts"][0])
                processed(after, inspect(reopened), 1)
        return {"error": error, "recovered": after, "restart_download_and_process": True}

    def download_kill(self, name):
        checkpoint = DOWNLOAD_KILLS[name]
        with self.peer() as peer:
            with self.probe(create=True) as alice:
                setup = self.setup(alice, peer, 2)
                alice.send({"op": "download", "request": {"records": setup["records"], "fault": checkpoint}})
                marker = alice.checkpoint(checkpoint)
                alice.crash()
            with self.probe() as reopened:
                after = inspect(reopened)
                if checkpoint == "before_commit":
                    require(after == setup["snapshot"], "下载提交前强杀保留了半批记录")
                    saved(download(reopened, setup["records"]), 2, 0, 2)
                    after = inspect(reopened)
                else:
                    saved(download(reopened, setup["records"]), 2, 0, 0)
                    require(inspect(reopened) == after, "下载提交后强杀的重试推进游标")
                downloaded(setup["snapshot"], after, setup["records"])
                received(reopened, 1)
                value = committed(process(reopened, 1), "receive")
                check_message(value, 1, setup["records"][0]["envelope"], setup["texts"][0])
                processed(after, inspect(reopened), 1)
        return {"checkpoint": marker, "recovered_downloads": after, "successful_response_before_kill": False}

    def process_failure(self, name):
        fault, code, sqlite_code = PROCESS_FAULTS[name]
        pending = fault != "reserve_refuse"
        with self.peer() as peer:
            with self.probe(create=True) as alice:
                setup = self.setup(alice, peer, 2, save=True)
                response = process(alice, 1, fault=fault)
                error = failure(response, code, sqlite_code, paused=True)
                metrics(response, restores=int(pending), receives=int(pending))
                if fault in ("reserve_refuse", "refuse_commit"):
                    require(response["trace"][-2:] == ["COMMIT", "ROLLBACK_AUTOMATIC"], "没有真实处理 COMMIT 拒绝")
                else:
                    require("UPDATE" in response["trace"] and response["trace"][-1] == "ROLLBACK",
                            "处理 SQL 故障没有回滚密码候选")
                after = inspect(alice)
                unchanged(setup["snapshot"], after, pending=pending)
                received(alice, 1)
                rejected = pending_blocked(alice, setup["records"], after) if pending else 0
                if not pending:
                    refusal = process(alice, 1)
                    failure(refusal, "crypto_paused", paused=True)
                    metrics(refusal)
            with self.probe() as reopened:
                require(inspect(reopened) == after, "失败后的原始下载数据或预约丢失")
                received(reopened, 1)
                if pending:
                    rejected += pending_blocked(reopened, setup["records"], after)
                else:
                    value = committed(process(reopened, 1), "receive")
                    check_message(value, 1, setup["records"][0]["envelope"], setup["texts"][0])
                    processed(after, inspect(reopened), 1)
        return {"error": error, "recovered": after, "pending_rejections": rejected,
                "raw_downloads_preserved": True}

    def process_checkpoint(self, probe, checkpoint):
        marker = probe.checkpoint(checkpoint)
        evidence = marker
        if "metrics" not in evidence:
            candidates = [item["payload"] for item in self.commands
                          if item["pid"] == probe.process.pid and item["direction"] == "stderr"
                          and item["payload"].get("checkpoint") == "candidate_ready"]
            require(len(candidates) == 1, "处理提交强杀缺少候选密码调用证据")
            evidence = candidates[0]
        computes = checkpoint != "after_reserve"
        metrics(evidence, restores=int(computes), receives=int(computes))
        return marker, evidence

    def process_kill(self, name):
        fault, checkpoint = PROCESS_KILLS[name]
        with self.peer() as peer:
            with self.probe(create=True) as alice:
                setup = self.setup(alice, peer, 2, save=True)
                alice.send({"op": "process", "request_id": "process-request", "sequence": "1", "fault": fault})
                marker, evidence = self.process_checkpoint(alice, checkpoint)
                alice.crash()
            with self.probe() as reopened:
                after = inspect(reopened)
                if checkpoint == "after_commit":
                    processed(setup["snapshot"], after, 1)
                    value = committed(process(reopened, 1), "receive", cached=True)
                    check_message(value, 1, setup["records"][0]["envelope"], setup["texts"][0])
                    require(committed(process(reopened, 1, "different-request"), "receive", cached=True) == value,
                            "提交后强杀重试改变消息")
                    received(reopened, 1, value)
                    require(inspect(reopened) == after, "提交后强杀重做了解密")
                    next_value = committed(process(reopened, 2, "next-process"), "receive")
                    check_message(next_value, 2, setup["records"][1]["envelope"], setup["texts"][1])
                    processed(after, inspect(reopened), 2)
                    rejected = 0
                else:
                    unchanged(setup["snapshot"], after, pending=True)
                    received(reopened, 1)
                    rejected = pending_blocked(reopened, setup["records"], after)
        return {"checkpoint": marker, "candidate_metrics": evidence["metrics"], "recovered": after,
                "pending_rejections": rejected, "successful_response_before_kill": False,
                "raw_downloads_preserved": True}
