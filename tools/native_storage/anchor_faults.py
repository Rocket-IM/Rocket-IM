"""独立锚预约、原生候选提交和确认之间的真实进程中断。"""

from anchor_support import (download, execute, metrics, process, recover, rejected,
                            send_action, snapshot, status, success)
from crypto_support import committed
from download_support import saved
from receive_support import check_message
from support import require

ANCHOR_KILLS = {
    "kill_after_local_gate": ("pause_after_local_gate", "after_local_gate", False),
    "kill_after_anchor_reserve": ("pause_after_anchor_reserve", "after_anchor_reserve", False),
    "kill_after_candidate_commit": ("pause_after_candidate_commit", "after_candidate_commit", True),
    "kill_after_anchor_finish": ("pause_after_anchor_finish", "after_anchor_finish", True),
}
CRYPTO_KILLS = {
    "kill_crypto_after_reserve": ("pause_after_reserve", "after_reserve", False),
    "kill_crypto_after_compute": ("pause_after_crypto", "after_crypto", False),
    "kill_crypto_before_commit": ("before_commit", "before_commit", False),
    "kill_crypto_after_commit": ("after_commit", "after_commit", True),
}
AUTHORITY_FAILURES = {
    "authority_before_save": ("before_save", False),
    "authority_lost_reserve_reply": ("after_reserve_save", False),
    "authority_lost_finish_reply": ("after_finish_save", True),
}


class FaultCases:
    def killed_send(self, name):
        outer = name in ANCHOR_KILLS
        fault, checkpoint, recoverable = (ANCHOR_KILLS if outer else CRYPTO_KILLS)[name]
        self.bootstrap()
        with self.peer() as peer:
            with self.probe() as client:
                setup = self.setup(client, peer)
                request = {"request_id": "fault-send", "action": send_action(),
                           "fault": "none" if outer else fault}
                client.send({"op": "execute", "request": request,
                             "anchor_fault": fault if outer else "none"})
                marker = client.checkpoint(checkpoint)
                computes = checkpoint not in ("after_local_gate", "after_anchor_reserve", "after_reserve")
                measured = marker
                if "metrics" not in measured:
                    candidates = [item["payload"] for item in self.commands
                                  if item.get("pid") == client.process.pid and item["direction"] == "stderr"
                                  and item["payload"].get("checkpoint") == "candidate_ready"]
                    require(len(candidates) == 1, "提交强杀缺少唯一候选调用证据")
                    measured = candidates[0]
                metrics(measured, restores=int(computes), sends=int(computes))
                client.crash()
            with self.probe() as reopened:
                before = snapshot(reopened)
                errors = self.blocked(reopened, setup["records"])
                if recoverable:
                    result = recover(reopened, "execute")
                    require(result["kind"] == "send" and not result["cached"], "恢复未返回原始发送提交")
                    expected = success(peer.request("peer_receive", envelope=result["value"]))
                    require(expected["text"] == send_action()["text"], "恢复后的唯一密文不能实际解密")
                    after = snapshot(reopened)
                    require(after == before, "恢复重做了密码状态或业务持久化")
                    cached = execute(reopened, "fault-send", send_action())
                    require(committed(cached, "send", cached=True) == result["value"], "恢复后缓存不是原密文")
                    require(snapshot(reopened) == before, "缓存重试重做了加密")
                else:
                    rejected(reopened.request("recover"), "anchor_unresolved")
                    require(snapshot(reopened) == before, "无完整 journal 恢复改写了状态")
            if not recoverable:
                with self.probe() as again:
                    errors += self.blocked(again, setup["records"])
                    rejected(again.request("recover"), "anchor_unresolved")
        return {"checkpoint": marker, "recoverable_exact_journal": recoverable,
                "blocked_errors": errors, "candidate_metrics": measured["metrics"],
                "successful_response_before_kill": False,
                "recovery_crypto_calls": 0}

    def authority_failure(self, name):
        failpoint, recoverable = AUTHORITY_FAILURES[name]
        self.bootstrap()
        with self.peer() as peer:
            with self.probe() as client:
                setup = self.setup(client, peer)
            with self.probe(failpoint=failpoint) as failed:
                response = execute(failed, "authority-send", send_action())
                error = rejected(response) if not recoverable else None
                if recoverable:
                    # 候选只执行一次，但 Finish 的持久化回复丢失，不能给宿主成功。
                    from crypto_support import failure
                    error = failure(response, paused=True)
                    metrics(response, restores=1, sends=1)
            with self.probe() as reopened:
                before = snapshot(reopened)
                errors = self.blocked(reopened, setup["records"])
                if recoverable:
                    result = recover(reopened, "execute")
                    decoded = success(peer.request("peer_receive", envelope=result["value"]))
                    require(decoded["text"] == send_action()["text"], "丢失回复恢复返回错误密文")
                    require(snapshot(reopened) == before, "重复 Finish 重算了密码候选")
                    committed(execute(reopened, "authority-send", send_action()), "send", cached=True)
                else:
                    rejected(reopened.request("recover"), "anchor_unresolved")
                    require(snapshot(reopened) == before, "未知 Reserve 结果被恢复为可发送")
        return {"helper_failpoint": failpoint, "error": error, "blocked_errors": errors,
                "exact_finish_recovery": recoverable}

    def download_kill_recover(self):
        self.bootstrap()
        with self.peer() as peer:
            with self.probe() as client:
                setup = self.setup(client, peer)
                client.send({"op": "download", "request": {"records": setup["records"], "fault": "none"},
                             "anchor_fault": "pause_after_candidate_commit"})
                marker = client.checkpoint("after_candidate_commit")
                metrics(marker)
                client.crash()
            with self.probe() as reopened:
                before = snapshot(reopened)
                require(before["download_cursor"] == "2" and before["processed_cursor"] == "0",
                        "下载候选提交没有共同保存完整原始记录")
                self.blocked(reopened, setup["records"])
                value = recover(reopened, "download")
                require(value["download_cursor"] == "2" and value["added"] == 2,
                        "下载恢复结果不匹配原始批次")
                require(snapshot(reopened) == before, "下载恢复重写业务状态")
                saved(download(reopened, setup["records"]), 2, 0, 0)
                require(snapshot(reopened) == before, "缓存下载再次推进下载游标")
        return {"checkpoint": marker, "raw_downloads_preserved": True,
                "provider_and_crypto_revision_unchanged": True, "recover_without_crypto": True}

    def process_kill_recover(self):
        from receive_support import committed as received_commit
        self.bootstrap()
        with self.peer() as peer:
            with self.probe() as client:
                setup = self.setup(client, peer)
                saved(download(client, setup["records"]), 2, 0, 2)
                client.send({"op": "process", "request_id": "process-one", "sequence": "1", "fault": "none",
                             "anchor_fault": "pause_after_candidate_commit"})
                marker = client.checkpoint("after_candidate_commit")
                metrics(marker, restores=1, receives=1)
                client.crash()
            with self.probe() as reopened:
                before = snapshot(reopened)
                self.blocked(reopened, setup["records"])
                outcome = recover(reopened, "execute")
                check_message(outcome["value"], 1, setup["records"][0]["envelope"], setup["texts"][0])
                require(snapshot(reopened) == before, "恢复重做解密或推进游标")
                value = received_commit(process(reopened), "receive", cached=True)
                require(value == outcome["value"], "恢复后的处理缓存不同")
                require(snapshot(reopened) == before, "处理缓存再次推进密码状态")
                received_commit(process(reopened, 2, "process-two"), "receive")
                after = snapshot(reopened)
                require(after["decryptions"] == "2" and after["processed_cursor"] == "2",
                        "恢复后没有按序处理下一条消息")
                status(reopened)
        return {"checkpoint": marker, "recover_without_decrypt": True, "next_record_processed_once": True}
