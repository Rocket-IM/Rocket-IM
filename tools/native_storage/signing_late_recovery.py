"""签名升级后清理日志已提交、作业后置保护检查前锁定的真实进程验证。"""

import json
from pathlib import Path

from anchor_support import download, execute, process, snapshot, status
from crypto_support import success
from download_support import saved
from protected_support import redact
from rebuild_support import committed, metrics, rejected
from signing_lifecycle import LifecycleCases
from support import require, sha, utc_now, write_json

CASE_NAMES = ("upgraded_receive_after_anchor_clear_lock", "upgraded_process_after_anchor_clear_lock")


class LateRecoveryCases(LifecycleCases):
    def late_lock(self, operation):
        fixture = self.fixture()
        fixture.bootstrap()
        with fixture.peer() as peer, fixture.probe() as old:
            data = fixture.setup(old, peer, records=1)
            if operation == "process":
                saved(download(old, data["records"]), 1, 0, 1)
            old_snapshot = snapshot(old)
            old_pid, peer_pid = old.process.pid, peer.process.pid
        self.switch(fixture)
        request_id = f"late-{operation}-once"
        action = {"op": "receive", **data["records"][0]}
        command = ({"op": "process", "request_id": request_id, "sequence": "1", "fault": "none"}
                   if operation == "process" else
                   {"op": "execute", "request": {"request_id": request_id, "action": action, "fault": "none"}})
        command["anchor_fault"] = "pause_after_anchor_clear"
        with fixture.probe() as paused:
            paused_pid = paused.process.pid
            require(paused_pid != old_pid, "v2 故障请求没有使用独立进程")
            require(snapshot(paused) == old_snapshot, "签名升级改变了 v1 已保存状态")
            response_id = paused.send(command)
            marker = paused.checkpoint("after_anchor_clear")
            metrics(marker, restores=1, receives=1)
            fixture.ctl("keychain_lock")
            locked_hash = sha(fixture.database)
            # Rust 检查点等待 10 秒；不能沿用普通请求 8 秒的响应时限。
            failed = paused.next_stdout(timeout=20)
            require(failed.get("id") == response_id, "锁定后的原响应 ID 不匹配")
            paused.check_threads(failed)
            failure = rejected(failed, "keychain_locked", measured=True)
            metrics(failed, restores=1, receives=1)
            require(failed["trace"] and failed["trace"][-1] == "COMMIT", "清理事务没有提交证据")
            require(sha(fixture.database) == locked_hash, "后置保护拒绝后继续改写数据库")
            still_paused = rejected(paused.request("recover"), "keychain_locked")
        require(paused.finished and paused.process.returncode == 0, "保护暂停后 close 未正常回收")
        require(sha(fixture.database) == locked_hash, "锁定后的 close 改写了已提交数据")
        saved_database = fixture.save_closed("v2-cleared-before-unlock.db")
        fixture.ctl("keychain_unlock")
        expected = {"sequence": "1", "duplicate": False,
                    "message": {"messageId": data["records"][0]["envelope"]["messageId"],
                                "senderAccount": "bob", "text": data["texts"][0]}}
        with fixture.probe() as reopened:
            recovered_pid = reopened.process.pid
            require(recovered_pid != paused_pid, "解锁恢复没有创建新进程")
            before = snapshot(reopened)
            require(before["identity"] == old_snapshot["identity"], "结果丢失导致密码身份替换")
            require(before["provider_hash"] != old_snapshot["provider_hash"]
                    and int(before["revision"]) == int(old_snapshot["revision"]) + 1
                    and int(before["decryptions"]) == int(old_snapshot["decryptions"]) + 1,
                    "故障前真实接收没有恰好提交一次")
            require(before["download_cursor"] == before["processed_cursor"] == "1"
                    and before["pending"] is None, "已经提交的接收仍有预约或丢失游标")
            healthy = status(reopened)
            recovery = reopened.request("recover")
            recovery_error = rejected(recovery, "anchor_unresolved")
            require(snapshot(reopened) == before, "无 journal 的 recover 改变已保存状态")
            read = reopened.request("received", sequence="1")
            require(success(read) == expected and read["events"] == [], "未读回完整原接收结果")
            metrics(read)
            retry = (process(reopened, 1, request_id) if operation == "process" else
                     execute(reopened, request_id, action))
            require(committed(retry, "receive", cached=True) == expected, "原请求缓存不是完整原接收结果")
            require(success(retry) == {"revision": before["revision"], "kind": "receive",
                                       "cached": True, "value": expected}, "缓存结果版本或元数据改变")
            require(snapshot(reopened) == before, "缓存重取改变 provider、游标或已保存记录")
            status(reopened)
        require(sha(saved_database) == locked_hash, "恢复覆盖了保留的原数据库副本")
        return {"operation": operation, "checkpoint": marker,
                "pids": {"v1": old_pid, "peer": peer_pid, "v2_paused": paused_pid, "v2_reopened": recovered_pid},
                "locked_error": failure, "same_instance_recover_error": still_paused,
                "failed_reply_metrics": failed["metrics"], "failed_reply_trace": failed["trace"],
                "close_succeeded": True, "saved_database_sha256": locked_hash,
                "v1_snapshot": old_snapshot, "v2_committed_snapshot": before, "healthy_without_journal": healthy,
                "recover_error_after_clear": recovery_error, "recover_metrics": recovery["metrics"],
                "full_cached_result": success(retry), "cached_metrics": retry["metrics"],
                "cached_events": retry["events"], "exact_result_retrieved_by_original_request": True,
                "provider_and_cursors_unchanged_during_retry": True,
                "recovery_contract": "journal 尚在时 recover；清理已提交而结果丢失时按原请求 ID 精确取回缓存。"}


def run_late(v1, v2, directory, commands):
    """只调用既有签名程序；逐项记录失败并锁定本轮专用钥匙串，不修改 ACL。"""
    output = Path(directory).resolve()
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    versions = [tuple(Path(path).resolve() for path in paths) for paths in (v1, v2)]
    require(all(len(paths) == 5 and all(path.is_file() for path in paths) for paths in versions),
            "晚期恢复验证需要两组已准备的五个程序")
    v1, v2 = versions
    require(v1[2] == v2[2], "helper 必须保留同一固定路径")
    require(v1[0] != v2[0] and sha(v1[0]) != sha(v2[0]), "v1/v2 必须使用不同字节的独立签名程序")
    start_offset = len(commands)
    report = {"status": "RUNNING", "started_at": utc_now(), "cases": [],
              "binaries_sha256": {str(path): sha(path) for paths in versions for path in paths},
              "scope": "test-mode only; after anchor_clear commit before Database::call post-check",
              "signed_identity_requirement": "签名者、identifier 与 DR 由调用者的主报告核验；本模块不改 ACL。"}
    for name, operation in zip(CASE_NAMES, ("receive", "process")):
        case_directory = output / name
        case_directory.mkdir(mode=0o700)
        case = {"name": name, "status": "RUNNING", "started_at": utc_now(), "command_offset": len(commands)}
        report["cases"].append(case)
        write_json(output / "late-recovery-report.json", redact(report))
        fixture = LateRecoveryCases(v1, v2, case_directory, commands)
        try:
            case["evidence"] = redact(fixture.late_lock(operation))
            case["status"] = "PASS"
        except Exception as error:
            case.update(status="FAIL", error=f"{type(error).__name__}: {error}")
        finally:
            case["cleanup"] = fixture.cleanup()
            if any(not entry["locked"] for entry in case["cleanup"]):
                case.update(status="FAIL", cleanup_error="本场景实验钥匙串未全部锁定")
            case.update(finished_at=utc_now(), command_count=len(commands) - case["command_offset"])
            entries = commands[case["command_offset"]:]
            case["pids"] = sorted({entry["pid"] for entry in entries if entry.get("pid") is not None})
            write_json(case_directory / "case.json", redact(case))
            write_json(output / "late-recovery-report.json", redact(report))
            with (output / "commands.jsonl").open("w") as target:
                for entry in commands[start_offset:]:
                    target.write(json.dumps(redact(entry), ensure_ascii=False) + "\n")
        print(json.dumps({"case": name, "status": case["status"], "error": case.get("error")}), flush=True)
    report["counts"] = {"planned": len(CASE_NAMES), "total": len(report["cases"]),
                        "passed": sum(case["status"] == "PASS" for case in report["cases"])}
    report["binaries_unchanged"] = all(sha(Path(path)) == value for path, value in report["binaries_sha256"].items())
    report["status"] = "PASS" if report["counts"]["passed"] == len(CASE_NAMES) and report["binaries_unchanged"] else "FAIL"
    report["finished_at"] = utc_now()
    write_json(output / "late-recovery-report.json", redact(report))
    return report
