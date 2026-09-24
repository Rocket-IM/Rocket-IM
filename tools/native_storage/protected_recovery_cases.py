"""加密库的真实中断、结果恢复、回滚journal与安全重建；复用原消息引擎。"""
import hashlib
import json
import os
import selectors
import shutil
import signal
import subprocess
import time

from anchor_support import execute, process, send_action, snapshot
from crypto_support import execute as crypto_execute, success
from protected_support import CryptoProbe, Fixture, RebuildFixture, redact
from rebuild_cases import Cases as PlainRebuildCases
from rebuild_faults import KILL_CASES
from rebuild_support import committed, metrics, rejected
from support import kill_and_reap, require, sha, utc_now, write_json

REBUILD_CASES = ("approval_gate_and_real_bidirectional", *KILL_CASES,
                 "source_approval_result_lost", "source_approval_finish_reply_lost", "refuse_join_commit")
CASE_NAMES = ("key_creation_interrupted", "identity_reservation_interrupted",
              "encrypted_rollback_journal", "committed_receive_locked_recovery",
              "actual_commit_refused", "bound_trust_deleted_with_bootstrap_snapshot",
              "protected_snapshot_anchor_rejection", "rebuilt_key_and_old_trust_required", "rebuilt_storage_key_missing",
              *("encrypted_rebuild_" + name for name in REBUILD_CASES))


class RebuildCases(RebuildFixture, PlainRebuildCases):
    pass


class Cases:
    def __init__(self, binaries, directory, commands):
        self.binaries, self.directory, self.commands = binaries, directory, commands

    def run(self, name):
        if name.startswith("encrypted_rebuild_"):
            fixture = RebuildCases(self.binaries, self.directory, self.commands)
            try:
                result = fixture.run(name.removeprefix("encrypted_rebuild_"))
                require(not fixture.candidate.read_bytes().startswith(b"SQLite format 3"), "重建候选落盘是明文")
                if name.endswith("approval_gate_and_real_bidirectional"):
                    result["storage_audit"] = self.rebuild_audit(fixture)
                return result
            finally:
                fixture.old.ctl("keychain_lock")
                fixture.source.ctl("keychain_lock")
        if name in ("rebuilt_key_and_old_trust_required", "rebuilt_storage_key_missing"):
            return self.rebuilt_key_and_old_trust_required(missing_key=name == "rebuilt_storage_key_missing")
        fixture = Fixture(self.binaries, self.directory, self.commands)
        try:
            return getattr(self, name)(fixture)
        finally:
            fixture.ctl("keychain_lock")

    def audit(self, fixture, extra=(), **fields):
        paths = [*fixture.device.iterdir(), *fixture.trusted.iterdir(), *extra]
        paths += list(fixture.directory.glob("process-*.jsonl"))
        # 只扫描明确路径；合成helper原始anchor.key仍属于未保护的独立实验边界。
        value = fixture.ctl("audit", paths=[str(path) for path in paths if path.is_file()], **fields)["result"]
        require(value["no_secret_matches"], "实际落盘存在审计样本")
        require(value["metadata"]["temp_store"] == 2, "临时存储没有限定内存")
        require(value["metadata"]["cipher_version"].startswith("4.14.0"), "使用了未核对SQLCipher版本")
        require(value["caller_thread"] != value["database_thread"], "审计数据库不在独立Rust线程")
        require(not fixture.database.with_name(fixture.database.name + "-wal").exists(), "本模式意外生成WAL")
        return value

    def key_creation_interrupted(self, fixture):
        request = {"op": "key_reserve", "db": str(fixture.database), "locator": fixture.locator}
        process_handle = subprocess.Popen([str(fixture.protection), "--test-mode"], stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        selector = selectors.DefaultSelector()
        record = {"at": utc_now(), "pid": process_handle.pid, "direction": "control_crash",
                  "payload": {"request": redact(request)}}
        self.commands.append(record)
        try:
            process_handle.stdin.write((json.dumps(request) + "\n").encode())
            process_handle.stdin.close()
            for name in ("stdout", "stderr"):
                stream = getattr(process_handle, name)
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            deadline = time.monotonic() + 8
            captured = b""
            while b"\n" not in captured:
                require(time.monotonic() < deadline, "保存钥匙检查点超时")
                for key, _ in selector.select(0.1):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    require(key.data == "stderr", "保存钥匙后强杀前交付了成功")
                    captured += chunk
                    require(len(captured) <= 4096, "检查点超限")
            marker = json.loads(captured)
            require(marker["checkpoint"] == "protected_key_saved" and marker["pid"] == process_handle.pid,
                    "非本进程钥匙检查点")
            process_handle.kill()
            require(process_handle.wait(timeout=3) == -signal.SIGKILL, "未执行真实SIGKILL")
            record["payload"].update(checkpoint=marker, returncode=-signal.SIGKILL, reaped=True)
        finally:
            record["payload"]["actual_returncode"] = kill_and_reap(process_handle)
            selector.close()
            process_handle.stdout.close()
            process_handle.stderr.close()
        require(not fixture.database.exists(), "保存钥匙窗口已创建数据库")
        with CryptoProbe(fixture.native, fixture.database, fixture.directory, self.commands,
                         flags=("--create", "--protected", str(fixture.config_path)), ready=False) as probe:
            require(probe.startup["error"]["code"] == "keychain_item_exists", "孤立钥匙被覆盖或再生成")
        require(not fixture.database.exists(), "拒绝后仍创建数据库")
        return {"checkpoint": marker, "orphan_key_retained": True, "database_not_created": True}

    def identity_reservation_interrupted(self, fixture):
        flags = ("--test-mode", "--protected", str(fixture.config_path))
        with CryptoProbe(fixture.native, fixture.database, fixture.directory, self.commands,
                         flags=("--create", *flags)) as probe:
            probe.send({"op": "execute", "request": {"request_id": "init", "action": {"op": "initialize"},
                        "fault": "pause_after_reserve"}})
            marker = probe.checkpoint("after_reserve")
            metrics(marker)
            probe.crash()
        with CryptoProbe(fixture.native, fixture.database, fixture.directory, self.commands, flags=flags) as probe:
            error = rejected(crypto_execute(probe, "init", {"op": "initialize"}), "crypto_pending")
            observed = success(probe.request("inspect"))
            require(observed["identity"] is None and observed["pending"] is not None, "未决身份被生成或清除")
        return {"checkpoint": marker, "error": error, "snapshot": observed, "audit": self.audit(fixture)}

    def encrypted_rollback_journal(self, fixture):
        fixture.bootstrap()
        with fixture.peer() as peer, fixture.probe() as probe:
            fixture.setup(probe, peer, records=0)
            # 真正入库一条正文，使随后的回滚页包含已保存正文及私密provider。
            incoming = success(peer.request("peer_send", message_id="saved-message", text="已处理正文-journal-secret"))
            committed(execute(probe, "saved-receive", {"op": "receive", "sequence": "1", "envelope": incoming}), "receive")
            probe.send({"op": "execute", "request": {"request_id": "interrupted-send",
                        "action": send_action(), "fault": "before_commit"}})
            marker = probe.checkpoint("before_commit")
            journal = fixture.database.with_name(fixture.database.name + "-journal")
            require(journal.is_file() and journal.stat().st_size > 4096, "没有捕获真实回滚journal")
            saved = self.directory / "captured-rollback-journal.bin"
            shutil.copyfile(journal, saved)
            interrupted = self.directory / "captured-before-commit.db"
            shutil.copyfile(fixture.database, interrupted)
            probe.crash()
        with fixture.probe() as probe:
            rejected(probe.request("recover"), "anchor_unresolved")
        audit = self.audit(fixture, [saved, interrupted])
        return {"checkpoint": marker, "journal_sha256": sha(saved), "journal_bytes": saved.stat().st_size,
                "audit": audit, "pending_preserved": True, "wal_not_used": True}

    def committed_receive_locked_recovery(self, fixture):
        fixture.bootstrap()
        with fixture.peer() as peer, fixture.probe() as probe:
            data = fixture.setup(probe, peer, records=1)
            probe.send({"op": "execute", "request": {"request_id": "receive-once", "fault": "none",
                        "action": {"op": "receive", **data["records"][0]}},
                        "anchor_fault": "pause_after_candidate_commit"})
            marker = probe.checkpoint("after_candidate_commit")
            metrics(marker, restores=1, receives=1)
            probe.crash()
        saved = fixture.save_closed("committed-receive.db")
        before = sha(fixture.database)
        audit_before = self.audit(fixture, [saved])
        fixture.ctl("keychain_lock")
        with fixture.probe(ready=False) as probe:
            require(probe.startup["error"]["paused"], "锁定仍可打开恢复")
        require(sha(fixture.database) == before, "锁定失败改写密码库")
        fixture.ctl("keychain_unlock")
        with fixture.probe() as probe:
            reply = probe.request("recover")
            result = success(reply); metrics(reply)
            require(reply["events"] == [], "恢复重复发事件")
            require(result["value"]["value"]["message"]["text"] == data["texts"][0], "恢复没有复用原正文")
            received = success(probe.request("received", sequence="1"))
            require(received["message"]["text"] == data["texts"][0], "重启无法读取原正文")
        return {"checkpoint": marker, "same_committed_result": True, "recovery_crypto_calls": 0,
                "audit_with_journal_result": audit_before, "final_audit": self.audit(fixture, [saved])}

    def actual_commit_refused(self, fixture):
        fixture.bootstrap()
        with fixture.peer() as peer, fixture.probe() as probe:
            fixture.setup(probe, peer, records=0)
            before = snapshot(probe)
            reply = execute(probe, "refused", send_action(), fault="refuse_commit")
            error = rejected(reply, measured=True); metrics(reply, restores=1, sends=1)
        with fixture.probe() as probe:
            after = snapshot(probe)
            require(after["provider_hash"] == before["provider_hash"], "拒绝提交仍更新provider")
            require(after["pending"] is not None, "拒绝后丢失预约")
            rejected(execute(probe, "refused", send_action()))
        return {"error": error, "actual_commit_rejected": True, "audit": self.audit(fixture)}

    def bound_trust_deleted_with_bootstrap_snapshot(self, fixture):
        fixture.bootstrap(bind=False)
        saved = fixture.save_closed("before-binding.db")
        fixture.bind()
        fixture.ctl("key_delete", trust=True)
        fixture.restore_closed(saved)
        with CryptoProbe(fixture.native, fixture.database, fixture.directory, self.commands,
                         flags=("--protected", str(fixture.config_path))) as probe:
            error = rejected(crypto_execute(probe, "forbidden", send_action()), "anchor_required")
            rejected(probe.request("received", sequence="1"), "anchor_required")
        return {"error": error, "deleted_trust_plus_v3_snapshot_cannot_send": True}

    def protected_snapshot_anchor_rejection(self, fixture):
        fixture.bootstrap()
        with fixture.peer() as peer, fixture.probe() as probe:
            fixture.setup(probe, peer, records=0)
        saved = fixture.save_closed("valid-old.db")
        with fixture.probe() as probe:
            committed(execute(probe, "advance", send_action()), "send")
        fixture.restore_closed(saved)
        with fixture.probe() as probe:
            error = rejected(execute(probe, "rollback", send_action()), "anchor_head_mismatch")
        return {"error": error, "encryption_did_not_bypass_anchor": True}

    def rebuild_audit(self, fixture):
        scope = {"service": fixture.old.scope["service"], "account": fixture.old.scope["account"], "device": "alice-successor"}
        purpose = hashlib.sha256(json.dumps([fixture.old.binding["binding"], str(fixture.candidate), scope],
                                           separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        paths = [fixture.candidate, *[path for path in fixture.old.trusted.iterdir() if path.is_file()],
                 *fixture.directory.glob("process-*.jsonl")]
        result = fixture.ctl("audit", purpose=purpose, paths=[str(path) for path in paths])["result"]
        require(result["no_secret_matches"], "重建新配置认证材料或正文落入未保护文件")
        require(any(n["category"] == "rebuild_client_seed" for n in result["needles"]), "未扫描重建新seed")
        return result

    def rebuilt_key_and_old_trust_required(self, missing_key=False):
        fixture = RebuildCases(self.binaries, self.directory, self.commands)
        try:
            fixture.bootstrap()
            with fixture.probe() as candidate:
                prepared = fixture.prepare(candidate)
                fixture.activate(candidate, fixture.approve(prepared))
            audit = self.rebuild_audit(fixture)
            before = sha(fixture.candidate)
            if missing_key:
                fixture.ctl("key_delete")
            else:
                fixture.old.ctl("key_delete", trust=True)
            with fixture.probe(ready=False) as candidate:
                expected = "keychain_item_missing" if missing_key else "protected_trust_missing"
                require(candidate.startup["error"]["code"] == expected, "丢失受保护材料后仍绕过门禁")
            require(sha(fixture.candidate) == before, "缺失保护材料仍改写候选库")
            return {"missing_candidate_key": missing_key, "old_trust_required_after_rebuild": not missing_key,
                    "candidate_unchanged": True, "audit": audit}
        finally:
            fixture.old.ctl("keychain_lock"); fixture.source.ctl("keychain_lock")
