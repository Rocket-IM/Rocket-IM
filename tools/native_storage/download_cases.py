"""原始下载记录与游标共同落盘、从保存密文接续处理的真实进程场景。"""

import base64
import shutil

from crypto_support import CryptoProbe
from download_faults import (DOWNLOAD_FAULTS, DOWNLOAD_KILLS, PROCESS_FAULTS,
                             PROCESS_KILLS, FaultCases)
from download_support import (check_message, committed, download, downloaded, execute,
                              failure, inspect, metrics, pending_blocked, process,
                              processed, received, record, saved, success, unchanged)
from receive_support import receive_action
from support import ROOT, require, sha

CASE_NAMES = ("normal_restart", "replay_overlap", "duplicate_receipts", "invalid_batches",
              "sequence_boundaries", "mixed_scope_batch", "without_group", "processing_order",
              "forged_authenticated_identity", "tampered_ciphertext", "concurrent_pending",
              "direct_receive_compatibility", "raw_capacity", "legacy_v2_rejected",
              *DOWNLOAD_FAULTS, *DOWNLOAD_KILLS, *PROCESS_FAULTS, *PROCESS_KILLS)


class Cases(FaultCases):
    def __init__(self, binary, directory, commands):
        self.binary, self.directory, self.commands = binary, directory, commands

    def probe(self, create=False, **options):
        flags = ("--test-mode", "--create") if create else ("--test-mode",)
        return CryptoProbe(self.binary, self.directory / "state.db", self.directory,
                           self.commands, flags=flags, **options)

    def peer(self):
        return CryptoProbe(self.binary, self.directory / "unused-peer.db", self.directory,
                           self.commands, account="bob", device="bob-device",
                           flags=("--memory-peer", "--test-mode"))

    def setup(self, alice, peer, count, save=False):
        initial = inspect(alice)
        require(initial["download_cursor"] == "0" and initial["processed_cursor"] == "0", "新库游标不是零")
        identity = committed(execute(alice, "initialize", {"op": "initialize"}), "initialize")
        peer_identity = success(peer.request("peer_identity"))
        group = {"op": "create_group", "conversation": "synthetic-conversation", "peer": peer_identity}
        welcome = committed(execute(alice, "create-group", group), "create_group")
        success(peer.request("peer_join", conversation=group["conversation"], peer=identity, welcome=welcome["welcome"]))
        records, texts = [], []
        for number in range(1, count + 1):
            text = f"合成原始下载消息🙂\u0000{number}"
            envelope = success(peer.request("peer_send", message_id=f"message-{number}", text=text))
            records.append(record(number, envelope))
            texts.append(text)
        before = inspect(alice)
        if save:
            saved(download(alice, records), count, 0, count)
            downloaded(before, inspect(alice), records)
        return {"records": records, "texts": texts, "snapshot": inspect(alice)}

    def run(self, name):
        for names, method in ((DOWNLOAD_FAULTS, self.download_failure), (DOWNLOAD_KILLS, self.download_kill),
                              (PROCESS_FAULTS, self.process_failure), (PROCESS_KILLS, self.process_kill)):
            if name in names:
                return method(name)
        return getattr(self, name)()

    def normal_restart(self):
        with self.peer() as peer:
            with self.probe(create=True) as alice:
                setup = self.setup(alice, peer, 3, save=True)
                for number in range(1, 4):
                    received(alice, number)
            values = []
            with self.probe() as reopened:
                require(inspect(reopened) == setup["snapshot"], "未处理的下载批次重启丢失")
                for number in range(1, 4):
                    before = inspect(reopened)
                    value = committed(process(reopened, number, f"process-{number}"), "receive")
                    check_message(value, number, setup["records"][number - 1]["envelope"], setup["texts"][number - 1])
                    processed(before, inspect(reopened), number)
                    received(reopened, number, value)
                    values.append(value)
                after = inspect(reopened)
            with self.probe() as reopened:
                require(inspect(reopened) == after, "处理结果重启后改变")
                for number, value in enumerate(values, 1):
                    require(committed(process(reopened, number, f"new-retry-{number}"), "receive", cached=True) == value,
                            "从保存密文重试改变已处理结果")
                    received(reopened, number, value)
                require(inspect(reopened) == after, "缓存处理重新推进密码状态")
        return {"downloaded_before_processing": setup["snapshot"], "final": after, "restart_cached_retries": 3}

    def replay_overlap(self):
        with self.peer() as peer, self.probe(create=True) as alice:
            setup = self.setup(alice, peer, 3)
            records = setup["records"]
            saved(download(alice, records[:2]), 2, 0, 2)
            before = inspect(alice)
            saved(download(alice, records[:2]), 2, 0, 0)
            require(inspect(alice) == before, "下载重放改变了状态")
            saved(download(alice, records[1:]), 3, 0, 1)
            after = inspect(alice)
            downloaded(before, after, records[2:])
            saved(download(alice, records), 3, 0, 0)
            require(inspect(alice) == after, "完整批次重放改变了状态")
        return {"exact_replays": 2, "overlap_appended_once": True, "final": after}

    def duplicate_receipts(self):
        with self.peer() as peer, self.probe(create=True) as alice:
            setup = self.setup(alice, peer, 1)
            envelope = setup["records"][0]["envelope"]
            records = [record(1, envelope), record(2, envelope)]
            saved(download(alice, records), 2, 0, 2)
            first = committed(process(alice, 1, "first-process"), "receive")
            before = inspect(alice)
            second = committed(process(alice, 2, "duplicate-process"), "receive", duplicate=True)
            check_message(second, 2, envelope, setup["texts"][0], duplicate=True)
            after = inspect(alice)
            processed(before, after, 2, duplicate=True)
            require(first["message"] == second["message"], "重复下载处理正文不一致")
            received(alice, 2, second)
            require(committed(process(alice, 2, "retry-duplicate"), "receive", cached=True, duplicate=True) == second,
                    "重复消息缓存不一致")
        return {"raw_records": 2, "decryptions": 1, "final": after}

    def invalid_batches(self):
        with self.peer() as peer, self.probe(create=True) as alice:
            setup = self.setup(alice, peer, 1)
            item = setup["records"][0]
            batches = [[], [record(i, item["envelope"]) for i in range(1, 18)],
                       [item, record(3, item["envelope"])], [item, item]]
            for batch in batches:
                response = download(alice, batch)
                failure(response, "invalid_download_batch", paused=False)
                metrics(response)
                require(inspect(alice) == setup["snapshot"], "非法批次保存部分记录")
            for fault in ("reserve_refuse", "after_reserve", "after_crypto", "pause_after_reserve", "pause_after_crypto"):
                response = download(alice, [item], fault)
                failure(response, "invalid_download_fault", paused=False)
                metrics(response)
                require(inspect(alice) == setup["snapshot"], "非法下载故障点改变状态")
            malformed = [{"op": "download", "request": {"records": [{**item, "extra": 1}]}},
                         {"op": "process", "request_id": "strict", "sequence": "1", "fault": "none", "envelope": item["envelope"]},
                         {"op": "download", "request": {"records": [{**item, "sequence": 1}]}}]
            for command in malformed:
                alice.send(command)
                failure(alice.next_stdout(), "invalid_request", paused=False)
                require(inspect(alice) == setup["snapshot"], "严格解析拒绝后改变状态")
        return {"invalid_batches": len(batches), "invalid_faults": 5, "strict_schema_rejections": len(malformed)}

    def sequence_boundaries(self):
        with self.peer() as peer, self.probe(create=True) as alice:
            setup = self.setup(alice, peer, 1)
            envelope = setup["records"][0]["envelope"]
            for sequence in ("0", "01", "-1", "18446744073709551616", ""):
                response = download(alice, [{"sequence": sequence, "envelope": envelope}])
                failure(response, "invalid_sequence", paused=False)
                metrics(response)
            for sequence in ("2", "9007199254740993", "18446744073709551615"):
                response = download(alice, [record(sequence, envelope)])
                failure(response, "download_gap", paused=False)
                metrics(response)
            saved(download(alice, setup["records"]), 1, 0, 1)
            before = inspect(alice)
            conflict = record(1, {**envelope, "messageId": "different-id"})
            for batch in ([conflict], [conflict, record(2, envelope)]):
                response = download(alice, batch)
                failure(response, "download_sequence_conflict", paused=False)
                metrics(response)
                require(inspect(alice) == before, "冲突批次部分保存或改变旧记录")
        return {"invalid_sequences": 5, "exact_large_sequence_gaps": 3, "conflict_batches": 2}

    def mixed_scope_batch(self):
        with self.peer() as peer, self.probe(create=True) as alice:
            setup = self.setup(alice, peer, 2)
            first, second = setup["records"]
            for field in ("service", "conversation"):
                response = download(alice, [first, {**second, "envelope": {**second["envelope"], field: "wrong-scope"}}])
                failure(response, "crypto_scope_mismatch", paused=False)
                metrics(response)
                require(inspect(alice) == setup["snapshot"], "混合范围批次保存了前半记录")
            saved(download(alice, setup["records"]), 2, 0, 2)
        return {"rejected_mixed_scope_batches": 2, "subsequent_correct_batch": True}

    def without_group(self):
        with self.probe(create=True) as alice:
            committed(execute(alice, "initialize", {"op": "initialize"}), "initialize")
            before = inspect(alice)
            envelope = {"service": "local-service", "conversation": "synthetic-conversation", "senderAccount": "bob",
                        "senderDevice": "bob-device", "messageId": "no-group", "ciphertext": "AA=="}
            response = download(alice, [record(1, envelope)])
            failure(response, "crypto_no_group", paused=False)
            metrics(response)
            require(inspect(alice) == before, "无群下载创建了状态")
        return {"group_required": True, "provider_calls": 0}

    def processing_order(self):
        with self.peer() as peer, self.probe(create=True) as alice:
            setup = self.setup(alice, peer, 2, save=True)
            for sequence, code in ((2, "receive_gap"), (3, "download_not_found")):
                response = process(alice, sequence, f"invalid-order-{sequence}")
                failure(response, code, paused=False)
                metrics(response)
                require(inspect(alice) == setup["snapshot"], "跳过处理或缺失下载改变了状态")
            received(alice, 1)
            value = committed(process(alice, 1), "receive")
            check_message(value, 1, setup["records"][0]["envelope"], setup["texts"][0])
            processed(setup["snapshot"], inspect(alice), 1)
        return {"downloaded_ahead_of_processed": True, "gap_rejected": True, "missing_rejected": True}

    def rejected_crypto(self, tamper):
        with self.peer() as peer:
            with self.probe(create=True) as alice:
                setup = self.setup(alice, peer, 2)
                envelope = setup["records"][0]["envelope"]
                if tamper:
                    data = bytearray(base64.b64decode(envelope["ciphertext"], validate=True))
                    data[-1] ^= 1
                    envelope = {**envelope, "ciphertext": base64.b64encode(data).decode()}
                else:
                    envelope = {**envelope, "messageId": "forged-authenticated-message-id"}
                records = [record(1, envelope), setup["records"][1]]
                saved(download(alice, records), 2, 0, 2)
                before = inspect(alice)
                downloaded(setup["snapshot"], before, records)
                response = process(alice, 1)
                code = "crypto_failed" if tamper else "crypto_identity_mismatch"
                error = failure(response, code, paused=True)
                metrics(response, restores=1, receives=1)
                after = inspect(alice)
                unchanged(before, after, pending=True)
                received(alice, 1)
                rejected = pending_blocked(alice, records, after)
            with self.probe() as reopened:
                require(inspect(reopened) == after, "密码失败后下载记录或预约重启丢失")
                rejected += pending_blocked(reopened, records, after)
                received(reopened, 1)
        return {"error": error, "download_cursor": "2", "processed_cursor": "0", "recovered": after,
                "pending_rejections": rejected, "raw_rejected_ciphertext_retained": True}

    def forged_authenticated_identity(self):
        return self.rejected_crypto(False)

    def tampered_ciphertext(self):
        return self.rejected_crypto(True)

    def concurrent_pending(self):
        with self.peer() as peer:
            with self.probe(create=True) as alice:
                setup = self.setup(alice, peer, 2, save=True)
                committed(process(alice, 1, "already-processed"), "receive")
                setup["snapshot"] = inspect(alice)
            with self.probe() as first, self.probe() as second:
                first.send({"op": "process", "request_id": "process-request", "sequence": "2", "fault": "pause_after_reserve"})
                marker, _ = self.process_checkpoint(first, "after_reserve")
                pending = inspect(second)
                unchanged(setup["snapshot"], pending, pending=True)
                rejected = pending_blocked(second, setup["records"], pending)
                first.crash()
            with self.probe() as reopened:
                require(inspect(reopened) == pending, "并发未决预约或原始下载记录丢失")
                rejected += pending_blocked(reopened, setup["records"], pending)
        return {"checkpoint": marker, "recovered": pending, "pending_rejections": rejected}

    def direct_receive_compatibility(self):
        with self.peer() as peer, self.probe(create=True) as alice:
            setup = self.setup(alice, peer, 3)
            first, second, third = setup["records"]
            value = committed(execute(alice, "direct-first", receive_action(1, first["envelope"])), "receive")
            check_message(value, 1, first["envelope"], setup["texts"][0])
            before = inspect(alice)
            require(before["download_cursor"] == "1" and before["processed_cursor"] == "1", "直接接收没有共同补入下载记录")
            saved(download(alice, [second, third]), 3, 1, 2)
            downloaded(before, inspect(alice), [second, third])
            value = committed(execute(alice, "direct-saved", receive_action(2, second["envelope"])), "receive")
            check_message(value, 2, second["envelope"], setup["texts"][1])
            before = inspect(alice)
            require(committed(process(alice, 2, "process-direct-cache"), "receive", cached=True) == value,
                    "直接接收与保存后处理没有共享缓存")
            conflict = {**third["envelope"], "messageId": "conflicting-direct"}
            response = execute(alice, "direct-conflict", receive_action(3, conflict))
            failure(response, "receive_sequence_conflict", paused=False)
            metrics(response)
            require(inspect(alice) == before, "直接接收绕过下载原文一致性检查")
            value = committed(process(alice, 3, "process-third"), "receive")
            check_message(value, 3, third["envelope"], setup["texts"][2])
            processed(before, inspect(alice), 3)
        return {"mixed_paths_share_downloads_and_receipts": True, "saved_envelope_conflict_rejected": True}

    def raw_capacity(self):
        with self.peer() as peer, self.probe(create=True) as alice:
            setup = self.setup(alice, peer, 1)
            envelope = setup["records"][0]["envelope"]
            for start in range(1, 129, 16):
                records = [record(i, envelope) for i in range(start, start + 16)]
                saved(download(alice, records), start + 15, 0, 16)
            before = inspect(alice)
            response = download(alice, [record(129, envelope)])
            failure(response, "crypto_limit", paused=False)
            metrics(response)
            require(inspect(alice) == before, "下载容量拒绝改变状态")
            saved(download(alice, [record(128, envelope)]), 128, 0, 0)
            require(inspect(alice) == before, "满容量精确重放改变状态")
        return {"maximum_batch": 16, "raw_records": 128, "processing_capacity_not_claimed": True}

    def legacy_v2_rejected(self):
        source = ROOT / "dist/native-storage/receive/runs/fe54b94c-9051-4147-81ff-5a6ebabd574d/normal_restart/state.db"
        require(source.is_file(), "缺少已验收 v2 接收数据库夹具")
        original = sha(source)
        destination = self.directory / "state.db"
        shutil.copyfile(source, destination)
        destination.chmod(0o600)
        require(sha(destination) == original, "旧 v2 数据库复制摘要不符")
        with self.probe(ready=False) as legacy:
            error = legacy.startup.get("error") or {}
            # 当前 Rocket 命名空间的 v2 升级门另由 Rust 旧 schema 测试覆盖。
            require(error.get("code") == "crypto_store_corrupt" and error.get("paused") is True,
                    "旧工程名 v2 格式未明确暂停拒绝")
        require(sha(source) == original and sha(destination) == original, "旧 v2 格式拒绝修改了原库或副本")
        return {"fixture": str(source), "fixture_sha256": original, "copy_sha256": original,
                "error": error, "rejection_boundary": "legacy_project_namespace",
                "original_and_copy_unchanged": True}
