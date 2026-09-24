"""真实 OpenMLS 接收、去重与连续处理游标的跨进程场景。"""

import base64
import shutil

from receive_faults import FAULTS, KILLS, FaultCases
from receive_support import (CryptoProbe, advanced, check_message, committed,
                             execute, failure, inspect, metrics, receive_action, received,
                             success, unchanged)
from support import ROOT, require, sha

CASE_NAMES = ("normal_restart", "idempotent_retries", "duplicate_sequence", "preflight_conflicts",
              "gap_ordering", "routing_rejection", "receive_without_group", *FAULTS, *KILLS,
              "concurrent_reservation", "tampered_ciphertext", "duplicate_refuse_commit",
              "duplicate_kill_after_commit", "legacy_format_rejected")


def tamper(envelope):
    data = bytearray(base64.b64decode(envelope["ciphertext"], validate=True))
    data[-1] ^= 1
    return {**envelope, "ciphertext": base64.b64encode(data).decode()}


class Cases(FaultCases):
    def __init__(self, binary, directory, commands):
        self.binary, self.directory, self.commands = binary, directory, commands

    def probe(self, create=False, test=True, **options):
        flags = ("--create",) if create else ()
        if test:
            flags += ("--test-mode",)
        return CryptoProbe(self.binary, self.directory / "state.db", self.directory,
                           self.commands, flags=flags, **options)

    def peer(self):
        return CryptoProbe(self.binary, self.directory / "unused-peer.db", self.directory,
                           self.commands, account="bob", device="bob-device",
                           flags=("--memory-peer", "--test-mode"))

    def send(self, peer, number):
        text = f"合成接收消息🙂\u0000{number}"
        envelope = success(peer.request("peer_send", message_id=f"message-{number}", text=text))
        require(envelope["senderAccount"] == "bob", "内存发送方身份不符")
        return envelope, text

    def setup(self, alice, peer):
        before = inspect(alice)
        require(before["processed_cursor"] == "0" and before["decryptions"] == "0"
                and before["inbox"] == [] and before["receipt_count"] == 0, "新库接收状态不是空")
        identity = committed(execute(alice, "initialize", {"op": "initialize"}), "initialize")
        peer_identity = success(peer.request("peer_identity"))
        group = {"op": "create_group", "conversation": "synthetic-conversation", "peer": peer_identity}
        welcome = committed(execute(alice, "create-group", group), "create_group")
        success(peer.request("peer_join", conversation=group["conversation"], peer=identity,
                             welcome=welcome["welcome"]))
        envelope, text = self.send(peer, "seed")
        seed = receive_action(1, envelope)
        before = inspect(alice)
        value = committed(execute(alice, "seed-request", seed), "receive")
        check_message(value, 1, envelope, text)
        after = inspect(alice)
        advanced(before, after, 1)
        received(alice, 1, value)
        return {"group": group, "seed": seed, "seed_value": value, "envelope": envelope,
                "text": text, "snapshot": after}

    def blocked(self, probe, setup, action, failed_request="failure-request"):
        before = inspect(probe)
        variants = [(failed_request, action), ("retry-new-request", action),
                    ("fresh-sequence", {**action, "sequence": str(int(action["sequence"]) + 1)}),
                    ("seed-request", setup["seed"]), ("old-sequence-new-request", setup["seed"]),
                    ("initialize", {"op": "initialize"}), ("retry-group", setup["group"]),
                    ("retry-send", {"op": "send", "attempt_id": "other-attempt",
                                    "message_id": "other-message", "text": "合成暂停发送"})]
        for request_id, value in variants:
            response = execute(probe, request_id, value)
            failure(response, "crypto_pending", paused=True)
            metrics(response)
            require(inspect(probe) == before, "未决预约拒绝改变了旧状态")
        received(probe, 1, setup["seed_value"])
        received(probe, action["sequence"])
        return len(variants)

    def run(self, name):
        if name in FAULTS:
            return self.failure_window(name)
        if name in KILLS:
            return self.kill_window(name)
        return getattr(self, name)()

    def normal_restart(self):
        with self.peer() as peer:
            with self.probe(create=True) as alice:
                setup = self.setup(alice, peer)
                before = setup["snapshot"]
                envelope, text = self.send(peer, 2)
                action = receive_action(2, envelope)
                value = committed(execute(alice, "receive-2", action), "receive")
                check_message(value, 2, envelope, text)
                after = inspect(alice)
                advanced(before, after, 2)
            with self.probe() as reopened:
                require(inspect(reopened) == after, "重启接收状态改变")
                received(reopened, 1, setup["seed_value"])
                received(reopened, 2, value)
                envelope, text = self.send(peer, 3)
                value = committed(execute(reopened, "receive-3", receive_action(3, envelope)), "receive")
                check_message(value, 3, envelope, text)
                advanced(after, inspect(reopened), 3)
                received(reopened, 3, value)
                final = inspect(reopened)
        return {"restart_continued": True, "final": final, "text": text}

    def idempotent_retries(self):
        with self.peer() as peer:
            with self.probe(create=True) as alice:
                setup = self.setup(alice, peer)
                for request_id in ("seed-request", "new-retry"):
                    value = committed(execute(alice, request_id, setup["seed"]), "receive", cached=True)
                    require(value == setup["seed_value"] and inspect(alice) == setup["snapshot"],
                            "相同序号重试推进状态或改变消息")
            with self.probe() as reopened:
                for request_id in ("seed-request", "restart-new-retry"):
                    value = committed(execute(reopened, request_id, setup["seed"]), "receive", cached=True)
                    require(value == setup["seed_value"] and inspect(reopened) == setup["snapshot"],
                            "重启重试推进状态或改变消息")
        return {"cached_retries": 4, "provider_calls": 0, "final": setup["snapshot"]}

    def duplicate_sequence(self):
        with self.peer() as peer:
            with self.probe(create=True) as alice:
                setup = self.setup(alice, peer)
                action = receive_action(2, setup["envelope"])
                value = committed(execute(alice, "duplicate", action), "receive", duplicate=True)
                check_message(value, 2, setup["envelope"], setup["text"], duplicate=True)
                after = inspect(alice)
                advanced(setup["snapshot"], after, 2, duplicate=True)
                received(alice, 2, value)
            with self.probe() as reopened:
                require(inspect(reopened) == after, "重复消息的处理凭据重启丢失")
                received(reopened, 2, value)
                for request_id in ("duplicate", "duplicate-new-retry"):
                    cached = committed(execute(reopened, request_id, action), "receive", cached=True,
                                       duplicate=True)
                    require(cached == value and inspect(reopened) == after, "重复消息缓存重試改变状态")
                envelope, text = self.send(peer, 3)
                next_value = committed(execute(reopened, "next-message", receive_action(3, envelope)), "receive")
                check_message(next_value, 3, envelope, text)
                advanced(after, inspect(reopened), 3)
        return {"duplicate": value, "zero_crypto_for_duplicate": True, "restart_continued": True}

    def preflight_conflicts(self):
        with self.peer() as peer, self.probe(create=True) as alice:
            setup = self.setup(alice, peer)
            altered = tamper(setup["envelope"])
            variants = [("seed-request", receive_action(2, setup["envelope"]), "crypto_request_conflict"),
                        ("same-sequence-conflict", receive_action(1, altered), "receive_sequence_conflict"),
                        ("same-message-conflict", receive_action(2, altered), "receive_message_conflict")]
            for request_id, action, code in variants:
                response = execute(alice, request_id, action)
                failure(response, code, paused=False)
                metrics(response)
                require(inspect(alice) == setup["snapshot"], "预检冲突改变状态")
        return {"conflicts": [row[2] for row in variants], "provider_calls": 0}

    def gap_ordering(self):
        with self.peer() as peer, self.probe(create=True) as alice:
            setup = self.setup(alice, peer)
            envelope, text = self.send(peer, 2)
            response = execute(alice, "gap", receive_action(3, envelope))
            failure(response, "receive_gap", paused=False)
            metrics(response)
            require(inspect(alice) == setup["snapshot"], "跳号拒绝推进了游标")
            value = committed(execute(alice, "next", receive_action(2, envelope)), "receive")
            check_message(value, 2, envelope, text)
            advanced(setup["snapshot"], inspect(alice), 2)
        return {"gap_rejected": True, "next_in_order_accepted": True}

    def routing_rejection(self):
        with self.peer() as peer, self.probe(create=True) as alice:
            setup = self.setup(alice, peer)
            envelope, text = self.send(peer, 2)
            for field in ("service", "conversation"):
                response = execute(alice, f"wrong-{field}", receive_action(2, {**envelope, field: "other-scope"}))
                failure(response, "crypto_scope_mismatch", paused=False)
                metrics(response)
                require(inspect(alice) == setup["snapshot"], "路由拒绝改变数据库")
            value = committed(execute(alice, "correct-route", receive_action(2, envelope)), "receive")
            check_message(value, 2, envelope, text)
        return {"wrong_routes": ["service", "conversation"], "provider_calls_on_rejection": 0}

    def receive_without_group(self):
        with self.probe(create=True) as alice:
            committed(execute(alice, "initialize", {"op": "initialize"}), "initialize")
            before = inspect(alice)
            envelope = {"service": "local-service", "conversation": "synthetic-conversation",
                        "senderAccount": "bob", "senderDevice": "bob-device", "messageId": "no-group",
                        "ciphertext": "AA=="}
            response = execute(alice, "no-group", receive_action(1, envelope))
            failure(response, "crypto_no_group", paused=False)
            metrics(response)
            require(inspect(alice) == before, "无群接收改变了数据库")
        return {"provider_calls": 0, "state_unchanged": True}

    def tampered_ciphertext(self):
        with self.peer() as peer:
            with self.probe(create=True) as alice:
                setup = self.setup(alice, peer)
                envelope, _ = self.send(peer, 2)
                action = receive_action(2, tamper(envelope))
                response = execute(alice, "failure-request", action)
                error = failure(response, "crypto_failed", paused=True)
                metrics(response, restores=1, receives=1)
                after = inspect(alice)
                unchanged(setup["snapshot"], after, pending=True)
                rejected = self.blocked(alice, setup, action)
            with self.probe() as reopened:
                require(inspect(reopened) == after, "密码失败的预约重启丢失")
                rejected += self.blocked(reopened, setup, action)
        return {"error": error, "persistent": after, "pending_rejections": rejected}

    def legacy_format_rejected(self):
        source = (ROOT / "dist/native-storage/crypto/runs/76f754f8-62e0-49b3-a1da-32d2bfa80444"
                  / "normal_restart/state.db")
        require(source.is_file(), "缺少已验收 v1 数据库夹具")
        original = sha(source)
        destination = self.directory / "state.db"
        shutil.copyfile(source, destination)
        destination.chmod(0o600)
        before = sha(destination)
        require(original == before, "旧格式复制摘要不符")
        with self.probe(ready=False) as legacy:
            error = legacy.startup.get("error") or {}
            require(error.get("code") == "crypto_store_upgrade_required", "旧格式未明确拒绝升级")
        require(sha(source) == original and sha(destination) == before, "旧格式拒绝修改了原库或副本")
        return {"fixture": str(source), "fixture_sha256": original, "copy_sha256": before,
                "error": error, "original_and_copy_unchanged": True}
