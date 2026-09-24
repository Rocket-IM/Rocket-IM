"""真实 OpenMLS 候选与 SQLite 共同提交的有界跨进程场景。"""

from crypto_support import (CryptoProbe, committed, digest, encrypted_state, execute,
                            failure, inspect, metrics, send_action, success, unchanged)
from support import require

FAULTS = {
    "reserve_refuse": ("commit_failed", 531, True),
    "after_reserve": ("crypto_injected_failure", None, True),
    "after_crypto": ("crypto_injected_failure", None, True),
    "after_sql": ("database_error", 1, True),
    "refuse_commit": ("commit_failed", 531, True),
}
KILLS = {"kill_after_reserve": ("pause_after_reserve", "after_reserve"),
         "kill_after_crypto": ("pause_after_crypto", "after_crypto"),
         "kill_before_commit": ("before_commit", "before_commit"),
         "kill_after_commit": ("after_commit", "after_commit")}
CASE_NAMES = ("normal_restart", "idempotent_retries", "preflight_conflicts", "send_without_group",
              *FAULTS, *KILLS, "concurrent_reservation", "scope_and_create", "fault_gate")


class Cases:
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

    def receive(self, peer, envelope, text):
        message = success(peer.request("peer_receive", envelope=envelope))
        require(message["text"] == text and message["messageId"] == envelope["messageId"]
                and message["senderAccount"] == "alice", "内存接收方解密结果不匹配")
        return digest(message["text"])

    def setup(self, alice, peer):
        initial = inspect(alice)
        require(initial["revision"] == "0" and initial["identity"] is None
                and initial["pending"] is None and initial["outbox"] == [], "新库不是空状态")
        identity = committed(execute(alice, "initialize", {"op": "initialize"}), "initialize")
        peer_identity = success(peer.request("peer_identity"))
        group = {"op": "create_group", "conversation": "synthetic-conversation", "peer": peer_identity}
        welcome = committed(execute(alice, "create-group", group), "create_group")
        success(peer.request("peer_join", conversation=group["conversation"],
                             peer=identity, welcome=welcome["welcome"]))
        seed = send_action("seed-attempt", "seed-message", "合成已提交正文🙂")
        envelope = committed(execute(alice, "seed-request", seed), "send")
        self.receive(peer, envelope, seed["text"])
        return {"group": group, "seed": seed, "envelope": envelope, "snapshot": inspect(alice)}

    def blocked(self, probe, setup, failed_request="failure-request", failed_action=None):
        action = failed_action or send_action()
        before = inspect(probe)
        variants = [(failed_request, action), ("retry-same-attempt", action),
                    ("retry-new-attempt", send_action("fresh-attempt", "fresh-message")),
                    ("retry-initialize", {"op": "initialize"}),
                    ("retry-group", setup["group"]), ("seed-request", setup["seed"]),
                    ("initialize", {"op": "initialize"})]
        for request_id, value in variants:
            response = execute(probe, request_id, value)
            failure(response, "crypto_pending", paused=True)
            metrics(response)
            require(inspect(probe) == before, "暂停拒绝改变了预约或旧持久状态")
        return len(variants)

    def run(self, name):
        if name in FAULTS:
            return self.failure_window(name)
        if name in KILLS:
            return self.kill_window(name)
        return getattr(self, name)()

    def normal_restart(self):
        received = []
        with self.peer() as peer:
            with self.probe(create=True) as alice:
                setup = self.setup(alice, peer)
                previous = setup["snapshot"]
                for number in (1, 2, 3):
                    action = send_action(f"attempt-{number}", f"message-{number}", f"正常中文🙂\u0000{number}")
                    envelope = committed(execute(alice, f"send-{number}", action), "send")
                    after = inspect(alice)
                    encrypted_state(previous, after, envelope)
                    received.append(self.receive(peer, envelope, action["text"]))
                    previous = after
            with self.probe() as reopened:
                require(inspect(reopened) == previous, "重开后 provider 或待发送密文不一致")
                action = send_action("attempt-4", "message-4", "重开后继续发送")
                envelope = committed(execute(reopened, "send-4", action), "send")
                after = inspect(reopened)
                encrypted_state(previous, after, envelope)
                received.append(self.receive(peer, envelope, action["text"]))
        return {"received": received, "final": after, "restart_continued": True}

    def idempotent_retries(self):
        retries = []
        with self.peer() as peer:
            with self.probe(create=True) as alice:
                setup = self.setup(alice, peer)
                for request_id in ("seed-request", "same-attempt-new-request"):
                    envelope = committed(execute(alice, request_id, setup["seed"]), "send", cached=True)
                    require(envelope == setup["envelope"], "同一次发送重试没有复用原密文字节")
                    require(inspect(alice) == setup["snapshot"], "缓存重试推进了持久状态")
                    retries.append(request_id)
            with self.probe() as reopened:
                for request_id in ("seed-request", "restart-new-request"):
                    envelope = committed(execute(reopened, request_id, setup["seed"]), "send", cached=True)
                    require(envelope == setup["envelope"], "重启缓存重试重算了密文")
                    require(inspect(reopened) == setup["snapshot"], "重启重试推进了状态")
                    retries.append(request_id)
        return {"retries": retries, "state_unchanged": True, "ciphertext_equal": True}

    def preflight_conflicts(self):
        with self.peer() as peer, self.probe(create=True) as alice:
            setup = self.setup(alice, peer)
            variants = [("seed-request", {**setup["seed"], "text": "另一正文"}, "crypto_request_conflict"),
                        ("attempt-conflict", {**setup["seed"], "text": "另一正文"}, "crypto_attempt_conflict"),
                        ("message-conflict", {**setup["seed"], "attempt_id": "another-attempt"},
                         "crypto_message_conflict")]
            for request_id, action, code in variants:
                response = execute(alice, request_id, action)
                failure(response, code, paused=False)
                metrics(response)
                require(inspect(alice) == setup["snapshot"], "预检冲突改变了数据库")
        return {"conflicts": [row[2] for row in variants], "provider_calls": 0}

    def send_without_group(self):
        with self.probe(create=True) as alice:
            committed(execute(alice, "initialize", {"op": "initialize"}), "initialize")
            before = inspect(alice)
            response = execute(alice, "send-no-group", send_action())
            failure(response, "crypto_no_group", paused=False)
            metrics(response)
            require(inspect(alice) == before, "缺少群时仍预约或改变状态")
        return {"provider_calls": 0, "state_unchanged": True}

    def failure_window(self, fault):
        code, sqlite_code, paused = FAULTS[fault]
        pending = fault != "reserve_refuse"
        with self.peer() as peer:
            with self.probe(create=True) as alice:
                setup = self.setup(alice, peer)
                response = execute(alice, "failure-request", send_action(), fault)
                error = failure(response, code, sqlite_code, paused)
                computed = fault not in ("reserve_refuse", "after_reserve")
                metrics(response, restores=int(computed), sends=int(computed))
                trace = response.get("trace") or []
                if fault in ("reserve_refuse", "refuse_commit"):
                    require(trace[-2:] == ["COMMIT", "ROLLBACK_AUTOMATIC"],
                            "没有真实 COMMIT 拒绝及自动回滚证据")
                if fault == "after_sql":
                    require("UPDATE" in trace and trace[-1] == "ROLLBACK",
                            "SQL 故障前没有真实写入，或未回滚")
                after = inspect(alice)
                unchanged(setup["snapshot"], after, pending=pending)
                rejected = self.blocked(alice, setup) if pending else 0
                if not pending:
                    refusal = execute(alice, "refused-instance-retry", send_action())
                    failure(refusal, "crypto_paused", paused=True)
                    metrics(refusal)
                    require(inspect(alice) == after, "预约提交失败的实例仍修改了原态")
            with self.probe() as reopened:
                require(inspect(reopened) == after, "重启没有保留准确的失败/预约状态")
                if pending:
                    rejected += self.blocked(reopened, setup)
                else:
                    envelope = committed(execute(reopened, "failure-request", send_action()), "send")
                    encrypted_state(after, inspect(reopened), envelope)
                    self.receive(peer, envelope, send_action()["text"])
        return {"error": error, "candidate_computed": computed, "persistent": after,
                "pending_rejections": rejected, "restart_verified": True}

    def kill_window(self, name):
        fault, checkpoint = KILLS[name]
        with self.peer() as peer:
            with self.probe(create=True) as alice:
                setup = self.setup(alice, peer)
                alice.send({"op": "execute", "request": {"request_id": "crash-request",
                           "action": send_action(), "fault": fault}})
                marker = alice.checkpoint(checkpoint)
                evidence = marker
                if "metrics" not in evidence:
                    candidates = [item["payload"] for item in self.commands
                                  if item["pid"] == alice.process.pid and item["direction"] == "stderr"
                                  and item["payload"].get("checkpoint") == "candidate_ready"]
                    require(len(candidates) == 1, "强杀提交窗口缺少候选计算次数证据")
                    evidence = candidates[0]
                computed = checkpoint != "after_reserve"
                metrics(evidence, restores=int(computed), sends=int(computed))
                alice.crash()
            with self.probe() as reopened:
                recovered = inspect(reopened)
                if checkpoint == "after_commit":
                    require(recovered["pending"] is None, "已提交后强杀残留预约")
                    envelope = committed(execute(reopened, "crash-request", send_action()), "send", cached=True)
                    encrypted_state(setup["snapshot"], recovered, envelope)
                    require(inspect(reopened) == recovered, "提交后重试推进密码状态")
                    self.receive(peer, envelope, send_action()["text"])
                    again = committed(execute(reopened, "new-crash-retry", send_action()), "send", cached=True)
                    require(again == envelope and inspect(reopened) == recovered, "新 request 重算密文")
                    rejected = 0
                else:
                    unchanged(setup["snapshot"], recovered, pending=True)
                    rejected = self.blocked(reopened, setup, "crash-request")
        return {"checkpoint": marker, "candidate_metrics": evidence["metrics"],
                "recovered": recovered, "pending_rejections": rejected,
                "successful_response_before_kill": False}

    def concurrent_reservation(self):
        with self.peer() as peer:
            with self.probe(create=True) as alice:
                setup = self.setup(alice, peer)
            with self.probe() as first, self.probe() as second:
                first.send({"op": "execute", "request": {"request_id": "concurrent-request",
                           "action": send_action(), "fault": "pause_after_reserve"}})
                marker = first.checkpoint("after_reserve")
                metrics(marker)
                pending = inspect(second)
                unchanged(setup["snapshot"], pending, pending=True)
                rejected = self.blocked(second, setup, "concurrent-request")
                first.crash()
            with self.probe() as reopened:
                require(inspect(reopened) == pending, "并发预约跨强杀丢失")
                rejected += self.blocked(reopened, setup, "concurrent-request")
        return {"checkpoint": marker, "pending_rejections": rejected, "recovered": pending}

    def scope_and_create(self):
        rejected = []
        with self.probe(ready=False) as absent:
            require(absent.startup["error"]["code"] == "crypto_store_missing", "缺库没有明确拒绝")
            rejected.append(absent.startup["error"])
        with self.probe(create=True) as alice:
            committed(execute(alice, "initialize", {"op": "initialize"}), "initialize")
            before = inspect(alice)
        with self.probe(create=True, ready=False) as duplicate:
            require(duplicate.startup["error"]["code"] == "crypto_store_exists", "已有库仍允许 create")
            rejected.append(duplicate.startup["error"])
        for options in ({"service": "other-service"}, {"account": "other-account"},
                        {"device": "other-device"}):
            with self.probe(ready=False, **options) as wrong:
                require(wrong.startup["error"]["code"] == "crypto_scope_mismatch", "范围错配未明确拒绝")
                rejected.append(wrong.startup["error"])
        with self.probe() as reopened:
            require(inspect(reopened) == before, "启动拒绝修改了原库")
        return {"startup_rejections": rejected, "original_state_unchanged": True}

    def fault_gate(self):
        with self.probe(create=True, test=False) as alice:
            before = inspect(alice)
            response = execute(alice, "forbidden-fault", {"op": "initialize"}, "after_reserve")
            failure(response, "test_mode_required", paused=False)
            metrics(response)
            require(inspect(alice) == before, "未启用测试模式仍触发故障预约")
            committed(execute(alice, "initialize", {"op": "initialize"}), "initialize")
        return {"fault_rejected_without_test_mode": True, "provider_calls_on_rejection": 0}
