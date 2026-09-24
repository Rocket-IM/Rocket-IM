"""接收预约、解密、共同提交各窗口的故障及真实进程强杀。"""

from receive_support import (advanced, check_message, committed, execute, failure, inspect,
                             metrics, receive_action, received, unchanged)
from support import require

FAULTS = {"reserve_refuse": ("commit_failed", 531, True),
          "after_reserve": ("crypto_injected_failure", None, True),
          "after_crypto": ("crypto_injected_failure", None, True),
          "after_sql": ("database_error", 1, True),
          "refuse_commit": ("commit_failed", 531, True)}
KILLS = {"kill_after_reserve": ("pause_after_reserve", "after_reserve"),
         "kill_after_crypto": ("pause_after_crypto", "after_crypto"),
         "kill_before_commit": ("before_commit", "before_commit"),
         "kill_after_commit": ("after_commit", "after_commit")}


class FaultCases:
    def failure_window(self, fault):
        code, sqlite_code, paused = FAULTS[fault]
        pending = fault != "reserve_refuse"
        with self.peer() as peer:
            with self.probe(create=True) as alice:
                setup = self.setup(alice, peer)
                envelope, text = self.send(peer, 2)
                action = receive_action(2, envelope)
                response = execute(alice, "failure-request", action, fault)
                error = failure(response, code, sqlite_code, paused)
                computed = fault not in ("reserve_refuse", "after_reserve")
                metrics(response, restores=int(computed), receives=int(computed))
                trace = response.get("trace") or []
                if fault in ("reserve_refuse", "refuse_commit"):
                    require(trace[-2:] == ["COMMIT", "ROLLBACK_AUTOMATIC"],
                            "缺少真实 COMMIT 拒绝和自动回滚证据")
                if fault == "after_sql":
                    require("UPDATE" in trace and trace[-1] == "ROLLBACK", "SQL 写入故障没有回滚")
                after = inspect(alice)
                unchanged(setup["snapshot"], after, pending=pending)
                received(alice, 2)
                rejected = self.blocked(alice, setup, action) if pending else 0
                if not pending:
                    refusal = execute(alice, "same-instance-retry", action)
                    failure(refusal, "crypto_paused", paused=True)
                    metrics(refusal)
                    require(inspect(alice) == after, "预约提交失败实例仍可改变状态")
            with self.probe() as reopened:
                require(inspect(reopened) == after, "失败后重启状态不等于持久化结果")
                received(reopened, 2)
                if pending:
                    rejected += self.blocked(reopened, setup, action)
                else:
                    value = committed(execute(reopened, "failure-request", action), "receive")
                    check_message(value, 2, envelope, text)
                    advanced(after, inspect(reopened), 2)
                    received(reopened, 2, value)
        return {"error": error, "candidate_computed": computed, "persistent": after,
                "pending_rejections": rejected, "restart_verified": True}

    def checkpoint_evidence(self, probe, checkpoint, computes=True):
        marker = probe.checkpoint(checkpoint)
        evidence = marker
        if "metrics" not in evidence:
            candidates = [item["payload"] for item in self.commands
                          if item["pid"] == probe.process.pid and item["direction"] == "stderr"
                          and item["payload"].get("checkpoint") == "candidate_ready"]
            require(len(candidates) == 1, "提交强杀窗口缺少候选调用次数")
            evidence = candidates[0]
        metrics(evidence, restores=int(computes), receives=int(computes))
        return marker, evidence

    def kill_window(self, name):
        fault, checkpoint = KILLS[name]
        with self.peer() as peer:
            with self.probe(create=True) as alice:
                setup = self.setup(alice, peer)
                envelope, text = self.send(peer, 2)
                action = receive_action(2, envelope)
                alice.send({"op": "execute", "request": {"request_id": "crash-request",
                           "action": action, "fault": fault}})
                marker, evidence = self.checkpoint_evidence(alice, checkpoint, checkpoint != "after_reserve")
                alice.crash()
            with self.probe() as reopened:
                recovered = inspect(reopened)
                if checkpoint == "after_commit":
                    advanced(setup["snapshot"], recovered, 2)
                    value = committed(execute(reopened, "crash-request", action), "receive", cached=True)
                    check_message(value, 2, envelope, text)
                    received(reopened, 2, value)
                    again = committed(execute(reopened, "new-crash-retry", action), "receive", cached=True)
                    require(again == value and inspect(reopened) == recovered, "提交后重试重做了解密")
                    rejected = 0
                else:
                    unchanged(setup["snapshot"], recovered, pending=True)
                    rejected = self.blocked(reopened, setup, action, "crash-request")
        return {"checkpoint": marker, "candidate_metrics": evidence["metrics"],
                "recovered": recovered, "pending_rejections": rejected,
                "successful_response_before_kill": False}

    def concurrent_reservation(self):
        with self.peer() as peer:
            with self.probe(create=True) as alice:
                setup = self.setup(alice, peer)
                envelope, _ = self.send(peer, 2)
                action = receive_action(2, envelope)
            with self.probe() as first, self.probe() as second:
                first.send({"op": "execute", "request": {"request_id": "concurrent-request",
                           "action": action, "fault": "pause_after_reserve"}})
                marker, _ = self.checkpoint_evidence(first, "after_reserve", computes=False)
                pending = inspect(second)
                unchanged(setup["snapshot"], pending, pending=True)
                rejected = self.blocked(second, setup, action, "concurrent-request")
                first.crash()
            with self.probe() as reopened:
                require(inspect(reopened) == pending, "并发预约跨进程强杀丢失")
                rejected += self.blocked(reopened, setup, action, "concurrent-request")
        return {"checkpoint": marker, "pending_rejections": rejected, "recovered": pending}

    def duplicate_refuse_commit(self):
        with self.peer() as peer:
            with self.probe(create=True) as alice:
                setup = self.setup(alice, peer)
                action = receive_action(2, setup["envelope"])
                response = execute(alice, "failure-request", action, "refuse_commit")
                error = failure(response, "commit_failed", 531, True)
                metrics(response)
                require(response["trace"][-2:] == ["COMMIT", "ROLLBACK_AUTOMATIC"],
                        "重复消息提交没有真实拒绝证据")
                after = inspect(alice)
                unchanged(setup["snapshot"], after, pending=True)
                rejected = self.blocked(alice, setup, action)
            with self.probe() as reopened:
                require(inspect(reopened) == after, "重复消息未决预约重启丢失")
                rejected += self.blocked(reopened, setup, action)
        return {"error": error, "provider_calls": 0, "recovered": after, "pending_rejections": rejected}

    def duplicate_kill_after_commit(self):
        with self.peer() as peer:
            with self.probe(create=True) as alice:
                setup = self.setup(alice, peer)
                action = receive_action(2, setup["envelope"])
                alice.send({"op": "execute", "request": {"request_id": "duplicate-crash",
                           "action": action, "fault": "after_commit"}})
                marker, evidence = self.checkpoint_evidence(alice, "after_commit", computes=False)
                alice.crash()
            with self.probe() as reopened:
                after = inspect(reopened)
                advanced(setup["snapshot"], after, 2, duplicate=True)
                value = committed(execute(reopened, "duplicate-crash", action), "receive", cached=True,
                                  duplicate=True)
                check_message(value, 2, setup["envelope"], setup["text"], duplicate=True)
                received(reopened, 2, value)
                require(inspect(reopened) == after, "重复消息提交后强杀的重试推进状态")
        return {"checkpoint": marker, "candidate_metrics": evidence["metrics"],
                "recovered": after, "successful_response_before_kill": False}
