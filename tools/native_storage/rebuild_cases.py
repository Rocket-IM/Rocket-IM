"""原生候选门禁、身份绑定、唯一后继和实际新群双向收发。"""

import base64
import copy
import json
import shutil

from anchor_support import execute, send_action
from crypto_support import CryptoProbe, failure, success
from rebuild_faults import FaultCases, KILL_CASES
from rebuild_support import (RebuildFixture, committed, metrics, plan_digest,
                             rejected, save_database)
from support import require, sha

MATERIAL_CASES = ("wrong_welcome", "wrong_commit", "wrong_admission_signature",
                  "wrong_approval_signature", "wrong_admission_target", "late_other_plan")
CASE_NAMES = ("approval_gate_and_real_bidirectional", "duplicate_prepare_approval_activation",
              "missing_precommitted_trust", "late_trust_substitution", "wrong_confirmation",
              "wrong_candidate_public_key", "wrong_candidate_key_package", "wrong_target_checkpoint",
              "source_unresolved_cannot_approve", "old_complete_journal_requires_exact_recover",
              "concurrent_candidates_single_successor", "old_entry_and_candidate_plain_entry_rejected",
              "active_complete_snapshot_rollback", *MATERIAL_CASES, *KILL_CASES,
              "source_approval_result_lost", "source_approval_finish_reply_lost", "refuse_join_commit",
              "old_history_envelope_rejected_after_activation")


def change_signature(signed):
    changed = copy.deepcopy(signed)
    raw = bytearray(base64.b64decode(changed["signature_bytes"], validate=True))
    raw[0] ^= 1
    changed["signature_bytes"] = base64.b64encode(raw).decode()
    return changed


class Cases(RebuildFixture, FaultCases):
    def run(self, name):
        if name in KILL_CASES:
            return self.killed_rebuild(name)
        if name in MATERIAL_CASES:
            return self.wrong_material(name)
        if name in ("wrong_candidate_public_key", "wrong_candidate_key_package", "wrong_target_checkpoint"):
            return self.wrong_candidate(name)
        return getattr(self, name)()

    def gates(self, probe):
        record = {"sequence": "1", "envelope": self.gate_envelope}
        replies = [execute(probe, "forbidden-initialize", {"op": "initialize"}),
                   execute(probe, "forbidden-send", send_action()),
                   execute(probe, "forbidden-receive", {"op": "receive", **record}),
                   probe.request("download", request={"records": [record], "fault": "none"}),
                   probe.request("process", request_id="forbidden-process", sequence="1",
                                 fault="none", anchor_fault="none"),
                   probe.request("received", sequence="1")]
        return [rejected(reply) for reply in replies]

    def approval_gate_and_real_bidirectional(self):
        self.bootstrap()
        with self.probe() as candidate:
            before_errors = self.gates(candidate)
            prepared = self.prepare(candidate)
            after_errors = self.gates(candidate)
            require(prepared["plan"]["old_scope"]["identity_key"] != prepared["plan"]["successor_scope"]["identity_key"], "新设备沿用了旧密码公钥")
            require(prepared["plan"]["trust"] == self.trust, "计划未使用故障前固定来源")
            material = self.approve(prepared)
            activated = self.activate(candidate, material)
            metrics(activated, restores=1, joins=1)
            fresh = success(candidate.request("inspect"))["snapshot"]
            require(fresh["inbox"] == fresh["outbox"] == fresh["downloads"] == [], "新范围复制了旧历史、待发送或下载记录")
            require(fresh["processed_cursor"] == fresh["download_cursor"] == "0", "新范围沿用了旧双游标")
            require(fresh["encryptions"] == fresh["decryptions"] == "0", "新范围沿用了旧收发代数")
            with self.source.probe() as source:
                exchange = self.bidirectional(candidate, source)
        preserved = self.old_preserved()
        require(preserved["old_anchor_fact"]["closure"] == "rebuilt", "旧scope未永久封存")
        with self.probe() as restarted:
            state = success(restarted.request("status"))
            require(state["stage"] == "active", "新范围重启丢失激活")
        return {"before_candidate_gate_errors": before_errors, "before_approval_gate_errors": after_errors,
                "plan_sha256": plan_digest(prepared["plan"]), "exchange": exchange,
                "old_history_snapshot": self.old_history["snapshot"], "fresh_successor_snapshot": fresh, **preserved}

    def old_history_envelope_rejected_after_activation(self):
        self.bootstrap()
        with self.probe() as candidate:
            prepared = self.prepare(candidate)
            material = self.approve(prepared)
            self.activate(candidate, material)
            before = success(candidate.request("inspect"))["snapshot"]
            anchor = success(candidate.request("status"))
            envelope = self.old_history["incoming"]
            rejected_reply = execute(candidate, "reject-old-history", {"op": "receive", "sequence": "1", "envelope": envelope})
            error = failure(rejected_reply, "crypto_scope_mismatch", paused=False)
            metrics(rejected_reply)
            downloaded = candidate.request("download", request={"records": [{"sequence": "1", "envelope": envelope}], "fault": "none"})
            download_error = failure(downloaded, "crypto_scope_mismatch", paused=False)
            metrics(downloaded)
            after = success(candidate.request("inspect"))["snapshot"]
            require(after == before, "旧历史入口拒绝仍写入消息或推进双游标")
            require(after["inbox"] == after["downloads"] == [] and after["download_cursor"] == after["processed_cursor"] == "0", "旧历史进入新范围")
            require(success(candidate.request("status")) == anchor, "旧范围拒绝消耗新范围预约")
        with self.probe() as restarted, self.source.probe() as source:
            require(success(restarted.request("inspect"))["snapshot"] == before,
                    "拒绝后重启改变新范围业务状态")
            exchange = self.bidirectional(restarted, source)
        return {"receive_error": error, "download_error": download_error,
                "new_scope_healthy_after_restart": True, "exchange": exchange,
                "same_new_snapshot": True, "preserved_old_database_sha256": self.original_hash}

    def duplicate_prepare_approval_activation(self):
        self.bootstrap()
        with self.probe() as candidate:
            prepared = self.prepare(candidate)
            again = self.prepare(candidate)
            require(again == prepared, "重复prepare生成新计划或新身份")
            material = self.approve(prepared)
            duplicate = self.approve(prepared, cached=True)
            require(duplicate == material, "重复批准没有返回原Commit/Welcome与签名")
            self.activate(candidate, material)
            duplicate_activation = self.activate(candidate, material)
            metrics(duplicate_activation)
            require(duplicate_activation["events"] == [], "重复激活重复派发成功事件")
        with self.probe() as restarted:
            resumed = self.prepare(restarted)
            require(resumed["plan"] == prepared["plan"] and resumed["identity"] == prepared["identity"], "重启后改变计划或身份")
            again = self.activate(restarted, material)
            metrics(again)
        return {"plan_sha256": plan_digest(prepared["plan"]), "exact_material_reused": True,
                "duplicate_crypto_calls": 0, **self.old_preserved()}

    def missing_precommitted_trust(self):
        self.bootstrap(trust=False)
        with self.probe() as candidate:
            error = rejected(candidate.request("prepare", fault="none"))
        require(not self.candidate.exists(), "没有故障前信任仍创建了新设备库")
        return {"error": error, "candidate_created": False}

    def late_trust_substitution(self):
        self.bootstrap()
        changed = copy.deepcopy(self.old.config)
        changed["rebuild_trust"]["checkpoint"]["crypto_state_ref"] = "fa" * 32
        self.old.write_config(changed)
        with self.probe(ready=None) as candidate:
            startup = candidate.next_stdout()
            if startup.get("ready") is True:
                candidate.ready = True
                error = rejected(candidate.request("prepare", fault="none"))
            else:
                require(startup.get("ready") is False and startup.get("error"), "替换信任未明确拒绝")
                error = startup["error"]
                candidate.finish(1)
        require(not self.candidate.exists(), "故障后替换信任创建了新候选")
        return {"error": error, "late_trust_refused": True}

    def wrong_confirmation(self):
        self.bootstrap()
        with self.probe() as candidate:
            prepared = self.prepare(candidate)
        with self.source.probe() as source:
            error = rejected(source.request("rebuild_approve", plan=prepared["plan"], peer=prepared["identity"],
                             confirm_plan_sha256="00" * 32, fault="none", anchor_fault="none"),
                             "rebuild_confirmation_required")
            material = self.approve(prepared, source=source)
        with self.probe() as candidate:
            self.activate(candidate, material)
        return {"error": error, "correct_confirmation_still_works": True}

    def wrong_candidate(self, name):
        self.bootstrap()
        with self.probe() as candidate:
            prepared = self.prepare(candidate)
            altered = copy.deepcopy(prepared)
            if name == "wrong_candidate_public_key":
                altered["identity"]["identityKey"] = self.source.identity["identityKey"]
            elif name == "wrong_candidate_key_package":
                altered["identity"]["keyPackage"] = self.old.identity["keyPackage"]
            else:
                altered["plan"]["trust"]["checkpoint"]["crypto_state_ref"] = "fb" * 32
            with self.source.probe() as source:
                reply = source.request("rebuild_approve", plan=altered["plan"], peer=altered["identity"],
                                       confirm_plan_sha256=plan_digest(altered["plan"]),
                                       fault="none", anchor_fault="none")
                error = rejected(reply, measured=True)
            self.gates(candidate)
        return {"error": error, "invalid_candidate_never_admitted": True}

    def source_unresolved_cannot_approve(self):
        self.bootstrap()
        with self.probe() as candidate:
            prepared = self.prepare(candidate)
        with self.source.probe() as source:
            source.send({"op": "execute", "request": {"request_id": "uncertain-source",
                        "action": send_action(), "fault": "none"}, "anchor_fault": "pause_after_anchor_reserve"})
            marker = source.checkpoint("after_anchor_reserve")
            source.crash()
        with self.source.probe() as source:
            error = rejected(source.request("rebuild_approve", plan=prepared["plan"], peer=prepared["identity"],
                             confirm_plan_sha256=plan_digest(prepared["plan"]), fault="none", anchor_fault="none"))
        return {"source_checkpoint": marker, "error": error, "old_signature_or_login_not_used": True}

    def old_complete_journal_requires_exact_recover(self):
        self.bootstrap(unresolved=False)
        self.interrupt_old("pause_after_candidate_commit", "after_candidate_commit")
        with self.probe() as candidate:
            error = rejected(candidate.request("prepare", fault="none"), "anchor_recovery_required")
        require(not self.candidate.exists(), "有完整旧日志仍创建后继")
        with self.old.probe() as old:
            recovery = old.request("recover")
            result = success(recovery)
            metrics(recovery)
            require(recovery["events"] == [], "精确恢复重复发布成功事件")
            require(result["value"]["kind"] == "send", "没有恢复原发送结果")
            cached = committed(execute(old, "uncertain-old-send", send_action("old-attempt", "old-message")), "send", cached=True)
            require(cached == result["value"]["value"], "精确恢复改变原密文")
        return {"error": error, "exact_old_recovery_without_crypto": True}

    def concurrent_candidates_single_successor(self):
        self.bootstrap()
        second_path = self.directory / "second-successor.db"
        with self.probe() as first, self.probe(candidate=second_path, device="alice-second") as second:
            # 初始材料顺序落盘；真正竞争的是两个来源进程同时批准。
            # helper 的非等待锁允许并发 Inspect 返回 busy，不把它当双成功保证。
            a, b = self.prepare(first), self.prepare(second)
            require(a["plan"]["successor_scope"] != b["plan"]["successor_scope"], "竞争装置没有独立候选")
            with self.source.probe() as source_a, self.source.probe() as source_b:
                for source, prepared in ((source_a, a), (source_b, b)):
                    source.send({"op": "rebuild_approve", "plan": prepared["plan"], "peer": prepared["identity"],
                                 "confirm_plan_sha256": plan_digest(prepared["plan"]),
                                 "fault": "none", "anchor_fault": "none"})
                replies = [source_a.next_stdout(), source_b.next_stdout()]
                winners = [index for index, reply in enumerate(replies) if reply.get("ok") is True]
                require(len(winners) == 1, "两个并发来源批准未产生唯一成功结果")
                winner = winners[0]
                material = committed(replies[winner], "rebuild_add")
                source_error = rejected(replies[1 - winner], measured=True)
            candidates, plans = [first, second], [a, b]
            self.activate(candidates[winner], material)
            loser = rejected(candidates[1 - winner].request("activate", material=material, fault="none"))
            self.gates(candidates[1 - winner])
        return {"winner_plan_sha256": plan_digest(plans[winner]["plan"]), "loser_plan_sha256": plan_digest(plans[1 - winner]["plan"]),
                "loser_error": loser, "second_approval_error": source_error,
                "candidate_materials_prepared_sequentially": True,
                "two_live_source_processes_sent_before_reading": True,
                "legal_successor_count": 1, **self.old_preserved()}

    def old_entry_and_candidate_plain_entry_rejected(self):
        self.bootstrap()
        with self.probe() as candidate:
            prepared = self.prepare(candidate)
            material = self.approve(prepared)
            self.activate(candidate, material)
        with CryptoProbe(self.old.native, self.old.database, self.directory, self.commands,
                         device="alice-old", flags=("--test-mode",), ready=False) as old:
            old_error = old.startup["error"]
        with CryptoProbe(self.old.native, self.candidate, self.directory, self.commands,
                         device="alice-successor", flags=("--test-mode",), ready=False) as new:
            candidate_error = new.startup["error"]
        return {"ordinary_old_entry_error": old_error, "ordinary_successor_entry_error": candidate_error,
                **self.old_preserved()}

    def active_complete_snapshot_rollback(self):
        self.bootstrap()
        with self.probe() as candidate:
            prepared = self.prepare(candidate)
            material = self.approve(prepared)
            self.activate(candidate, material)
        backup = self.directory / "old-active-copy.db"
        saved_hash = save_database(self.candidate, backup)
        with self.probe() as candidate:
            committed(execute(candidate, "advance-new", send_action()), "send")
        require(sha(self.candidate) != saved_hash, "新库没有实际推进")
        shutil.copyfile(backup, self.candidate)
        with self.probe() as restored:
            error = rejected(execute(restored, "after-rollback", send_action()))
            errors = self.gates(restored)
        return {"snapshot_sha256": saved_hash, "error": error, "old_active_copy_blocked": errors}

    def wrong_material(self, name):
        self.bootstrap()
        with self.probe() as candidate:
            prepared = self.prepare(candidate)
            original = self.approve(prepared)
            changed = copy.deepcopy(original)
            if name in ("wrong_welcome", "wrong_commit"):
                field = name.removeprefix("wrong_")
                raw = bytearray(base64.b64decode(changed[field], validate=True))
                raw[-1] ^= 1
                changed[field] = base64.b64encode(raw).decode()
            elif name in ("wrong_admission_signature", "wrong_approval_signature"):
                field = name.split("_")[1]
                changed[field] = change_signature(changed[field])
            else:
                field = "admission" if name == "wrong_admission_target" else "approval"
                statement = json.loads(base64.b64decode(changed[field]["statement_bytes"], validate=True))
                if field == "admission":
                    statement["checkpoint_after"]["conversation_id"] = "other-target"
                else:
                    statement["rebuild_id"] = "fc" * 32
                changed[field]["statement_bytes"] = base64.b64encode(json.dumps(statement).encode()).decode()
            error = rejected(candidate.request("activate", material=changed, fault="none"))
            self.gates(candidate)
            self.activate(candidate, original)
        return {"error": error, "valid_original_still_activates": True,
                "plan_sha256": plan_digest(prepared["plan"])}
