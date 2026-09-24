"""候选、唯一关联、真实入群和确认窗口的真实 SIGKILL。"""

from crypto_support import success
from rebuild_support import committed, metrics, plan_digest, rejected
from support import require, sha

KILL_CASES = {
    "kill_after_slot": ("prepare", "after_slot", False),
    "kill_after_identity": ("prepare", "after_identity", True),
    "kill_after_plan": ("prepare", "after_plan", True),
    "kill_after_link": ("activate", "after_link", True),
    "kill_after_join_reserve": ("activate", "after_join_reserve", False),
    "kill_after_join_crypto": ("activate", "after_join_crypto", False),
    "kill_before_join_commit": ("activate", "before_join_commit", False),
    "kill_after_join_commit": ("activate", "after_join_commit", True),
    "kill_after_join_finish": ("activate", "after_join_finish", True),
    "kill_after_active": ("activate", "after_active", True),
}


class FaultCases:
    def killed_rebuild(self, name):
        operation, stage, resumable = KILL_CASES[name]
        self.bootstrap()
        prepared, material = None, None
        with self.probe() as candidate:
            if operation == "activate":
                prepared = self.prepare(candidate)
                material = self.approve(prepared)
                candidate.send({"op": "activate", "material": material, "fault": stage})
            else:
                candidate.send({"op": "prepare", "fault": stage})
            marker = candidate.checkpoint(stage)
            if stage in ("after_identity", "after_plan"):
                metrics(marker, news=1)
            elif stage in ("after_join_crypto", "before_join_commit", "after_join_commit", "after_join_finish", "after_active"):
                metrics(marker, restores=1, joins=1)
            else:
                metrics(marker)
            candidate.crash()
        preserved_hash = sha(self.candidate)
        with self.probe() as resumed:
            if not resumable:
                code = "rebuild_initialization_unresolved" if stage == "after_slot" else "rebuild_join_unresolved"
                request = {"fault": "none"}
                if material is not None:
                    request["material"] = material
                error = rejected(resumed.request(operation, **request), code)
                self.gates(resumed)
                # 再次恢复仍不能重新生成身份或密码状态。
                rejected(resumed.request(operation, **request), code)
                result = {"error": error, "remains_paused": True}
            else:
                if prepared is None:
                    saved = success(resumed.request("status"))
                    prepared = self.prepare(resumed)
                    require(saved["identity"] == prepared["identity"], "中断后重新生成设备身份")
                    if saved["plan"] is not None:
                        require(saved["plan"] == prepared["plan"], "中断后重新生成已保存计划")
                    second = self.prepare(resumed)
                    require(second == prepared, "恢复后重复prepare改变身份")
                    material = self.approve(prepared)
                else:
                    state = success(resumed.request("status"))
                    require(state["plan"] == prepared["plan"], "恢复改用另一计划")
                reply = self.activate(resumed, material)
                if stage in ("after_join_commit", "after_join_finish", "after_active"):
                    metrics(reply)
                    require(reply["events"] == [], "恢复已提交入群或激活重复派发事件")
                else:
                    metrics(reply, restores=1, joins=1)
                duplicate = self.activate(resumed, material)
                metrics(duplicate)
                require(duplicate["events"] == [], "重复恢复发布成功事件")
                result = {"same_plan_sha256": plan_digest(prepared["plan"]),
                          "successor_identity_key": prepared["identity"]["identityKey"],
                          "recovery_metrics": reply["metrics"], "exact_saved_material_reused": True}
        if not resumable:
            require(sha(self.candidate) == preserved_hash, "未决窗口被自动清除或重写")
        return {"checkpoint": marker, "resumable_from_committed_state": resumable,
                "no_success_response_before_kill": True, **result, **self.old_preserved()}

    def source_approval_result_lost(self):
        self.bootstrap()
        with self.probe() as candidate:
            prepared = self.prepare(candidate)
        with self.source.probe() as source:
            source.send({"op": "rebuild_approve", "plan": prepared["plan"], "peer": prepared["identity"],
                         "confirm_plan_sha256": plan_digest(prepared["plan"]), "fault": "none",
                         "anchor_fault": "pause_after_candidate_commit"})
            marker = source.checkpoint("after_candidate_commit")
            metrics(marker, restores=1)
            source.crash()
        with self.source.probe() as source:
            reply = source.request("recover")
            result = success(reply)
            metrics(reply)
            require(reply["events"] == [], "source Add恢复重复发布事件")
            require(result["value"]["kind"] == "rebuild_add", "恢复不是原Add结果")
            material = result["value"]["value"]
            duplicate = self.approve(prepared, source=source, cached=True)
            require(duplicate == material, "丢响应后重新计算Add或签名材料")
        with self.probe() as candidate:
            self.activate(candidate, material)
            with self.source.probe() as source:
                exchange = self.bidirectional(candidate, source)
        return {"checkpoint": marker, "source_recovery_crypto_calls": 0,
                "same_add_material_reused": True, "exchange": exchange}

    def source_approval_finish_reply_lost(self):
        self.bootstrap()
        with self.probe() as candidate:
            prepared = self.prepare(candidate)
        with self.source.probe(failpoint="after_finish_save") as source:
            reply = source.request("rebuild_approve", plan=prepared["plan"], peer=prepared["identity"],
                                   confirm_plan_sha256=plan_digest(prepared["plan"]), fault="none", anchor_fault="none")
            error = rejected(reply, measured=True)
            metrics(reply, restores=1)
        with self.source.probe() as source:
            reply = source.request("recover")
            result = success(reply)
            metrics(reply)
            require(reply["events"] == [], "Finish结果丢失恢复重复发布事件")
            material = result["value"]["value"]
            require(self.approve(prepared, source=source, cached=True) == material, "Finish恢复重跑Add")
        with self.probe() as candidate:
            self.activate(candidate, material)
        return {"error": error, "finish_saved_response_lost": True,
                "exact_source_recovery_crypto_calls": 0}

    def refuse_join_commit(self):
        self.bootstrap()
        with self.probe() as candidate:
            prepared = self.prepare(candidate)
            material = self.approve(prepared)
            reply = candidate.request("activate", material=material, fault="refuse_join_commit")
            error = rejected(reply, measured=True)
            metrics(reply, restores=1, joins=1)
            self.gates(candidate)
        with self.probe() as candidate:
            rejected(candidate.request("activate", material=material, fault="none"), "rebuild_join_unresolved")
            self.gates(candidate)
        return {"error": error, "actual_commit_rejected": True, "no_success_event": True,
                "uncommitted_join_not_recomputed": True}
