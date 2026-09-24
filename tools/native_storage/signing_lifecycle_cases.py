"""签名升级的混合版本安全重建与实际 SIGKILL 结果恢复场景。"""

from anchor_support import download, execute, process, snapshot, status
from crypto_support import send_action, success
from download_support import saved
from protected_support import RebuildFixture
from rebuild_support import committed, metrics, plan_digest, rejected
from support import require, sha


class RecoveryCases:
    def mixed_rebuild_upgrade(self):
        fixture = RebuildFixture.__new__(RebuildFixture)
        fixture.directory, fixture.commands = self.directory, self.commands
        fixture.rebuild_binary = self.v1[3]
        fixture.old = self.fixture("old", "alice-old")
        fixture.source = self.fixture("source", "alice-source")
        fixture.candidate = self.directory / "successor.db"
        fixture._candidate_locators = {}
        fixture.bootstrap()
        with fixture.probe() as old_candidate:
            prepared = fixture.prepare(old_candidate)
            prepare_pid = old_candidate.process.pid
        original_plan = plan_digest(prepared["plan"])
        self.switch(fixture.old)
        fixture.source.native, fixture.source.protection = self.v2[1], self.v2[4]
        fixture.rebuild_binary = self.v2[3]
        with self.native(fixture.source, ready=False) as native:
            native_pid = native.process.pid
            require(native.startup["error"]["code"] == "anchor_required",
                    "已绑定来源经过 v2 原生入口时没有维持锚强制边界")
        # 来源仍运行 v1 anchored，候选由 v2 rebuild 激活；两端均读旧 ACL。
        with fixture.source.probe() as source:
            approve_pid = source.process.pid
            material = fixture.approve(prepared, source=source)
            with fixture.probe() as candidate:
                activate_pid = candidate.process.pid
                resumed = fixture.prepare(candidate)
                require(resumed == prepared, "v2 prepare 改变了 v1 保存的计划或身份")
                activated = fixture.activate(candidate, material)
                metrics(activated, restores=1, joins=1)
                fresh = success(candidate.request("inspect"))["snapshot"]
                require(fresh["inbox"] == fresh["outbox"] == fresh["downloads"] == [],
                        "重建候选错误复制旧数据")
                require(fresh["download_cursor"] == fresh["processed_cursor"] == "0", "新身份沿用旧游标")
                exchange = fixture.bidirectional(candidate, source)
                after = success(candidate.request("inspect"))["snapshot"]
        preserved = fixture.old_preserved()
        protection_audit = fixture.source.ctl("audit", paths=[str(fixture.source.database)])["result"]
        require(protection_audit["no_secret_matches"], "混合版本来源库包含未保护审计样本")
        with fixture.probe() as restarted:
            require(success(restarted.request("status"))["stage"] == "active", "重启丢失混合版本激活状态")
            require(success(restarted.request("inspect"))["snapshot"] == after, "候选重启改变真实互通结果")
        return {"pids": {"v1_prepare": prepare_pid, "v1_source_approval": approve_pid,
                         "v2_activate": activate_pid, "v2_native_bound_gate": native_pid},
                "mixed_roles": {"native_crypto": "v2", "native_anchored_source": "v1",
                                "native_rebuild": "v2", "native_protection": "v2"},
                "plan_sha256": original_plan, "same_prepared_identity_and_plan": True,
                "v2_native_enforced_anchor_required": True, "v2_protection_audit": protection_audit,
                "fresh_successor_snapshot": fresh, "after_bidirectional_snapshot": after,
                "exchange": exchange, **preserved}

    def committed_receive_upgrade_recovery(self):
        fixture = self.fixture()
        fixture.bootstrap()
        with fixture.peer() as peer, fixture.probe() as old:
            data = fixture.setup(old, peer, records=1)
            saved(download(old, data["records"]), 1, 0, 1)
            old.send({"op": "process", "request_id": "upgrade-receive-once", "sequence": "1",
                      "fault": "none", "anchor_fault": "pause_after_candidate_commit"})
            marker = old.checkpoint("after_candidate_commit")
            metrics(marker, restores=1, receives=1)
            old.crash()
        saved_database = fixture.save_closed("v1-committed-before-upgrade.db")
        before_hash = sha(fixture.database)
        self.switch(fixture)
        fixture.ctl("keychain_lock")
        error = self.refused(fixture)
        self.unchanged(fixture, before_hash)
        fixture.ctl("keychain_unlock")
        with fixture.probe() as upgraded:
            before = snapshot(upgraded)
            reply = upgraded.request("recover")
            value = success(reply)
            metrics(reply)
            require(reply["events"] == [] and value["kind"] == "execute", "恢复类型不符或重复派发成功事件")
            outcome = value["value"]
            require(outcome["kind"] == "receive" and outcome["cached"] is False, "恢复未返回原接收提交")
            exact = outcome["value"]
            require(exact["message"] == {"messageId": data["records"][0]["envelope"]["messageId"],
                    "senderAccount": "bob", "text": data["texts"][0]}, "恢复没有复用原始正文与发送身份")
            read = upgraded.request("received", sequence="1")
            require(success(read) == exact and read["events"] == [], "查询结果不是原始完整接收结果")
            metrics(read)
            require(snapshot(upgraded) == before, "recover 重做了密码状态或业务写入")
            cached = committed(process(upgraded, 1, "upgrade-receive-once"), "receive", cached=True)
            require(cached == exact, "原请求 ID 重试未返回原接收结果")
            require(snapshot(upgraded) == before, "缓存重试改变 provider 或游标")
            status(upgraded)
            recovered_pid = upgraded.process.pid
        require(sha(saved_database) == before_hash, "升级恢复覆盖了保留的原数据库副本")
        return {"checkpoint": marker, "locked_error": error, "v2_recovered_pid": recovered_pid,
                "saved_database_sha256": before_hash, "snapshot": before,
                "exact_result": exact, "recovery_metrics": reply["metrics"], "recovery_events": reply["events"],
                "same_full_committed_result": True, "original_request_id_cached_without_crypto": True}

    def unresolved_upgrade_recovery(self):
        evidence = []
        for fault, checkpoint, computed in (("pause_after_reserve", "after_reserve", False),
                                           ("pause_after_crypto", "after_crypto", True)):
            fixture = self.fixture(checkpoint)
            fixture.bootstrap()
            with fixture.peer() as peer, fixture.probe() as old:
                fixture.setup(old, peer, records=0)
                before = snapshot(old)
                action = send_action("upgrade-pending-attempt", "upgrade-pending-message", "未决升级合成正文")
                old.send({"op": "execute", "request": {"request_id": "upgrade-pending",
                          "action": action, "fault": fault}, "anchor_fault": "none"})
                marker = old.checkpoint(checkpoint)
                metrics(marker, restores=int(computed), sends=int(computed))
                old.crash()
            saved_database = fixture.save_closed("v1-unresolved-before-upgrade.db")
            saved_hash = sha(saved_database)
            self.switch(fixture)
            rounds = []
            expected_pending = None
            for _ in range(2):
                with fixture.probe() as upgraded:
                    pending = snapshot(upgraded)
                    require(pending["pending"] is not None, "未提交预约被升级清除")
                    require(pending["provider_hash"] == before["provider_hash"]
                            and pending["identity"] == before["identity"]
                            and pending["outbox"] == before["outbox"], "未提交密码候选进入持久业务状态")
                    if expected_pending is None:
                        expected_pending = pending
                    require(pending == expected_pending, "再次重开改变未决预约或已保存状态")
                    recovery = upgraded.request("recover")
                    recovery_error = rejected(recovery, "anchor_unresolved")
                    retry = execute(upgraded, "upgrade-pending", action)
                    retry_error = rejected(retry)
                    new_retry = execute(upgraded, "upgrade-pending-new-id", action)
                    new_error = rejected(new_retry)
                    require(snapshot(upgraded) == pending, "升级 recover 或重试重新计算了候选")
                    rounds.append({"pid": upgraded.process.pid, "recover_error": recovery_error,
                                   "retry_error": retry_error, "new_id_retry_error": new_error,
                                   "metrics": [recovery["metrics"], retry["metrics"], new_retry["metrics"]]})
            require(sha(saved_database) == saved_hash, "未决恢复覆盖了原保存数据库")
            evidence.append({"checkpoint": marker, "candidate_computed_before_kill": computed,
                             "preserved_database_sha256": saved_hash, "pending_snapshot": expected_pending,
                             "rounds": rounds, "recovery_crypto_calls": 0})
        return {"faults": evidence, "unresolved_reservations_preserved": True,
                "no_auto_recomputation_after_upgrade": True}
