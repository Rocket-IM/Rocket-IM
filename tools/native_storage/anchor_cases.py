"""完整设备数据库回滚、固定绑定和独立本机 authority 的可复现场景。"""

import base64
import copy
import json
import shutil
import sqlite3

from anchor_faults import ANCHOR_KILLS, AUTHORITY_FAILURES, CRYPTO_KILLS, FaultCases
from anchor_support import (Fixture, download, execute, metrics, process, recover,
                            rejected, send_action, snapshot, status, success)
from crypto_support import CryptoProbe, committed, failure
from download_support import saved
from receive_support import check_message, committed as received_commit
from support import require, sha

CASE_NAMES = (
    "normal_send_download_process_restart", "cached_operations_still_anchored",
    "whole_database_rollback", "download_only_rollback", "prebind_v3_rollback",
    "wrong_scope", "wrong_anchor_key", "wrong_client_key", "missing_config",
    "missing_authority", "authority_unavailable_after_bind", "unbound_v3_refused", "rebind_refused", "plain_client_refused",
    "concurrent_local_gate", "journal_tamper", "joint_rollback_expected_undetectable",
    *ANCHOR_KILLS, *CRYPTO_KILLS, *AUTHORITY_FAILURES,
    "download_kill_recover", "process_kill_recover",
)


class Cases(Fixture, FaultCases):
    def run(self, name):
        if name in ANCHOR_KILLS or name in CRYPTO_KILLS:
            return self.killed_send(name)
        if name in AUTHORITY_FAILURES:
            return self.authority_failure(name)
        if name in ("wrong_scope", "wrong_anchor_key", "wrong_client_key", "missing_config", "missing_authority"):
            return self.configuration_failure(name)
        return getattr(self, name)()

    def normal_send_download_process_restart(self):
        self.bootstrap()
        with self.peer() as peer:
            with self.probe() as client:
                setup = self.setup(client, peer)
                envelope = committed(execute(client, "normal-send", send_action()), "send")
                message = success(peer.request("peer_receive", envelope=envelope))
                require(message["text"] == send_action()["text"], "已确认发送不能实际解密")
                saved(download(client, setup["records"]), 2, 0, 2)
                value = received_commit(process(client), "receive")
                check_message(value, 1, setup["records"][0]["envelope"], setup["texts"][0])
                before, anchor = snapshot(client), status(client)
            with self.probe() as reopened:
                require(snapshot(reopened) == before and status(reopened) == anchor, "重启改变持久状态或独立锚")
                received = reopened.request("received", sequence="1")
                require(success(received) == value, "健康锚下无法查询已提交消息")
                metrics(received)
                next_value = received_commit(process(reopened, 2, "process-two"), "receive")
                check_message(next_value, 2, setup["records"][1]["envelope"], setup["texts"][1])
                status(reopened)
        return {"bidirectional_real_openmls": True, "raw_download_and_process_restart": True,
                "initial_anchor": anchor}

    def cached_operations_still_anchored(self):
        self.bootstrap()
        with self.peer() as peer, self.probe() as client:
            setup = self.setup(client, peer)
            envelope = committed(execute(client, "cached-send", send_action()), "send")
            saved(download(client, setup["records"]), 2, 0, 2)
            value = received_commit(process(client), "receive")
            before = snapshot(client)
            previous = status(client)
            responses = [execute(client, "cached-send", send_action()), download(client, setup["records"]), process(client)]
            require(committed(responses[0], "send", cached=True) == envelope, "缓存发送改变密文")
            saved(responses[1], 2, 1, 0)
            require(received_commit(responses[2], "receive", cached=True) == value, "缓存处理改变消息")
            after = status(client)
            require(snapshot(client) == before and after["local_head"] == previous["local_head"],
                    "缓存改变了完整业务 head")
            require(int(after["remote_revision"]) == int(previous["remote_revision"]) + 6,
                    "三个缓存访问没有逐次检查、预约并完成独立锚")
        return {"cached_send_download_process": 3, "crypto_calls": 0, "authority_revision_advanced": 6}

    def whole_database_rollback(self):
        return self.rollback(False)

    def download_only_rollback(self):
        return self.rollback(True)

    def rollback(self, only_download):
        self.bootstrap()
        with self.peer() as peer:
            with self.probe() as client:
                setup = self.setup(client, peer)
                before = snapshot(client)
            old = self.save_closed()
            with self.probe() as client:
                if only_download:
                    saved(download(client, setup["records"]), 2, 0, 2)
                    after = snapshot(client)
                    require(after["provider_hash"] == before["provider_hash"] and after["revision"] == before["revision"],
                            "仅下载实验意外推进密码状态")
                else:
                    committed(execute(client, "advance-send", send_action()), "send")
                advanced = status(client)
            self.restore_closed(old)
            restored_hash = sha(self.database)
            with self.probe() as client:
                state = status(client, "anchor_head_mismatch")
                require(state["local_head"] != state["remote_head"], "完整回滚未改变 head 比较")
                errors = self.blocked(client, setup["records"])
                rejected(client.request("recover"))
                require(snapshot(client) == before, "回滚门禁改变旧业务状态")
            with self.probe() as again:
                status(again, "anchor_head_mismatch")
                self.blocked(again, setup["records"])
        return {"closed_database_snapshot_sha256": sha(old), "restored_initial_sha256": restored_hash,
                "remote_advanced": advanced, "download_only": only_download, "blocked_errors": errors}

    def startup_rejection(self, config=None, code=None):
        with self.probe(config=config or self.config_path, ready=None) as client:
            response = client.next_stdout()
            if response.get("ready") is True:
                client.ready = True
                result = execute(client, "initialize", {"op": "initialize"})
                error = rejected(result, code)
            else:
                require(response.get("ready") is False and response.get("error"), "启动错误没有明确报告")
                error = response["error"]
                if code is not None:
                    require(error.get("code") == code, f"启动错误类别不符：{error}")
                if "metrics" in response:
                    metrics(response)
                client.finish(1)
        return error

    def prebind_v3_rollback(self):
        self.bootstrap(bind=False)
        old = self.save_closed("unbound-v3.db")
        self.bind()
        self.restore_closed(old)
        before = sha(self.database)
        error = self.startup_rejection(code="anchor_binding_missing")
        require(sha(self.database) == before, "未绑定库被自动重新绑定")
        return {"error": error, "prebind_v3_sha256": before, "automatic_enrollment": False}

    def configuration_failure(self, name):
        self.bootstrap()
        original = sha(self.database)
        config = copy.deepcopy(self.config)
        if name == "wrong_scope":
            config["scope"]["account"] = "other-account"
        elif name == "wrong_anchor_key":
            config["anchor_public_key"] = self.client_key
        elif name == "wrong_client_key":
            config["client_seed"] = "aa" * 32
        elif name == "missing_authority":
            config["directory"] = str(self.trusted / "nonexistent-authority")
        path = self.trusted / "wrong-config.json"
        if name != "missing_config":
            self.write_config(config, path)
        error = self.startup_rejection(path, "anchor_config" if name == "missing_config" else "anchor_binding_mismatch")
        require(sha(self.database) == original, "配置拒绝改写了已绑定数据库")
        return {"error": error, "database_unchanged": True}

    def authority_unavailable_after_bind(self):
        self.bootstrap()
        offline = self.trusted / "authority-offline"
        original = sha(self.database)
        self.authority.rename(offline)
        with self.probe() as client:
            response = client.request("status")
            error = rejected(response)
        require(sha(self.database) == original, "无法访问锚的状态检查修改了数据库")
        with self.probe() as client:
            rejected(execute(client, "initialize", {"op": "initialize"}))
        offline.rename(self.authority)
        with self.probe() as client:
            state = status(client, "anchor_unresolved")
            rejected(execute(client, "initialize", {"op": "initialize"}))
            rejected(client.request("recover"), "anchor_unresolved")
        return {"unavailable_error": error, "restored_authority_does_not_clear_local_gate": True,
                "restarted_state": state}

    def unbound_v3_refused(self):
        self.bootstrap(bind=False)
        before = sha(self.database)
        error = self.startup_rejection(code="anchor_binding_missing")
        require(sha(self.database) == before, "普通启动自动迁移了 v3 数据库")
        return {"error": error, "explicit_bind_required": True}

    def rebind_refused(self):
        self.bootstrap()
        before = sha(self.database)
        response = self.command([self.binary, self.database, self.config_path, "--bind"], expected=1)
        require(response.get("ok") is False or response.get("ready") is False, "已绑定数据库可以再次登记信任")
        require(sha(self.database) == before, "重复绑定改写了数据库")
        return {"error": response.get("error"), "database_unchanged": True}

    def plain_client_refused(self):
        self.bootstrap()
        before = sha(self.database)
        with CryptoProbe(self.native, self.database, self.directory, self.commands,
                         flags=("--test-mode",), ready=False) as client:
            error = client.startup.get("error")
            require(error is not None and error["code"] == "anchor_required", "旧客户端未明确拒绝锚绑定库")
        require(sha(self.database) == before, "旧客户端绕过锚绑定修改库")
        return {"error": error, "database_unchanged": True}

    def concurrent_local_gate(self):
        self.bootstrap()
        with self.peer() as peer, self.probe() as first:
            setup = self.setup(first, peer)
            with self.probe() as second:
                first.send({"op": "execute", "request": {"request_id": "concurrent", "action": send_action(),
                                                           "fault": "none"},
                            "anchor_fault": "pause_after_local_gate"})
                marker = first.checkpoint("after_local_gate")
                errors = self.blocked(second, setup["records"])
                first.crash()
                errors += self.blocked(second, setup["records"])
                rejected(second.request("recover"), "anchor_unresolved")
        with self.probe() as reopened:
            self.blocked(reopened, setup["records"])
            rejected(reopened.request("recover"), "anchor_unresolved")
        return {"checkpoint": marker, "second_live_client_and_restart_blocked": True, "blocked_errors": errors}

    def journal_tamper(self):
        self.bootstrap()
        with self.peer() as peer:
            with self.probe() as client:
                self.setup(client, peer)
                client.send({"op": "execute", "request": {"request_id": "tamper-send", "action": send_action(), "fault": "none"},
                             "anchor_fault": "pause_after_candidate_commit"})
                marker = client.checkpoint("after_candidate_commit")
                client.crash()
            before = sha(self.database)
            # 测试故意损坏 journal；应用 API 没有原始 SQL 或清理预约的入口。
            connection = sqlite3.connect(self.database, isolation_level=None)
            try:
                connection.execute("BEGIN IMMEDIATE")
                raw = connection.execute("SELECT journal_json FROM anchor_control WHERE singleton = 1").fetchone()[0]
                signed = json.loads(raw)
                signature = bytearray(base64.b64decode(signed["signature_bytes"], validate=True))
                signature[0] ^= 1
                signed["signature_bytes"] = base64.b64encode(signature).decode()
                connection.execute("UPDATE anchor_control SET journal_json = ? WHERE singleton = 1",
                                   (json.dumps(signed),))
                connection.execute("COMMIT")
            finally:
                connection.close()
            damaged = sha(self.database)
            require(before != damaged, "journal 故障夹具没有实际修改")
            error = self.startup_rejection(code="anchor_signature")
            require(sha(self.database) == damaged, "journal 损坏后自动修复或清除预约")
        return {"checkpoint": marker, "before_sha256": before, "damaged_sha256": damaged,
                "error": error, "tampered_journal_not_recovered": True}

    def joint_rollback_expected_undetectable(self):
        self.bootstrap()
        with self.peer() as peer:
            with self.probe() as client:
                self.setup(client, peer)
                old_status, old_snapshot = status(client), snapshot(client)
            old = self.save_closed()
            trusted_snapshot = self.directory / "trusted-snapshot"
            shutil.copytree(self.trusted, trusted_snapshot)
            trusted_snapshot.chmod(0o700)
            with self.probe() as client:
                committed(execute(client, "joint-advance", send_action()), "send")
                require(status(client)["local_head"] != old_status["local_head"], "负例没有先实际推进状态")
            self.restore_closed(old)
            shutil.rmtree(self.trusted)
            shutil.copytree(trusted_snapshot, self.trusted)
            with self.probe() as client:
                restored = status(client)
                require(restored == old_status and snapshot(client) == old_snapshot,
                        "共同回滚负例没有恢复三个故障域")
                committed(execute(client, "joint-new-send", send_action("after-joint", "after-joint")), "send")
        return {"classification": "EXPECTED_UNDETECTABLE", "assurance": "synthetic_local",
                "rolled_back": ["complete_device_database", "authority_directory", "trusted_config"],
                "not_a_production_independent_failure_domain": True}
