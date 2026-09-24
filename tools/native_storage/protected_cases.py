"""真实独立进程的保护门禁；只操作本轮合成钥匙串、密文库和公开定位器。"""

import json
import os
from pathlib import Path
import secrets
import shutil
import uuid

from anchor_support import execute, snapshot, status
from crypto_support import digest, execute as crypto_execute, send_action, success
from protected_support import CryptoProbe, Fixture
from rebuild_support import committed, metrics, rejected
from support import require, sha

CASE_NAMES = (
    "restart_identity_messages", "locked_cold", "locked_warm", "missing_key_cold",
    "missing_key_warm", "wrong_storage_key", "trust_client_seed", "trust_anchor_public_key",
    "trust_program", "trust_scope_binding", "locator_scope_binding", "locator_item_missing",
    "locator_cross_database", "ciphertext_bitflip", "plaintext_downgrade_rejected",
    "missing_trust_key", "keychain_file_unavailable", "keychain_record_cross_database",
)


def startup_error(response):
    require(response.get("ready") is False, "保护失败仍启动成功")
    require(response.get("result") is None and response.get("events", []) == [],
            "保护失败交付了数据或成功事件")
    error = response.get("error") or {}
    require(error.get("paused") is True and error.get("code"), "保护失败没有明确暂停原因")
    return error


class Cases:
    def __init__(self, binaries, directory, commands):
        self.binaries, self.directory, self.commands = binaries, Path(directory).resolve(), commands
        self.fixtures = []

    def fixture(self, name=None):
        directory = self.directory / name if name is not None else self.directory
        fixture = Fixture(self.binaries, directory, self.commands)
        self.fixtures.append(fixture)
        return fixture

    def run(self, name):
        require(name in CASE_NAMES, "未知保护场景")
        failed = False
        try:
            return getattr(self, name)()
        except BaseException:
            failed = True
            raise
        finally:
            errors = []
            for fixture in self.fixtures:
                try:
                    fixture.ctl("keychain_lock")
                except Exception as error:
                    errors.append(type(error).__name__)
            if errors and not failed:
                raise AssertionError("本场景实验钥匙串未全部锁定：" + ",".join(errors))

    def refused(self, fixture):
        with fixture.probe(ready=False) as probe:
            return startup_error(probe.startup)

    def native(self, fixture, create=False, ready=True, protected=True):
        flags = ("--test-mode",) + (("--create",) if create else ())
        if protected:
            flags += ("--protected", str(fixture.config_path))
        return CryptoProbe(fixture.native, fixture.database, fixture.directory, fixture.commands,
                           service=fixture.scope["service"], account=fixture.scope["account"],
                           device=fixture.scope["device"], flags=flags, ready=ready)

    def native_refused(self, fixture, create=False):
        with self.native(fixture, create=create, ready=False) as probe:
            return startup_error(probe.startup)

    def unchanged(self, fixture, before):
        require(sha(fixture.database) == before, "保护失败覆盖或修改了已有数据库")

    def still_identity(self, fixture, probe, evidence=False):
        response = execute(probe, "initialize", {"op": "initialize"})
        identity = committed(response, "initialize", cached=True)
        require(identity == fixture.identity, "重新打开后重生成或替换了身份")
        if evidence:
            return {"identity": digest(identity["identityKey"]), "trace": response["trace"],
                    "metrics": response["metrics"], "events": response["events"], "cached": True}
        return digest(identity["identityKey"])

    def blocked(self, probe):
        requests = [probe.request("inspect"), probe.request("received", sequence="1"),
                    execute(probe, "initialize", {"op": "initialize"}),
                    execute(probe, "protected-blocked-send", send_action()), probe.request("recover")]
        return [rejected(response) for response in requests]

    def exchange(self, client, peer, number):
        incoming_text, outgoing_text = f"保护重启后接收🙂{number}", f"保护重启后发送🙂{number}"
        envelope = success(peer.request("peer_send", message_id=f"protected-in-{number}", text=incoming_text))
        received = committed(execute(client, f"protected-receive-{number}",
                                     {"op": "receive", "sequence": str(number), "envelope": envelope}), "receive")
        require(received["message"]["text"] == incoming_text, "实际接收未解密为预期正文")
        outgoing = committed(execute(client, f"protected-send-{number}",
                                     send_action(f"protected-attempt-{number}",
                                                 f"protected-out-{number}", outgoing_text)), "send")
        require(success(peer.request("peer_receive", envelope=outgoing))["text"] == outgoing_text,
                "实际发送密文不能被对端解密")
        return received

    def restart_identity_messages(self):
        fixture = self.fixture()
        fixture.bootstrap()
        with fixture.peer() as peer:
            with fixture.probe() as client:
                first_pid = client.process.pid
                peer_identity = success(peer.request("peer_identity"))
                welcome = committed(execute(client, "create-group", {"op": "create_group",
                                    "conversation": "protected-restart", "peer": peer_identity}), "create_group")
                success(peer.request("peer_join", conversation="protected-restart", peer=fixture.identity,
                                     welcome=welcome["welcome"]))
                first = self.exchange(client, peer, 1)
                before = snapshot(client)
            with fixture.probe() as reopened:
                second_pid = reopened.process.pid
                require(first_pid != second_pid, "没有使用真实独立重启进程")
                identity = self.still_identity(fixture, reopened)
                require(snapshot(reopened) == before, "重启改变了已提交快照")
                response = reopened.request("received", sequence="1")
                require(success(response) == first and response["events"] == [], "重启未读回精确已处理消息")
                metrics(response)
                second = self.exchange(reopened, peer, 2)
                after = snapshot(reopened)
            with fixture.probe() as again:
                require(success(again.request("received", sequence="2")) == second, "第二轮消息未持久化")
                self.still_identity(fixture, again)
                status(again)
        return {"pids": [first_pid, second_pid], "identity": identity, "bidirectional_rounds": 2,
                "download_cursor": after["download_cursor"], "processed_cursor": after["processed_cursor"]}

    def locked_cold(self):
        fixture = self.fixture()
        fixture.bootstrap()
        with fixture.probe() as client:
            before = snapshot(client)
        initial_hash = sha(fixture.database)
        fixture.ctl("keychain_lock")
        error = self.refused(fixture)
        self.unchanged(fixture, initial_hash)
        fixture.ctl("keychain_unlock")
        with fixture.probe() as client:
            self.still_identity(fixture, client)
            require(snapshot(client) == before, "解锁重开改变已有状态")
        return {"error": error, "database_unchanged": True, "reopened_original_identity": True}

    def locked_warm(self):
        fixture = self.fixture()
        fixture.bootstrap()
        fixture.group("warm-protection", history=True)
        with fixture.probe() as client:
            before, initial_hash = snapshot(client), sha(fixture.database)
            fixture.ctl("keychain_lock")
            locked = self.blocked(client)
            self.unchanged(fixture, initial_hash)
            locked_hash = sha(fixture.database)
            fixture.ctl("keychain_unlock")
            still_paused = self.blocked(client)
            self.unchanged(fixture, initial_hash)
            paused_hash = sha(fixture.database)
            with fixture.probe() as reopened:
                self.unchanged(fixture, initial_hash)
                require(snapshot(reopened) == before, "重开未保留锁定前精确状态")
                self.unchanged(fixture, initial_hash)
                read_hash = sha(fixture.database)
                # 缓存业务结果仍经过锚预约/结束，会合法更新加密控制页；此后核对逻辑状态。
                cached = self.still_identity(fixture, reopened, evidence=True)
                require(snapshot(reopened) == before, "合法缓存请求改变了既有业务状态")
                cached_hash = sha(fixture.database)
        return {"locked_errors": locked, "same_instance_after_unlock_errors": still_paused,
                "new_process_resumed": True, "blocked_and_read_phases_unchanged": True,
                "database_sha256": {"initial": initial_hash, "locked": locked_hash,
                                    "unlocked_old_instance_paused": paused_hash,
                                    "reopened_read": read_hash, "after_legal_cached_request": cached_hash},
                "cached_request": cached, "logical_snapshot_unchanged_after_cached_request": True}

    def missing_key(self, warm):
        fixture = self.fixture()
        fixture.bootstrap()
        before = sha(fixture.database)
        errors = []
        if warm:
            with fixture.probe() as client:
                fixture.ctl("key_delete")
                errors = self.blocked(client)
        else:
            fixture.ctl("key_delete")
        errors.append(self.refused(fixture))
        errors.append(self.native_refused(fixture, create=True))
        errors.append(self.refused(fixture))
        absent = fixture.ctl("key_delete", expected=1)
        require(absent.get("ok") is False and absent.get("result") is None
                and absent.get("error", {}).get("paused") is True, "失败重开或create重建了丢失的钥匙")
        self.unchanged(fixture, before)
        return {"warm": warm, "errors": errors, "key_still_absent": True, "database_unchanged": True}

    def missing_key_cold(self):
        return self.missing_key(False)

    def missing_key_warm(self):
        return self.missing_key(True)

    def wrong_storage_key(self):
        fixture = self.fixture()
        fixture.bootstrap(bind=False)
        before = sha(fixture.database)
        fixture.ctl("key_tamper", target="key", field="key", value=secrets.token_hex(32))
        error = self.native_refused(fixture)
        require(isinstance(error.get("sqlite_code"), int), "错误钥匙未实际到达 SQLCipher 开库读取")
        self.unchanged(fixture, before)
        return {"unbound_database": True, "sqlcipher_rejection": error, "database_unchanged": True}

    def trust_tamper(self, field, value=None, name=None):
        fixture = self.fixture(name)
        fixture.bootstrap()
        before = sha(fixture.database)
        if field == "anchor_public_key":
            value = fixture.client_key
        elif field == "program":
            value = str(fixture.native)
        fixture.ctl("key_tamper", target="trust", field=f"config.{field}", value=value)
        error = self.refused(fixture)
        self.unchanged(fixture, before)
        return {"field": field, "error": error, "database_unchanged": True}

    def trust_client_seed(self):
        return self.trust_tamper("client_seed", secrets.token_hex(32))

    def trust_anchor_public_key(self):
        return self.trust_tamper("anchor_public_key")

    def trust_program(self):
        return self.trust_tamper("program")

    def trust_scope_binding(self):
        return {"scope_cases": [self.trust_tamper(f"scope.{field}", f"other-{field}", field)
                                 for field in ("service", "account", "device")]}

    def locator_tamper(self, field, name=None):
        fixture = self.fixture(name)
        fixture.bootstrap()
        before = sha(fixture.database)
        changed = {**fixture.locator, field: f"lab-{uuid.uuid4()}" if field == "item" else f"other-{field}"}
        fixture.write_config(changed)
        error = self.refused(fixture)
        self.unchanged(fixture, before)
        fixture.write_config()
        with fixture.probe() as client:
            self.still_identity(fixture, client)
        return {"field": field, "error": error, "original_locator_restored": True, "database_unchanged": True}

    def locator_scope_binding(self):
        return {"scope_cases": [self.locator_tamper(field, field) for field in ("service", "account", "device")]}

    def locator_item_missing(self):
        return self.locator_tamper("item")

    def locator_cross_database(self):
        first, second = self.fixture("first"), self.fixture("second")
        first.bootstrap()
        second.bootstrap()
        before = [sha(first.database), sha(second.database)]
        first.write_config(second.locator)
        second.write_config(first.locator)
        errors = [self.refused(first), self.refused(second)]
        for fixture, expected in zip((first, second), before):
            self.unchanged(fixture, expected)
            fixture.write_config()
            with fixture.probe() as client:
                self.still_identity(fixture, client)
        return {"errors": errors, "two_original_databases_unchanged": True,
                "original_locators_resume_their_own_identities": True}

    def ciphertext_bitflip(self):
        fixture = self.fixture()
        fixture.bootstrap()
        original = fixture.save_closed("encrypted-original.db")
        original_hash = sha(original)
        require(fixture.database.stat().st_size > 128, "密文库太小，无法执行页内篡改")
        with fixture.database.open("r+b") as target:
            target.seek(128)
            value = target.read(1)
            target.seek(128)
            target.write(bytes([value[0] ^ 1]))
            target.flush()
            os.fsync(target.fileno())
        altered = sha(fixture.database)
        require(altered != original_hash, "未实际改动密文数据库")
        error = self.refused(fixture)
        require(isinstance(error.get("sqlite_code"), int), "密文篡改未到达 SQLCipher 完整性拒绝")
        self.unchanged(fixture, altered)
        require(sha(original) == original_hash, "篡改实验覆盖了保存的原件")
        return {"flipped_byte_offset": 128, "error": error, "original_sha256": original_hash,
                "altered_sha256": altered, "altered_database_not_overwritten": True}

    def plaintext_downgrade_rejected(self):
        fixture = self.fixture()
        with self.native(fixture, create=True, protected=False) as client:
            committed(crypto_execute(client, "initialize", {"op": "initialize"}), "initialize")
        with fixture.database.open("rb") as source:
            require(source.read(16) == b"SQLite format 3\x00", "旧入口没有生成实际明文 SQLite 库")
        before = sha(fixture.database)
        original = fixture.directory / "legacy-plaintext-original.db"
        shutil.copyfile(fixture.database, original)
        original.chmod(0o600)
        errors = [self.native_refused(fixture), self.native_refused(fixture, create=True), self.refused(fixture)]
        self.unchanged(fixture, before)
        require(sha(original) == before, "旧明文原件被修改")
        return {"errors": errors, "legacy_plaintext_fixture": True, "automatic_migration": False,
                "original_sha256": before}

    def missing_trust_key(self):
        fixture = self.fixture()
        fixture.bootstrap()
        before = sha(fixture.database)
        fixture.ctl("key_delete", trust=True)
        errors = [self.refused(fixture), self.native_refused(fixture), self.native_refused(fixture, create=True)]
        self.unchanged(fixture, before)
        return {"errors": errors, "database_unchanged": True, "unbound_entry_refused_downgrade": True}

    def keychain_file_round(self, fixture, before, live=None):
        initial_hash = sha(fixture.database)
        parked = fixture.keychain.with_name(fixture.keychain.name + ".offline")
        require(not parked.exists(), "隔离钥匙串暂存路径已存在")
        fixture.keychain.rename(parked)
        try:
            require(not fixture.keychain.exists(), "钥匙串文件未实际移离固定路径")
            errors = self.blocked(live) if live is not None else []
            errors.append(self.refused(fixture))
            self.unchanged(fixture, initial_hash)
            unavailable_hash = sha(fixture.database)
        finally:
            recreated = fixture.keychain.exists()
            if recreated:
                # 只保留本场景意外重建的文件，先归还原件，不覆盖任何实验现场。
                unexpected = fixture.keychain.with_name(fixture.keychain.name + f".unexpected-{uuid.uuid4()}")
                fixture.keychain.rename(unexpected)
            parked.rename(fixture.keychain)
            fixture.ctl("keychain_unlock")
            require(not recreated, "固定路径缺失时意外重建了钥匙串文件")
        still_paused = self.blocked(live) if live is not None else []
        self.unchanged(fixture, initial_hash)
        with fixture.probe() as reopened:
            require(snapshot(reopened) == before, "归还原钥匙串后的逻辑快照不一致")
            self.unchanged(fixture, initial_hash)
            read_hash = sha(fixture.database)
            cached = self.still_identity(fixture, reopened, evidence=True)
            require(snapshot(reopened) == before, "归还原钥匙串后缓存请求改变业务状态")
            cached_hash = sha(fixture.database)
        return {"warm": live is not None, "unavailable_errors": errors,
                "same_instance_after_restore_errors": still_paused, "original_keychain_restored": True,
                "database_sha256": {"initial": initial_hash, "unavailable": unavailable_hash,
                                    "reopened_read": read_hash, "after_legal_cached_request": cached_hash},
                "cached_request": cached, "original_identity_and_logical_snapshot_preserved": True}

    def keychain_file_unavailable(self):
        evidence = []
        for warm in (False, True):
            fixture = self.fixture("warm" if warm else "cold")
            fixture.bootstrap()
            fixture.group("keychain-file-unavailable", history=True)
            with fixture.probe() as client:
                before = snapshot(client)
                if warm:
                    evidence.append(self.keychain_file_round(fixture, before, client))
            if not warm:
                evidence.append(self.keychain_file_round(fixture, before))
        return {"file_unavailable_cases": evidence}

    def keychain_record_cross_database(self):
        source = self.fixture("source")
        source.bootstrap()
        source_hash = sha(source.database)
        evidence = []
        for name, targets in (("key", (False,)), ("trust", (True,)), ("key_and_trust", (False, True))):
            fixture = self.fixture(name)
            fixture.bootstrap()
            before = sha(fixture.database)
            for trust in targets:
                fixture.ctl("key_copy", source_db=str(source.database),
                            source_locator=json.dumps(source.locator), trust=trust)
            error = self.refused(fixture)
            self.unchanged(fixture, before)
            self.unchanged(source, source_hash)
            evidence.append({"substitution": name, "error": error,
                             "source_database_sha256": source_hash, "target_database_sha256": before,
                             "both_databases_unchanged": True})
        with source.probe() as client:
            self.still_identity(source, client)
        return {"record_substitutions": evidence, "source_original_identity_usable": True}
