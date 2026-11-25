"""跨 Rust/Python 字节摘要及真实最后期限检查；不是密码安装测试的替代。"""
import json
from pathlib import Path
import unittest
import tempfile
import sqlite3
from contextlib import closing
from unittest.mock import patch
from contract import ProtocolError, validate_request
from join_recovery_contract import signed_digest
from key_package_commit import TimedResult, before_commit


class RecoveryContractTests(unittest.TestCase):
    def test_shared_signed_bytes_vector(self):
        vector=json.loads((Path(__file__).resolve().parents[2]/"api/realtime/join-recovery-vectors.json").read_text())["positive"]
        self.assertEqual(signed_digest(vector["proof"]),vector["signed_record_sha256"])

    def test_interval_boundaries_and_exact_result_retry(self):
        for now,valid in ((99,False),(100,True),(199.99,True),(200,False)):
            with self.subTest(now=now),patch("key_package_commit.time.time",return_value=now):
                value=TimedResult({"state":"accepted"},200,100,"recovery_expired")
                if valid:before_commit(value)
                else:
                    with self.assertRaises(ProtocolError) as raised:before_commit(value)
                    self.assertEqual(raised.exception.code,"recovery_expired")
                before_commit(dict(value))  # 已保存精确原件重试不刷新 TTL。

    def test_outer_requests_have_no_unsigned_authority_fields(self):
        request={"kind":"get","service_id":"S1","conversation_id":"G1","recovery_id":"R1"}
        validate_request("join_recovery",request)
        for key in ("actor","target","authorized","expires_at_unix_secs"):
            with self.subTest(key=key),self.assertRaises(ProtocolError):
                validate_request("join_recovery",request|{key:True})


class RecoveryRequestConflictTests(unittest.TestCase):
    """真实 SQLite 请求唯一账本；不以合成数据代替 MLS 或公开签名验证。"""

    def setUp(self):
        from join_recovery_storage import SCHEMA, reserve_request
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        statement = next(part for part in SCHEMA.split(";") if "CREATE TABLE recovery_requests" in part)
        self.db.execute(statement)
        self.original = {"signer": {"account_id": "A", "device_id": "A1"},
                         "request_id": "saved-request", "nonce": "saved-nonce"}
        self.proof = {"synthetic_public_request": "saved"}
        reserve_request(self.db, self.original, self.proof, "saved-recovery")

    def rows(self):
        return tuple(self.db.execute("SELECT * FROM recovery_requests ORDER BY request_id"))

    def test_fresh_terminal_request_check_does_not_reserve(self):
        from join_recovery_storage import check_request
        before = self.rows()
        request = self.original | {"request_id": "fresh-close", "nonce": "fresh-nonce"}
        self.assertFalse(check_request(self.db, request, {"synthetic_public_request": "close"}))
        self.assertEqual(self.rows(), before)

    def test_exact_reserved_request_is_read_only(self):
        from join_recovery_storage import check_request
        before = self.rows()
        self.assertTrue(check_request(self.db, self.original, self.proof))
        self.assertEqual(self.rows(), before)

    def test_existing_id_or_nonce_cannot_change_proof(self):
        from join_recovery_storage import check_request
        before = self.rows()
        for request in (self.original | {"nonce": "fresh-nonce"},
                        self.original | {"request_id": "fresh-close"}):
            with self.subTest(request=request), self.assertRaises(ProtocolError) as raised:
                check_request(self.db, request, {"synthetic_public_request": "different"})
            self.assertEqual(raised.exception.code, "idempotency_conflict")
            self.assertEqual(self.rows(), before)


class RecoverySchemaTests(unittest.TestCase):
    def setUp(self):
        from storage import Store
        from test_support import fixture
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "relay.sqlite3"
        self.fixture = fixture()
        self.store = Store(self.path, self.fixture)

    def snapshot(self):
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("BEGIN")
            schema = tuple(db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name"))
            result = {"__schema__": schema}
            for kind, name, _, _ in schema:
                if kind == "table":
                    result[name] = tuple(db.execute(f'SELECT * FROM "{name}" ORDER BY rowid'))
            db.commit()
            return result

    def legacy(self):
        with self.store.transaction() as db:
            db.execute("DROP TABLE recovery_witness_bindings")
            db.execute("DROP TABLE recovery_witness_configs")
            db.execute("UPDATE meta SET value='1' WHERE key='recovery_schema'")

    def reload(self, **kwargs):
        from storage import Store
        return Store(self.path, self.fixture, **kwargs)

    def test_public_store_installs_recovery_schema_two(self):
        from storage import Store
        with closing(self.store.connect()) as db:
            self.assertEqual(Store.meta(db, "recovery_schema"), "2")

    def test_schema_one_upgrade_preserves_original_tables_and_restart(self):
        self.legacy()
        before = self.snapshot()
        self.reload()
        after = self.snapshot()
        for table in set(before) - {"__schema__", "meta"}:
            self.assertEqual(before[table], after[table], table)
        self.assertEqual(dict(after["meta"]), dict(before["meta"]) | {"recovery_schema": "2"})
        self.assertEqual(after["recovery_witness_configs"], ())
        self.assertEqual(after["recovery_witness_bindings"], ())
        self.reload()
        self.assertEqual(after, self.snapshot())

    def test_failed_trusted_configuration_rolls_back_entire_schema_migration(self):
        self.legacy()
        before = self.snapshot()
        config = Path(self.temporary.name) / "untrusted.json"
        config.write_text("{}")
        with patch.dict("os.environ", {"RIM_RECOVERY_WITNESS_CONFIG_SHA256": "00" * 32}):
            for _ in range(2):
                with self.assertRaisesRegex(ValueError, "独立固定摘要不符"):
                    self.reload(recovery_witness_config=config)
                self.assertEqual(before, self.snapshot())

    def test_schema_two_missing_table_is_not_recreated(self):
        with self.store.transaction() as db:
            db.execute("DROP TABLE recovery_witness_bindings")
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "见证持久账本缺失"):
            self.reload()
        self.assertEqual(before, self.snapshot())

    def test_marker_downgrade_does_not_erase_witness_ledger(self):
        with self.store.transaction() as db:
            db.execute("UPDATE meta SET value='1' WHERE key='recovery_schema'")
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "未标记见证账本"):
            self.reload()
        self.assertEqual(before, self.snapshot())
