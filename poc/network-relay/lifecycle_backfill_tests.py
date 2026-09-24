"""历史库升级、权限证据关联与真实 SQLite 配额回归；签名/密文使用明确合成替身。"""

import base64
import concurrent.futures
import copy
import json
import sqlite3
import threading
from unittest.mock import patch

from contract import ProtocolError, encode_json
from lifecycle_backfill import VERSION
from permission_tests import proof
from quota_test_support import QuotaFixture
from receipt_test_support import ReceiptFixture, VerifiedCloseFixture, receipt_fixture
from storage import Store, replace_members
from test_support import envelope, fixture


class LifecycleBackfillTests(QuotaFixture):
    def setUp(self):
        super().setUp()
        self.fixture = receipt_fixture()
        extra = {"account_id": "C", "device_id": "C1", "token": "synthetic-C1-token",
                 "signature_key": base64.b64encode(bytes([6]) * 32).decode()}
        self.fixture["devices"].append(extra)
        self.members = sorted([{key: item[key] for key in ("account_id", "device_id")}
                               for item in self.fixture["devices"]], key=lambda item: (item["account_id"], item["device_id"]))
        self.fixture["conversation"]["members"] = self.members
        self.fixture["permission_checkpoint"]["members"] = sorted(
            self.fixture["permission_checkpoint"]["members"] + [{key: extra[key] for key in ("account_id", "device_id", "signature_key")}],
            key=lambda item: (item["account_id"], item["device_id"]))
        self.path = self.path.with_name("signed.sqlite3")
        self.signer, self.verifier = ReceiptFixture(), VerifiedCloseFixture()
        self.store = Store(self.path, self.fixture, self.verifier, self.signer)

    def reopen(self):
        self.store = Store(self.path, self.fixture, self.verifier, self.signer)

    def accept(self, logical="M1", availability="deleted", live=False):
        with patch("messages.now_ms", return_value=1000):
            accepted = self.call("submit_message", {"envelope": envelope(logical, recipients=self.members[1:])})
        if live:
            self.control({"action": "set_availability", "acceptance_id": accepted["acceptance_id"], "availability": availability})
        elif availability != "available":
            # 仅模块迁移装置构造旧版投影；真实旧 Relay 进程由独立联合验证覆盖。
            with self.store.transaction() as db:
                db.execute("UPDATE attempts SET availability=? WHERE acceptance_id=?", (availability, accepted["acceptance_id"]))
                db.execute("UPDATE events SET availability=? WHERE acceptance_id=? AND availability='available'", (availability, accepted["acceptance_id"]))
        return accepted

    def old5(self):
        with self.store.transaction() as db:
            db.execute("DROP TABLE lifecycle_backfill")
            db.execute("DELETE FROM meta WHERE key='lifecycle_backfill_version'")
            db.execute("UPDATE meta SET value='rim-poc-storage-5' WHERE key='schema'")

    def upgrade(self):
        self.old5()
        before = self.snapshot()
        self.reopen()
        after = self.snapshot()
        for name in before.keys() - {"__schema__", "meta"}:
            self.assertEqual(after[name], before[name], name)

    def run_backfill(self):
        return self.control({"action": "backfill_lifecycle", "version": VERSION})

    def assert_code(self, code, operation):
        with self.assertRaises(ProtocolError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)

    def assert_failure_unchanged(self, code, operation=None):
        before = self.snapshot()
        self.assert_code(code, operation or self.run_backfill)
        self.assertEqual(self.snapshot(), before)

    def test_fresh_scope_empty_and_request_is_strict_controller_only(self):
        expected = {"version": VERSION, "scope_count": "0", "pending_count": "0", "appended_count": "0",
                    "existing_count": "0", "skipped_count": "0"}
        self.assertEqual(self.run_backfill(), expected)
        self.assert_failure_unchanged("unsupported_version", lambda: self.control({"action": "backfill_lifecycle", "version": "next"}))
        self.assert_failure_unchanged("invalid_envelope", lambda: self.control({"action": "backfill_lifecycle", "version": VERSION, "after": "0"}))
        with self.store.transaction() as db:
            self.assert_code("permission_denied", lambda: self.controller.execute(self.store, db, "synthetic-A1-token",
                             {"action": "backfill_lifecycle", "version": VERSION}))

    def test_scope_freezes_only_historical_terminal_slots_and_preserves_original_facts(self):
        first = self.accept()
        self.accept("M2", "expired")
        third = self.accept("M3", "available")
        with self.store.transaction() as db:
            db.execute("UPDATE events SET availability='access_removed' WHERE device='B1' AND acceptance_id=?", (first["acceptance_id"],))
        self.upgrade()
        before = self.snapshot()
        result = self.run_backfill()
        self.assertEqual((result["scope_count"], result["appended_count"], result["skipped_count"], result["pending_count"]), ("10", "9", "1", "0"))
        after = self.snapshot()
        for name in before.keys() - {"events", "lifecycle_backfill"}:
            self.assertEqual(before[name], after[name], name)
        self.assertEqual(after["events"][:len(before["events"])], before["events"])
        self.control({"action": "set_availability", "acceptance_id": third["acceptance_id"], "availability": "deleted"})
        self.assertEqual(self.run_backfill(), result)
        self.reopen()
        self.assertEqual(self.run_backfill(), result)

    def test_repeated_and_concurrent_runs_commit_one_notice_per_original_slot(self):
        self.accept()
        self.upgrade()
        barrier = threading.Barrier(2)
        def run():
            barrier.wait(timeout=5)
            return self.run_backfill()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = [future.result(timeout=10) for future in [pool.submit(run), pool.submit(run)]]
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0]["appended_count"], "5")
        before = self.snapshot()
        self.reopen()
        self.assertEqual(self.run_backfill(), results[0])
        self.assertEqual(self.snapshot(), before)

    def test_existing_exact_notifications_are_adopted_even_if_access_removed(self):
        self.accept(live=True)
        with self.store.transaction() as db:
            db.execute("UPDATE events SET availability='access_removed' WHERE device='B1' AND json_extract(content,'$.type')='message_availability'")
        self.upgrade()
        before = self.snapshot()["events"]
        result = self.run_backfill()
        self.assertEqual((result["existing_count"], result["appended_count"]), ("5", "0"))
        self.assertEqual(self.snapshot()["events"], before)

    def permission(self, change):
        with patch("permissions.time.time", return_value=1100):
            return self.call("submit_permission_change", {"service_id": "S1", "conversation_id": "G1", "change": change})

    def test_removed_revoked_and_readded_targets_never_receive_historical_notice(self):
        self.accept()
        self.permission(proof())
        self.permission(proof("C2", "2", nonce="d" * 64, action={"kind": "revoke_device", "account_id": "A", "device_id": "A2"}))
        # 合成成员投影与检查点同时重加；历史 remove/revoke 链仍永久排除此原消息。
        with self.store.transaction() as db:
            checkpoint = json.loads(db.execute("SELECT checkpoint FROM permission_checkpoint").fetchone()[0])
            checkpoint["members"] = copy.deepcopy(self.fixture["permission_checkpoint"]["members"])
            db.execute("UPDATE permission_checkpoint SET checkpoint=?", (encode_json(checkpoint).decode(),))
            replace_members(db, [(m["account_id"], m["device_id"]) for m in checkpoint["members"]])
        self.upgrade()
        result = self.run_backfill()
        self.assertEqual((result["appended_count"], result["skipped_count"]), ("2", "3"))
        with self.store.transaction() as db:
            devices = {row[0] for row in db.execute("SELECT device FROM lifecycle_backfill WHERE status='appended'")}
        self.assertEqual(devices, {"A3", "C1"})

    def test_lost_membership_pending_is_permanent_skip_after_later_readd(self):
        self.accept()
        with self.store.transaction() as db:
            db.execute("UPDATE events SET availability='access_removed' WHERE device='B1'")
        self.upgrade()
        result = self.run_backfill()
        self.assertEqual(result["skipped_count"], "1")
        with self.store.transaction() as db:
            db.execute("UPDATE events SET availability='deleted' WHERE device='B1'")
        before = self.snapshot()
        self.assertEqual(self.run_backfill(), result)
        self.assertEqual(self.snapshot(), before)

    def test_unsigned_legacy_pending_refuses_and_does_not_inject_fixture_trust(self):
        self.fixture = fixture()
        self.members = self.fixture["conversation"]["members"]
        self.path = self.path.with_name("unsigned.sqlite3")
        self.store = Store(self.path, self.fixture)
        self.accept()
        self.old5()
        self.store = Store(self.path, self.fixture)
        self.assert_failure_unchanged("lifecycle_backfill_untrusted")
        with self.store.transaction() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM permission_checkpoint").fetchone()[0], 0)
            self.assertEqual(self.store.meta(db, "schema"), "rim-poc-storage-6")

    def test_missing_or_inconsistent_authorization_chain_fails_closed(self):
        self.accept()
        self.permission(proof())
        self.upgrade()
        for sql in ("DELETE FROM permission_changes", "UPDATE permission_changes SET version_offset=2",
                    "UPDATE permission_changes SET actor_device='A2'", "UPDATE permission_changes SET nonce='bad'",
                    "DELETE FROM permission_resolutions", "UPDATE conversation SET crypto_state_ref='bad'"):
            with self.subTest(sql=sql), self.store.transaction() as db:
                db.execute("SAVEPOINT corrupt")
                db.execute(sql)
                self.assert_code("lifecycle_backfill_untrusted", lambda: self.controller.execute(
                    self.store, db, self.fixture["controller_token"], {"action": "backfill_lifecycle", "version": VERSION}))
                self.assertEqual(db.execute("SELECT COUNT(*) FROM lifecycle_backfill WHERE status!='pending'").fetchone()[0], 0)
                db.execute("ROLLBACK TO corrupt")

    def test_original_acceptance_or_scope_binding_mismatch_fails_closed(self):
        self.accept()
        self.upgrade()
        for sql, code in (("UPDATE lifecycle_backfill SET attempt_id='other'", "lifecycle_backfill_conflict"),
                          ("UPDATE attempts SET result=json_set(result,'$.acceptance_id','wrong')", "lifecycle_backfill_untrusted"),
                          ("UPDATE events SET content=json_remove(content,'$.acceptance_receipt')", "lifecycle_backfill_untrusted")):
            with self.subTest(sql=sql), self.store.transaction() as db:
                db.execute("SAVEPOINT corrupt")
                db.execute(sql)
                self.assert_code(code, lambda: self.controller.execute(self.store, db, self.fixture["controller_token"],
                                 {"action": "backfill_lifecycle", "version": VERSION}))
                db.execute("ROLLBACK TO corrupt")

    def test_wrong_existing_notification_binding_or_duplicates_refuse_without_append(self):
        accepted = self.accept(live=True)
        self.upgrade()
        with self.store.transaction() as db:
            row = db.execute("SELECT content FROM events WHERE device='B1' AND seq=2").fetchone()
            duplicate = json.loads(row["content"])
            Store.append_event(db, ("B", "B1"), duplicate, accepted["acceptance_id"])
        self.assert_failure_unchanged("lifecycle_backfill_conflict")
        with self.store.transaction() as db:
            db.execute("DELETE FROM events WHERE device='B1' AND seq=3")
            db.execute("UPDATE events SET content=json_set(content,'$.target_event_id','wrong') WHERE device='B1' AND seq=2")
        self.assert_failure_unchanged("lifecycle_backfill_conflict")

    def test_full_stream_mid_fanout_rolls_back_all_markers_and_events(self):
        self.accept()
        self.seed_stream("B1", 10000)
        self.upgrade()
        inserted, original = [], Store.append_event
        def append(*args):
            original(*args)
            inserted.append(args[1])
        with patch("lifecycle_backfill.Store.append_event", side_effect=append):
            self.assert_failure_unchanged("resource_exhausted")
        self.assertEqual(inserted, [("A", "A2"), ("A", "A3")])
        self.reopen()
        self.assert_failure_unchanged("resource_exhausted")

    def test_global_60000_limit_rolls_back_partial_append_and_marker(self):
        self.accept()
        self.seed_streams({"A1": 10000, "A2": 9999, "A3": 9999, "B1": 10000, "B2": 10000, "C1": 10000})
        self.upgrade()
        inserted, original = [], Store.append_event
        def append(*args):
            original(*args)
            inserted.append(args[1])
        with patch("lifecycle_backfill.Store.append_event", side_effect=append):
            self.assert_failure_unchanged("resource_exhausted")
        self.assertEqual(len(inserted), 2)

    def test_schema_failure_rolls_back_version_and_scope_then_retries(self):
        self.accept()
        self.old5()
        before = self.snapshot()
        with patch("lifecycle_backfill.SCHEMA", "INVALID SQL"), self.assertRaises(sqlite3.OperationalError):
            self.reopen()
        self.assertEqual(self.snapshot(), before)
        self.reopen()
        self.assertEqual(self.run_backfill()["scope_count"], "5")

    def test_old_versions_upgrade_and_future_or_missing_scope_refuse(self):
        for version in range(1, 6):
            with self.subTest(version=version):
                path = self.path.with_name(f"old-{version}.sqlite3")
                store = Store(path, fixture())
                with store.transaction() as db:
                    tables = ["lifecycle_backfill"]
                    if version <= 4:
                        tables += ["history_transfers"]
                    if version <= 3:
                        tables += ["join_materials", "membership_history", "device_public_keys"]
                        db.execute("DELETE FROM meta WHERE key='join_enabled'")
                    if version <= 2:
                        tables += ["permission_resolutions"]
                    if version == 1:
                        tables += ["permission_changes", "permission_checkpoint"]
                    for table in tables:
                        db.execute(f"DROP TABLE {table}")
                    db.execute("DELETE FROM meta WHERE key='lifecycle_backfill_version'")
                    old = "rim-poc-1" if version == 1 else f"rim-poc-storage-{version}"
                    db.execute("UPDATE meta SET value=? WHERE key='schema'", (old,))
                store = Store(path, fixture())
                with store.transaction() as db:
                    self.assertEqual(store.meta(db, "schema"), "rim-poc-storage-6")
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM lifecycle_backfill").fetchone()[0], 0)
        for mutation in ("UPDATE meta SET value='rim-poc-storage-7' WHERE key='schema'", "DROP TABLE lifecycle_backfill"):
            with self.store.transaction() as db:
                db.execute(mutation)
            before = self.snapshot()
            with self.assertRaises(ValueError):
                self.reopen()
            self.assertEqual(self.snapshot(), before)
            if "UPDATE" in mutation:
                with self.store.transaction() as db:
                    db.execute("UPDATE meta SET value='rim-poc-storage-6' WHERE key='schema'")
