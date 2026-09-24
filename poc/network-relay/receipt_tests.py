"""终态事务、候选恢复与信任固定回归；实际签名安全由 Rust 联合用例验证。"""

import base64
import concurrent.futures
import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import permissions
from contract import ProtocolError, encode_json, validate_request
from permission_tests import permission_fixture, proof
from receipt_contract import proof_digest, validate_receipt
from receipt_test_support import ReceiptFixture, VerifiedCloseFixture, close_for, receipt_fixture
from server import DISPATCH
from storage import Store


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "relay.sqlite3"
        self.signer = ReceiptFixture()
        self.fixture = receipt_fixture()
        self.store = Store(self.path, self.fixture, VerifiedCloseFixture(), self.signer)

    def tearDown(self):
        self.directory.cleanup()

    def call(self, operation, value, token="synthetic-A1-token", now=1100):
        validate_request(operation, value)
        with self.store.transaction() as db, patch("permissions.time.time", return_value=now):
            device = self.store.authenticate(db, token)
            return DISPATCH[operation](self.store, db, device, value)

    def submit(self, change, **kwargs):
        return self.call("submit_permission_change", {"service_id": "S1", "conversation_id": "G1", "change": change}, **kwargs)

    def close(self, change, **kwargs):
        return self.call("close_permission_change", {"service_id": "S1", "conversation_id": "G1", "change": change, "close": close_for(change)}, **kwargs)

    def page(self, records=True, after="1"):
        return self.call("get_permission_records" if records else "get_permission_changes",
                         {"service_id": "S1", "conversation_id": "G1", "after_version": after, "limit": "32"})

    def assert_code(self, code, call):
        with self.assertRaises(ProtocolError) as caught:
            call()
        self.assertEqual(caught.exception.code, code)

    def test_accepted_then_close_returns_original_signed_record_even_after_expiry(self):
        change = proof()
        result = self.submit(change)
        accepted = validate_receipt(result["receipt"])
        self.assertEqual((accepted["outcome"], accepted["authorization_version"]), ("accepted", "2"))
        self.assertEqual(accepted["proof_sha256"], proof_digest(change))
        self.assertEqual(self.close(change, now=999999), {"change": change, "receipt": result["receipt"]})
        self.assertEqual(self.submit(change, now=999999), result)
        self.assertEqual(self.signer.calls, 1)

    def test_expired_candidate_can_close_and_never_revives(self):
        change = proof()
        record = self.close(change, now=999999)
        closed = validate_receipt(record["receipt"])
        self.assertEqual((closed["outcome"], closed["authorization_version"], closed["crypto_state_ref"]), ("closed", "1", "a" * 64))
        self.assertEqual(self.close(change, now=9999999), record)
        self.assert_code("permission_closed", lambda: self.submit(change, now=9999999))
        changed = {**change, "commit_bytes": "AQ=="}
        self.assert_code("idempotency_conflict", lambda: self.close(changed))
        self.assert_code("idempotency_conflict", lambda: self.submit(changed))
        self.assertEqual(self.page()["records"], [])
        self.assertEqual(self.signer.calls, 1)

    def test_close_cannot_issue_a_floor_before_candidate_predecessor(self):
        self.assert_code("permission_version", lambda: self.close(proof(version="2")))
        with self.store.transaction() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM permission_resolutions").fetchone()[0], 0)
        self.assertEqual(self.signer.calls, 0)

    def test_submit_and_close_race_has_one_terminal_decision(self):
        change = proof()
        barrier = threading.Barrier(2)
        def operation(close):
            barrier.wait()
            try:
                value = self.close(change) if close else self.submit(change)
                return validate_receipt(value["receipt"])["outcome"]
            except ProtocolError as error:
                return error.code
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            futures = [pool.submit(operation, close) for close in (False, True)]
            outcomes = [future.result() for future in futures]
        self.assertIn(outcomes, (["accepted", "accepted"], ["permission_closed", "closed"]))
        with self.store.transaction() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM permission_resolutions").fetchone()[0], 1)
        self.assertEqual(self.signer.calls, 1)

    def test_signer_failure_rolls_back_acceptance_and_close(self):
        self.signer.fail = True
        self.assert_code("receipt_signer_unavailable", lambda: self.submit(proof()))
        self.assert_code("receipt_signer_unavailable", lambda: self.close(proof()))
        with self.store.transaction() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM permission_resolutions").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM permission_changes").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT authorization_version FROM conversation").fetchone()[0], "1")
        self.signer.fail = False
        self.assertEqual(self.submit(proof())["authorization_version"], "2")

    def test_restart_rejects_missing_changed_or_late_injected_service_key(self):
        result = self.submit(proof())
        with self.assertRaises(ValueError):
            Store(self.path, permission_fixture(), VerifiedCloseFixture())
        changed = ReceiptFixture(base64.b64encode(bytes([30]) * 32).decode())
        with self.assertRaises(ValueError):
            Store(self.path, permission_fixture(), VerifiedCloseFixture(), changed)
        self.store = Store(self.path, self.fixture, VerifiedCloseFixture(), ReceiptFixture())
        self.assertEqual(self.submit(proof(), now=999999), result)
        legacy = Path(self.directory.name) / "legacy.sqlite3"
        Store(legacy, permission_fixture(), VerifiedCloseFixture())
        with self.assertRaises(ValueError):
            Store(legacy, self.fixture, VerifiedCloseFixture(), ReceiptFixture())

    def test_initialization_receipt_failure_leaves_no_partial_schema_or_trust(self):
        path = Path(self.directory.name) / "interrupted.sqlite3"
        with patch("permissions.RECEIPT_SCHEMA", permissions.RECEIPT_SCHEMA + "INVALID SQL;"), self.assertRaises(sqlite3.OperationalError):
            Store(path, self.fixture, VerifiedCloseFixture(), ReceiptFixture())
        db = sqlite3.connect(path)
        try:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0], 0)
        finally:
            db.close()
        self.assertTrue(Store(path, self.fixture, VerifiedCloseFixture(), ReceiptFixture()).receipt_enabled)

    def test_total_record_limit_includes_closed_but_keeps_exact_retry(self):
        with patch("permission_records.MAX_PERMISSION_RECORDS", 1):
            change = proof()
            record = self.close(change)
            self.assertEqual(self.close(change), record)
            self.assert_code("resource_exhausted", lambda: self.close(proof("C2", nonce="d" * 64)))
            self.assert_code("resource_exhausted", lambda: self.submit(proof("C2", nonce="d" * 64)))
        self.assertEqual(self.page()["records"], [])

    def test_records_page_preserves_pairing_bytes_budget_and_raw_proof_api(self):
        first = proof(commit=b"x" * (512 * 1024))
        second = proof("C2", "2", nonce="d" * 64, action={"kind": "revoke_device", "account_id": "A", "device_id": "A2"}, commit=b"y" * (512 * 1024))
        accepted = self.submit(first)
        self.submit(second)
        page = self.page()
        self.assertEqual(page["records"], [{"change": first, "receipt": accepted["receipt"]}])
        self.assertEqual((page["next_after_version"], page["authorization_version"], page["has_more"]), ("2", "3", True))
        self.assertLess(len(encode_json({"ok": True, "result": page})), 900 * 1024)
        self.assertEqual(self.page(after="2")["records"][0]["change"], second)
        self.assertEqual(self.page(records=False)["changes"], [first])
        self.assert_code("permission_denied", lambda: self.close(first, token="synthetic-A3-token"))

    def test_v2_upgrade_keeps_old_acceptances_without_inventing_receipts(self):
        legacy = Path(self.directory.name) / "storage2.sqlite3"
        old = Store(legacy, permission_fixture(), VerifiedCloseFixture())
        req = {"service_id": "S1", "conversation_id": "G1", "change": proof()}
        with old.transaction() as db, patch("permissions.time.time", return_value=1100):
            device = old.authenticate(db, "synthetic-A1-token")
            original = DISPATCH["submit_permission_change"](old, db, device, req)
            db.execute("DROP TABLE permission_resolutions")
            for table in ("lifecycle_backfill", "history_transfers", "join_materials", "membership_history", "device_public_keys"):
                db.execute(f"DROP TABLE {table}")
            db.execute("DELETE FROM meta WHERE key IN ('join_enabled','lifecycle_backfill_version')")
            db.execute("UPDATE meta SET value='rim-poc-storage-2' WHERE key='schema'")
        self.store = Store(legacy, permission_fixture(), VerifiedCloseFixture())
        self.assertFalse(self.store.receipt_enabled)
        self.assertEqual(self.submit(proof(), now=999999), original)
        self.assert_code("receipt_not_enabled", lambda: self.page())


if __name__ == "__main__":
    unittest.main()
