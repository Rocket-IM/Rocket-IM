"""迁移授权、选择、幂等及实验库升级；密码验证使用明确替身。"""

import copy
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from contract import ProtocolError, encode_json, validate_request
from device_join_test_support import device_join_fixture, device_join_request
from history_transfer_test_support import VerifiedHistoryFixture, selection_item, transfer
from permission_tests import proof
from receipt_test_support import ReceiptFixture
from server import DISPATCH
from storage import Store, revoke_device
from synchronization import set_availability
from test_support import envelope


class HistoryTransferTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "relay.sqlite3"
        self.fixture, self.verifier, self.signer = device_join_fixture(), VerifiedHistoryFixture(), ReceiptFixture()
        self.store = Store(self.path, self.fixture, self.verifier, self.signer)
        targets = [m for m in self.fixture["conversation"]["members"] if m["device_id"] != "A1"]
        self.items = []
        for name in ("M1", "M2"):
            original = envelope(name, recipients=targets)
            accepted = self.call("submit_message", {"envelope": original}, "synthetic-A1-token")
            self.items.append(selection_item(accepted, original))
        self.call("submit_permission_change", device_join_request())
        self.request = transfer(self.items)

    def tearDown(self):
        self.directory.cleanup()

    def call(self, operation, value, token="synthetic-B1-token", now=1100):
        validate_request(operation, value)
        with self.store.transaction() as db, patch("history_transfers.time.time", return_value=now):
            return DISPATCH[operation](self.store, db, self.store.authenticate(db, token), value)

    def submit(self, value=None, **kwargs):
        return self.call("submit_history_transfer", value or self.request, **kwargs)

    def get(self, token="synthetic-B3-token", **kwargs):
        return self.call("get_history_transfer", {"service_id": "S1", "conversation_id": "G1", "transfer_id": "T1"}, token, **kwargs)

    def sender_request(self):
        return transfer(self.items, source={"account_id": "A", "device_id": "A1"}, target={"account_id": "A", "device_id": "A2"})

    def assert_code(self, code, operation):
        with self.assertRaises(ProtocolError) as error:
            operation()
        self.assertEqual(error.exception.code, code)

    def count(self):
        with self.store.transaction() as db:
            return db.execute("SELECT COUNT(*) FROM history_transfers").fetchone()[0]

    def test_target_only_transfer_preserves_old_stream_and_all_original_receipts(self):
        with self.store.transaction() as db:
            before = [tuple(r) for r in db.execute("SELECT * FROM events")]
        accepted = self.submit()
        self.assertEqual(self.get(), accepted)
        for token in ("synthetic-B1-token", "synthetic-B2-token", "synthetic-A1-token"):
            self.assert_code("history_denied", lambda: self.get(token))
        with self.store.transaction() as db:
            self.assertEqual([tuple(r) for r in db.execute("SELECT * FROM events")], before)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events WHERE device='B3'").fetchone()[0], 0)

    def test_retry_accepts_reordered_outer_fields_and_restart_preserves_original_receipt(self):
        accepted = self.submit()
        changed = copy.deepcopy(self.request)
        for name in ("request", "package"):
            changed[name] = dict(reversed(list(changed[name].items())))
        self.signer.fail = True
        self.store = Store(self.path, self.fixture, self.verifier, self.signer)
        self.assertEqual(self.submit(changed), accepted)
        self.assertEqual(self.get(), accepted)
        self.assertEqual(self.count(), 1)

    def test_token_cross_account_and_original_sender_without_receipt_are_rejected(self):
        self.assert_code("history_denied", lambda: self.submit(token="synthetic-B2-token"))
        wrong = transfer(self.items, target={"account_id": "A", "device_id": "A2"})
        self.assert_code("history_denied", lambda: self.submit(wrong))
        with self.store.transaction() as db:
            row = db.execute("SELECT result FROM attempts WHERE acceptance_id=?", (self.items[0]["acceptance_id"],)).fetchone()
            result = json.loads(row[0]); result.pop("acceptance_receipt")
            db.execute("UPDATE attempts SET result=? WHERE acceptance_id=?", (encode_json(result).decode(), self.items[0]["acceptance_id"]))
        self.assert_code("history_unavailable", lambda: self.submit(self.sender_request(), token="synthetic-A1-token"))
        self.assertEqual(self.count(), 0)

    def test_original_sender_succeeds_without_self_event_and_does_not_create_one(self):
        with self.store.transaction() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events WHERE device='A1'").fetchone()[0], 0)
            before = [tuple(row) for row in db.execute("SELECT * FROM events")]
        accepted = self.submit(self.sender_request(), token="synthetic-A1-token")
        self.assertEqual(self.get("synthetic-A2-token"), accepted)
        self.assertEqual(self.submit(self.sender_request(), token="synthetic-A1-token"), accepted)
        with self.store.transaction() as db:
            self.assertEqual([tuple(row) for row in db.execute("SELECT * FROM events")], before)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0], 0)

    def test_same_account_new_device_cannot_borrow_original_sender_role(self):
        joined = device_join_request("D2", "2", account="A", nonce="e" * 64, key_package=b"A3-package")
        self.call("submit_permission_change", joined, "synthetic-A1-token")
        request = transfer(self.items, source={"account_id": "A", "device_id": "A3"}, target={"account_id": "A", "device_id": "A2"},
                           authorization_version="3", crypto_state_ref="d" * 64)
        self.assert_code("history_unavailable", lambda: self.submit(request, token="synthetic-A3-token"))
        self.assertEqual(self.count(), 0)

    def test_same_account_recipient_still_requires_own_available_message_event(self):
        with self.store.transaction() as db:
            db.execute("UPDATE events SET availability='access_removed' WHERE device='A2' AND acceptance_id=?", (self.items[0]["acceptance_id"],))
        request = transfer(self.items, source={"account_id": "A", "device_id": "A2"}, target={"account_id": "A", "device_id": "A1"})
        self.assert_code("history_unavailable", lambda: self.submit(request, token="synthetic-A2-token"))
        self.assertEqual(self.count(), 0)

    def test_sender_deleted_selection_rejects_whole_batch_despite_queryable_receipt(self):
        request = self.sender_request()
        self.submit(request, token="synthetic-A1-token")
        with self.store.transaction() as db:
            set_availability(db, self.items[1]["acceptance_id"], "deleted")
        status = self.call("get_attempt", {"service_id": "S1", "conversation_id": "G1", "logical_message_id": "M2", "attempt_id": "P1"}, "synthetic-A1-token")
        self.assertEqual(status["availability"], "deleted")
        self.assertIn("acceptance_receipt", status)
        self.assertNotIn("payload", status)
        self.assertNotIn("envelope", status)
        self.assert_code("history_unavailable", lambda: self.submit(request, token="synthetic-A1-token"))
        self.assert_code("history_unavailable", lambda: self.get("synthetic-A2-token"))

    def test_sender_original_expiry_is_enforced_even_before_availability_projection(self):
        with self.store.transaction() as db:
            row = db.execute("SELECT result FROM attempts WHERE acceptance_id=?", (self.items[1]["acceptance_id"],)).fetchone()
            result = json.loads(row[0]); result["expires_at_unix_ms"] = "1100000"
            db.execute("UPDATE attempts SET result=? WHERE acceptance_id=?", (encode_json(result).decode(), self.items[1]["acceptance_id"]))
        self.assert_code("history_unavailable", lambda: self.submit(self.sender_request(), token="synthetic-A1-token"))
        self.assertEqual(self.count(), 0)

    def test_revoked_sender_cannot_query_receipt_or_release_already_accepted_batch(self):
        self.submit(self.sender_request(), token="synthetic-A1-token")
        with self.store.transaction() as db:
            revoke_device(db, ("A", "A1"))
        self.assert_code("history_denied", lambda: self.get("synthetic-A2-token"))
        self.assert_code("device_revoked", lambda: self.call("get_attempt", {"service_id": "S1", "conversation_id": "G1", "logical_message_id": "M1", "attempt_id": "P1"}, "synthetic-A1-token"))

    def test_unaccepted_sender_attempt_cannot_be_migrated(self):
        original = envelope("M3")
        rejected = self.call("submit_message", {"envelope": original}, "synthetic-A1-token")
        self.assertEqual(rejected["outcome"], "rejected_final")
        request = transfer([selection_item({"acceptance_id": rejected["closure_id"]}, original)],
                           source={"account_id": "A", "device_id": "A1"}, target={"account_id": "A", "device_id": "A2"})
        self.assert_code("history_unavailable", lambda: self.submit(request, token="synthetic-A1-token"))
        self.assertEqual(self.count(), 0)

    def test_one_deleted_original_rejects_whole_selection_and_all_later_retries(self):
        self.submit()
        with self.store.transaction() as db:
            set_availability(db, self.items[1]["acceptance_id"], "deleted")
        self.assert_code("history_unavailable", self.get)
        self.assert_code("history_unavailable", self.submit)
        self.assertEqual(self.count(), 1)

    def test_source_event_loss_rejects_even_when_accepted_record_remains_available(self):
        with self.store.transaction() as db:
            db.execute("UPDATE events SET availability='access_removed' WHERE account='B' AND device='B1' AND acceptance_id=?", (self.items[0]["acceptance_id"],))
        self.assert_code("history_unavailable", self.submit)
        self.assertEqual(self.count(), 0)

    def test_original_expiry_is_checked_without_pull_or_projection(self):
        with self.store.transaction() as db:
            row = db.execute("SELECT result FROM attempts WHERE acceptance_id=?", (self.items[0]["acceptance_id"],)).fetchone()
            result = json.loads(row[0]); result["expires_at_unix_ms"] = "1100000"
            db.execute("UPDATE attempts SET result=? WHERE acceptance_id=?", (encode_json(result).decode(), self.items[0]["acceptance_id"]))
        self.assert_code("history_unavailable", self.submit)
        with self.store.transaction() as db:
            self.assertEqual(db.execute("SELECT availability FROM attempts WHERE acceptance_id=?", (self.items[0]["acceptance_id"],)).fetchone()[0], "available")

    def test_request_expiry_is_right_open_on_submit_retry_and_get(self):
        self.assert_code("history_expired", lambda: self.submit(now=999))
        self.submit(now=1299)
        self.assert_code("history_expired", lambda: self.submit(now=1300))
        self.assert_code("history_expired", lambda: self.get(now=1300))

    def test_source_revocation_prevents_target_release_and_target_revocation_blocks_token(self):
        self.submit()
        with self.store.transaction() as db:
            revoke_device(db, ("B", "B1"))
        self.assert_code("history_denied", self.get)
        with self.store.transaction() as db:
            revoke_device(db, ("B", "B3"))
        self.assert_code("device_revoked", self.get)

    def test_unchanged_device_membership_does_not_bypass_new_checkpoint(self):
        self.submit()
        change = proof("R1", "2", nonce="d" * 64, action={"kind": "revoke_device", "account_id": "A", "device_id": "A2"})
        self.call("submit_permission_change", {"service_id": "S1", "conversation_id": "G1", "change": change}, "synthetic-A1-token")
        self.assert_code("history_context", self.get)
        self.assert_code("history_context", self.submit)

    def test_unknown_digest_or_unsigned_original_fails_without_partial_acceptance(self):
        bad = copy.deepcopy(self.items); bad[0]["envelope_sha256"] = "0" * 64
        self.assert_code("history_unavailable", lambda: self.submit(transfer(bad)))
        with self.store.transaction() as db:
            row = db.execute("SELECT result FROM attempts WHERE acceptance_id=?", (self.items[0]["acceptance_id"],)).fetchone()
            result = json.loads(row[0]); result.pop("acceptance_receipt")
            db.execute("UPDATE attempts SET result=? WHERE acceptance_id=?", (encode_json(result).decode(), self.items[0]["acceptance_id"]))
        self.assert_code("history_unavailable", self.submit)
        self.assertEqual(self.count(), 0)

    def test_id_nonce_conflict_and_capacity_never_replace_original(self):
        accepted = self.submit()
        changed = copy.deepcopy(self.request)
        # 仍合法编码长度，实际密文字节改变。
        changed["package"]["ciphertext"] = "AQEBAQEBAQEBAQEBAQEBAQ=="
        self.assert_code("history_conflict", lambda: self.submit(changed))
        self.assert_code("history_conflict", lambda: self.submit(transfer(self.items, transfer_id="T2")))
        with patch("history_transfers.MAX_TRANSFERS", 1):
            self.assert_code("resource_exhausted", lambda: self.submit(transfer(self.items, transfer_id="T2", nonce="e" * 64)))
        self.assertEqual(self.get(), accepted)

    def test_failed_public_verifier_signer_or_response_budget_rolls_back(self):
        with patch.object(self.verifier, "verify_history_transfer", side_effect=ProtocolError("history_signature", "test", status=403)):
            self.assert_code("history_signature", self.submit)
        self.signer.fail = True
        self.assert_code("receipt_signer_unavailable", self.submit)
        self.signer.fail = False
        with patch("history_transfers.MAX_RESPONSE_BYTES", 1):
            self.assert_code("resource_exhausted", self.submit)
        self.assertEqual(self.count(), 0)
        self.assertEqual(self.submit(), self.get())

    def test_v4_upgrade_creates_only_empty_history_table_without_new_trust(self):
        with self.store.transaction() as db:
            before = [tuple(row) for row in db.execute("SELECT * FROM device_public_keys")]
            db.execute("DROP TABLE history_transfers")
            db.execute("DROP TABLE lifecycle_backfill")
            db.execute("DELETE FROM meta WHERE key='lifecycle_backfill_version'")
            db.execute("UPDATE meta SET value='rim-poc-storage-4' WHERE key='schema'")
        self.store = Store(self.path, self.fixture, self.verifier, self.signer)
        with self.store.transaction() as db:
            self.assertEqual(self.store.meta(db, "schema"), "rim-poc-storage-7")
            self.assertEqual([tuple(row) for row in db.execute("SELECT * FROM device_public_keys")], before)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM join_materials").fetchone()[0], 1)
        self.assertEqual(self.count(), 0)

    def test_expiry_during_signer_call_prevents_commit(self):
        from receipt_test_support import signed
        with patch("history_transfers.time.time", return_value=1299) as clock:
            def signing(statement):
                clock.return_value = 1300
                return signed(statement)
            with patch.object(self.signer, "sign", side_effect=signing), self.store.transaction() as db:
                self.assert_code("history_expired", lambda: DISPATCH["submit_history_transfer"](
                    self.store, db, self.store.authenticate(db, "synthetic-B1-token"), self.request))
        self.assertEqual(self.count(), 0)

    def test_failed_v4_upgrade_is_atomic_and_retryable(self):
        with self.store.transaction() as db:
            db.execute("DROP TABLE history_transfers")
            db.execute("DROP TABLE lifecycle_backfill")
            db.execute("DELETE FROM meta WHERE key='lifecycle_backfill_version'")
            db.execute("UPDATE meta SET value='rim-poc-storage-4' WHERE key='schema'")
        with patch("history_transfers.HISTORY_SCHEMA", "INVALID SQL"), self.assertRaises(sqlite3.OperationalError):
            Store(self.path, self.fixture, self.verifier, self.signer)
        with self.store.transaction() as db:
            self.assertEqual(self.store.meta(db, "schema"), "rim-poc-storage-4")
        self.store = Store(self.path, self.fixture, self.verifier, self.signer)
        self.assertEqual(self.count(), 0)


if __name__ == "__main__":
    unittest.main()
