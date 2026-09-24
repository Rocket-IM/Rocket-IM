"""设备加入的目录、事务和范围回归；合成 helper 不代表密码验签通过。"""

import base64
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from contract import ProtocolError, encode_json, validate_request
from device_join_test_support import device_join_fixture, device_join_request, edit_statement
from join_test_support import VerifiedJoinFixture, change_action
from permission_tests import proof
from receipt_test_support import ReceiptFixture, close_for
from server import DISPATCH
from storage import Store, revoke_device
from test_support import envelope


class DeviceJoinTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "relay.sqlite3"
        self.fixture, self.verifier, self.signer = device_join_fixture(), VerifiedJoinFixture(), ReceiptFixture()
        self.store = Store(self.path, self.fixture, self.verifier, self.signer)

    def tearDown(self):
        self.directory.cleanup()

    def call(self, operation, value, token="synthetic-B1-token", now=1100):
        validate_request(operation, value)
        with self.store.transaction() as db, patch("permissions.time.time", return_value=now):
            return DISPATCH[operation](self.store, db, self.store.authenticate(db, token), value)

    def submit(self, request=None, **kwargs):
        return self.call("submit_permission_change", request or device_join_request(), **kwargs)

    def material(self, token="synthetic-B3-token"):
        return self.call("get_join_material", {"service_id": "S1", "conversation_id": "G1", "change_id": "D1"}, token)

    def assert_code(self, code, operation):
        with self.assertRaises(ProtocolError) as error:
            operation()
        self.assertEqual(error.exception.code, code)

    def assert_unjoined(self):
        with self.store.transaction() as db:
            for table in ("permission_changes", "permission_resolutions", "join_materials"):
                self.assertEqual(db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], 0)
            self.assertIsNone(db.execute("SELECT 1 FROM membership_history WHERE account='B' AND device='B3'").fetchone())
            self.assertIsNone(db.execute("SELECT 1 FROM members WHERE account='B' AND device='B3'").fetchone())
            self.assertEqual(db.execute("SELECT authorization_version FROM conversation").fetchone()[0], "1")

    def test_nonowner_same_account_add_has_exact_material_and_future_only_events(self):
        targets = [m for m in self.fixture["conversation"]["members"] if m["device_id"] != "A1"]
        self.call("submit_message", {"envelope": envelope(recipients=targets)}, "synthetic-A1-token")
        request = device_join_request()
        accepted = self.submit(request)
        self.assertEqual(self.material(), {"record": {"change": request["change"], "receipt": accepted["receipt"]}, "join": request["join"]})
        for token in ("synthetic-B1-token", "synthetic-B2-token", "synthetic-A1-token", "synthetic-A3-token"):
            self.assert_code("permission_denied", lambda: self.material(token))
        pull = {"service_id": "S1", "after_seq": "0", "limit": "100"}
        self.assertEqual(self.call("pull_events", pull, "synthetic-B3-token")["events"], [])
        targets.append({"account_id": "B", "device_id": "B3"})
        self.call("submit_message", {"envelope": envelope("M2", recipients=targets, authorization_version="2", crypto_state_ref="b" * 64)}, "synthetic-A1-token")
        self.assertEqual(len(self.call("pull_events", pull, "synthetic-B3-token")["events"]), 1)
        self.assertEqual(self.verifier.joins, [request["join"]])

    def test_owner_cannot_authorize_other_account_device_and_bearer_cannot_impersonate(self):
        request = device_join_request(actor={"account_id": "A", "device_id": "A1"})
        self.assert_code("permission_denied", lambda: self.submit(request, token="synthetic-A1-token"))
        self.assert_code("permission_denied", lambda: self.submit(token="synthetic-B2-token"))
        self.assert_code("permission_denied", lambda: self.submit(token="synthetic-B3-token"))
        self.assert_unjoined()

    def test_add_member_still_cannot_add_existing_account(self):
        request = device_join_request(actor={"account_id": "A", "device_id": "A1"})
        change_action(request, kind="add_member")
        self.assert_code("permission_denied", lambda: self.submit(request, token="synthetic-A1-token"))
        self.assert_unjoined()

    def test_unknown_wrong_pin_revoked_and_ever_device_are_rejected(self):
        request = device_join_request()
        member = json.loads(base64.b64decode(request["change"]["statement_bytes"]))["action"]["member"]
        for changed in ({**member, "device_id": "unknown"}, {**member, "signature_key": base64.b64encode(bytes([71]) * 32).decode()}):
            candidate = copy.deepcopy(request)
            change_action(candidate, member=changed)
            self.assert_code("permission_denied", lambda: self.submit(candidate))
        with self.store.transaction() as db:
            db.execute("INSERT INTO membership_history VALUES ('B','B3')")
        self.assert_code("permission_denied", self.submit)
        with self.store.transaction() as db:
            db.execute("DELETE FROM membership_history WHERE account='B' AND device='B3'")
            revoke_device(db, ("B", "B3"))
        self.assert_code("permission_denied", self.submit)

    def test_signer_and_material_failure_roll_back_all_join_state(self):
        self.signer.fail = True
        self.assert_code("receipt_signer_unavailable", self.submit)
        self.assert_unjoined()
        self.signer.fail = False
        with patch("permissions.save_join", side_effect=ProtocolError("resource_exhausted", "test")):
            self.assert_code("resource_exhausted", self.submit)
        self.assert_unjoined()
        self.assertEqual(self.submit()["outcome"], "accepted")

    def test_exact_retry_after_expiry_and_restart_keeps_original_result(self):
        request = device_join_request()
        accepted, material = self.submit(request), self.material()
        self.store = Store(self.path, self.fixture, self.verifier, self.signer)
        self.signer.fail = True
        self.assertEqual(self.submit(request, now=999999), accepted)
        self.assertEqual(self.material(), material)
        changed = copy.deepcopy(request)
        changed["join"]["welcome"] = "AQ=="
        self.assert_code("idempotency_conflict", lambda: self.submit(changed))
        self.assertEqual(len(self.verifier.joins), 1)

    def test_closed_candidate_does_not_consume_device_or_key_package(self):
        request = device_join_request()
        self.call("close_permission_change", {"service_id": "S1", "conversation_id": "G1", "change": request["change"], "close": close_for(request["change"])})
        self.assert_code("permission_closed", lambda: self.submit(request))
        self.assertEqual(self.submit(device_join_request("D2", nonce="d" * 64))["outcome"], "accepted")

    def test_revoked_joined_device_cannot_fetch_welcome_or_rejoin(self):
        self.submit()
        removed = proof("R1", "2", nonce="d" * 64, action={"kind": "revoke_device", "account_id": "B", "device_id": "B3"})
        request = {"service_id": "S1", "conversation_id": "G1", "change": removed}
        edit_statement(request, actor={"account_id": "B", "device_id": "B1"})
        self.submit(request)
        self.assert_code("device_revoked", self.material)
        again = device_join_request("D2", "3", nonce="e" * 64)
        edit_statement(again, from_state_ref="d" * 64, to_state_ref="e" * 64)
        self.assert_code("permission_denied", lambda: self.submit(again))

    def test_material_checks_original_action_and_target_not_only_row(self):
        self.submit()
        with self.store.transaction() as db:
            change = json.loads(db.execute("SELECT proof FROM permission_changes WHERE change_id='D1'").fetchone()[0])
            damaged = {"change": change}
            edit_statement(damaged, action={"kind": "remove_member", "account_id": "A"})
            db.execute("UPDATE permission_changes SET proof=? WHERE change_id='D1'", (encode_json(change).decode(),))
        self.assert_code("permission_conflict", self.material)

    def test_schema4_restart_does_not_replace_candidate_pin(self):
        fixture = copy.deepcopy(self.fixture)
        next(d for d in fixture["devices"] if d["device_id"] == "B3")["signature_key"] = base64.b64encode(bytes([77]) * 32).decode()
        self.store = Store(self.path, fixture, self.verifier, self.signer)
        self.assertEqual(self.submit()["outcome"], "accepted")

    def test_legacy_join_disabled_blocks_both_add_kinds(self):
        with self.store.transaction() as db:
            for table in ("lifecycle_backfill", "history_transfers", "join_materials", "membership_history", "device_public_keys"):
                db.execute(f"DROP TABLE {table}")
            db.execute("DELETE FROM meta WHERE key IN ('join_enabled','lifecycle_backfill_version')")
            db.execute("UPDATE meta SET value='rim-poc-storage-3' WHERE key='schema'")
        self.store = Store(self.path, self.fixture, self.verifier, self.signer)
        self.assert_code("join_not_enabled", self.submit)
        request = device_join_request()
        change_action(request, kind="add_member")
        self.assert_code("join_not_enabled", lambda: self.submit(request))
        with self.store.transaction() as db:
            self.assertIsNone(db.execute("SELECT 1 FROM device_public_keys WHERE device='B3'").fetchone())


if __name__ == "__main__":
    unittest.main()
