"""入群目录、材料和事务迁移回归；真实MLS验证属于Rust联合验收。"""

import base64
import copy
import concurrent.futures
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from contract import ProtocolError, encode_json, validate_request
from join_test_support import VerifiedJoinFixture, change_action, join_fixture, join_request
from permission_tests import proof
from permission_verifier import PermissionVerifier
from receipt_test_support import ReceiptFixture, close_for
from server import DISPATCH
from storage import Store, revoke_device
from test_support import envelope


class JoinTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "relay.sqlite3"
        self.fixture, self.verifier, self.signer = join_fixture(), VerifiedJoinFixture(), ReceiptFixture()
        self.store = Store(self.path, self.fixture, self.verifier, self.signer)

    def tearDown(self):
        self.directory.cleanup()

    def call(self, operation, value, token="synthetic-A1-token", now=1100):
        validate_request(operation, value)
        with self.store.transaction() as db, patch("permissions.time.time", return_value=now):
            return DISPATCH[operation](self.store, db, self.store.authenticate(db, token), value)

    def submit(self, request=None, **kwargs):
        return self.call("submit_permission_change", request or join_request(), **kwargs)

    def material(self, change_id="J1", token="synthetic-D1-token"):
        return self.call("get_join_material", {"service_id": "S1", "conversation_id": "G1", "change_id": change_id}, token)

    def assert_code(self, code, operation):
        with self.assertRaises(ProtocolError) as error:
            operation()
        self.assertEqual(error.exception.code, code)

    def assert_unjoined(self):
        with self.store.transaction() as db:
            for table in ("permission_changes", "permission_resolutions", "join_materials"):
                self.assertEqual(db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM membership_history WHERE account='D'").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM members WHERE account='D'").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT authorization_version FROM conversation").fetchone()[0], "1")

    def test_join_get_is_target_bound_and_old_events_are_not_backfilled(self):
        targets = [m for m in self.fixture["conversation"]["members"] if m["device_id"] != "A1"]
        old = self.call("submit_message", {"envelope": envelope(recipients=targets)})
        request = join_request()
        accepted = self.submit(request)
        self.assertEqual(self.material(), {"record": {"change": request["change"], "receipt": accepted["receipt"]}, "join": request["join"]})
        for token in ("synthetic-A1-token", "synthetic-A2-token", "synthetic-E1-token"):
            self.assert_code("permission_denied", lambda: self.material(token=token))
        page = {"service_id": "S1", "after_seq": "0", "limit": "100"}
        self.assertEqual(self.call("pull_events", page, "synthetic-D1-token")["events"], [])
        self.assertEqual(self.call("submit_message", {"envelope": envelope(recipients=targets)}), old)
        targets.append({"account_id": "D", "device_id": "D1"})
        self.call("submit_message", {"envelope": envelope("M2", recipients=targets, authorization_version="2", crypto_state_ref="b" * 64)})
        self.assertEqual(len(self.call("pull_events", page, "synthetic-D1-token")["events"]), 1)
        self.assertEqual(self.verifier.joins, [request["join"]])

    def test_exact_retry_preserves_material_after_expiry_restart_and_rejects_change(self):
        request = join_request()
        accepted = self.submit(request)
        material = self.material()
        self.store = Store(self.path, self.fixture, self.verifier, self.signer)
        self.signer.fail = True
        self.assertEqual(self.submit(request, now=9999999), accepted)
        self.assertEqual(self.material(), material)
        changed = copy.deepcopy(request)
        changed["join"]["welcome"] = "AQ=="
        self.assert_code("idempotency_conflict", lambda: self.submit(changed))
        self.assertEqual(len(self.verifier.joins), 1)

    def test_concurrent_duplicate_accepts_one_join_and_consumes_key_package_once(self):
        request = join_request()
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            results = list(pool.map(lambda _: self.submit(request), range(2)))
        self.assertEqual(results[0], results[1])
        self.assertEqual(len(self.verifier.joins), 1)
        self.assertEqual(self.signer.calls, 1)
        with self.store.transaction() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM join_materials").fetchone()[0], 1)

    def test_competing_old_candidate_returns_verified_version_error_before_ledger(self):
        self.submit()
        with patch.object(self.verifier, "verify", side_effect=ProtocolError("permission_version", "已验证前驱冲突", status=409)) as helper:
            self.assert_code("permission_version", lambda: self.submit(join_request("J2", nonce="d" * 64)))
        helper.assert_called_once()
        self.assertEqual(self.signer.calls, 1)

    def test_failed_verifier_signer_and_material_storage_leave_no_partial_join(self):
        with patch.object(self.verifier, "verify", side_effect=ProtocolError("permission_signature", "test")):
            self.assert_code("permission_signature", self.submit)
        self.assert_unjoined()
        self.signer.fail = True
        self.assert_code("receipt_signer_unavailable", self.submit)
        self.assert_unjoined()
        self.signer.fail = False
        with patch("permissions.save_join", side_effect=ProtocolError("resource_exhausted", "test")):
            self.assert_code("resource_exhausted", self.submit)
        self.assert_unjoined()

    def test_unknown_changed_revoked_or_preexisting_account_is_rejected(self):
        request = join_request()
        member = json.loads(base64.b64decode(request["change"]["statement_bytes"]))["action"]["member"]
        for changed_member in ({**member, "device_id": "unknown"}, {**member, "signature_key": base64.b64encode(bytes([70]) * 32).decode()},
                               {k: self.fixture["devices"][0][k] for k in ("account_id", "device_id", "signature_key")}):
            changed = copy.deepcopy(request)
            change_action(changed, member=changed_member)
            self.assert_code("permission_denied", lambda: self.submit(changed))
        self.assert_code("permission_denied", lambda: self.submit(request, token="synthetic-A2-token"))
        with self.store.transaction() as db:
            revoke_device(db, ("D", "D1"))
        self.assert_code("permission_denied", self.submit)
        self.assert_unjoined()

    def test_closed_candidate_does_not_consume_key_package(self):
        request = join_request()
        self.call("close_permission_change", {"service_id": "S1", "conversation_id": "G1", "change": request["change"], "close": close_for(request["change"])})
        self.assert_code("permission_closed", lambda: self.submit(request))
        accepted = self.submit(join_request("J2", nonce="d" * 64))
        self.assertEqual(accepted["authorization_version"], "2")
        self.assert_code("permission_replay", lambda: self.submit(join_request("J3", "2", account="E", key_package=b"fixture-key-package-D", nonce="e" * 64)))

    def test_removed_account_cannot_rejoin_or_fetch_old_welcome(self):
        self.submit()
        removed = proof("R1", "2", nonce="d" * 64, action={"kind": "remove_member", "account_id": "D"})
        self.submit({"service_id": "S1", "conversation_id": "G1", "change": removed})
        self.assert_code("permission_denied", self.material)
        request = join_request("J2", "3", nonce="e" * 64)
        statement = json.loads(base64.b64decode(request["change"]["statement_bytes"]))
        statement.update(from_state_ref="d" * 64, to_state_ref="e" * 64)
        request["change"]["statement_bytes"] = base64.b64encode(encode_json(statement)).decode()
        self.assert_code("permission_denied", lambda: self.submit(request))

    def test_new_member_can_verify_public_prior_chain_without_any_welcome(self):
        removed = proof("R1")
        self.submit({"service_id": "S1", "conversation_id": "G1", "change": removed})
        request = join_request("J1", "2", nonce="d" * 64)
        self.submit(request)
        page = self.call("get_permission_records", {"service_id": "S1", "conversation_id": "G1", "after_version": "1", "limit": "32"}, "synthetic-D1-token")
        self.assertEqual([r["change"] for r in page["records"]], [removed, request["change"]])
        self.assertEqual(page["next_after_version"], "3")
        self.assertTrue(all(set(record) == {"change", "receipt"} for record in page["records"]))

    def test_join_digest_and_full_response_budget_fail_before_acceptance(self):
        request = join_request()
        request["join"]["welcome"] = "AQ=="
        self.assert_code("join_material_mismatch", lambda: self.submit(request))
        large = join_request(commit=b"c" * (300 * 1024), welcome=b"w" * (400 * 1024))
        self.assert_code("resource_exhausted", lambda: self.submit(large))
        self.assert_unjoined()

    def test_helper_complete_input_budget_is_checked_before_launch(self):
        verifier = PermissionVerifier(sys.executable)
        with patch.object(verifier, "_run") as run:
            self.assert_code("resource_exhausted", lambda: verifier._call({"checkpoint": self.fixture["permission_checkpoint"],
                             **join_request(commit=b"c" * (512 * 1024), welcome=b"w" * (512 * 1024))}))
        run.assert_not_called()

    def test_restart_fixture_cannot_replace_directory_pin(self):
        changed = copy.deepcopy(self.fixture)
        next(d for d in changed["devices"] if d["device_id"] == "D1")["signature_key"] = base64.b64encode(bytes([77]) * 32).decode()
        self.store = Store(self.path, changed, self.verifier, self.signer)
        self.assertEqual(self.submit()["outcome"], "accepted")

    def make_schema3(self):
        with self.store.transaction() as db:
            for table in ("lifecycle_backfill", "history_transfers", "join_materials", "membership_history", "device_public_keys"):
                db.execute(f"DROP TABLE {table}")
            db.execute("DELETE FROM meta WHERE key IN ('join_enabled','lifecycle_backfill_version')")
            db.execute("UPDATE meta SET value='rim-poc-storage-3' WHERE key='schema'")

    def test_schema3_upgrade_disables_add_and_uses_only_persisted_checkpoint_keys(self):
        self.make_schema3()
        self.store = Store(self.path, self.fixture, self.verifier, self.signer)
        with self.store.transaction() as db:
            self.assertEqual(self.store.meta(db, "schema"), "rim-poc-storage-6")
            self.assertEqual(self.store.meta(db, "join_enabled"), "0")
            self.assertIsNone(db.execute("SELECT 1 FROM device_public_keys WHERE account='D'").fetchone())
        self.assert_code("join_not_enabled", self.submit)
        self.assertEqual(self.submit({"service_id": "S1", "conversation_id": "G1", "change": proof()})["outcome"], "accepted")

    def test_failed_schema_migration_rolls_back_and_can_retry(self):
        import join_materials
        self.make_schema3()
        with patch("join_materials.JOIN_SCHEMA", join_materials.JOIN_SCHEMA + "INVALID SQL;"), self.assertRaises(sqlite3.OperationalError):
            Store(self.path, self.fixture, self.verifier, self.signer)
        with self.store.transaction() as db:
            self.assertEqual(self.store.meta(db, "schema"), "rim-poc-storage-3")
            self.assertEqual(db.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='join_materials'").fetchone()[0], 0)
        self.store = Store(self.path, self.fixture, self.verifier, self.signer)
        self.assert_code("join_not_enabled", self.submit)


if __name__ == "__main__":
    unittest.main()
