"""一致性视图的权限与存储边界；这里的签名替身不构成密码验签证据。"""

import copy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from contract import ProtocolError, encode_json, validate_request
from permission_tests import proof
from receipt_contract import validate_consistency_head
from receipt_signer import ReceiptSigner
from receipt_test_support import ReceiptFixture, VerifiedCloseFixture, receipt_fixture, signed
from server import DISPATCH
from storage import Store


class ConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "relay.sqlite3"
        self.fixture = receipt_fixture()
        self.signer = ReceiptFixture()
        self.store = Store(self.path, self.fixture, VerifiedCloseFixture(), self.signer)
        self.request = {"service_id": "S1", "conversation_id": "G1", "challenge": "c" * 64}

    def call(self, request=None, token="synthetic-A1-token", operation="get_consistency_head"):
        value = self.request if request is None else request
        validate_request(operation, value)
        with self.store.transaction() as db, patch("permissions.time.time", return_value=1100):
            return DISPATCH[operation](self.store, db, self.store.authenticate(db, token), value)

    def assert_code(self, code, call):
        with self.assertRaises(ProtocolError) as error:
            call()
        self.assertEqual(error.exception.code, code)
        self.assertEqual(error.exception.outcome, "not_recorded")

    def test_head_binds_authenticated_actor_and_whole_database_checkpoint_without_records(self):
        with self.store.transaction() as db:
            before = list(db.iterdump())
        result = self.call(token="synthetic-A2-token")
        self.assertEqual(set(result), {"head"})
        head = validate_consistency_head(result["head"])
        self.assertEqual(head["actor"], {"account_id": "A", "device_id": "A2"})
        self.assertEqual(head["checkpoint"], self.fixture["permission_checkpoint"])
        self.assertEqual(head["challenge"], self.request["challenge"])
        with self.store.transaction() as db:
            self.assertEqual(list(db.iterdump()), before)

    def test_after_permission_commit_restart_reads_persistent_checkpoint_not_fixture(self):
        self.call({"service_id": "S1", "conversation_id": "G1", "change": proof()}, operation="submit_permission_change")
        result = self.call()
        head = validate_consistency_head(result["head"])
        self.assertEqual(head["checkpoint"]["authorization_version"], "2")
        self.assertTrue(all(member["account_id"] == "A" for member in head["checkpoint"]["members"]))
        self.store = Store(self.path, self.fixture, VerifiedCloseFixture(), ReceiptFixture())
        self.assertEqual(self.call(), result)
        self.assert_code("permission_denied", lambda: self.call(token="synthetic-B1-token"))

    def test_wrong_context_unknown_and_revoked_devices_cannot_obtain_head(self):
        for field in ("service_id", "conversation_id"):
            self.assert_code("permission_denied", lambda: self.call({**self.request, field: "OTHER"}))
        self.assert_code("unauthenticated", lambda: self.call(token="invalid"))
        change = proof(action={"kind": "revoke_device", "account_id": "A", "device_id": "A2"})
        self.call({"service_id": "S1", "conversation_id": "G1", "change": change}, operation="submit_permission_change")
        self.assert_code("device_revoked", lambda: self.call(token="synthetic-A2-token"))

    def test_signature_mode_and_signer_failure_are_explicit_and_do_not_mutate(self):
        self.store.receipt_enabled = False
        self.assert_code("receipt_not_enabled", self.call)
        self.store.receipt_enabled = True
        self.store.receipt_signer = None
        self.assert_code("receipt_signer_unavailable", self.call)
        self.store.receipt_signer = self.signer
        self.signer.fail = True
        with self.store.transaction() as db:
            before = list(db.iterdump())
        self.assert_code("receipt_signer_unavailable", self.call)
        with self.store.transaction() as db:
            self.assertEqual(list(db.iterdump()), before)

    def test_inconsistent_database_projection_is_never_signed(self):
        # 明确损坏的本机数据库装置；不通过 API 建立或伪造授权。
        for field, value in (("service_id", "OTHER"), ("authorization_version", "9"), ("members", [])):
            with self.subTest(field=field):
                checkpoint = copy.deepcopy(self.fixture["permission_checkpoint"])
                checkpoint[field] = value
                with self.store.transaction() as db:
                    db.execute("UPDATE permission_checkpoint SET checkpoint=?", (encode_json(checkpoint).decode(),))
                self.assert_code("permission_conflict", self.call)
        self.assertEqual(self.signer.calls, 0)

    def test_signer_whitelist_rejects_mismatched_or_malformed_head_output(self):
        statement = validate_consistency_head(self.call()["head"])
        signer = ReceiptSigner(Path(sys.executable), self.path.parent / "unused-seed")
        signer.signature_key = self.fixture["relay_receipt_key"]
        for field, value in (("challenge", "d" * 64), ("actor", {"account_id": "A", "device_id": "A2"}),
                             ("checkpoint", {}), ("extra", True)):
            altered = {**statement, field: value}
            with self.subTest(field=field), patch.object(signer, "_call", return_value={"receipt": signed(altered)}):
                self.assert_code("receipt_signer_unavailable", lambda: signer.sign(statement))
        with patch.object(signer, "_call", return_value={"receipt": signed(statement)}):
            self.assertEqual(validate_consistency_head(signer.sign(statement)), statement)


if __name__ == "__main__":
    unittest.main()
