"""state_stale 拒绝事务与合同；验证器和签名器均为明确替身。"""

import base64
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from contract import ProtocolError, encode_json, validate_envelope, validate_request
from messages import rejected_error
from permission_tests import permission_fixture, proof
from receipt_contract import message_rejection_statement, validate_message_rejection
from receipt_signer import ReceiptSigner
from receipt_test_support import ReceiptFixture, VerifiedCloseFixture, receipt_fixture, signed
from server import DISPATCH
from storage import Store
from test_support import envelope, key


class MessageRejectionTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="rim-message-rejection-")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "relay.sqlite3"
        self.fixture = receipt_fixture()
        self.signer = ReceiptFixture()
        self.store = Store(self.path, self.fixture, VerifiedCloseFixture(), self.signer)

    def call(self, operation, request):
        validate_request(operation, request)
        with self.store.transaction() as db, patch("permissions.time.time", return_value=1100):
            return DISPATCH[operation](self.store, db, self.store.authenticate(db, "synthetic-A1-token"), request)

    def packet(self, **changes):
        with self.store.transaction() as db:
            recipients = [{"account_id": a, "device_id": d} for a, d in self.store.members(db) if (a, d) != ("A", "A1")]
        return envelope(**{"recipients": recipients, **changes})

    def advance(self, second=False):
        change = proof("C2", "2", "e" * 64, {"kind": "revoke_device", "account_id": "A", "device_id": "A3"}) if second else proof()
        return self.call("submit_permission_change", {"service_id": "S1", "conversation_id": "G1", "change": change})

    def rows(self):
        with self.store.transaction() as db:
            return list(db.iterdump())

    def error(self, code, operation, request, status=409):
        before = self.rows()
        with self.assertRaises(ProtocolError) as raised:
            self.call(operation, request)
        value = raised.exception
        self.assertEqual((value.code, value.status), (code, status))
        self.assertEqual(self.rows(), before)
        return value

    def test_stale_proof_binds_original_bytes_and_complete_first_repeated_error(self):
        packet = self.packet()
        self.advance()
        request = {"envelope": packet}
        value = self.call("submit_message", request)
        statement = validate_message_rejection(value["rejection_receipt"])
        header, head, payload = validate_envelope(packet)
        with self.store.transaction() as db:
            conv = db.execute("SELECT * FROM conversation").fetchone()
            self.assertEqual(statement, message_rejection_statement(header, head, payload, request, value["closure_id"], conv))
            row = db.execute("SELECT header,payload,result FROM attempts").fetchone()
            self.assertEqual((row["header"], row["payload"], json.loads(row["result"])), (head, payload, value))
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)
        self.assertIsNone(statement["replaces_attempt_id"])
        self.assertIsNone(statement["predecessor_closure_id"])
        first = rejected_error(value)
        repeated = self.error("state_stale", "submit_message", request)
        self.assertEqual((repeated.outcome, repeated.details), (first.outcome, first.details))
        self.assertEqual(first.details["rejection_receipt"], value["rejection_receipt"])
        self.assertEqual(self.call("get_attempt", key()), value)
        self.assertEqual(self.call("close_attempt", key()), value)

    def test_later_permission_and_restart_do_not_resign_or_change_floor(self):
        packet = self.packet()
        self.advance()
        value = self.call("submit_message", {"envelope": packet})
        self.advance(second=True)
        before = self.rows()
        calls = self.signer.calls
        self.signer.fail = True
        self.assertEqual(self.error("state_stale", "submit_message", {"envelope": packet}).details["rejection_receipt"], value["rejection_receipt"])
        self.assertEqual(self.signer.calls, calls)
        self.store = Store(self.path, self.fixture, VerifiedCloseFixture(), ReceiptFixture())
        self.assertEqual(self.call("get_attempt", key()), value)
        self.assertEqual(self.call("close_attempt", {**key(), "envelope_sha256": "c" * 64}), value)
        self.assertEqual(self.rows(), before)
        self.assertEqual(validate_message_rejection(value["rejection_receipt"])["required_authorization_version"], "2")

    def test_signer_failure_rolls_back_new_and_successor_attempts(self):
        parent = self.call("close_attempt", key())
        self.advance()
        requests = ({"envelope": self.packet(logical_id="NEW")},
                    {"envelope": self.packet(attempt_id="P2"), "replaces_attempt_id": "P1", "closure_id": parent["closure_id"]})
        self.signer.fail = True
        for request in requests:
            self.assertEqual(self.error("receipt_signer_unavailable", "submit_message", request, 503).outcome, "not_recorded")
        self.store.receipt_signer = None
        self.assertEqual(self.error("receipt_signer_unavailable", "submit_message", requests[0], 503).outcome, "not_recorded")
        with self.store.transaction() as db:
            self.assertEqual(db.execute("SELECT tail FROM logical_messages").fetchone()[0], "P1")
            self.assertIsNone(db.execute("SELECT successor FROM attempts").fetchone()[0])

    def test_unsigned_mode_does_not_require_or_invent_a_signer(self):
        self.store = Store(self.path.parent / "unsigned.sqlite3", permission_fixture(), VerifiedCloseFixture())
        self.advance()
        value = self.call("submit_message", {"envelope": self.packet()})
        self.assertEqual(value["code"], "state_stale")
        self.assertNotIn("rejection_receipt", value)
        self.assertEqual(self.call("get_attempt", key()), value)
        self.assertEqual(self.call("close_attempt", key()), value)

    def test_preexisting_unsigned_stale_rejection_never_gets_backfilled(self):
        self.advance()
        packet = self.packet()
        with patch.object(self.store, "receipt_enabled", False):
            old = self.call("submit_message", {"envelope": packet})
        self.assertNotIn("rejection_receipt", old)
        calls = self.signer.calls
        self.signer.fail = True
        error = self.error("state_stale", "submit_message", {"envelope": packet})
        self.assertNotIn("rejection_receipt", error.details)
        self.assertEqual(self.call("get_attempt", key()), old)
        self.assertEqual(self.call("close_attempt", key()), old)
        self.assertEqual(self.signer.calls, calls)

    def test_future_version_and_other_rejection_codes_stay_unsigned(self):
        self.advance()
        calls = self.signer.calls
        self.signer.fail = True
        cases = (("future", "state_stale", {"authorization_version": "3"}),
                 ("state", "state_conflict", {"authorization_version": "2", "crypto_state_ref": "c" * 64}),
                 ("recipients", "recipient_set_mismatch", {"authorization_version": "2", "crypto_state_ref": "b" * 64,
                    "recipients": [{"account_id": "A", "device_id": "A2"}]}))
        for logical_id, code, changes in cases:
            packet = self.packet(logical_id=logical_id, **changes)
            value = self.call("submit_message", {"envelope": packet})
            self.assertEqual(value["code"], code)
            self.assertNotIn("rejection_receipt", value)
            self.assertNotIn("rejection_receipt", self.error(code, "submit_message", {"envelope": packet}).details)
        self.assertEqual(self.signer.calls, calls)

    def test_checkpoint_scope_floor_members_and_shape_must_match_projection(self):
        self.advance()
        with self.store.transaction() as db:
            original = db.execute("SELECT checkpoint FROM permission_checkpoint").fetchone()[0]
        cp = json.loads(original)
        variants = ({**cp, "service_id": "OTHER"}, {**cp, "conversation_id": "OTHER"},
                    {**cp, "authorization_version": "3"}, {**cp, "crypto_state_ref": "c" * 64},
                    {**cp, "members": cp["members"][:-1]}, {**cp, "authorization_version": "02"}, None)
        for altered in variants:
            with self.subTest(checkpoint=altered):
                with self.store.transaction() as db:
                    db.execute("UPDATE permission_checkpoint SET checkpoint=?", (encode_json(altered).decode(),))
                self.assertEqual(self.error("receipt_signer_unavailable", "submit_message", {"envelope": self.packet()}, 503).outcome, "not_recorded")
        with self.store.transaction() as db:
            db.execute("DELETE FROM permission_checkpoint")
        self.error("receipt_signer_unavailable", "submit_message", {"envelope": self.packet()}, 503)

    def test_successor_proof_binds_the_original_parent_exactly(self):
        parent = self.call("close_attempt", {**key(), "envelope_sha256": "c" * 64})
        self.advance()
        packet = self.packet(attempt_id="P2")
        request = {"envelope": packet, "replaces_attempt_id": "P1", "closure_id": parent["closure_id"]}
        value = self.call("submit_message", request)
        statement = validate_message_rejection(value["rejection_receipt"])
        self.assertEqual((statement["replaces_attempt_id"], statement["predecessor_closure_id"]), ("P1", parent["closure_id"]))
        self.assertEqual(self.error("state_stale", "submit_message", request).details["rejection_receipt"], value["rejection_receipt"])
        for changed in ({"envelope": packet}, {**request, "replaces_attempt_id": "OTHER"},
                        {**request, "closure_id": "OTHER"}):
            error = self.error("idempotency_conflict", "submit_message", changed)
            self.assertNotIn("rejection_receipt", error.details)
        self.assertEqual(self.call("get_attempt", key(attempt_id="P2")), value)

    def test_accepted_original_still_wins_after_permission_changes(self):
        packet = self.packet()
        accepted = self.call("submit_message", {"envelope": packet})
        self.advance()
        before = self.rows()
        self.signer.fail = True
        self.assertEqual(self.call("submit_message", {"envelope": packet}), accepted)
        self.assertEqual(self.call("close_attempt", key()), accepted)
        self.assertEqual(self.rows(), before)

    def test_changed_ciphertext_is_not_returned_as_original_signed_rejection(self):
        self.advance()
        value = self.call("submit_message", {"envelope": self.packet()})
        error = self.error("idempotency_conflict", "submit_message", {"envelope": self.packet(payload=b"different-opaque-fixture")})
        self.assertNotIn("rejection_receipt", error.details)
        self.assertEqual(self.call("get_attempt", key()), value)

    def test_statement_requires_exact_version_code_fields_and_nullable_pair(self):
        self.advance()
        statement = validate_message_rejection(self.call("submit_message", {"envelope": self.packet()})["rejection_receipt"])
        variants = [{k: v for k, v in statement.items() if k != name} for name in statement]
        variants += [{**statement, **change} for change in ({"code": "state_conflict"}, {"outcome": "accepted"},
                     {"protocol_version": "rim-message-closure-1"}, {"extra": True}, {"required_crypto_state_ref": "C" * 64},
                     {"replaces_attempt_id": "P0"}, {"replaces_attempt_id": "P1", "predecessor_closure_id": "old"},
                     {"replaces_attempt_id": "P0", "predecessor_closure_id": statement["closure_id"]})]
        variants += [{**statement, "required_authorization_version": value} for value in (2, True, None, "02", "-1", str(1 << 64))]
        for value in variants:
            with self.assertRaises(ProtocolError):
                validate_message_rejection(signed(value))
        maximum = {**statement, "required_authorization_version": str((1 << 64) - 1)}
        self.assertEqual(validate_message_rejection(signed(maximum)), maximum)

    def test_signer_whitelist_checks_exact_rejection_statement(self):
        self.advance()
        statement = validate_message_rejection(self.call("submit_message", {"envelope": self.packet()})["rejection_receipt"])
        signer = ReceiptSigner(Path(sys.executable), self.path.parent / "unused-key")
        signer.signature_key = self.fixture["relay_receipt_key"]
        with patch.object(signer, "_call", return_value={"receipt": signed(statement)}):
            self.assertEqual(validate_message_rejection(signer.sign(statement)), statement)
        wrong = {**statement, "required_authorization_version": "3"}
        with patch.object(signer, "_call", return_value={"receipt": signed(wrong)}):
            with self.assertRaises(ProtocolError) as raised:
                signer.sign(statement)
        self.assertEqual((raised.exception.code, raised.exception.status), ("receipt_signer_unavailable", 503))

    def test_api_source_exposes_optional_proof_and_exact_statement_fields(self):
        self.advance()
        statement = validate_message_rejection(self.call("submit_message", {"envelope": self.packet()})["rejection_receipt"])
        defs = json.loads((Path(__file__).resolve().parents[2] / "api/realtime/message.schema.json").read_text())["$defs"]
        self.assertEqual(set(statement), set(defs["MessageRejectionStatement"]["required"]))
        for name in ("Rejected", "Error"):
            self.assertEqual(defs[name]["properties"]["rejection_receipt"], {"$ref": "#/$defs/SignedMessageRejection"})
        # 仅核对声明源；不替代完整 JSON Schema 验证或密码验签。


if __name__ == "__main__":
    unittest.main()
