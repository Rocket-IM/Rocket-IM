"""签名消息封口的事务与输入边界；签名替身不作为密码正确性证据。"""

import base64
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from contract import ProtocolError, validate_request
from receipt_contract import (message_closure_statement, message_envelope_digest,
                              validate_message_closure)
from receipt_signer import ReceiptSigner
from receipt_test_support import ReceiptFixture, VerifiedCloseFixture, receipt_fixture, signed
from server import DISPATCH
from storage import Store
from test_support import envelope, key


class MessageClosureTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="rim-message-closure-")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "relay.sqlite3"
        self.fixture = receipt_fixture()
        self.signer = ReceiptFixture()
        self.store = Store(self.path, self.fixture, VerifiedCloseFixture(), self.signer)
        self.request = {**key(), "envelope_sha256": "c" * 64}

    def call(self, operation="close_attempt", request=None, token="synthetic-A1-token"):
        value = self.request if request is None else request
        validate_request(operation, value)
        with self.store.transaction() as db:
            return DISPATCH[operation](self.store, db, self.store.authenticate(db, token), value)

    def rows(self):
        with self.store.transaction() as db:
            return list(db.iterdump())

    def packet(self, **changes):
        recipients = [m for m in self.fixture["conversation"]["members"]
                      if m != {"account_id": "A", "device_id": "A1"}]
        return envelope(recipients=recipients, **changes)

    def assert_code(self, code, call, status=None):
        before = self.rows()
        with self.assertRaises(ProtocolError) as raised:
            call()
        self.assertEqual(raised.exception.code, code)
        if status is not None:
            self.assertEqual(raised.exception.status, status)
        self.assertEqual(self.rows(), before)

    def test_signed_null_attempt_records_exact_request_and_survives_reload(self):
        value = self.call()
        statement = validate_message_closure(value["closure_receipt"])
        self.assertEqual(statement, message_closure_statement(self.request,
                         {"account_id": "A", "device_id": "A1"}, value["closure_id"]))
        self.assertIsNone(statement["replaces_attempt_id"])
        self.assertIsNone(statement["predecessor_closure_id"])
        with self.store.transaction() as db:
            row = db.execute("SELECT header,payload,result FROM attempts").fetchone()
            self.assertIsNone(row["header"])
            self.assertIsNone(row["payload"])
            self.assertEqual(json.loads(row["result"]), value)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)
        self.assertEqual(self.call("get_attempt", key()), value)
        before = self.rows()
        self.store = Store(self.path, self.fixture, VerifiedCloseFixture(), ReceiptFixture())
        self.assertEqual(self.call(), value)
        self.assertEqual(self.rows(), before)

    def test_exact_retry_preserves_proof_and_changed_or_missing_binding_conflicts(self):
        value = self.call()
        self.assertEqual(self.call(), value)
        self.assertEqual(self.signer.calls, 1)
        for changed in ({**self.request, "envelope_sha256": "d" * 64}, key(),
                        {**self.request, "replaces_attempt_id": "P0", "closure_id": "different"}):
            self.assert_code("idempotency_conflict", lambda: self.call(request=changed), 409)
        self.assertEqual(self.call("get_attempt", key()), value)
        self.assertEqual(self.signer.calls, 1)

    def test_successor_binds_parent_and_repeat_cannot_rebind(self):
        first = self.call()
        successor = {**key(attempt_id="P2"), "envelope_sha256": "d" * 64,
                     "replaces_attempt_id": "P1", "closure_id": first["closure_id"]}
        self.assert_code("attempt_chain_conflict", lambda: self.call(request={**successor, "closure_id": "wrong"}), 409)
        second = self.call(request=successor)
        statement = validate_message_closure(second["closure_receipt"])
        self.assertEqual((statement["replaces_attempt_id"], statement["predecessor_closure_id"]), ("P1", first["closure_id"]))
        self.assertNotEqual(second["closure_id"], first["closure_id"])
        self.assertEqual(self.call(request=successor), second)
        self.assertEqual(self.call(), first)
        self.assert_code("idempotency_conflict", lambda: self.call(request={**successor, "closure_id": "wrong"}), 409)
        self.assert_code("idempotency_conflict", lambda: self.call(request={**key(attempt_id="P2"), "envelope_sha256": "d" * 64}), 409)

    def test_request_shape_rejects_digest_types_and_unknown_or_null_predecessors(self):
        for value in (None, True, 4, "", "c" * 63, "C" * 64, "g" * 64, "c" * 64 + "\n"):
            self.assert_code("invalid_envelope", lambda: self.call(request={**self.request, "envelope_sha256": value}), 400)
        for extra in ({"envelope": envelope()}, {"replaces_attempt_id": "P0"},
                      {"replaces_attempt_id": None, "closure_id": None}, {"sender": {"account_id": "B", "device_id": "B1"}}):
            self.assert_code("invalid_envelope", lambda: self.call(request={**self.request, **extra}), 400)
        self.assert_code("invalid_envelope", lambda: self.call("get_attempt", self.request), 400)

    def test_authentication_and_scope_bind_the_actual_sender(self):
        self.assert_code("unauthenticated", lambda: self.call(token="invalid"), 401)
        self.assert_code("permission_denied", lambda: self.call(request={**self.request, "service_id": "OTHER"}), 403)
        first = self.call()
        other = self.call(token="synthetic-A2-token")
        self.assertNotEqual(first["closure_id"], other["closure_id"])
        self.assertEqual(validate_message_closure(other["closure_receipt"])["sender"], {"account_id": "A", "device_id": "A2"})

    def test_missing_signer_never_creates_unsigned_replacement(self):
        self.store.receipt_enabled = False
        self.assert_code("receipt_signer_unavailable", self.call, 503)
        self.store.receipt_enabled = True
        self.store.receipt_signer = None
        self.assert_code("receipt_signer_unavailable", self.call, 503)
        self.assertEqual(self.signer.calls, 0)

    def test_signer_failure_rolls_back_new_chain_and_predecessor_successor(self):
        self.signer.fail = True
        self.assert_code("receipt_signer_unavailable", self.call, 503)
        self.signer.fail = False
        first = self.call()
        successor = {**key(attempt_id="P2"), "envelope_sha256": "d" * 64,
                     "replaces_attempt_id": "P1", "closure_id": first["closure_id"]}
        self.signer.fail = True
        self.assert_code("receipt_signer_unavailable", lambda: self.call(request=successor), 503)
        with self.store.transaction() as db:
            self.assertEqual(db.execute("SELECT tail FROM logical_messages").fetchone()[0], "P1")
            self.assertIsNone(db.execute("SELECT successor FROM attempts").fetchone()[0])

    def test_accepted_chain_wins_even_without_signer_or_with_different_binding(self):
        accepted = self.call("submit_message", {"envelope": self.packet()})
        before = self.rows()
        self.store.receipt_enabled = False
        self.store.receipt_signer = None
        request = {**self.request, "attempt_id": "P2", "replaces_attempt_id": "OTHER", "closure_id": "OTHER"}
        self.assertEqual(self.call(request=request), accepted)
        self.assertEqual(self.rows(), before)

    def test_rejected_final_is_not_resigned_as_cancelled(self):
        rejected = self.call("submit_message", {"envelope": self.packet(authorization_version="2")})
        self.assertEqual(rejected["outcome"], "rejected_final")
        self.store.receipt_enabled = False
        self.assertEqual(self.call(), rejected)
        self.assertNotIn("closure_receipt", rejected)
        self.assertEqual(self.signer.calls, 0)

    def test_legacy_unsigned_closure_never_upgrades(self):
        old = self.call(request=key())
        self.assertNotIn("closure_receipt", old)
        before = self.rows()
        self.signer.fail = True
        self.assertEqual(self.call(), old)
        self.assertEqual(self.call("get_attempt", key()), old)
        self.assertEqual(self.rows(), before)
        self.assertEqual(self.signer.calls, 0)

    def test_delayed_original_submit_cannot_be_accepted_after_signed_close(self):
        packet = self.packet()
        digest = message_envelope_digest(*(base64.b64decode(packet[n]) for n in ("header_bytes", "payload_bytes")))
        value = self.call(request={**key(), "envelope_sha256": digest})
        self.assert_code("attempt_closed", lambda: self.call("submit_message", {"envelope": packet}), 409)
        self.assertEqual(self.call("get_attempt", key()), value)

    def test_successor_acceptance_wins_old_close_but_old_query_keeps_proof(self):
        first = self.call()
        accepted = self.call("submit_message", {"envelope": self.packet(attempt_id="P2"),
                            "replaces_attempt_id": "P1", "closure_id": first["closure_id"]})
        self.assertEqual(accepted["outcome"], "accepted")
        before = self.rows()
        self.assertEqual(self.call(), accepted)
        self.assertEqual(self.call(request={**self.request, "envelope_sha256": "d" * 64}), accepted)
        self.assertEqual(self.call("get_attempt", key()), first)
        self.assertEqual(self.rows(), before)
        with self.store.transaction() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM attempts WHERE outcome='accepted'").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT accepted_attempt FROM logical_messages").fetchone()[0], "P2")

    def test_signed_statement_requires_explicit_nullable_predecessor_pair(self):
        statement = validate_message_closure(self.call()["closure_receipt"])
        for name in ("replaces_attempt_id", "predecessor_closure_id"):
            missing = {k: v for k, v in statement.items() if k != name}
            self.assert_code("invalid_envelope", lambda: validate_message_closure(signed(missing)))
            self.assert_code("invalid_envelope", lambda: validate_message_closure(signed({**statement, name: "P0"})))
        for changes in ({"outcome": "accepted"}, {"protocol_version": "rim-message-acceptance-1"},
                        {"extra": True}, {"sender": {"account_id": "A"}}, {"envelope_sha256": "Z" * 64}):
            self.assert_code("invalid_envelope", lambda: validate_message_closure(signed({**statement, **changes})))

    def test_signer_whitelist_checks_exact_statement_and_response_shape(self):
        statement = validate_message_closure(self.call()["closure_receipt"])
        signer = ReceiptSigner(Path(sys.executable), self.path.parent / "unused-key")
        signer.signature_key = self.fixture["relay_receipt_key"]
        with patch.object(signer, "_call", return_value={"receipt": signed(statement)}):
            self.assertEqual(validate_message_closure(signer.sign(statement)), statement)
        for name in ("service_id", "conversation_id", "logical_message_id", "attempt_id", "closure_id", "envelope_sha256"):
            wrong = {**statement, name: "d" * 64 if name == "envelope_sha256" else "OTHER"}
            with patch.object(signer, "_call", return_value={"receipt": signed(wrong)}):
                self.assert_code("receipt_signer_unavailable", lambda: signer.sign(statement), 503)

    def test_signed_statement_rejects_self_referencing_attempt_or_closure(self):
        statement = {**validate_message_closure(self.call()["closure_receipt"]),
                     "replaces_attempt_id": "P0", "predecessor_closure_id": "previous-closure"}
        self.assertEqual(validate_message_closure(signed(statement)), statement)
        for name, current in (("replaces_attempt_id", "attempt_id"),
                              ("predecessor_closure_id", "closure_id")):
            with self.subTest(field=name):
                self.assert_code("invalid_envelope", lambda: validate_message_closure(
                    signed({**statement, name: statement[current]})), 400)

    def test_api_source_matches_runtime_closure_fields(self):
        root = Path(__file__).resolve().parents[2]
        definitions = json.loads((root / "api/realtime/message.schema.json").read_text())["$defs"]
        self.assertIn("envelope_sha256", definitions["CloseRequest"]["properties"])
        self.assertIn("closure_receipt", definitions["Closed"]["properties"])
        statement = validate_message_closure(self.call()["closure_receipt"])
        self.assertEqual(set(statement), set(definitions["MessageClosureStatement"]["required"]))
        self.assertFalse(definitions["MessageClosureStatement"]["additionalProperties"])
        self.assertEqual(definitions["MessageClosureStatement"]["properties"]["outcome"]["const"], statement["outcome"])
        # Schema源说明形状；本测试不冒充通用JSON Schema验证器。


if __name__ == "__main__":
    unittest.main()
