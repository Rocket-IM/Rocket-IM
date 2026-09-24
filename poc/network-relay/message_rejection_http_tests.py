"""真实 HTTP/SQLite 与独立 helper 失败；helper 使用明确合成签名替身。"""

import base64
from contextlib import closing
import json
import sqlite3
import time
import unittest

from contract import encode_json
from permission_tests import proof
from receipt_contract import validate_message_rejection
from receipt_test_support import ReceiptHTTPFixture, SERVICE_KEY
from test_support import envelope, key


class MessageRejectionHTTPTests(ReceiptHTTPFixture):
    def records(self):
        uri = (self.path / "relay.sqlite3").resolve().as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, isolation_level=None)) as db:
            db.execute("BEGIN")
            try:
                result = list(db.iterdump())
                db.commit()
                return result
            except BaseException:
                db.rollback()
                raise

    def packet(self, **changes):
        recipients = [m for m in self.fixture_value()["conversation"]["members"]
                      if m != {"account_id": "A", "device_id": "A1"}]
        return envelope(**{"recipients": recipients, **changes})

    def advance(self, second=False):
        change = self.change
        if second:
            change = proof("C2", "2", "e" * 64, {"kind": "revoke_device", "account_id": "A", "device_id": "A3"})
            statement = json.loads(base64.b64decode(change["statement_bytes"]))
            statement.update(issued_at_unix_secs=str(int(time.time())), expires_at_unix_secs=str(int(time.time()) + 300))
            change["statement_bytes"] = base64.b64encode(encode_json(statement)).decode()
        status, reply = self.request("submit_permission_change", {"service_id": "S1", "conversation_id": "G1", "change": change})
        self.assertEqual(status, 200, reply)

    def rejected(self, request):
        status, reply = self.request("submit_message", request)
        self.assertEqual((status, reply["error"]["code"], reply["error"]["outcome"]), (409, "state_stale", "rejected_final"))
        return reply["error"]

    def test_first_repeat_query_close_restart_and_later_permission_keep_identical_proof(self):
        packet = self.packet()
        self.advance()
        request = {"envelope": packet}
        first = self.rejected(request)
        statement = validate_message_rejection(first["rejection_receipt"])
        self.assertEqual((statement["required_authorization_version"], statement["required_crypto_state_ref"]), ("2", "b" * 64))
        self.assertEqual(statement["sender"], {"account_id": "A", "device_id": "A1"})
        value = {name: field for name, field in first.items() if name != "message"}
        self.assertEqual(self.rejected(request), first)
        self.assertEqual(self.request("get_attempt", key()), (200, {"ok": True, "result": value}))
        self.assertEqual(self.request("close_attempt", key()), (200, {"ok": True, "result": value}))
        self.advance(second=True)
        before = self.records()
        self.stop()
        self.start()
        self.assertEqual(self.rejected(request), first)
        self.assertEqual(self.request("get_attempt", key()), (200, {"ok": True, "result": value}))
        self.assertEqual(self.request("close_attempt", {**key(), "envelope_sha256": "c" * 64}), (200, {"ok": True, "result": value}))
        self.assertEqual(self.records(), before)

    def test_real_helper_failure_rolls_back_new_and_successor_rejection(self):
        status, reply = self.request("close_attempt", key())
        self.assertEqual(status, 200, reply)
        parent = reply["result"]
        self.advance()
        before = self.records()
        self.key_path.write_text(base64.b64encode(bytes([30]) * 32).decode())
        requests = ({"envelope": self.packet(logical_id="NEW")},
                    {"envelope": self.packet(attempt_id="P2"), "replaces_attempt_id": "P1", "closure_id": parent["closure_id"]})
        try:
            for request in requests:
                status, reply = self.request("submit_message", request)
                self.assertEqual((status, reply["error"]["code"], reply["error"]["outcome"]), (503, "receipt_signer_unavailable", "not_recorded"))
                self.assertNotIn("rejection_receipt", reply["error"])
                self.assertEqual(self.records(), before)
        finally:
            self.key_path.write_text(SERVICE_KEY)
        self.assertIn("rejection_receipt", self.rejected(requests[1]))

    def test_signed_successor_retry_cannot_change_or_omit_predecessor(self):
        status, reply = self.request("close_attempt", {**key(), "envelope_sha256": "c" * 64})
        self.assertEqual(status, 200, reply)
        parent = reply["result"]
        self.advance()
        request = {"envelope": self.packet(attempt_id="P2"), "replaces_attempt_id": "P1", "closure_id": parent["closure_id"]}
        first = self.rejected(request)
        statement = validate_message_rejection(first["rejection_receipt"])
        self.assertEqual((statement["replaces_attempt_id"], statement["predecessor_closure_id"]), ("P1", parent["closure_id"]))
        before = self.records()
        for changed in ({"envelope": request["envelope"]}, {**request, "replaces_attempt_id": "OTHER"}, {**request, "closure_id": "OTHER"}):
            status, reply = self.request("submit_message", changed)
            self.assertEqual((status, reply["error"]["code"]), (409, "idempotency_conflict"))
            self.assertNotIn("rejection_receipt", reply["error"])
            self.assertEqual(self.records(), before)
        self.assertEqual(self.rejected(request), first)

    def test_unsigned_future_record_stays_unsigned_after_it_becomes_stale(self):
        request = {"envelope": self.packet(authorization_version="2", crypto_state_ref="b" * 64)}
        old = self.rejected(request)
        self.assertNotIn("rejection_receipt", old)
        self.advance()
        self.advance(second=True)
        before = self.records()
        self.key_path.write_text(base64.b64encode(bytes([30]) * 32).decode())
        try:
            self.assertEqual(self.rejected(request), old)
            value = {name: field for name, field in old.items() if name != "message"}
            self.assertEqual(self.request("get_attempt", key()), (200, {"ok": True, "result": value}))
            self.assertEqual(self.request("close_attempt", key()), (200, {"ok": True, "result": value}))
            self.assertEqual(self.records(), before)
        finally:
            self.key_path.write_text(SERVICE_KEY)

    def test_future_and_other_rejections_do_not_call_failed_helper(self):
        self.advance()
        self.key_path.write_text(base64.b64encode(bytes([30]) * 32).decode())
        cases = (("future", "state_stale", {"authorization_version": "3"}),
                 ("state", "state_conflict", {"authorization_version": "2", "crypto_state_ref": "c" * 64}),
                 ("recipients", "recipient_set_mismatch", {"authorization_version": "2", "crypto_state_ref": "b" * 64,
                    "recipients": [{"account_id": "A", "device_id": "A2"}]}))
        try:
            for logical_id, code, changes in cases:
                status, reply = self.request("submit_message", {"envelope": self.packet(logical_id=logical_id, **changes)})
                self.assertEqual((status, reply["error"]["code"], reply["error"]["outcome"]), (409, code, "rejected_final"))
                self.assertNotIn("rejection_receipt", reply["error"])
        finally:
            self.key_path.write_text(SERVICE_KEY)

    def test_checkpoint_projection_mismatch_never_persists_a_signed_rejection(self):
        self.advance()
        # 明确离线损坏装置：没有公开控制器绕过签名权限链。
        self.stop()
        with closing(sqlite3.connect(self.path / "relay.sqlite3", isolation_level=None)) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE conversation SET crypto_state_ref=?", ("c" * 64,))
            db.commit()
        self.start()
        before = self.records()
        status, reply = self.request("submit_message", {"envelope": self.packet()})
        self.assertEqual((status, reply["error"]["code"], reply["error"]["outcome"]), (503, "receipt_signer_unavailable", "not_recorded"))
        self.assertNotIn("rejection_receipt", reply["error"])
        self.assertEqual(self.records(), before)


if __name__ == "__main__":
    unittest.main()
