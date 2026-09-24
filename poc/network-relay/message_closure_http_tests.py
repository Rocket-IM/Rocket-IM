"""签名封口真实HTTP/SQLite回归；helper为明示替身，真实验签另由Rust联合验证。"""

import base64
import sqlite3
import unittest
from contextlib import closing

from receipt_contract import validate_message_closure
from receipt_test_support import ReceiptHTTPFixture, SERVICE_KEY
from test_support import envelope, key


class MessageClosureHTTPTests(ReceiptHTTPFixture):
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

    def signed_close(self, **fields):
        status, reply = self.request("close_attempt", {**key(), "envelope_sha256": "c" * 64, **fields})
        self.assertEqual(status, 200, reply)
        return reply["result"]

    def packet(self, **changes):
        recipients = [m for m in self.fixture_value()["conversation"]["members"]
                      if m != {"account_id": "A", "device_id": "A1"}]
        return envelope(recipients=recipients, **changes)

    def test_signed_close_exact_repeat_query_restart_and_late_submit(self):
        first = self.signed_close()
        statement = validate_message_closure(first["closure_receipt"])
        self.assertEqual(statement["sender"], {"account_id": "A", "device_id": "A1"})
        self.assertIsNone(statement["replaces_attempt_id"])
        self.assertIsNone(statement["predecessor_closure_id"])
        before = self.records()
        self.assertEqual(self.signed_close(), first)
        self.assertEqual(self.request("get_attempt", key()), (200, {"ok": True, "result": first}))
        self.stop()
        self.start()
        self.assertEqual(self.signed_close(), first)
        status, reply = self.request("submit_message", {"envelope": self.packet()})
        self.assertEqual((status, reply["error"]["code"]), (409, "attempt_closed"))
        self.assertEqual(self.records(), before)

    def test_binding_changes_and_digest_shape_fail_without_mutation(self):
        self.signed_close()
        before = self.records()
        for request in (key(), {**key(), "envelope_sha256": "d" * 64},
                        {**key(), "envelope_sha256": "c" * 64, "replaces_attempt_id": "P0", "closure_id": "OTHER"}):
            status, reply = self.request("close_attempt", request)
            self.assertEqual((status, reply["error"]["code"]), (409, "idempotency_conflict"))
        for value in (None, 1, "C" * 64, "c" * 63):
            status, reply = self.request("close_attempt", {**key(), "envelope_sha256": value})
            self.assertEqual((status, reply["error"]["code"]), (400, "invalid_envelope"))
        self.assertEqual(self.records(), before)

    def test_real_helper_failure_rolls_back_new_and_successor_chains(self):
        parent = self.signed_close()
        before = self.records()
        self.key_path.write_text(base64.b64encode(bytes([30]) * 32).decode())
        requests = ({**key(logical_id="NEW"), "envelope_sha256": "c" * 64},
                    {**key(attempt_id="P2"), "envelope_sha256": "d" * 64,
                     "replaces_attempt_id": "P1", "closure_id": parent["closure_id"]})
        try:
            for request in requests:
                status, reply = self.request("close_attempt", request)
                self.assertEqual((status, reply["error"]["code"]), (503, "receipt_signer_unavailable"))
                self.assertEqual(self.records(), before)
        finally:
            self.key_path.write_text(SERVICE_KEY)
        self.assertEqual(self.signed_close(), parent)

    def test_successor_accepted_prioritizes_original_fact_and_preserves_old_query(self):
        parent = self.signed_close()
        status, reply = self.request("submit_message", {"envelope": self.packet(attempt_id="P2"),
                                     "replaces_attempt_id": "P1", "closure_id": parent["closure_id"]})
        self.assertEqual(status, 200, reply)
        accepted = reply["result"]
        self.assertEqual(accepted["outcome"], "accepted")
        before = self.records()
        self.assertEqual(self.signed_close(), accepted)
        self.assertEqual(self.signed_close(envelope_sha256="d" * 64), accepted)
        self.assertEqual(self.request("get_attempt", key()), (200, {"ok": True, "result": parent}))
        self.assertEqual(self.records(), before)

    def test_unsigned_legacy_record_is_not_upgraded(self):
        status, reply = self.request("close_attempt", key())
        self.assertEqual(status, 200, reply)
        old = reply["result"]
        self.assertNotIn("closure_receipt", old)
        before = self.records()
        self.assertEqual(self.signed_close(), old)
        self.assertEqual(self.records(), before)


if __name__ == "__main__":
    unittest.main()
