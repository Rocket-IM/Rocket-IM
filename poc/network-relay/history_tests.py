"""消息接受凭证的 SQLite 回归；签名替身不作为真实密码学验证证据。"""

import base64
import concurrent.futures
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from contract import MAX_HEADER_BYTES, MAX_PAYLOAD_BYTES, ProtocolError, encode_json, validate_request
from receipt_contract import message_envelope_digest, validate_message_acceptance
from receipt_signer import ReceiptSigner
from receipt_test_support import ReceiptFixture, VerifiedCloseFixture, receipt_fixture, signed
from permission_tests import proof
from server import DISPATCH
from storage import Store, revoke_device
from test_support import envelope, key


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "relay.sqlite3"
        self.fixture = receipt_fixture()
        self.signer = ReceiptFixture()
        self.store = Store(self.path, self.fixture, VerifiedCloseFixture(), self.signer)
        self.targets = [m for m in self.fixture["conversation"]["members"] if m != {"account_id": "A", "device_id": "A1"}]

    def tearDown(self):
        self.directory.cleanup()

    def call(self, operation, value, token="synthetic-A1-token"):
        validate_request(operation, value)
        with self.store.transaction() as db:
            return DISPATCH[operation](self.store, db, self.store.authenticate(db, token), value)

    def submit(self, logical_id="M1", payload=b"opaque-fixture"):
        return self.call("submit_message", {"envelope": envelope(logical_id, payload=payload, recipients=self.targets)})

    def pull(self, after="0", token="synthetic-A2-token", stream_id=None):
        request = {"service_id": "S1", "after_seq": after, "limit": "100"}
        if stream_id is not None:
            request["stream_id"] = stream_id
        return self.call("pull_events", request, token)

    def assert_empty(self):
        with self.store.transaction() as db:
            for table in ("logical_messages", "attempts", "events"):
                self.assertEqual(db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], 0)

    def test_one_signature_binds_original_bytes_and_all_target_events(self):
        original = envelope(recipients=self.targets)
        raw_header = base64.b64decode(original["header_bytes"]) + b"  \n"
        original["header_bytes"] = base64.b64encode(raw_header).decode()
        accepted = self.call("submit_message", {"envelope": original})
        statement = validate_message_acceptance(accepted["acceptance_receipt"])
        self.assertEqual(statement["envelope_sha256"], message_envelope_digest(raw_header, base64.b64decode(original["payload_bytes"])))
        self.assertEqual(statement["acceptance_id"], accepted["acceptance_id"])
        self.assertEqual((statement["authorization_version"], statement["crypto_state_ref"]), ("1", "a" * 64))
        for recipient in self.targets:
            event = self.pull(token=f"synthetic-{recipient['device_id']}-token")["events"][0]["event"]
            self.assertEqual(event, {"type": "message", "acceptance_id": accepted["acceptance_id"],
                                    "envelope": original, "acceptance_receipt": accepted["acceptance_receipt"]})
        self.assertEqual(self.signer.calls, 1)

    def test_concurrent_duplicate_and_restart_reuse_original_receipt(self):
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            results = list(pool.map(lambda _: self.submit(), range(2)))
        self.assertEqual(results[0], results[1])
        self.assertEqual(self.signer.calls, 1)
        self.store = Store(self.path, self.fixture, VerifiedCloseFixture(), self.signer)
        self.signer.fail = True
        self.assertEqual(self.submit(), results[0])
        self.assertEqual(self.call("get_attempt", key()), results[0])
        self.assertEqual(self.call("close_attempt", key()), results[0])
        self.assertEqual(self.signer.calls, 1)
        self.assertEqual(self.pull()["watermark"], "1")

    def test_signature_failure_rolls_back_attempt_chain_and_all_events(self):
        self.signer.fail = True
        with self.assertRaises(ProtocolError) as error:
            self.submit()
        self.assertEqual((error.exception.code, error.exception.outcome), ("receipt_signer_unavailable", "not_recorded"))
        self.assert_empty()
        self.signer.fail = False
        self.assertIn("acceptance_receipt", self.submit())
        self.assertEqual(self.pull()["events"][0]["event_seq"], "1")

    def test_event_write_failure_rolls_back_already_signed_acceptance(self):
        with patch.object(self.store, "append_event", side_effect=ProtocolError("resource_exhausted", "test capacity")):
            with self.assertRaises(ProtocolError):
                self.submit()
        self.assertEqual(self.signer.calls, 1)
        self.assert_empty()
        self.assertIn("acceptance_receipt", self.submit())

    def test_preexisting_unsigned_records_never_get_backfilled(self):
        # 模拟前一版已固定Service权限回执钥、尚未给消息签名的数据库。
        with patch.object(self.store, "receipt_enabled", False):
            original = self.submit()
        self.store = Store(self.path, self.fixture, VerifiedCloseFixture(), self.signer)
        self.assertEqual(self.submit(), original)
        self.assertNotIn("acceptance_receipt", self.call("get_attempt", key()))
        self.assertNotIn("acceptance_receipt", self.pull()["events"][0]["event"])
        self.assertEqual(self.signer.calls, 0)
        self.assertIn("acceptance_receipt", self.submit("M2"))

    def test_revoke_sender_preserves_remaining_recipients_original_record(self):
        accepted = self.submit()
        with self.store.transaction() as db:
            revoke_device(db, ("A", "A1"))
        self.store = Store(self.path, self.fixture, VerifiedCloseFixture(), self.signer)
        event = self.pull()["events"][0]
        self.assertEqual(event["availability"], "available")
        self.assertEqual(event["event"]["acceptance_receipt"], accepted["acceptance_receipt"])
        # Relay仍提供原目标历史字节；端侧是否允许显示不由此测试证明。
        with self.assertRaises(ProtocolError) as error:
            self.submit()
        self.assertEqual(error.exception.code, "device_revoked")

    def test_permission_change_keeps_original_message_receipt_and_targets(self):
        accepted = self.submit()
        with patch("permissions.time.time", return_value=1100):
            self.call("submit_permission_change", {"service_id": "S1", "conversation_id": "G1", "change": proof()})
        self.assertEqual(self.submit(), accepted)
        self.assertEqual(self.call("get_attempt", key()), accepted)
        self.assertEqual(self.pull()["events"][0]["event"]["acceptance_receipt"], accepted["acceptance_receipt"])
        removed = self.pull(token="synthetic-B1-token")["events"][0]
        self.assertEqual(removed["availability"], "access_removed")
        self.assertNotIn("event", removed)
        self.assertEqual(self.signer.calls, 2)

    def test_maximum_envelope_with_receipt_pages_without_skipping(self):
        for logical_id in ("M1", "M2"):
            value = envelope(logical_id, payload=b"x" * MAX_PAYLOAD_BYTES, recipients=self.targets)
            raw = base64.b64decode(value["header_bytes"]).ljust(MAX_HEADER_BYTES, b" ")
            value["header_bytes"] = base64.b64encode(raw).decode()
            self.call("submit_message", {"envelope": value})
        first = self.pull()
        self.assertEqual((len(first["events"]), first["next_after_seq"], first["has_more"]), (1, "1", True))
        second = self.pull(first["next_after_seq"], stream_id=first["stream_id"])
        self.assertEqual((len(second["events"]), second["next_after_seq"], second["has_more"]), (1, "2", False))
        self.assertNotEqual(first["events"][0]["event_id"], second["events"][0]["event_id"])
        for page in (first, second):
            self.assertIn("acceptance_receipt", page["events"][0]["event"])
            self.assertLessEqual(len(encode_json({"ok": True, "result": page})), 900 * 1024)
            self.assertLess(len(encode_json(page)) + 16 * 1024, 1024 * 1024)

    def test_helper_protocol_whitelist_and_result_binding(self):
        from receipt_contract import message_acceptance_statement
        from sys import executable
        signer = ReceiptSigner(executable, self.path.absolute())
        signer.signature_key = self.signer.key
        raw = envelope(recipients=self.targets)
        statement = message_acceptance_statement(json.loads(base64.b64decode(raw["header_bytes"])),
                    base64.b64decode(raw["header_bytes"]), base64.b64decode(raw["payload_bytes"]), "K1")
        with patch.object(signer, "_call", return_value={"receipt": signed(statement)}) as helper:
            self.assertEqual(validate_message_acceptance(signer.sign(statement)), statement)
            self.assertEqual(helper.call_args.args[0]["expected_signature_key"], self.signer.key)
        for changed in ({**statement, "acceptance_id": "K2"}, {**statement, "extra": True}):
            with patch.object(signer, "_call", return_value={"receipt": signed(changed)}), self.assertRaises(ProtocolError):
                signer.sign(statement)
        with patch.object(signer, "_call") as helper, self.assertRaises(ProtocolError):
            signer.sign({**statement, "protocol_version": "unknown"})
        helper.assert_not_called()


if __name__ == "__main__":
    unittest.main()
