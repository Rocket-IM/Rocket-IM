"""普通签名流的身份、字节与事务边界；签名替身不构成密码验签证据。"""

import base64
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from contract import ProtocolError, encode_json, validate_request
from receipt_signer import ReceiptSigner
from receipt_test_support import ReceiptFixture, VerifiedCloseFixture, receipt_fixture, signed
from server import DISPATCH
from storage import Store
from stream_page_contract import MAX_PAGE_BYTES, validate_stream_page_receipt
from test_support import envelope


class StreamPageTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "relay.sqlite3"
        self.fixture = receipt_fixture()
        self.signer = ReceiptFixture()
        self.store = Store(self.path, self.fixture, VerifiedCloseFixture(), self.signer)
        self.request = {"service_id": "S1", "after_seq": "0", "limit": "100"}

    def call(self, request=None, token="synthetic-A2-token", operation="pull_events_signed"):
        value = self.request if request is None else request
        validate_request(operation, value)
        with self.store.transaction() as db:
            return DISPATCH[operation](self.store, db, self.store.authenticate(db, token), value)

    def rows(self):
        with self.store.transaction() as db:
            return list(db.iterdump())

    def submit(self, logical="M1", payload=b"opaque-fixture"):
        recipients = [member for member in self.fixture["conversation"]["members"]
                      if member != {"account_id": "A", "device_id": "A1"}]
        result = self.call({"envelope": envelope(logical_id=logical, payload=payload, recipients=recipients)},
                           "synthetic-A1-token", "submit_message")
        self.assertEqual(result["outcome"], "accepted")
        return result

    def assert_code(self, code, call):
        with self.assertRaises(ProtocolError) as error:
            call()
        self.assertEqual(error.exception.code, code)
        self.assertEqual(error.exception.outcome, "not_recorded")

    def page(self, **options):
        result = self.call(**options)
        raw = base64.b64decode(result["page_bytes"], validate=True)
        statement = validate_stream_page_receipt(result["receipt"])
        self.assertEqual(statement["page_sha256"], hashlib.sha256(raw).hexdigest())
        page = json.loads(raw)
        self.assertEqual(statement["stream_id"], page["stream_id"])
        return result, page, statement

    def test_empty_page_binds_service_and_authenticated_device_and_survives_restart(self):
        before = self.rows()
        first, page, statement = self.page()
        self.assertEqual(set(first), {"page_bytes", "receipt"})
        self.assertEqual(set(page), {"stream_id", "events", "next_after_seq", "watermark", "has_more"})
        self.assertEqual(page["events"], [])
        self.assertEqual((page["next_after_seq"], page["watermark"], page["has_more"]), ("0", "0", False))
        self.assertEqual((statement["service_id"], statement["account_id"], statement["device_id"]), ("S1", "A", "A2"))
        self.assertEqual((statement["after_seq"], statement["limit"]), ("0", "100"))
        for token, pair in (("synthetic-A1-token", ("A", "A1")), ("synthetic-B1-token", ("B", "B1"))):
            _, other, origin = self.page(token=token)
            self.assertEqual((origin["account_id"], origin["device_id"]), pair)
            self.assertNotEqual(other["stream_id"], page["stream_id"])
        self.store = Store(self.path, self.fixture, VerifiedCloseFixture(), ReceiptFixture())
        self.assertEqual(self.call(), first)
        self.assertEqual(self.rows(), before)

    def test_caller_cannot_select_another_service_subject_or_stream(self):
        before = self.rows()
        self.assert_code("permission_denied", lambda: self.call({**self.request, "service_id": "OTHER"}))
        self.assert_code("cursor_invalid", lambda: self.call({**self.request, "stream_id": "OTHER"}))
        self.assert_code("unauthenticated", lambda: self.call(token="invalid"))
        for field in ("account_id", "device_id"):
            self.assert_code("invalid_envelope", lambda: self.call({**self.request, field: "OTHER"}))
        self.assertEqual(self.rows(), before)
        self.assertEqual(self.signer.calls, 0)

    def test_page_budget_preserves_contiguous_slots_and_original_bytes(self):
        # 合成的大消息用已有接受入口保存；页面限额不截断单个事件或漏掉下一槽。
        for logical in ("M1", "M2"):
            self.submit(logical, b"x" * (300 * 1024))
        first, page, statement = self.page()
        self.assertLessEqual(len(base64.b64decode(first["page_bytes"])), MAX_PAGE_BYTES)
        self.assertEqual([event["event_seq"] for event in page["events"]], ["1"])
        self.assertEqual((page["next_after_seq"], page["watermark"], page["has_more"]), ("1", "2", True))
        self.assertEqual(statement["limit"], "100")
        request = {**self.request, "stream_id": page["stream_id"], "after_seq": "1"}
        _, second, next_statement = self.page(request=request)
        self.assertEqual([event["event_seq"] for event in second["events"]], ["2"])
        self.assertEqual((second["next_after_seq"], second["has_more"], next_statement["after_seq"]), ("2", False, "1"))
        self.assertNotEqual(statement["page_sha256"], hashlib.sha256(encode_json(page) + b" ").hexdigest())

    def test_unavailable_signer_rolls_back_expiration_and_never_returns_unsigned_page(self):
        self.submit()
        before = self.rows()
        self.signer.fail = True
        with patch("synchronization.now_ms", return_value=10**15):
            self.assert_code("receipt_signer_unavailable", self.call)
        self.assertEqual(self.rows(), before)
        self.store.receipt_enabled = False
        self.assert_code("receipt_not_enabled", self.call)
        self.store.receipt_enabled = True
        self.store.receipt_signer = None
        self.assert_code("receipt_signer_unavailable", self.call)
        self.assertEqual(self.rows(), before)

    def test_expiration_keeps_slot_identity_and_signs_the_new_projection(self):
        self.submit()
        _, original, statement = self.page()
        with patch("synchronization.now_ms", return_value=10**15):
            _, expired, expired_statement = self.page()
        for field in ("stream_id", "event_seq", "event_id"):
            self.assertEqual(original["events"][0][field], expired["events"][0][field])
        self.assertEqual(expired["events"][0]["availability"], "expired")
        self.assertNotIn("event", expired["events"][0])
        self.assertNotEqual(statement["page_sha256"], expired_statement["page_sha256"])

    def test_receipt_whitelist_rejects_changed_or_malformed_helper_output(self):
        statement = validate_stream_page_receipt(self.call()["receipt"])
        signer = ReceiptSigner(Path(sys.executable), self.path.parent / "unused-seed")
        signer.signature_key = self.fixture["relay_receipt_key"]
        for field, value in (("service_id", "OTHER"), ("account_id", "OTHER"), ("device_id", "OTHER"),
                             ("stream_id", "OTHER"), ("after_seq", "1"), ("limit", "101"),
                             ("page_sha256", "d" * 64), ("extra", True)):
            with self.subTest(field=field), patch.object(signer, "_call", return_value={"receipt": signed({**statement, field: value})}):
                self.assert_code("receipt_signer_unavailable", lambda: signer.sign(statement))
        with patch.object(signer, "_call", return_value={"receipt": signed(statement)}):
            self.assertEqual(validate_stream_page_receipt(signer.sign(statement)), statement)


if __name__ == "__main__":
    unittest.main()
