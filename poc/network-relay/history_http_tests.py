"""真实环回 HTTP/SQLite 的消息签名原子性；helper 使用已标明的合成替身。"""

import base64
import http.client
import subprocess
import sys
import unittest
from pathlib import Path

from contract import MAX_HEADER_BYTES, MAX_PAYLOAD_BYTES, encode_json
from receipt_contract import validate_message_acceptance
from receipt_test_support import ReceiptHTTPFixture, SERVICE_KEY
from test_support import envelope, key


class HistoryHTTPTests(ReceiptHTTPFixture):
    def message_request(self, logical_id="M1", payload=b"opaque-fixture"):
        targets = [m for m in self.fixture_value()["conversation"]["members"] if m != {"account_id": "A", "device_id": "A1"}]
        return {"envelope": envelope(logical_id, payload=payload, recipients=targets)}

    def submit(self, logical_id="M1"):
        return self.request("submit_message", self.message_request(logical_id))

    def page(self, after="0", stream_id=None):
        request = {"service_id": "S1", "after_seq": after, "limit": "100"}
        if stream_id is not None:
            request["stream_id"] = stream_id
        status, value = self.request("pull_events", request, "synthetic-A2-token")
        self.assertEqual(status, 200, value)
        return value["result"]

    def test_message_before_commit_exit_rolls_back_receipt_and_every_event(self):
        self.control({"action": "hook", "hook": "before_commit_exit"})
        with self.assertRaises(http.client.RemoteDisconnected):
            self.submit()
        self.assertEqual(self.process.wait(timeout=3), 86)
        self.stop()
        self.start()
        self.assertEqual(self.page()["events"], [])
        status, missing = self.request("get_attempt", key())
        self.assertEqual((status, missing["result"]["outcome"]), (200, "not_found"))
        status, accepted = self.submit()
        self.assertEqual(status, 200)
        event = self.page()["events"][0]
        self.assertEqual(event["event_seq"], "1")
        self.assertEqual(event["event"]["acceptance_receipt"], accepted["result"]["acceptance_receipt"])

    def test_message_after_commit_exit_recovers_original_signed_record(self):
        self.control({"action": "hook", "hook": "after_commit_exit"})
        with self.assertRaises(http.client.RemoteDisconnected):
            self.submit()
        self.assertEqual(self.process.wait(timeout=3), 87)
        self.stop()
        self.start()
        event = self.page()["events"][0]["event"]
        status, original = self.request("get_attempt", key())
        self.assertEqual(status, 200)
        self.assertEqual(event["acceptance_receipt"], original["result"]["acceptance_receipt"])
        self.assertEqual(validate_message_acceptance(event["acceptance_receipt"])["acceptance_id"], event["acceptance_id"])
        self.assertEqual(self.submit(), (status, original))
        self.assertEqual(self.page()["watermark"], "1")

    def test_lost_response_and_restart_preserve_exact_receipt(self):
        self.control({"action": "hook", "hook": "drop_after_commit"})
        with self.assertRaises(http.client.RemoteDisconnected):
            self.submit()
        self.assertIsNone(self.process.poll())
        original = self.submit()
        self.assertEqual(original[0], 200)
        self.stop()
        self.start()
        self.assertEqual(self.submit(), original)
        self.assertEqual(self.page()["events"][0]["event"]["acceptance_receipt"], original[1]["result"]["acceptance_receipt"])

    def test_missing_key_rejects_new_message_without_consuming_hook_or_breaking_retry(self):
        original = self.submit()
        self.assertEqual(original[0], 200)
        self.key_path.unlink()
        self.control({"action": "hook", "hook": "drop_after_commit"})
        status, rejected = self.submit("M2")
        self.assertEqual((status, rejected["error"]["code"], rejected["error"]["outcome"]), (503, "receipt_signer_unavailable", "not_recorded"))
        self.assertEqual(self.page()["watermark"], "1")
        # 验签/签名失败未消费hook，原样重试不再调用缺钥的签名器。
        with self.assertRaises(http.client.RemoteDisconnected):
            self.submit()
        self.assertEqual(self.submit(), original)
        self.stop()
        command = [sys.executable, "-B", str(Path(__file__).with_name("server.py")), "--database", str(self.path / "relay.sqlite3"),
                   "--fixture", str(self.fixture_path), "--permission-verifier", str(self.verifier_path),
                   "--receipt-signer", str(self.signer_path), "--receipt-key", str(self.key_path)]
        failed = subprocess.run(command, capture_output=True, timeout=5)
        self.assertNotEqual(failed.returncode, 0)
        self.key_path.write_text(SERVICE_KEY)
        self.start()
        self.assertEqual(self.submit(), original)
        self.assertEqual(self.submit("M2")[0], 200)

    def test_maximum_signed_events_fit_full_http_pages_without_cursor_skip(self):
        for logical_id in ("M1", "M2"):
            value = self.message_request(logical_id, b"x" * MAX_PAYLOAD_BYTES)
            raw = base64.b64decode(value["envelope"]["header_bytes"]).ljust(MAX_HEADER_BYTES, b" ")
            value["envelope"]["header_bytes"] = base64.b64encode(raw).decode()
            self.assertEqual(self.request("submit_message", value)[0], 200)
        first = self.page()
        second = self.page(first["next_after_seq"], first["stream_id"])
        self.assertEqual((len(first["events"]), first["next_after_seq"], first["has_more"]), (1, "1", True))
        self.assertEqual((len(second["events"]), second["next_after_seq"], second["has_more"]), (1, "2", False))
        for page in (first, second):
            validate_message_acceptance(page["events"][0]["event"]["acceptance_receipt"])
            self.assertLessEqual(len(encode_json({"ok": True, "result": page})), 900 * 1024)


if __name__ == "__main__":
    unittest.main()
