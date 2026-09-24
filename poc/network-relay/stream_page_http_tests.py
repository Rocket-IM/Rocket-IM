"""普通签名页的真实 HTTP 边界；签名 helper 为替身，真实密码验收由 Rust 联合验证。"""

import base64
import hashlib
import json
import unittest

from receipt_test_support import ReceiptHTTPFixture
from stream_page_contract import validate_stream_page_receipt
from test_support import envelope


class StreamPageHTTPTests(ReceiptHTTPFixture):
    def pull(self, token="synthetic-A2-token", **changes):
        request = {"service_id": "S1", "after_seq": "0", "limit": "1", **changes}
        return self.request("pull_events_signed", request, token)

    def test_authenticated_page_signature_covers_exact_delivery_slots_across_restart(self):
        recipients = [member for member in self.fixture_value()["conversation"]["members"]
                      if member != {"account_id": "A", "device_id": "A1"}]
        status, accepted = self.request("submit_message", {"envelope": envelope(recipients=recipients)})
        self.assertEqual(status, 200, accepted)
        self.assertEqual(accepted["result"]["outcome"], "accepted")
        status, result = self.pull()
        self.assertEqual(status, 200, result)
        value = result["result"]
        statement = validate_stream_page_receipt(value["receipt"])
        raw = base64.b64decode(value["page_bytes"], validate=True)
        page = json.loads(raw)
        self.assertEqual(statement["page_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual((statement["service_id"], statement["account_id"], statement["device_id"]), ("S1", "A", "A2"))
        self.assertEqual((statement["stream_id"], statement["after_seq"], statement["limit"]), (page["stream_id"], "0", "1"))
        self.assertEqual(page["events"][0]["event"]["acceptance_id"], accepted["result"]["acceptance_id"])
        self.stop()
        self.start()
        self.assertEqual(self.pull(), (status, result))
        next_status, next_result = self.pull(stream_id=page["stream_id"], after_seq="1")
        self.assertEqual(next_status, 200, next_result)
        self.assertEqual(json.loads(base64.b64decode(next_result["result"]["page_bytes"]))["events"], [])

    def test_invalid_identity_and_stream_requests_do_not_return_pages(self):
        for token, changes, status, code in (("invalid", {}, 401, "unauthenticated"),
                                           ("synthetic-A2-token", {"service_id": "OTHER"}, 403, "permission_denied"),
                                           ("synthetic-A2-token", {"account_id": "B"}, 400, "invalid_envelope"),
                                           ("synthetic-A2-token", {"stream_id": "OTHER"}, 409, "cursor_invalid")):
            actual, value = self.pull(token, **changes)
            self.assertEqual((actual, value["error"]["code"]), (status, code))
            self.assertNotIn("result", value)

    def test_signer_failure_is_explicit_without_raw_page_fallback(self):
        self.key_path.write_text(base64.b64encode(bytes([30]) * 32).decode())
        status, value = self.pull()
        self.assertEqual((status, value["error"]["code"]), (503, "receipt_signer_unavailable"))
        self.assertNotIn("result", value)


if __name__ == "__main__":
    unittest.main()
