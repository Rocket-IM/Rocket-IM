"""实际HTTP/SQLite入群故障回归；复用合成helper，不宣称真实Welcome解密验证。"""

import http.client
import unittest

from contract import encode_json
from join_test_support import JoinHTTPFixture, join_request
from receipt_test_support import SERVICE_KEY
from test_support import envelope


class JoinHTTPTests(JoinHTTPFixture):
    def permission_page(self):
        status, value = self.request("get_permission_records", {"service_id": "S1", "conversation_id": "G1", "after_version": "1", "limit": "32"})
        self.assertEqual(status, 200, value)
        return value["result"]

    def test_lost_join_response_recovers_identical_target_material_without_old_messages(self):
        targets = [m for m in self.fixture_value()["conversation"]["members"] if m["device_id"] != "A1"]
        self.assertEqual(self.request("submit_message", {"envelope": envelope(recipients=targets)})[0], 200)
        request = join_request(current_time=True)
        self.control({"action": "hook", "hook": "drop_after_commit"})
        with self.assertRaises(http.client.RemoteDisconnected):
            self.submit_join(request)
        status, accepted = self.submit_join(request)
        self.assertEqual(status, 200)
        status, material = self.material()
        self.assertEqual(status, 200)
        self.assertEqual(material["result"], {"record": {"change": request["change"], "receipt": accepted["result"]["receipt"]}, "join": request["join"]})
        for token in ("synthetic-A1-token", "synthetic-E1-token"):
            self.assertEqual(self.material(token=token)[0], 403)
        _, events = self.request("pull_events", {"service_id": "S1", "after_seq": "0", "limit": "100"}, "synthetic-D1-token")
        self.assertEqual(events["result"]["events"], [])
        self.stop()
        self.start()
        self.assertEqual(self.material(), (status, material))
        self.assertEqual(self.submit_join(request), (200, accepted))

    def test_before_commit_exit_rolls_back_join_and_key_package_consumption(self):
        request = join_request(current_time=True)
        self.control({"action": "hook", "hook": "before_commit_exit"})
        with self.assertRaises(http.client.RemoteDisconnected):
            self.submit_join(request)
        self.assertEqual(self.process.wait(timeout=3), 86)
        self.stop()
        self.start()
        self.assertEqual(self.permission_page()["records"], [])
        self.assertEqual(self.material()[0], 403)
        self.assertEqual(self.submit_join(request)[0], 200)
        self.assertEqual(self.material()[0], 200)

    def test_after_commit_exit_keeps_membership_receipt_and_welcome_together(self):
        request = join_request(current_time=True)
        self.control({"action": "hook", "hook": "after_commit_exit"})
        with self.assertRaises(http.client.RemoteDisconnected):
            self.submit_join(request)
        self.assertEqual(self.process.wait(timeout=3), 87)
        self.stop()
        self.start()
        status, material = self.material()
        self.assertEqual(status, 200)
        self.assertEqual(material["result"]["join"], request["join"])
        status, accepted = self.submit_join(request)
        self.assertEqual(status, 200)
        self.assertEqual(material["result"]["record"]["receipt"], accepted["result"]["receipt"])
        self.assertEqual(len(self.permission_page()["records"]), 1)

    def test_signature_failure_keeps_fault_hook_and_no_partial_join(self):
        request = join_request(current_time=True)
        self.key_path.unlink()
        self.control({"action": "hook", "hook": "drop_after_commit"})
        status, failed = self.submit_join(request)
        self.assertEqual((status, failed["error"]["code"]), (503, "receipt_signer_unavailable"))
        self.assertEqual(self.permission_page()["records"], [])
        self.assertEqual(self.material()[0], 403)
        self.key_path.write_text(SERVICE_KEY)
        with self.assertRaises(http.client.RemoteDisconnected):
            self.submit_join(request)
        self.assertEqual(self.material()[0], 200)

    def test_full_material_budget_rejects_before_acceptance_and_valid_large_join_fits(self):
        oversized = join_request(commit=b"c" * (300 * 1024), welcome=b"w" * (400 * 1024), current_time=True)
        self.assertLess(len(encode_json(oversized)), 1024 * 1024)
        status, failed = self.submit_join(oversized)
        self.assertEqual((status, failed["error"]["code"]), (429, "resource_exhausted"))
        self.assertEqual(self.permission_page()["records"], [])
        self.assertEqual(self.material()[0], 403)
        request = join_request(commit=b"c" * (280 * 1024), welcome=b"w" * (360 * 1024), current_time=True)
        self.assertEqual(self.submit_join(request)[0], 200)
        status, material = self.material()
        self.assertEqual(status, 200)
        self.assertLessEqual(len(encode_json(material)), 900 * 1024)
        self.assertEqual(material["result"]["join"], request["join"])


if __name__ == "__main__":
    unittest.main()
