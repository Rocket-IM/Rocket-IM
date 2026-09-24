"""实际 HTTP/SQLite 的设备加入故障与鉴权；签名进程是明确的合成装置。"""

import concurrent.futures
import http.client
import unittest

from device_join_test_support import DeviceJoinHTTPFixture, device_join_request
from test_support import envelope


class DeviceJoinHTTPTests(DeviceJoinHTTPFixture):
    def test_lost_response_exact_retry_restart_and_target_only_material(self):
        targets = [m for m in self.fixture_value()["conversation"]["members"] if m["device_id"] != "A1"]
        self.assertEqual(self.request("submit_message", {"envelope": envelope(recipients=targets)})[0], 200)
        request = device_join_request(current_time=True)
        self.control({"action": "hook", "hook": "drop_after_commit"})
        with self.assertRaises(http.client.RemoteDisconnected):
            self.submit_device(request)
        accepted = self.submit_device(request)
        self.assertEqual(accepted[0], 200, accepted)
        material = self.device_material()
        self.assertEqual(material[0], 200, material)
        self.assertEqual(material[1]["result"]["record"]["receipt"], accepted[1]["result"]["receipt"])
        for token in ("synthetic-B1-token", "synthetic-B2-token", "synthetic-A1-token"):
            self.assertEqual(self.device_material(token=token)[0], 403)
        status, page = self.request("pull_events", {"service_id": "S1", "after_seq": "0", "limit": "100"}, "synthetic-B3-token")
        self.assertEqual(status, 200)
        self.assertEqual(page["result"]["events"], [])
        self.stop()
        self.start()
        self.assertEqual(self.submit_device(request), accepted)
        self.assertEqual(self.device_material(), material)

    def test_authorization_rejection_preserves_hook_for_valid_old_device(self):
        self.control({"action": "hook", "hook": "drop_after_commit"})
        request = device_join_request(actor={"account_id": "A", "device_id": "A1"}, current_time=True)
        status, denied = self.submit_device(request, "synthetic-A1-token")
        self.assertEqual((status, denied["error"]["code"]), (403, "permission_denied"))
        self.assertEqual(self.device_material()[0], 403)
        with self.assertRaises(http.client.RemoteDisconnected):
            self.submit_device()
        self.assertEqual(self.device_material()[0], 200)

    def test_before_commit_exit_leaves_device_unjoined_then_retry_accepts(self):
        request = device_join_request(current_time=True)
        self.control({"action": "hook", "hook": "before_commit_exit"})
        with self.assertRaises(http.client.RemoteDisconnected):
            self.submit_device(request)
        self.assertEqual(self.process.wait(timeout=3), 86)
        self.stop()
        self.start()
        self.assertEqual(self.device_material()[0], 403)
        self.assertEqual(self.submit_device(request)[0], 200)
        self.assertEqual(self.device_material()[0], 200)

    def test_concurrent_exact_duplicates_return_one_original_record(self):
        request = device_join_request(current_time=True)
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            results = list(pool.map(lambda _: self.submit_device(request), range(2)))
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0][0], 200, results[0])
        status, page = self.request("get_permission_records", {"service_id": "S1", "conversation_id": "G1", "after_version": "1", "limit": "32"}, "synthetic-B3-token")
        self.assertEqual(status, 200, page)
        self.assertEqual(page["result"]["records"], [self.device_material()[1]["result"]["record"]])


if __name__ == "__main__":
    unittest.main()
