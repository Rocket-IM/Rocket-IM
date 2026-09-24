"""真实 HTTP/SQLite 的迁移故障回归；HPKE 和设备签名使用明确替身。"""

import concurrent.futures
import http.client
import unittest

from history_transfer_test_support import HistoryTransferHTTPFixture, transfer
from receipt_test_support import SERVICE_KEY


class HistoryTransferHTTPTests(HistoryTransferHTTPFixture):
    def test_sender_acceptance_query_remains_metadata_and_deleted_transfer_is_denied(self):
        request = transfer([self.item], current_time=True, source={"account_id": "A", "device_id": "A1"}, target={"account_id": "A", "device_id": "A2"})
        accepted = self.submit_transfer(request, token="synthetic-A1-token")
        self.assertEqual(accepted[0], 200, accepted)
        self.assertEqual(self.get_transfer("synthetic-A2-token"), accepted)
        self.control({"action": "set_availability", "acceptance_id": self.item["acceptance_id"], "availability": "deleted"})
        status, value = self.request("get_attempt", {"service_id": "S1", "conversation_id": "G1", "logical_message_id": "M1", "attempt_id": "P1"})
        self.assertEqual(status, 200, value)
        self.assertEqual(value["result"]["availability"], "deleted")
        self.assertIn("acceptance_receipt", value["result"])
        self.assertNotIn("payload", value["result"])
        self.assertNotIn("envelope", value["result"])
        for status, value in (self.submit_transfer(request, token="synthetic-A1-token"), self.get_transfer("synthetic-A2-token")):
            self.assertEqual((status, value["error"]["code"]), (403, "history_unavailable"))

    def test_lost_response_restart_and_concurrent_exact_retry_keep_one_record(self):
        self.control({"action": "hook", "hook": "drop_after_commit"})
        with self.assertRaises(http.client.RemoteDisconnected):
            self.submit_transfer()
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            results = list(pool.map(lambda _: self.submit_transfer(), range(2)))
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0][0], 200, results[0])
        self.assertEqual(self.get_transfer(), results[0])
        self.stop()
        self.start()
        self.assertEqual(self.get_transfer(), results[0])
        for token in ("synthetic-B1-token", "synthetic-B2-token", "synthetic-A1-token"):
            self.assertEqual(self.get_transfer(token)[0], 403)

    def test_before_commit_exit_rolls_back_package_and_nonce(self):
        self.control({"action": "hook", "hook": "before_commit_exit"})
        with self.assertRaises(http.client.RemoteDisconnected):
            self.submit_transfer()
        self.assertEqual(self.process.wait(timeout=3), 86)
        self.stop()
        self.start()
        self.assertEqual(self.get_transfer()[0], 403)
        self.assertEqual(self.submit_transfer()[0], 200)

    def test_after_commit_exit_preserves_complete_package_and_receipt(self):
        self.control({"action": "hook", "hook": "after_commit_exit"})
        with self.assertRaises(http.client.RemoteDisconnected):
            self.submit_transfer()
        self.assertEqual(self.process.wait(timeout=3), 87)
        self.stop()
        self.start()
        status, value = self.get_transfer()
        self.assertEqual(status, 200, value)
        self.assertEqual(value["result"]["request"], self.transfer["request"])
        self.assertEqual(value["result"]["package"], self.transfer["package"])
        self.assertEqual(self.submit_transfer(), (status, value))

    def test_deleted_original_blocks_both_get_and_exact_retry(self):
        self.assertEqual(self.submit_transfer()[0], 200)
        self.control({"action": "set_availability", "acceptance_id": self.item["acceptance_id"], "availability": "deleted"})
        for result in (self.submit_transfer(), self.get_transfer()):
            self.assertEqual((result[0], result[1]["error"]["code"]), (403, "history_unavailable"))

    def test_invalid_source_and_missing_signer_preserve_hook_until_valid_acceptance(self):
        self.control({"action": "hook", "hook": "drop_after_commit"})
        status, error = self.submit_transfer(token="synthetic-B2-token")
        self.assertEqual((status, error["error"]["code"]), (403, "history_denied"))
        self.key_path.unlink()
        status, error = self.submit_transfer()
        self.assertEqual((status, error["error"]["code"]), (503, "receipt_signer_unavailable"))
        self.assertEqual(self.get_transfer()[0], 403)
        self.key_path.write_text(SERVICE_KEY)
        with self.assertRaises(http.client.RemoteDisconnected):
            self.submit_transfer()
        self.assertEqual(self.get_transfer()[0], 200)


if __name__ == "__main__":
    unittest.main()
