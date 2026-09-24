"""真实 HTTP/SQLite 故障恢复；helper 为明确测试替身，密码验签由 Rust 联合验收。"""

import base64
import concurrent.futures
import http.client
import json
import sqlite3
import subprocess
import sys
import threading
import unittest
from pathlib import Path

from http_test_support import RelayHTTPFixture
from receipt_contract import validate_receipt
from receipt_test_support import SERVICE_KEY, ReceiptHTTPFixture, close_for
from test_support import envelope


class DeliveryReceiptHTTPTests(RelayHTTPFixture):
    """真实 HTTP/SQLite 回执事务；合成载荷不作为密码接收证据。"""

    def setUp(self):
        super().setUp()
        status, body = self.request("submit_message", {"envelope": envelope()})
        self.assertEqual(status, 200, body)
        self.accepted = body["result"]
        status, page = self.request("pull_events", {"service_id": "S1", "after_seq": "0", "limit": "10"}, "synthetic-B1-token")
        self.assertEqual(status, 200, page)
        self.delivery = {"service_id": "S1", "acceptance_id": self.accepted["acceptance_id"],
                         "attempt_id": "P1", "event_id": page["result"]["events"][0]["event_id"]}
        self.before = self.persisted()

    def report(self, token="synthetic-B1-token"):
        return self.request("report_delivery", self.delivery, token)

    def persisted(self):
        # 独立只读连接只观察已提交事实，不通过再次报告来推测故障结果。
        db = sqlite3.connect(f"{(self.path / 'relay.sqlite3').as_uri()}?mode=ro", uri=True, isolation_level=None)
        try:
            db.execute("BEGIN")
            state = {"receipts": db.execute("SELECT acceptance_id,account,device,delivered,is_read FROM receipts ORDER BY acceptance_id,account,device").fetchall(),
                     "events": db.execute("SELECT account,device,seq,event_id,content,acceptance_id,availability FROM events ORDER BY account,device,seq").fetchall()}
            db.commit()
            return state
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def assert_committed_delivery(self, state):
        self.assertEqual(state["receipts"], [(self.accepted["acceptance_id"], "B", "B1", 1, 0)])
        expected = {"type": "delivery", "acceptance_id": self.accepted["acceptance_id"],
                    "attempt_id": "P1", "device": {"account_id": "B", "device_id": "B1"}}
        deliveries = [row for row in state["events"] if json.loads(row[4])["type"] == "delivery"]
        self.assertEqual([(row[0], row[1], row[2]) for row in deliveries], [("A", "A1", 1), ("A", "A2", 2), ("B", "B1", 2)])
        self.assertEqual(len({row[3] for row in deliveries}), 3)
        self.assertEqual([json.loads(row[4]) for row in deliveries], [expected] * 3)
        self.assertTrue(all(row[5:] == (self.accepted["acceptance_id"], "available") for row in deliveries))
        self.assertEqual([row for row in state["events"] if json.loads(row[4])["type"] == "message"], self.before["events"])
        self.assertEqual(len(state["events"]), 5)

    def assert_retry_unchanged(self, committed):
        expected = {"ok": True, "result": {"acceptance_id": self.accepted["acceptance_id"], "attempt_id": "P1",
                    "device": {"account_id": "B", "device_id": "B1"}, "delivered": True, "read": False}}
        self.assertEqual(self.report(), (200, expected))
        self.assertEqual(self.persisted(), committed)
        self.stop()
        self.start()
        self.assertEqual(self.persisted(), committed)
        self.assertEqual(self.report(), (200, expected))
        self.assertEqual(self.persisted(), committed)

    def test_lost_delivery_response_commits_once_and_restart_reuses_result(self):
        self.control({"action": "hook", "hook": "drop_after_commit"})
        with self.assertRaises(http.client.RemoteDisconnected):
            self.report()
        self.assertIsNone(self.process.poll())
        committed = self.persisted()
        self.assert_committed_delivery(committed)
        self.assert_retry_unchanged(committed)

    def test_delivery_before_commit_exit_rolls_back_receipt_and_every_event(self):
        self.control({"action": "hook", "hook": "before_commit_exit"})
        with self.assertRaises(http.client.RemoteDisconnected):
            self.report()
        self.assertEqual(self.process.wait(timeout=3), 86)
        self.stop()
        self.start()
        self.assertEqual(self.persisted(), self.before)
        self.assertEqual(self.report()[0], 200)
        committed = self.persisted()
        self.assert_committed_delivery(committed)
        self.assert_retry_unchanged(committed)

    def test_delivery_after_commit_exit_keeps_receipt_and_every_event(self):
        self.control({"action": "hook", "hook": "after_commit_exit"})
        with self.assertRaises(http.client.RemoteDisconnected):
            self.report()
        self.assertEqual(self.process.wait(timeout=3), 87)
        committed = self.persisted()
        self.assert_committed_delivery(committed)
        self.stop()
        self.start()
        self.assertEqual(self.persisted(), committed)
        self.assert_retry_unchanged(committed)

    def assert_rejection_preserves_hook(self, token, status, code):
        self.control({"action": "hook", "hook": "drop_after_commit"})
        actual, body = self.report(token)
        self.assertEqual((actual, body["error"]["code"]), (status, code))
        self.assertIsNone(self.process.poll())
        self.assertEqual(self.persisted(), self.before)
        with self.assertRaises(http.client.RemoteDisconnected):
            self.report()
        committed = self.persisted()
        self.assert_committed_delivery(committed)
        self.assert_retry_unchanged(committed)

    def test_invalid_credential_does_not_consume_delivery_hook(self):
        self.assert_rejection_preserves_hook("invalid-token", 401, "unauthenticated")

    def test_other_devices_event_does_not_consume_delivery_hook(self):
        # A2 是消息目标，但 B1 的 event_id 不能替它确认。
        self.assert_rejection_preserves_hook("synthetic-A2-token", 403, "permission_denied")

    def test_disabled_controls_cannot_arm_delivery_fault(self):
        self.stop()
        self.start(controls=False)
        for hook in ("drop_after_commit", "before_commit_exit", "after_commit_exit"):
            status, body = self.request("", {"action": "hook", "hook": hook}, "synthetic-controller-token", True)
            self.assertEqual((status, body["error"]["code"]), (403, "permission_denied"))
        self.assertEqual(self.report()[0], 200)
        self.assertIsNone(self.process.poll())
        self.assert_committed_delivery(self.persisted())


class ReceiptHTTPTests(ReceiptHTTPFixture):
    def submit(self):
        return self.request("submit_permission_change", {"service_id": "S1", "conversation_id": "G1", "change": self.change})

    def close(self):
        return self.request("close_permission_change", {"service_id": "S1", "conversation_id": "G1", "change": self.change, "close": close_for(self.change)})

    def page(self):
        status, value = self.request("get_permission_records", {"service_id": "S1", "conversation_id": "G1", "after_version": "1", "limit": "32"})
        self.assertEqual(status, 200, value)
        return value["result"]

    def test_close_before_commit_exit_leaves_candidate_available_to_submit(self):
        self.control({"action": "hook", "hook": "before_commit_exit"})
        with self.assertRaises(http.client.RemoteDisconnected):
            self.close()
        self.assertEqual(self.process.wait(timeout=3), 86)
        self.stop()
        self.start()
        self.assertEqual(self.page()["records"], [])
        status, accepted = self.submit()
        self.assertEqual(status, 200)
        self.assertEqual(validate_receipt(accepted["result"]["receipt"])["outcome"], "accepted")

    def test_close_after_commit_exit_keeps_permanent_closed_receipt(self):
        self.control({"action": "hook", "hook": "after_commit_exit"})
        with self.assertRaises(http.client.RemoteDisconnected):
            self.close()
        self.assertEqual(self.process.wait(timeout=3), 87)
        self.stop()
        self.start()
        status, closed = self.close()
        self.assertEqual(status, 200)
        self.assertEqual(validate_receipt(closed["result"]["receipt"])["outcome"], "closed")
        status, rejected = self.submit()
        self.assertEqual((status, rejected["error"]["code"]), (409, "permission_closed"))
        self.assertEqual(self.page()["records"], [])

    def test_lost_close_response_recovers_identical_receipt(self):
        self.control({"action": "hook", "hook": "drop_after_commit"})
        with self.assertRaises(http.client.RemoteDisconnected):
            self.close()
        self.assertIsNone(self.process.poll())
        status, closed = self.close()
        self.assertEqual(status, 200)
        self.stop()
        self.start()
        self.assertEqual(self.close(), (status, closed))
        self.assertEqual(self.page()["authorization_version"], "1")

    def test_lost_accepted_response_is_resolved_by_signed_close(self):
        self.control({"action": "hook", "hook": "drop_after_commit"})
        with self.assertRaises(http.client.RemoteDisconnected):
            self.submit()
        status, resolved = self.close()
        self.assertEqual(status, 200)
        self.assertEqual(validate_receipt(resolved["result"]["receipt"])["outcome"], "accepted")
        self.assertEqual(self.page()["records"], [resolved["result"]])
        _, retried = self.submit()
        self.assertEqual(retried["result"]["receipt"], resolved["result"]["receipt"])

    def test_http_submit_close_race_returns_one_consistent_terminal(self):
        barrier = threading.Barrier(2)
        def operation(close):
            barrier.wait()
            status, value = self.close() if close else self.submit()
            return value["error"]["code"] if status != 200 else validate_receipt(value["result"]["receipt"])["outcome"]
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            futures = [pool.submit(operation, close) for close in (False, True)]
            outcomes = [future.result() for future in futures]
        self.assertIn(outcomes, (["accepted", "accepted"], ["permission_closed", "closed"]))
        self.assertEqual(len(self.page()["records"]), 1 if outcomes[0] == "accepted" else 0)

    def test_runtime_key_change_fails_before_acceptance_and_restart_rejects_it(self):
        self.key_path.write_text(base64.b64encode(bytes([30]) * 32).decode())
        status, failed = self.submit()
        self.assertEqual((status, failed["error"]["code"]), (503, "receipt_signer_unavailable"))
        self.assertEqual(self.page()["authorization_version"], "1")
        self.stop()
        command = [sys.executable, "-B", str(Path(__file__).with_name("server.py")), "--database", str(self.path / "relay.sqlite3"),
                   "--fixture", str(self.fixture_path), "--permission-verifier", str(self.verifier_path),
                   "--receipt-signer", str(self.signer_path), "--receipt-key", str(self.key_path)]
        failed = subprocess.run(command, capture_output=True, timeout=5)
        self.assertNotEqual(failed.returncode, 0)
        self.key_path.write_text(SERVICE_KEY)
        self.start()
        self.assertEqual(self.submit()[0], 200)


if __name__ == "__main__":
    unittest.main()
