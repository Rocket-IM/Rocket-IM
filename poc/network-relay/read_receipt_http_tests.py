"""真实 HTTP/SQLite 已读事务故障测试；合成载荷不作为密码或用户阅读证据。"""

import http.client
import json
import sqlite3
import unittest

from http_test_support import RelayHTTPFixture
from test_support import envelope


class ReadReceiptHTTPTests(RelayHTTPFixture):
    def setUp(self):
        super().setUp()
        status, body = self.request("submit_message", {"envelope": envelope()})
        self.assertEqual(status, 200, body)
        self.accepted = body["result"]
        self.acceptance_id = self.accepted["acceptance_id"]
        self.before = self.persisted()

    def report(self, ids=None, token="synthetic-B1-token"):
        return self.request("report_read", {"service_id": "S1", "acceptance_ids": [self.acceptance_id] if ids is None else ids}, token)

    def persisted(self):
        # 独立只读事务观察故障后的已提交事实，不用重试请求推断原提交结果。
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

    def assert_committed_read(self, state):
        self.assertEqual(state["receipts"], [(self.acceptance_id, "B", "B1", 1, 1)])
        self.assertEqual([row for row in state["events"] if json.loads(row[4])["type"] == "message"], self.before["events"])
        for kind, positions in (("delivery", [("A", "A1", 1), ("A", "A2", 2), ("B", "B1", 2)]),
                                ("read", [("A", "A1", 2), ("A", "A2", 3), ("B", "B1", 3)])):
            rows = [row for row in state["events"] if json.loads(row[4])["type"] == kind]
            expected = {"type": kind, "acceptance_id": self.acceptance_id, "attempt_id": "P1",
                        "device": {"account_id": "B", "device_id": "B1"}}
            self.assertEqual([(row[0], row[1], row[2]) for row in rows], positions)
            self.assertEqual([json.loads(row[4]) for row in rows], [expected] * 3)
            self.assertTrue(all(row[5:] == (self.acceptance_id, "available") for row in rows))
        self.assertEqual(len(state["events"]), 8)
        self.assertEqual(len({row[3] for row in state["events"]}), 8)

    def assert_retry_unchanged(self, committed):
        expected = {"ok": True, "result": {"receipts": [{"acceptance_id": self.acceptance_id, "attempt_id": "P1",
                    "device": {"account_id": "B", "device_id": "B1"}, "delivered": True, "read": True}]}}
        self.assertEqual(self.report(), (200, expected))
        self.assertEqual(self.persisted(), committed)
        self.stop()
        self.start()
        self.assertEqual(self.persisted(), committed)
        self.assertEqual(self.report(), (200, expected))
        self.assertEqual(self.persisted(), committed)

    def deliver(self, account, device):
        event = next(row for row in self.before["events"] if row[:2] == (account, device))
        return self.request("report_delivery", {"service_id": "S1", "acceptance_id": self.acceptance_id,
                            "attempt_id": "P1", "event_id": event[3]}, f"synthetic-{device}-token")

    def test_lost_read_response_commits_receipt_and_both_notifications_once(self):
        self.control({"action": "hook", "hook": "drop_after_commit"})
        with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError)):
            self.report()
        self.assertIsNone(self.process.poll())
        committed = self.persisted()
        self.assert_committed_read(committed)
        self.assert_retry_unchanged(committed)

    def test_read_before_commit_exit_leaves_no_receipt_or_notification(self):
        self.control({"action": "hook", "hook": "before_commit_exit"})
        with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError)):
            self.report()
        self.assertEqual(self.process.wait(timeout=3), 86)
        self.assertEqual(self.persisted(), self.before)
        self.stop()
        self.start()
        self.assertEqual(self.persisted(), self.before)
        self.assertEqual(self.report()[0], 200)
        committed = self.persisted()
        self.assert_committed_read(committed)
        self.assert_retry_unchanged(committed)

    def test_read_after_commit_exit_keeps_receipt_and_every_notification(self):
        self.control({"action": "hook", "hook": "after_commit_exit"})
        with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError)):
            self.report()
        self.assertEqual(self.process.wait(timeout=3), 87)
        committed = self.persisted()
        self.assert_committed_read(committed)
        self.stop()
        self.start()
        self.assertEqual(self.persisted(), committed)
        self.assert_retry_unchanged(committed)

    def test_read_after_delivery_adds_only_read_notifications(self):
        self.assertEqual(self.deliver("B", "B1")[0], 200)
        delivered = self.persisted()
        self.assertEqual(len(delivered["events"]), 5)
        self.assertEqual(self.report()[0], 200)
        committed = self.persisted()
        self.assert_committed_read(committed)
        self.assertEqual([row for row in committed["events"] if json.loads(row[4])["type"] != "read"], delivered["events"])
        self.assert_retry_unchanged(committed)

    def test_read_implies_own_delivery_without_creating_other_device_receipts(self):
        self.assertEqual(self.report()[0], 200)
        committed = self.persisted()
        self.assert_committed_read(committed)
        # 通知 A2 不等于替 A2 确认；它稍后单独报告送达时仍保持未读。
        status, body = self.deliver("A", "A2")
        self.assertEqual(status, 200, body)
        self.assertFalse(body["result"]["read"])
        separate = self.persisted()
        self.assertEqual(separate["receipts"], [(self.acceptance_id, "A", "A2", 1, 0), (self.acceptance_id, "B", "B1", 1, 1)])
        self.assertEqual(len(separate["events"]), 11)
        self.assertEqual([row for row in separate["events"] if json.loads(row[4])["type"] == "read"],
                         [row for row in committed["events"] if json.loads(row[4])["type"] == "read"])

    def test_mixed_valid_and_unknown_or_unauthorized_batch_is_atomic(self):
        packet = envelope("M2", "P2", sender={"account_id": "B", "device_id": "B1"},
                          recipients=[{"account_id": "A", "device_id": "A1"}, {"account_id": "A", "device_id": "A2"}])
        status, body = self.request("submit_message", {"envelope": packet}, "synthetic-B1-token")
        self.assertEqual(status, 200, body)
        inaccessible = body["result"]["acceptance_id"]
        before = self.persisted()
        for other in ("unknown-acceptance", inaccessible):
            with self.subTest(target=other):
                status, body = self.report([self.acceptance_id, other])
                self.assertEqual((status, body["error"]["code"]), (403, "permission_denied"))
                self.assertEqual(body["error"]["outcome"], "not_recorded")
                self.assertEqual(self.persisted(), before)

    def test_empty_duplicate_and_over_limit_read_batches_are_rejected(self):
        for ids in ([], [self.acceptance_id, self.acceptance_id], [f"unknown-{number}" for number in range(101)]):
            with self.subTest(size=len(ids)):
                status, body = self.report(ids)
                self.assertEqual((status, body["error"]["code"]), (400, "invalid_envelope"))
                self.assertEqual(body["error"]["outcome"], "not_recorded")
                self.assertEqual(self.persisted(), self.before)

    def assert_rejection_preserves_hook(self, token, status, code):
        self.control({"action": "hook", "hook": "drop_after_commit"})
        actual, body = self.report(token=token)
        self.assertEqual((actual, body["error"]["code"]), (status, code))
        self.assertIsNone(self.process.poll())
        self.assertEqual(self.persisted(), self.before)
        with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError)):
            self.report()
        self.assertIsNone(self.process.poll())
        committed = self.persisted()
        self.assert_committed_read(committed)
        self.assert_retry_unchanged(committed)

    def test_invalid_credential_cannot_consume_armed_read_hook(self):
        self.assert_rejection_preserves_hook("invalid-token", 401, "unauthenticated")

    def test_authenticated_sender_is_not_a_read_target_and_cannot_consume_hook(self):
        self.assert_rejection_preserves_hook("synthetic-A1-token", 403, "permission_denied")

    def test_disabled_controls_cannot_arm_read_fault(self):
        self.stop()
        self.start(controls=False)
        for hook in ("drop_after_commit", "before_commit_exit", "after_commit_exit"):
            status, body = self.request("", {"action": "hook", "hook": hook}, "synthetic-controller-token", True)
            self.assertEqual((status, body["error"]["code"]), (403, "permission_denied"))
        self.assertEqual(self.report()[0], 200)
        self.assertIsNone(self.process.poll())
        self.assert_committed_read(self.persisted())


if __name__ == "__main__":
    unittest.main()
