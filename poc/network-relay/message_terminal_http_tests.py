"""消息封口的真实 HTTP 提交窗口；载荷仅为合成字节，不验证 MLS。"""

import http.client
import json
import sqlite3
import unittest
from contextlib import closing

from http_test_support import RelayHTTPFixture
from test_support import envelope, key


class MessageTerminalHTTPTests(RelayHTTPFixture):
    def records(self):
        # 独立只读连接与显式事务，只读取消息记录和非秘密设备流标识。
        queries = {
            "chains": "SELECT key,tail,accepted_attempt FROM logical_messages ORDER BY key",
            "attempts": "SELECT logical_key,attempt_id,header,payload,outcome,closure_id,successor,"
                        "result,acceptance_id,availability FROM attempts ORDER BY logical_key,attempt_id",
            "events": "SELECT account,device,seq,event_id,content,acceptance_id,availability "
                      "FROM events ORDER BY account,device,seq",
            "receipts": "SELECT acceptance_id,account,device,delivered,is_read FROM receipts "
                        "ORDER BY acceptance_id,account,device",
            "streams": "SELECT account,device,stream_id FROM devices ORDER BY account,device",
        }
        uri = (self.path / "relay.sqlite3").resolve().as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, isolation_level=None)) as db:
            db.row_factory = sqlite3.Row
            db.execute("BEGIN")
            try:
                value = {name: [dict(row) for row in db.execute(sql)] for name, sql in queries.items()}
                db.commit()
                return value
            except BaseException:
                db.rollback()
                raise

    def close(self, request):
        status, body = self.request("close_attempt", request)
        self.assertEqual(status, 200, body)
        return body["result"]

    def found(self, request):
        lookup = {name: request[name] for name in key()}
        status, body = self.request("get_attempt", lookup)
        self.assertEqual(status, 200, body)
        return body["result"]

    def exit_close(self, request, hook):
        self.control({"action": "hook", "hook": hook})
        with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError)):
            self.request("close_attempt", request)
        self.assertEqual(self.process.wait(timeout=3), 86 if hook == "before_commit_exit" else 87)
        self.stop()

    def assert_sealed(self, request, snapshot):
        matching = [row for row in snapshot["attempts"] if row["attempt_id"] == request["attempt_id"]]
        self.assertEqual(len(matching), 1)
        row = matching[0]
        self.assertIsNone(row["header"])
        self.assertIsNone(row["payload"])
        self.assertIsNone(row["acceptance_id"])
        self.assertEqual(row["outcome"], "cancelled_before_accept")
        value = json.loads(row["result"])
        self.assertEqual(value, {"outcome": "cancelled_before_accept", "logical_message_id": request["logical_message_id"],
                                 "attempt_id": request["attempt_id"], "closure_id": row["closure_id"]})
        self.assertTrue(row["closure_id"])
        self.assertEqual(snapshot["events"], [])
        self.assertEqual(snapshot["receipts"], [])
        return value

    def assert_late_submit_closed(self, request, value, snapshot):
        packet = envelope(logical_id=request["logical_message_id"], attempt_id=request["attempt_id"])
        submission = {"envelope": packet, **{name: request[name] for name in ("replaces_attempt_id", "closure_id") if name in request}}
        status, body = self.request("submit_message", submission)
        self.assertEqual(status, 409, body)
        self.assertEqual(body["error"], {"code": "attempt_closed", "message": "尝试已封口", **value})
        self.assertEqual(self.records(), snapshot)

    def test_unknown_close_before_commit_rolls_back_new_chain(self):
        request = key()
        baseline = self.records()
        self.exit_close(request, "before_commit_exit")
        self.assertEqual(self.records(), baseline)
        self.start()
        self.assertEqual(self.found(request), {"outcome": "not_found", "logical_message_id": "M1", "attempt_id": "P1"})
        self.assertEqual(self.records(), baseline)
        value = self.close(request)
        snapshot = self.records()
        self.assertEqual(self.assert_sealed(request, snapshot), value)
        self.assert_late_submit_closed(request, value, snapshot)

    def test_unknown_close_after_commit_restores_null_byte_tombstone(self):
        request = key()
        streams = self.records()["streams"]
        self.exit_close(request, "after_commit_exit")
        snapshot = self.records()
        value = self.assert_sealed(request, snapshot)
        self.assertEqual(snapshot["streams"], streams)
        self.assertEqual([(row["tail"], row["accepted_attempt"]) for row in snapshot["chains"]], [("P1", None)])
        self.start()
        self.assertEqual(self.found(request), value)
        self.assertEqual(self.close(request), value)
        self.assert_late_submit_closed(request, value, snapshot)

    def successor_request(self):
        parent = self.close(key())
        return {**key(attempt_id="P2"), "replaces_attempt_id": "P1", "closure_id": parent["closure_id"]}, parent

    def assert_successor_chain(self, request, parent, snapshot):
        value = self.assert_sealed(request, snapshot)
        self.assertEqual(len(snapshot["attempts"]), 2)
        previous, current = snapshot["attempts"]
        self.assertEqual((previous["attempt_id"], previous["successor"], previous["closure_id"]), ("P1", "P2", parent["closure_id"]))
        self.assertEqual(json.loads(previous["result"]), parent)
        self.assertIsNone(previous["header"])
        self.assertIsNone(previous["payload"])
        self.assertIsNone(current["successor"])
        self.assertEqual([(row["tail"], row["accepted_attempt"]) for row in snapshot["chains"]], [("P2", None)])
        return value

    def test_successor_close_before_commit_restores_parent_and_tail(self):
        request, parent = self.successor_request()
        baseline = self.records()
        self.exit_close(request, "before_commit_exit")
        self.assertEqual(self.records(), baseline)
        self.start()
        self.assertEqual(self.found(key()), parent)
        self.assertEqual(self.found(request)["outcome"], "not_found")
        self.assertEqual(self.records(), baseline)
        value = self.close(request)
        snapshot = self.records()
        self.assertEqual(self.assert_successor_chain(request, parent, snapshot), value)
        self.assert_late_submit_closed(request, value, snapshot)

    def test_successor_close_after_commit_restores_complete_chain(self):
        request, parent = self.successor_request()
        streams = self.records()["streams"]
        self.exit_close(request, "after_commit_exit")
        snapshot = self.records()
        value = self.assert_successor_chain(request, parent, snapshot)
        self.assertEqual(snapshot["streams"], streams)
        self.start()
        self.assertEqual(self.found(key()), parent)
        self.assertEqual(self.found(request), value)
        self.assertEqual(self.close(request), value)
        self.assert_late_submit_closed(request, value, snapshot)

    def test_invalid_close_does_not_consume_armed_exit(self):
        cases = (("unauthorized", "invalid-token", {}, 401, "unauthenticated"),
                 ("invalid_chain", "synthetic-A1-token", {"replaces_attempt_id": "missing", "closure_id": "missing-proof"},
                  409, "attempt_chain_conflict"))
        for label, token, extra, expected_status, code in cases:
            with self.subTest(case=label):
                request = key(logical_id=label)
                baseline = self.records()
                self.control({"action": "hook", "hook": "before_commit_exit"})
                status, body = self.request("close_attempt", {**request, **extra}, token)
                self.assertEqual((status, body["error"]["code"]), (expected_status, code))
                self.assertIsNone(self.process.poll())
                self.assertEqual(self.records(), baseline)
                with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError)):
                    self.request("close_attempt", request)
                self.assertEqual(self.process.wait(timeout=3), 86)
                self.stop()
                self.start()
                self.assertEqual(self.records(), baseline)

    def test_close_existing_terminal_returns_original_across_both_exit_windows(self):
        for terminal in ("accepted", "rejected_final"):
            for hook in ("before_commit_exit", "after_commit_exit"):
                with self.subTest(terminal=terminal, hook=hook):
                    logical_id = terminal + "-" + hook
                    request = key(logical_id=logical_id)
                    changes = {} if terminal == "accepted" else {"authorization_version": "2"}
                    status, body = self.request("submit_message", {"envelope": envelope(logical_id=logical_id, **changes)})
                    self.assertEqual(status, 200 if terminal == "accepted" else 409, body)
                    value = self.found(request)
                    self.assertEqual(value["outcome"], terminal)
                    baseline = self.records()
                    self.assertEqual(self.close(request), value)
                    self.exit_close(request, hook)
                    self.assertEqual(self.records(), baseline)
                    self.start()
                    self.assertEqual(self.found(request), value)
                    self.assertEqual(self.close(request), value)
                    self.assertEqual(self.records(), baseline)

    def test_disabled_controls_cannot_arm_close_exit(self):
        self.stop()
        self.start(controls=False)
        for hook in ("before_commit_exit", "after_commit_exit"):
            status, body = self.request("", {"action": "hook", "hook": hook}, "synthetic-controller-token", True)
            self.assertEqual((status, body["error"]["code"]), (403, "permission_denied"))
        request = key()
        value = self.close(request)
        self.assertIsNone(self.process.poll())
        snapshot = self.records()
        self.assertEqual(self.assert_sealed(request, snapshot), value)
        self.stop()
        self.start(controls=False)
        self.assertEqual(self.found(request), value)
        self.assertEqual(self.records(), snapshot)

    def test_lost_close_response_reuses_same_persistent_closure(self):
        request = key()
        self.control({"action": "hook", "hook": "drop_after_commit"})
        with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError)):
            self.request("close_attempt", request)
        self.assertIsNone(self.process.poll())
        snapshot = self.records()
        value = self.assert_sealed(request, snapshot)
        self.assertEqual(self.close(request), value)
        self.stop()
        self.start()
        self.assertEqual(self.found(request), value)
        self.assertEqual(self.close(request), value)
        self.assert_late_submit_closed(request, value, snapshot)


if __name__ == "__main__":
    unittest.main()
