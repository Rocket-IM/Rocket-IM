"""真实本机 HTTP/独立 Relay 进程的中断、输入和重启回归。"""

import concurrent.futures
import http.client
import json
from http_test_support import RelayHTTPFixture
import socket
import sqlite3
import subprocess
import sys
import time
import unittest
from pathlib import Path

from contract import encode_json
from test_support import envelope, fixture, key
from permission_tests import permission_fixture, proof


class HTTPTests(RelayHTTPFixture):
    def test_http_auth_input_and_valid_submit(self):
        status, error = self.request("pull_events", {"service_id": "S1", "after_seq": "0", "limit": "1"}, "invalid-token")
        self.assertEqual((status, error["error"]["code"]), (401, "unauthenticated"))
        status, error = self.request("pull_events", {"service_id": "S1", "after_seq": "0", "limit": True})
        self.assertEqual((status, error["error"]["code"]), (400, "invalid_envelope"))
        status, accepted = self.request("submit_message", {"envelope": envelope()})
        self.assertEqual(status, 200)
        self.assertEqual(accepted["result"]["outcome"], "accepted")

    def test_duplicate_or_malformed_content_length_rejected(self):
        authority = self.url.removeprefix("http://").split(":")
        for lengths in ("Content-Length: 2\r\nContent-Length: 2\r\n", "Content-Length: -1\r\n", "Content-Length: 02\r\n"):
            with self.subTest(lengths=lengths):
                with socket.create_connection((authority[0], int(authority[1])), timeout=2) as connection:
                    raw = ("POST /v1/pull_events HTTP/1.1\r\nHost: localhost\r\n" + lengths +
                           "Content-Type: application/json\r\nAuthorization: Bearer synthetic-A1-token\r\nConnection: close\r\n\r\n{}").encode()
                    connection.sendall(raw)
                    response = http.client.HTTPResponse(connection)
                    response.begin()
                    self.assertEqual(response.status, 400)
                    self.assertEqual(json.loads(response.read())["error"]["code"], "invalid_envelope")

    def test_lost_accept_response_keeps_process_and_reuses_acceptance(self):
        self.control({"action": "hook", "hook": "drop_after_commit"})
        with self.assertRaises(http.client.RemoteDisconnected):
            self.request("submit_message", {"envelope": envelope()})
        self.assertIsNone(self.process.poll())
        _, found = self.request("get_attempt", key())
        _, retried = self.request("submit_message", {"envelope": envelope()})
        self.assertEqual(found, retried)
        self.assertEqual(self.control({"action": "stats"})["message_events"], "2")

    def test_unauthorized_request_does_not_consume_armed_hook(self):
        self.control({"action": "hook", "hook": "drop_after_commit"})
        status, _ = self.request("submit_message", {"envelope": envelope()}, "invalid-token")
        self.assertEqual(status, 401)
        with self.assertRaises(http.client.RemoteDisconnected):
            self.request("submit_message", {"envelope": envelope()})
        self.assertEqual(self.control({"action": "stats"})["accepted"], "1")

    def test_exit_before_commit_rolls_back_every_target(self):
        self.control({"action": "hook", "hook": "before_commit_exit"})
        with self.assertRaises(http.client.RemoteDisconnected):
            self.request("submit_message", {"envelope": envelope()})
        self.assertEqual(self.process.wait(timeout=3), 86)
        self.stop()
        self.start()
        _, found = self.request("get_attempt", key())
        self.assertEqual(found["result"]["outcome"], "not_found")
        self.assertEqual(self.control({"action": "stats"})["events"], "0")
        _, accepted = self.request("submit_message", {"envelope": envelope()})
        self.assertEqual(accepted["result"]["outcome"], "accepted")

    def test_exit_after_commit_restores_acceptance_and_streams(self):
        streams = self.control({"action": "stats"})["streams"]
        self.control({"action": "hook", "hook": "after_commit_exit"})
        with self.assertRaises(http.client.RemoteDisconnected):
            self.request("submit_message", {"envelope": envelope()})
        self.assertEqual(self.process.wait(timeout=3), 87)
        self.stop()
        self.start()
        _, found = self.request("get_attempt", key())
        _, retried = self.request("submit_message", {"envelope": envelope()})
        self.assertEqual(found, retried)
        self.assertEqual([s["stream_id"] for s in streams], [s["stream_id"] for s in self.control({"action": "stats"})["streams"]])
        self.assertEqual(self.control({"action": "stats"})["message_events"], "2")

    def test_concurrent_submit_does_not_publish_uncommitted_watermark(self):
        self.control({"action": "hook", "hook": "delay_before_commit", "delay_ms": "500"})
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            first = pool.submit(self.request, "submit_message", {"envelope": envelope(logical_id="M1")})
            deadline = time.monotonic() + 2
            locked = False
            while time.monotonic() < deadline:
                db = sqlite3.connect(self.path / "relay.sqlite3", timeout=0, isolation_level=None)
                try:
                    db.execute("BEGIN IMMEDIATE")
                    db.rollback()
                except sqlite3.OperationalError:
                    locked = True
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)
                    break
                finally:
                    db.close()
                time.sleep(0.01)
            self.assertTrue(locked)
            second = pool.submit(self.request, "submit_message", {"envelope": envelope(logical_id="M2")})
            self.assertEqual(first.result()[0], 200)
            self.assertEqual(second.result()[0], 200)
        _, page = self.request("pull_events", {"service_id": "S1", "after_seq": "0", "limit": "100"}, "synthetic-B1-token")
        self.assertEqual([e["event_seq"] for e in page["result"]["events"]], ["1", "2"])

    def test_permission_helper_rejection_and_controller_bypass_keep_empty_chain(self):
        self.stop()
        self.path = self.path / "permission-mode"
        self.path.mkdir(mode=0o700)
        self.fixture_path.write_bytes(encode_json(permission_fixture()))
        verifier = self.path / "rejecting-public-verifier"
        verifier.write_text(f"#!{sys.executable}\nimport sys\nsys.stdin.buffer.read()\nprint('{{\"ok\":false,\"error\":{{\"code\":\"permission_signature\",\"message\":\"invalid\"}}}}')\nsys.exit(1)\n")
        verifier.chmod(0o700)
        self.start(verifier=verifier)
        status, error = self.request("submit_permission_change", {"service_id": "S1", "conversation_id": "G1", "change": proof()})
        self.assertEqual((status, error["error"]["code"]), (403, "permission_signature"))
        for action in ("set_state", "revoke_device", "add_control"):
            status, error = self.request("", {"action": action}, "synthetic-controller-token", True)
            self.assertEqual((status, error["error"]["code"]), (403, "permission_denied"))
        _, page = self.request("get_permission_changes", {"service_id": "S1", "conversation_id": "G1", "after_version": "1", "limit": "32"})
        self.assertEqual(page["result"], {"changes": [], "next_after_version": "1", "authorization_version": "1", "has_more": False})
        self.stop()
        completed = subprocess.run([sys.executable, "-B", str(Path(__file__).with_name("server.py")), "--database", str(self.path / "relay.sqlite3"),
                                    "--fixture", str(self.fixture_path), "--port", "0"], capture_output=True, text=True, timeout=5)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("--permission-verifier", completed.stderr)

    def test_legacy_permission_endpoints_report_disabled(self):
        request = {"service_id": "S1", "conversation_id": "G1", "after_version": "1", "limit": "32"}
        status, error = self.request("get_permission_changes", request)
        self.assertEqual((status, error["error"]["code"]), (409, "permission_not_enabled"))

    def test_controller_operations_require_explicit_startup_switch(self):
        self.stop()
        self.start(controls=False)
        status, result = self.request("", {"action": "stats"}, "synthetic-controller-token", True)
        self.assertEqual((status, result["error"]["code"]), (403, "permission_denied"))


if __name__ == "__main__":
    unittest.main()
