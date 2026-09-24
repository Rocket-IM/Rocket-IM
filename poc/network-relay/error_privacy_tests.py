"""M01 错误观测面：真实回环 HTTP 加具名合成故障，不代表生产日志隔离。"""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import socket
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from contract import encode_json
from controls import TestControls
import server
from storage import Store
from test_support import envelope, fixture, key


CANARY = "SYNTHETIC_M01_ERROR_PRIVATE_CANARY_8f421ce0"
FIXED_FAILURE = {"event": "relay_request_failed"}


class ErrorPrivacyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="rim-error-privacy-")
        self.addCleanup(temporary.cleanup)
        self.stdout, self.stderr = io.StringIO(), io.StringIO()
        self.enterContext(redirect_stdout(self.stdout))
        self.enterContext(redirect_stderr(self.stderr))
        self.store = Store(Path(temporary.name) / "relay.sqlite", fixture())
        self.relay = server.RelayServer(("127.0.0.1", 0), self.store, TestControls(False))
        self.condition = threading.Condition()
        self.completed = 0
        original_worker = self.relay.process_request_thread

        def observed_worker(request, address):
            try:
                return original_worker(request, address)
            finally:
                # 原 worker 的错误处理和资源释放完成后才允许检查日志或恢复注入。
                with self.condition:
                    self.completed += 1
                    self.condition.notify_all()

        self.relay.process_request_thread = observed_worker
        self.thread = threading.Thread(target=self.relay.serve_forever,
                                       kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.baseline = self.records()

    def close_server(self):
        self.relay.shutdown()
        self.thread.join(timeout=3)
        self.relay.server_close()

    def records(self):
        # 包括所有表和字段；读取也通过原 Store 的显式事务完成。
        with self.store.transaction() as db:
            tables = db.execute("SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
            return [(name, sql, sorted((tuple(row) for row in db.execute(f'SELECT * FROM "{name}"')), key=repr))
                    for name, sql in tables]

    def raw_http(self, request):
        with self.condition:
            expected = self.completed + 1
        with socket.create_connection(self.relay.server_address, timeout=3) as connection:
            connection.sendall(request)
            connection.shutdown(socket.SHUT_WR)
            received = bytearray()
            while True:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                received.extend(chunk)
                self.assertLess(len(received), 2 * 1024 * 1024)
        with self.condition:
            self.assertTrue(self.condition.wait_for(lambda: self.completed >= expected, timeout=3),
                            "HTTP worker 未完成错误处理或释放")
        return bytes(received)

    def request(self, operation, value, token="synthetic-A1-token"):
        body = encode_json(value)
        headers = (f"POST /v1/{operation} HTTP/1.1\r\nHost: localhost\r\n"
                   f"Content-Length: {len(body)}\r\nContent-Type: application/json\r\n"
                   f"Authorization: Bearer {token}\r\nConnection: close\r\n\r\n").encode("ascii")
        return self.raw_http(headers + body)

    def parsed(self, response):
        self.assertTrue(response.startswith(b"HTTP/1.1 "), "错误必须显式返回 HTTP 状态")
        headers, body = response.split(b"\r\n\r\n", 1)
        self.assertIn(b"Content-Type: application/json; charset=utf-8", headers)
        self.assertIn(b"Cache-Control: no-store", headers)
        return int(headers.split(b" ", 2)[1]), json.loads(body)

    def private_error(self, response, status, code, outcome="not_recorded"):
        self.assertNotIn(CANARY.encode(), response, "HTTP 错误反射了合成秘密标记")
        self.assertNotIn(CANARY, self.stderr.getvalue(), "stderr 泄露合成错误详情")
        self.assertNotIn(CANARY, self.stdout.getvalue(), "stdout 泄露合成错误详情")
        actual, value = self.parsed(response)
        self.assertEqual((actual, value["ok"], value["error"]["code"], value["error"]["outcome"]),
                         (status, False, code, outcome))
        self.assertNotIn("result", value)

    def test_unknown_method_does_not_reflect_request_method(self):
        response = self.raw_http(f"{CANARY} /v1/get_attempt HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
        self.private_error(response, 501, "unsupported_operation")
        # 固定错误格式仍须保持 HEAD 无响应正文的既有 HTTP 语义。
        head = self.raw_http(f"HEAD /{CANARY} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
        headers, body = head.split(b"\r\n\r\n", 1)
        self.assertTrue(headers.startswith(b"HTTP/1.1 501 "))
        self.assertNotIn(CANARY.encode(), head)
        self.assertEqual(body, b"")
        self.assertEqual(self.records(), self.baseline)
        self.assertEqual((self.stdout.getvalue(), self.stderr.getvalue()), ("", ""))

    def test_malformed_first_line_and_version_do_not_reflect_request(self):
        requests = (f"POST /{CANARY} HTTP/1.1 EXTRA\r\n\r\n",
                    f"POST /v1/get_attempt HTTP/{CANARY}\r\n\r\n")
        for raw in requests:
            with self.subTest(case="first_line" if "EXTRA" in raw else "version"):
                self.private_error(self.raw_http(raw.encode()), 400, "invalid_envelope")
                self.assertEqual(self.records(), self.baseline)
        self.assertEqual((self.stdout.getvalue(), self.stderr.getvalue()), ("", ""))

    def test_unhandled_exception_is_private_rolls_back_and_service_recovers(self):
        original = server.DISPATCH["submit_message"]

        def fail_after_insert(store, db, device, req):
            original(store, db, device, req)
            raise RuntimeError(CANARY)

        # 真实 submit 已写候选尝试和目标事件，再在事务提交前触发具名合成异常。
        with patch.dict(server.DISPATCH, {"submit_message": fail_after_insert}):
            response = self.request("submit_message", {"envelope": envelope()})
        self.assertEqual(self.records(), self.baseline, "未处理异常留下部分提交")
        self.private_error(response, 503, "outcome_unknown", "outcome_unknown")
        self.assertEqual(self.stdout.getvalue(), "")
        self.assertEqual([json.loads(line) for line in self.stderr.getvalue().splitlines()], [FIXED_FAILURE])
        status, value = self.parsed(self.request("get_attempt", key()))
        self.assertEqual((status, value["result"]["outcome"]), (200, "not_found"))
        status, value = self.parsed(self.request("submit_message", {"envelope": envelope()}))
        self.assertEqual((status, value["result"]["outcome"]), (200, "accepted"))
        self.assertEqual([json.loads(line) for line in self.stderr.getvalue().splitlines()], [FIXED_FAILURE])

    def test_known_protocol_errors_do_not_echo_input_or_credentials(self):
        response = self.request("get_attempt", {**key(), "private_input": CANARY})
        self.private_error(response, 400, "invalid_envelope")
        response = self.request("get_attempt", key(), token=CANARY)
        self.private_error(response, 401, "unauthenticated")
        self.assertEqual(self.records(), self.baseline)
        self.assertEqual((self.stdout.getvalue(), self.stderr.getvalue()), ("", ""))

    def test_known_database_errors_remain_private_and_atomic(self):
        original = server.DISPATCH["submit_message"]
        for error_type, code in ((sqlite3.OperationalError, "temporarily_unavailable"),
                                 (sqlite3.DatabaseError, "outcome_unknown")):
            with self.subTest(error_type=error_type.__name__):
                def fail_after_insert(store, db, device, req):
                    original(store, db, device, req)
                    raise error_type(CANARY)

                with patch.dict(server.DISPATCH, {"submit_message": fail_after_insert}):
                    response = self.request("submit_message", {"envelope": envelope()})
                self.private_error(response, 503, code, "outcome_unknown")
                self.assertEqual(self.records(), self.baseline)
        self.assertEqual((self.stdout.getvalue(), self.stderr.getvalue()), ("", ""))


if __name__ == "__main__":
    unittest.main()
