"""M12.e 原 RelayServer 异常释放回归；故障注入是合成测试，不模拟 OS 资源耗尽。"""

from contextlib import redirect_stderr
import http.client
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from contract import encode_json
from controls import TestControls
import server
from storage import Store
from test_support import envelope, fixture, key


class BackpressureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="rim-backpressure-module-")
        self.addCleanup(temporary.cleanup)
        self.store = Store(Path(temporary.name) / "relay.sqlite", fixture())
        self.relay = server.RelayServer(("127.0.0.1", 0), self.store, TestControls(False))
        self.condition = threading.Condition()
        self.completed = 0
        self.closed = []
        self.errors = []
        self.connections = []
        original_worker = self.relay.process_request_thread
        original_shutdown = self.relay.shutdown_request

        def observed_worker(request, address):
            try:
                return original_worker(request, address)
            finally:
                # 必须等原 worker 的 finally 已释放槽位，再通知测试调度器。
                with self.condition:
                    self.completed += 1
                    self.condition.notify_all()

        def observed_shutdown(request):
            try:
                return original_shutdown(request)
            finally:
                with self.condition:
                    self.closed.append(request.fileno())
                    self.condition.notify_all()

        def observed_error(_request, _address):
            # 只保存异常类型，避免原 traceback 打印请求参数或合成凭证。
            with self.condition:
                self.errors.append(type(sys.exception()).__name__)
                self.condition.notify_all()

        self.relay.process_request_thread = observed_worker
        self.relay.shutdown_request = observed_shutdown
        self.relay.handle_error = observed_error
        self.thread = threading.Thread(target=self.relay.serve_forever,
                                       kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.baseline = self.message_counts()

    def close_server(self):
        for connection in self.connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        self.relay.shutdown()
        self.thread.join(timeout=3)
        self.relay.server_close()

    def message_counts(self):
        # 观察仅在原 Store 的显式事务中执行，不依赖裸连接读数据。
        with self.store.transaction() as db:
            return tuple(db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                         for table in ("logical_messages", "attempts", "events", "receipts"))

    def connect(self):
        connection = socket.create_connection(self.relay.server_address, timeout=3)
        self.connections.append(connection)
        return connection

    @staticmethod
    def headers(operation, body, expect=False):
        continuation = "Expect: 100-continue\r\n" if expect else ""
        return (f"POST /v1/{operation} HTTP/1.1\r\nHost: localhost\r\n"
                f"Content-Length: {len(body)}\r\nContent-Type: application/json\r\n"
                "Authorization: Bearer synthetic-A1-token\r\n"
                f"{continuation}Connection: close\r\n\r\n").encode("ascii")

    def hold(self):
        body = encode_json({"service_id": "S1", "after_seq": "0", "limit": "1"})
        connection = self.connect()
        connection.sendall(self.headers("pull_events", body, expect=True) + body[:1])
        interim = bytearray()
        while not interim.endswith(b"\r\n\r\n"):
            chunk = connection.recv(1)
            self.assertTrue(chunk, "占用请求在 100-continue 前被关闭")
            interim.extend(chunk)
            self.assertLess(len(interim), 8192)
        self.assertEqual(bytes(interim), b"HTTP/1.1 100 Continue\r\n\r\n")
        return connection, body[1:]

    @staticmethod
    def response(connection):
        response = http.client.HTTPResponse(connection)
        response.begin()
        try:
            return response.status, json.loads(response.read())
        finally:
            response.close()

    def request(self, operation, value):
        body = encode_json(value)
        connection = self.connect()
        connection.sendall(self.headers(operation, body) + body)
        try:
            return self.response(connection)
        finally:
            connection.close()

    def assert_saturated(self):
        # 原并发门禁在 accept 后读取 HTTP 请求前执行，故第九条连接无需正文。
        connection = self.connect()
        try:
            status, value = self.response(connection)
        finally:
            connection.close()
        self.assertEqual(status, 503)
        self.assertEqual(value["error"]["code"], "resource_exhausted")
        self.assertEqual(value["error"]["outcome"], "not_recorded")
        self.assertEqual(value["error"]["retry_after_ms"], "1000")

    def wait_completed(self, count):
        with self.condition:
            self.assertTrue(self.condition.wait_for(lambda: self.completed >= count, timeout=3),
                            "原 worker 未按时退出并释放槽位")

    def release(self, held):
        expected = self.completed + len(held)
        for connection, remainder in held:
            connection.sendall(remainder)
        for connection, _ in held:
            try:
                status, value = self.response(connection)
                self.assertEqual(status, 200)
                self.assertEqual(value["result"]["events"], [])
            finally:
                connection.close()
        self.wait_completed(expected)

    def recover_and_refill(self, held):
        held.append(self.hold())
        self.assertEqual(len(held), 8)
        self.assert_saturated()
        self.release(held)
        # 不是单个请求探活：所有八槽都必须再次通过 100-continue，且第九条仍拒绝。
        again = [self.hold() for _ in range(8)]
        self.assert_saturated()
        self.release(again)
        self.assertTrue(self.thread.is_alive())
        self.assertEqual(self.message_counts(), self.baseline)

    def assert_closed(self, connection, before):
        try:
            self.assertEqual(connection.recv(1), b"")
        except ConnectionResetError:
            pass
        finally:
            connection.close()
        with self.condition:
            self.assertTrue(self.condition.wait_for(lambda: len(self.closed) > before, timeout=3))
            self.assertEqual(self.closed[-1], -1, "原 shutdown_request 未关闭服务端 socket")

    def test_handler_exception_rolls_back_and_restores_all_eight_slots(self):
        held = [self.hold() for _ in range(7)]
        original = server.DISPATCH["submit_message"]
        failure_detail = "synthetic_handler_before_commit_failure"
        diagnostics = io.StringIO()
        observed_error = self.relay.handle_error

        def record_private_error(request, address):
            observed_error(request, address)
            server.RelayServer.handle_error(self.relay, request, address)

        def fail_after_original_sql(store, db, device, request):
            original(store, db, device, request)
            # 原实现确实已写入；异常必须经原 with transaction 回滚，而非假造成功结果。
            self.assertEqual(db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0], 1)
            raise RuntimeError(failure_detail)

        with (redirect_stderr(diagnostics),
              patch.object(self.relay, "handle_error", new=record_private_error),
              patch.dict(server.DISPATCH, {"submit_message": fail_after_original_sql})):
            connection = self.connect()
            body = encode_json({"envelope": envelope()})
            before = len(self.closed)
            connection.sendall(self.headers("submit_message", body) + body)
            response = http.client.HTTPResponse(connection)
            response.begin()
            try:
                self.assertEqual(response.status, 503)
                self.assertEqual(response.getheader("Connection"), "close")
                self.assertEqual(response.getheader("Cache-Control"), "no-store")
                raw = response.read()
                self.assertEqual(json.loads(raw), {"ok": False, "error": {
                    "code": "outcome_unknown", "message": "请求处理失败，结果不确定，请查原尝试",
                    "outcome": "outcome_unknown"}})
                observed = encode_json(response.getheaders()) + raw
                for private in (failure_detail, "synthetic-A1-token"):
                    self.assertNotIn(private.encode(), observed)
            finally:
                response.close()
            self.assert_closed(connection, before)
            self.wait_completed(1)
        self.assertEqual(self.errors, ["RuntimeError"])
        self.assertEqual([json.loads(line) for line in diagnostics.getvalue().splitlines()],
                         [{"event": "relay_request_failed"}])
        self.assertEqual(self.message_counts(), self.baseline)
        self.recover_and_refill(held)
        status, found = self.request("get_attempt", key())
        self.assertEqual(status, 200)
        self.assertEqual(found["result"]["outcome"], "not_found")

    def test_thread_start_exception_closes_socket_and_restores_all_eight_slots(self):
        held = [self.hold() for _ in range(7)]
        before = len(self.closed)
        # 仅一次明确的 Python 启动异常；不是实际 OS 线程耗尽证据。
        with patch.object(threading.Thread, "start", side_effect=RuntimeError("synthetic_start_failure")) as start:
            connection = self.connect()
            self.assert_closed(connection, before)
            self.assertEqual(start.call_count, 1)
        self.assertEqual(self.errors, ["RuntimeError"])
        self.assertEqual(self.completed, 0, "启动失败不应执行 worker")
        self.recover_and_refill(held)

    def test_saturated_sendall_failure_keeps_original_eight_slots_owned(self):
        held = [self.hold() for _ in range(8)]
        original = socket.socket.sendall
        injected = threading.Event()

        def fail_only_accept_thread(connection, data, *args, **kwargs):
            if threading.current_thread() is self.thread:
                injected.set()
                raise BrokenPipeError("synthetic_saturated_send_failure")
            return original(connection, data, *args, **kwargs)

        before = len(self.closed)
        with patch.object(socket.socket, "sendall", new=fail_only_accept_thread):
            connection = self.connect()
            self.assert_closed(connection, before)
            self.assertTrue(injected.is_set())
        self.assertEqual(self.completed, 0)
        self.assert_saturated()
        self.release(held)
        again = [self.hold() for _ in range(8)]
        self.assert_saturated()
        self.release(again)
        self.assertEqual(self.errors, [])
        self.assertTrue(self.thread.is_alive())
        self.assertEqual(self.message_counts(), self.baseline)


if __name__ == "__main__":
    unittest.main()
