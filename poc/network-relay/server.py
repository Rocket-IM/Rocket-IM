#!/usr/bin/env python3
"""仅绑定本机的阶段 0 HTTP Relay；不提供生产 TLS、登录或密码能力。"""

import argparse
import os
import re
import socket
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from contract import MAX_REQUEST_BYTES, ProtocolError, encode_json, parse_json, validate_request
from controls import TestControls
from messages import close_attempt, get_attempt, rejected_error, submit
from storage import Store
from permission_verifier import PermissionVerifier
from receipt_signer import ReceiptSigner
from permissions import get_consistency_head, get_permission_changes, get_permission_records, submit_permission_change
from permission_records import close_permission_change
from join_materials import get_join_material
from history_transfers import get_history_transfer, submit_history_transfer
from rebuild_streams import register_rebuild_stream, pull_rebuild_events
from rebuild_stream_storage import authorize_operation
from synchronization import get_crypto_dependencies, project_expiration, pull_events, report_delivery, report_read
from stream_pages import pull_events_signed

DISPATCH = {"submit_message": submit, "get_attempt": get_attempt, "close_attempt": close_attempt,
            "pull_events": pull_events, "pull_events_signed": pull_events_signed,
            "report_delivery": report_delivery, "report_read": report_read,
            "get_crypto_dependencies": get_crypto_dependencies,
            "submit_permission_change": submit_permission_change, "get_permission_changes": get_permission_changes,
            "close_permission_change": close_permission_change, "get_permission_records": get_permission_records,
            "get_join_material": get_join_material, "submit_history_transfer": submit_history_transfer,
            "get_history_transfer": get_history_transfer, "get_consistency_head": get_consistency_head,
            "register_rebuild_stream": register_rebuild_stream, "pull_rebuild_events": pull_rebuild_events}


class RelayServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 8
    allow_reuse_address = True

    def __init__(self, address, store, controls):
        if address[0] != "127.0.0.1":
            raise ValueError("实验 Relay 仅允许绑定 127.0.0.1")
        self.store = store
        self.controls = controls
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            try:
                request.settimeout(1)
                payload = encode_json({"ok": False, "error": {"code": "resource_exhausted", "message": "实验并发已达上限",
                                       "outcome": "not_recorded", "retry_after_ms": "1000"}})
                headers = ("HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json; charset=utf-8\r\n"
                           f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n").encode("ascii")
                request.sendall(headers + payload)
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, _request, _client_address):
        # 未处理异常仍留下失败信号；异常文本、请求和线程 traceback 可能含秘密。
        print(encode_json({"event": "relay_request_failed"}).decode(), file=sys.stderr, flush=True)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "Rockets-IM-POC"
    sys_version = ""

    def setup(self):
        self.request.settimeout(8)
        super().setup()

    def log_message(self, _format, *_args):
        # 只保留启动结果；测试报告由调用方收集，避免输出凭证或请求内容。
        return

    def response(self, status, value):
        data = encode_json(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)
        self.close_connection = True

    def error_response(self, error):
        self.response(error.status, {"ok": False, "error": {"code": error.code, "message": error.message,
                      "outcome": error.outcome, **error.details}})

    def send_error(self, code, message=None, explain=None):
        # 基类会把非法方法或首行反射到状态说明和 HTML；只保留原错误状态。
        # 解析版本失败时基类可能仍处于 HTTP/0.9，实验入口统一返回完整 HTTP 响应。
        self.request_version = "HTTP/1.1"
        if code == 501:
            error = ProtocolError("unsupported_operation", "不支持此 HTTP 操作", status=code)
        else:
            error = ProtocolError("invalid_envelope", "HTTP 请求格式或版本不受支持", status=code)
        self.error_response(error)

    def request_body(self):
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get("Transfer-Encoding") is not None or len(lengths) != 1 or re.fullmatch(r"[1-9][0-9]{0,9}", lengths[0]) is None:
            raise ProtocolError("invalid_envelope", "必须提供唯一且规范的 Content-Length")
        size = int(lengths[0])
        if size > MAX_REQUEST_BYTES:
            raise ProtocolError("invalid_envelope", "请求超过 1 MiB 上限", status=413)
        if self.headers.get_all("Content-Type", []) != ["application/json"]:
            raise ProtocolError("invalid_envelope", "Content-Type 必须为 application/json", status=415)
        credentials = self.headers.get_all("Authorization", [])
        if len(credentials) != 1 or not credentials[0].startswith("Bearer ") or not 1 <= len(credentials[0][7:]) <= 256:
            raise ProtocolError("unauthenticated", "需要设备或测试控制器 Bearer 凭证", status=401)
        raw = self.rfile.read(size)
        if len(raw) != size:
            raise ProtocolError("invalid_envelope", "请求体长度不完整")
        return credentials[0][7:], parse_json(raw)

    def do_POST(self):
        try:
            token, req = self.request_body()
            control = self.path == "/_test/control"
            operation = self.path.removeprefix("/v1/") if self.path.startswith("/v1/") else ""
            if not control:
                validate_request(operation, req)
            hook = None
            with self.server.store.transaction() as db:
                if control:
                    value = self.server.controls.execute(self.server.store, db, token, req)
                    if req.get("action") in {"set_availability", "backfill_lifecycle"}:
                        hook = self.server.controls.take_hook()
                else:
                    device = self.server.store.authenticate(db, token)
                    authorize_operation(db, device, operation)
                    # 拉取先校验旧水位，再投影到期并读取新水位，避免未来游标跳过新通知。
                    if operation not in {"pull_events", "pull_events_signed", "pull_rebuild_events"}:
                        project_expiration(db)
                    value = DISPATCH[operation](self.server.store, db, device, req)
                    if operation in {"submit_message", "close_attempt", "report_delivery", "report_read", "submit_permission_change", "close_permission_change", "submit_history_transfer", "register_rebuild_stream", "pull_rebuild_events", "pull_events_signed"}:
                        hook = self.server.controls.take_hook()
                self.before_commit(hook)
            self.after_commit(hook)
            if hook and hook["name"] == "drop_after_commit":
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                return
            if value.get("outcome") == "rejected_final" and operation == "submit_message":
                raise rejected_error(value)
            self.response(200, {"ok": True, "result": value})
        except ProtocolError as error:
            self.error_response(error)
        except sqlite3.OperationalError:
            self.error_response(ProtocolError("temporarily_unavailable", "持久化暂时不可用，请查原尝试或重试原字节", outcome="outcome_unknown", status=503, retry_after_ms="1000"))
        except (socket.timeout, TimeoutError):
            self.close_connection = True
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except sqlite3.DatabaseError:
            self.error_response(ProtocolError("outcome_unknown", "持久化结果不确定，请查原尝试", outcome="outcome_unknown", status=503))
        except Exception:
            # Store 的上下文已完成回滚；异常也可能出现在提交后，不能宣称未记录。
            self.server.handle_error(self.request, self.client_address)
            self.error_response(ProtocolError("outcome_unknown", "请求处理失败，结果不确定，请查原尝试", outcome="outcome_unknown", status=503))

    @staticmethod
    def before_commit(hook):
        if hook and hook["name"] == "before_commit_exit":
            os._exit(86)
        if hook and hook["name"] == "delay_before_commit":
            time.sleep(hook["delay_ms"] / 1000)

    @staticmethod
    def after_commit(hook):
        if hook and hook["name"] == "after_commit_exit":
            os._exit(87)
        if hook and hook["name"] == "delay_after_commit":
            time.sleep(hook["delay_ms"] / 1000)

    def do_GET(self):
        self.error_response(ProtocolError("unsupported_operation", "仅接受已定义的 POST 操作", status=405))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--enable-test-controls", action="store_true")
    parser.add_argument("--permission-verifier", type=Path)
    parser.add_argument("--receipt-signer", type=Path)
    parser.add_argument("--receipt-key", type=Path)
    args = parser.parse_args()
    if not args.database.is_absolute() or not args.fixture.is_absolute():
        parser.error("database 与 fixture 必须是绝对路径")
    if not 0 <= args.port <= 65535:
        parser.error("port 必须为 0—65535")
    fixture = parse_json(args.fixture.read_bytes())
    verifier = PermissionVerifier(args.permission_verifier) if args.permission_verifier else None
    if bool(args.receipt_signer) != bool(args.receipt_key):
        parser.error("--receipt-signer 与 --receipt-key 必须同时提供")
    signer = ReceiptSigner(args.receipt_signer, args.receipt_key) if args.receipt_signer else None
    store = Store(args.database, fixture, verifier, signer)
    if store.permission_enabled and verifier is None:
        parser.error("已有权限检查点必须配置 --permission-verifier")
    server = RelayServer(("127.0.0.1", args.port), store, TestControls(args.enable_test_controls))
    print(encode_json({"status": "ready", "url": f"http://127.0.0.1:{server.server_port}", "database": str(store.path)}).decode(), flush=True)
    try:
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
