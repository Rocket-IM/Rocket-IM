#!/usr/bin/env python3
"""M07/M09 测试 Relay 包装器：复用真实 HTTP/SQLite 业务，增加确定时序屏障。"""

import argparse
import socket
import sys
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "poc/network-relay"))

from contract import ProtocolError, encode_json, parse_json
from controls import TestControls, stats
from permission_verifier import PermissionVerifier
from receipt_signer import ReceiptSigner
from server import Handler, RelayServer
from storage import Store

if __package__:
    from .concurrency_probe import TransactionProbe
else:
    from concurrency_probe import TransactionProbe


class ObservedStore(Store):
    def __init__(self, path, fixture, probe, permission_verifier=None, receipt_signer=None):
        self.probe = probe
        super().__init__(path, fixture, permission_verifier, receipt_signer)

    def connect(self):
        db = super().connect()

        def trace(statement):
            label = self.probe.current_label()
            if label is not None and statement.strip().upper() == "BEGIN IMMEDIATE":
                self.probe.record(label, "begin_requested")

        db.set_trace_callback(trace)
        return db

    @contextmanager
    def transaction(self):
        label = self.probe.current_label()
        if label is None:
            with super().transaction() as db:
                yield db
            return
        self.probe.record(label, "requested")
        acquired = False
        try:
            self.probe.checkpoint(label, "before_begin")
            # BEGIN、commit、rollback 和连接关闭全部由原 Store 实现执行。
            with super().transaction() as db:
                acquired = True
                self.probe.record(label, "acquired")
                yield db
                pending = stats(db)
                for stream in pending["streams"]:
                    stream["events"] = str(db.execute(
                        "SELECT COUNT(*) FROM events WHERE account=? AND device=?",
                        (stream["account_id"], stream["device_id"])).fetchone()[0])
                self.probe.checkpoint(label, "before_commit", pending)
            self.probe.record(label, "committed")
        except BaseException:
            self.probe.record(label, "rolled_back" if acquired else "not_started")
            raise


class ObservedHandler(Handler):
    def do_POST(self):
        probe = self.server.store.probe
        try:
            if self.path == "/_test/transactions":
                if self.headers.get_all("X-RIM-Test-Transaction") or self.headers.get_all("X-RIM-Test-Key"):
                    raise ProtocolError("test_transaction_invalid", "事务控制请求不能携带事务标签")
                # 只访问已加载的合成控制器凭证和内存屏障，避免等待被测事务的锁。
                token, req = self.request_body()
                value = probe.execute(token, req)
                self.response(200, {"ok": True, "result": value})
                return
            with probe.bind(self.headers):
                super().do_POST()
        except ProtocolError as error:
            self.error_response(error)
        except (socket.timeout, TimeoutError, BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    def response(self, status, value):
        super().response(status, value)
        label = self.server.store.probe.current_label()
        if label is not None:
            self.server.store.probe.record(label, "responded", status=status)


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
    if not args.enable_test_controls:
        parser.error("本包装器必须显式启用 --enable-test-controls")
    if not args.database.is_absolute() or not args.fixture.is_absolute() or not 0 <= args.port <= 65535:
        parser.error("database/fixture 必须为绝对路径，port 必须为 0—65535")
    fixture = parse_json(args.fixture.read_bytes())
    verifier = PermissionVerifier(args.permission_verifier) if args.permission_verifier else None
    if bool(args.receipt_signer) != bool(args.receipt_key):
        parser.error("--receipt-signer 与 --receipt-key 必须同时提供")
    signer = ReceiptSigner(args.receipt_signer, args.receipt_key) if args.receipt_signer else None
    probe = TransactionProbe(fixture["controller_token"], True)
    store = ObservedStore(args.database, fixture, probe, verifier, signer)
    if store.permission_enabled and verifier is None:
        parser.error("已有权限检查点必须配置 --permission-verifier")
    server = RelayServer(("127.0.0.1", args.port), store, TestControls(True))
    server.RequestHandlerClass = ObservedHandler
    print(encode_json({"status": "ready", "url": f"http://127.0.0.1:{server.server_port}",
                       "database": str(store.path)}).decode(), flush=True)
    try:
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        probe.close()
        server.server_close()


if __name__ == "__main__":
    main()
