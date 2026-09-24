"""M07/M09真实HTTP装置：按事务信号协调，只读观察独立已提交视图。"""

from contextlib import closing
import hashlib
import http.client
import json
import selectors
import sqlite3
import subprocess
import sys
import threading
import time
from urllib.parse import urlparse

from .fixture import NetworkLab, ROOT, check


class ConcurrencyLab(NetworkLab):
    def __init__(self, binary, directory, permission_verifier=None, receipt_signer=None):
        super().__init__(binary, directory, permission_verifier, receipt_signer)
        self.case_evidence = {}
        self.probe_key = None
        self.count_lock = threading.Lock()

    def start(self):
        self.server_log = (self.directory / "relay.stderr.log").open("a")
        command = [sys.executable, "-B", str(ROOT / "tests/interop/network_poc/concurrency_relay.py"),
                   "--database", str(self.directory / "relay.sqlite"),
                   "--fixture", str(self.fixture_path), "--port", "0", "--enable-test-controls"]
        if self.permission_verifier:
            command.extend(["--permission-verifier", str(self.permission_verifier)])
        if self.receipt_signer:
            command.extend(["--receipt-signer", str(self.receipt_signer), "--receipt-key", str(self.receipt_key)])
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=self.server_log, text=True)
        self.process_count += 1
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            check(bool(selector.select(timeout=15)), "M07 Relay启动超时")
            line = self.process.stdout.readline()
        check(bool(line), "M07 Relay启动失败，查看stderr")
        ready = json.loads(line)
        check(ready["status"] == "ready", "M07 Relay未就绪")
        self.url = urlparse(ready["url"])
        check(self.url.hostname == "127.0.0.1", "M07只允许loopback")
        self.probe_key = None

    def post(self, route, fields, token, *, expected=200, label=None):
        headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
        if label is not None:
            check(self.probe_key is not None, "事务计划未登记")
            headers.update({"X-RIM-Test-Transaction": label, "X-RIM-Test-Key": self.probe_key})
        connection = http.client.HTTPConnection(self.url.hostname, self.url.port, timeout=10)
        try:
            with self.count_lock:
                self.http_count += 1
            connection.request("POST", route, json.dumps(fields), headers)
            response = connection.getresponse()
            reply = json.loads(response.read(2 * 1024 * 1024))
            check(response.status in (expected if isinstance(expected, tuple) else (expected,)),
                  f"事务装置 {route}: {response.status} != {expected}; {reply}")
            check(reply["ok"] == (response.status == 200), "HTTP状态与结果不一致")
            return reply["result"] if reply["ok"] else reply["error"]
        finally:
            connection.close()

    def http(self, device, operation, fields, *, expected=200, label=None):
        return self.post("/v1/" + operation, fields, self.tokens[device], expected=expected, label=label)

    def probe(self, action, **fields):
        result = self.post("/_test/transactions", {"action": action, **fields}, self.controller_token)
        if action == "arm":
            self.probe_key = result["key"]
        return result

    def wait_for(self, label, stage):
        deadline = time.monotonic() + 4
        while True:
            state = self.probe("status")
            if any(event["label"] == label and event["stage"] == stage for event in state["events"]):
                return state
            check(time.monotonic() < deadline, f"未观察到事务信号 {label}/{stage}: {state}")
            # 只轮询明确信号；间隔不作为事务已进入或提交顺序的证据。
            threading.Event().wait(0.01)

    def committed_view(self):
        """测试专用独立读连接；不修改Relay表，也不越过Rust读取客户端存储。"""
        path = (self.directory / "relay.sqlite").resolve().as_uri() + "?mode=ro"
        with closing(sqlite3.connect(path, uri=True, isolation_level=None, timeout=1)) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            try:
                value = {
                    "logical": db.execute("SELECT key,tail,accepted_attempt FROM logical_messages ORDER BY key").fetchall(),
                    "attempts": db.execute("SELECT logical_key,attempt_id,outcome,acceptance_id,result FROM attempts ORDER BY logical_key,attempt_id").fetchall(),
                    "events": db.execute("SELECT account,device,seq,event_id,content,acceptance_id FROM events ORDER BY account,device,seq").fetchall(),
                    "streams": db.execute("SELECT account,device,stream_id FROM devices ORDER BY account,device").fetchall(),
                }
                db.commit()
            except BaseException:
                db.rollback()
                raise
        encoded = json.dumps(value, sort_keys=True).encode()
        return {"sha256": hashlib.sha256(encoded).hexdigest(), "attempts": len(value["attempts"]),
                "accepted": sum(row[2] == "accepted" for row in value["attempts"]),
                "events": len(value["events"])}
