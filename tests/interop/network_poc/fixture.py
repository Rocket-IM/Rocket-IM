"""阶段 0 独立 Rust 设备与本机 HTTP Relay 装置；凭证、公钥均为合成材料。"""

import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import selectors
import subprocess
import sys
import time
from urllib.parse import urlparse

from .stream_fixture import StreamPage, sign_test_page


ROOT = Path(__file__).resolve().parents[3]
ACCOUNTS = {"a1": "alice", "a2": "alice", "b1": "bob", "c1": "charlie"}
JOIN_CANDIDATES = {"d1": "david"}
DEVICE_CANDIDATES = {"b2": "bob", "a3": "alice"}
SERVICE = "synthetic-network"
CONVERSATION = "G1"


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def identity(device):
    return {"account_id": (ACCOUNTS | JOIN_CANDIDATES | DEVICE_CANDIDATES)[device], "device_id": device}


class NetworkLab:
    def __init__(self, binary, directory, permission_verifier=None, receipt_signer=None, *,
                 service=SERVICE, relay_entrypoint=None, relay_args=()):
        self.binary, self.directory = Path(binary), Path(directory)
        self.service = service
        self.relay_entrypoint = Path(relay_entrypoint) if relay_entrypoint is not None else ROOT / "poc/network-relay/server.py"
        self.relay_args = tuple(relay_args)
        self.directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.process = None
        self.process_count = self.http_count = 0
        self.tokens = {d: secrets.token_urlsafe(32) for d in ACCOUNTS}
        self.controller_token = secrets.token_urlsafe(32)
        self.public = {}
        self.streams = {}
        self.server_log = None
        self.permission_verifier = permission_verifier
        self.receipt_signer = receipt_signer
        self.receipt_key = self.directory / "relay-receipt.key"

    def relay_key(self, operation, **fields):
        result = subprocess.run([str(self.receipt_signer)], input=json.dumps(
            {"operation": operation, "key_path": str(self.receipt_key), **fields}),
            text=True, capture_output=True, timeout=10)
        self.process_count += 1
        check(result.returncode == 0, f"Service 回执工具 {operation} 失败: {result.stdout[:200]}")
        reply = json.loads(result.stdout)
        check(reply["ok"], "Service 回执工具没有完成请求")
        return reply["result"]

    def rust(self, device, operation, *, expected_exit=0, **fields):
        data = {"directory": str(self.directory / device), "service": self.service,
                "account": identity(device)["account_id"], "device": device,
                "operation": operation, **fields}
        result = subprocess.run([str(self.binary)], input=json.dumps(data), text=True,
                                capture_output=True, timeout=30)
        self.process_count += 1
        check(result.returncode == expected_exit,
              f"Rust {operation}: exit {result.returncode}, expected {expected_exit}; {result.stdout[:300]}")
        if expected_exit in (83, 84, 85):
            check(not result.stdout.strip(), "提交前退出不应输出成功")
            return None
        reply = json.loads(result.stdout)
        check(reply["ok"] == (expected_exit == 0), "Rust 响应状态与退出码不符")
        return reply["result"] if reply["ok"] else reply["error"]

    def authorize_fixture_peer(self, signer, target):
        """两个预置信任的合成设备建立各自检查点；不是生产新设备引导流程。"""
        now = int(time.time())
        request = {"service": self.service, "account": ACCOUNTS[signer], "signer_device": signer,
                   "new_device": target,
                   "new_signature_key": list(base64.b64decode(self.public[target]["signature_key"])),
                   "key_package_sha256": list(hashlib.sha256(base64.b64decode(
                       self.public[target]["key_package"])).digest()),
                   "expected_roster_version": 0, "nonce": list(os.urandom(32)),
                   "issued_at_unix_secs": now, "expires_at_unix_secs": now + 120}
        authorization = self.rust(signer, "sign_authorization", request=request)["authorization"]
        self.rust(signer, "authorize", authorization=authorization,
                  key_package=self.public[target]["key_package"], now_unix_secs=now)

    def initialize(self, pending_limit=1000, *, permissions=False, owner_account_id="alice",
                   join_candidate=False, device_candidates=False):
        for device in ACCOUNTS:
            self.public[device] = self.rust(device, "init")
        self.authorize_fixture_peer("a1", "a2")
        self.authorize_fixture_peer("a2", "a1")
        peers = [{"account": ACCOUNTS[d], "device": d,
                  "signature_key": self.public[d]["signature_key"],
                  "key_package": self.public[d]["key_package"]} for d in ("a2", "b1", "c1")]
        created = self.rust("a1", "create", peers=peers)
        pins = [{"account": ACCOUNTS[d], "device": d,
                 "signature_key": self.public[d]["signature_key"]} for d in ACCOUNTS]
        for device in ("a2", "b1", "c1"):
            self.rust(device, "join", welcome=created["welcome"], pins=pins)
        checkpoints = []
        for device in ACCOUNTS:
            self.rust(device, "wire_configure", conversation_id=CONVERSATION,
                      authorization_version="1", pending_limit=pending_limit)
            checkpoints.append(self.rust(device, "wire_inspect")["crypto_state_ref"])
        check(len(set(checkpoints)) == 1, "独立设备公共状态引用必须一致")
        self.state_ref = checkpoints[0]
        self.fixture = {"service_id": self.service, "controller_token": self.controller_token,
                        "devices": [{**identity(d), "token": self.tokens[d]} for d in ACCOUNTS],
                        "conversation": {"conversation_id": CONVERSATION,
                                         "members": [identity(d) for d in ACCOUNTS],
                                         "authorization_version": "1",
                                         "crypto_state_ref": self.state_ref}}
        if permissions:
            recovery_pin = {}
            if self.receipt_signer:
                self.relay_receipt_key = self.relay_key("init")["signature_key"]
                self.fixture["relay_receipt_key"] = self.relay_receipt_key
                recovery_pin["relay_receipt_key"] = self.relay_receipt_key
            self.checkpoint = {"service_id": self.service, "conversation_id": CONVERSATION,
                               "authorization_version": "1", "crypto_state_ref": self.state_ref,
                               "owner_account_id": owner_account_id,
                               "members": [{**identity(d), "signature_key": self.public[d]["signature_key"]}
                                           for d in sorted(ACCOUNTS, key=lambda d: (ACCOUNTS[d], d))]}
            for device in ACCOUNTS:
                self.rust(device, "permission_bootstrap", checkpoint=self.checkpoint, **recovery_pin)
            for device in self.fixture["devices"]:
                device["signature_key"] = self.public[device["device_id"]]["signature_key"]
            self.fixture["permission_checkpoint"] = self.checkpoint
            check(self.permission_verifier and Path(self.permission_verifier).is_file(),
                  "签名权限场景缺少明确的公开验证程序")
        candidates = (JOIN_CANDIDATES if join_candidate else {}) | (DEVICE_CANDIDATES if device_candidates else {})
        if candidates:
            check(permissions and self.receipt_signer, "新增成员场景需要签名权限及固定回执钥")
            for device in candidates:
                self.tokens[device] = secrets.token_urlsafe(32)
                self.public[device] = self.rust(device, "init")
                self.fixture["devices"].append({**identity(device), "token": self.tokens[device],
                                                "signature_key": self.public[device]["signature_key"]})
        self.fixture_path = self.directory / "fixture.json"
        self.fixture_path.write_text(json.dumps(self.fixture))
        self.fixture_path.chmod(0o600)
        self.start()

    def start(self):
        self.server_log = (self.directory / "relay.stderr.log").open("a")
        command = [sys.executable, "-B", str(self.relay_entrypoint),
                   "--database", str(self.directory / "relay.sqlite"),
                   "--fixture", str(self.fixture_path), "--port", "0", "--enable-test-controls"]
        if self.permission_verifier:
            command.extend(["--permission-verifier", str(self.permission_verifier)])
        if self.receipt_signer:
            command.extend(["--receipt-signer", str(self.receipt_signer), "--receipt-key", str(self.receipt_key)])
        command.extend(self.relay_args)
        self.process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE, stderr=self.server_log, text=True)
        self.process_count += 1
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            check(bool(selector.select(timeout=15)), "Relay 启动超时")
            line = self.process.stdout.readline()
        check(bool(line), "Relay 启动失败，检查装置 stderr")
        ready = json.loads(line)
        check(ready["status"] == "ready", "Relay 未就绪")
        self.url = urlparse(ready["url"])
        check(self.url.hostname == "127.0.0.1", "实验必须仅监听本机")

    def stop(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
            self.process.stdout.close()
            self.process = None
        if self.server_log:
            self.server_log.close()
            self.server_log = None

    def restart(self):
        self.stop()
        self.start()

    def http(self, device, operation, fields, *, expected=200, raw=None, token=None):
        connection = http.client.HTTPConnection(self.url.hostname, self.url.port, timeout=10)
        body = json.dumps(fields).encode() if raw is None else raw
        auth = self.tokens[device] if token is None else token
        try:
            self.http_count += 1
            connection.request("POST", "/v1/" + operation, body=body,
                               headers={"Authorization": "Bearer " + auth,
                                        "Content-Type": "application/json"})
            response = connection.getresponse()
            payload = response.read(2 * 1024 * 1024)
            reply = json.loads(payload)
            check(response.status in (expected if isinstance(expected, tuple) else (expected,)),
                  f"HTTP {operation}: {response.status}, expected {expected}; {reply}")
            return reply["result"] if reply["ok"] else reply["error"]
        finally:
            connection.close()

    def control(self, action, *, expected=200, **fields):
        connection = http.client.HTTPConnection(self.url.hostname, self.url.port, timeout=10)
        try:
            self.http_count += 1
            connection.request("POST", "/_test/control", json.dumps({"action": action, **fields}),
                               headers={"Authorization": "Bearer " + self.controller_token,
                                        "Content-Type": "application/json"})
            response = connection.getresponse()
            reply = json.loads(response.read())
            check(response.status == expected, f"测试控制 {action} 状态 {response.status}: {reply}")
            return reply["result"] if reply["ok"] else reply["error"]
        finally:
            connection.close()

    def prepare(self, logical, attempt="P1", payload=None, **fields):
        return self.rust("a1", "wire_send", logical_message_id=logical, attempt_id=attempt,
                         payload=payload or "synthetic-network-" + logical, **fields)

    def submit(self, packet, *, device="a1", expected=200, **fields):
        return self.http(device, "submit_message", {"envelope": packet["envelope"], **fields},
                         expected=expected)

    def attempt(self, logical, attempt="P1", operation="get_attempt", **options):
        return self.http("a1", operation, {"service_id": self.service,
                         "conversation_id": CONVERSATION, "logical_message_id": logical,
                         "attempt_id": attempt}, **options)

    def pull(self, device, after="0", limit="100", **options):
        data = {"service_id": self.service, "after_seq": after, "limit": limit}
        if device in self.streams:
            data["stream_id"] = self.streams[device]
        signed = hasattr(self, "relay_receipt_key")
        result = self.http(device, "pull_events_signed" if signed else "pull_events", data, **options)
        if signed and "page_bytes" in result:
            result = StreamPage(result)
        if "stream_id" in result:
            self.streams[device] = result["stream_id"]
        return result

    def download(self, device, page, **options):
        if isinstance(page, StreamPage):
            return self.rust(device, "wire_download_signed", **page.signed_input(), **options)
        return self.rust(device, "wire_download", **page, **options)

    def sign_test_page(self, page, **options):
        return sign_test_page(self, page, **options)

    def receive(self, device, packet, **options):
        return self.rust(device, "wire_receive", **packet["envelope"], **options)

    def close(self):
        self.stop()
