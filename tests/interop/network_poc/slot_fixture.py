"""M11 合成重复投递装置；真实 Rust 签名参数与设备恢复沿用 NetworkLab。"""

import json
import selectors
import subprocess
import sys
from urllib.parse import urlparse

from .fixture import NetworkLab, ROOT, check, identity


class SlotLab(NetworkLab):
    def __init__(self, binary, directory, permission_verifier=None, receipt_signer=None):
        super().__init__(binary, directory, permission_verifier, receipt_signer)
        self.case_evidence = {}

    def start(self):
        self.server_log = (self.directory / "relay.stderr.log").open("a")
        command = [sys.executable, "-B", str(ROOT / "tests/interop/network_poc/slot_relay.py"),
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
            check(bool(selector.select(timeout=15)), "M11 Relay 启动超时")
            line = self.process.stdout.readline()
        check(bool(line), "M11 Relay 启动失败，查看 stderr")
        ready = json.loads(line)
        check(ready["status"] == "ready", "M11 Relay 未就绪")
        self.url = urlparse(ready["url"])
        check(self.url.hostname == "127.0.0.1", "M11 只允许本机 loopback")

    def duplicate(self, device, event_id):
        return self.control("duplicate_message_slot", **identity(device), event_id=event_id)
