"""HTTP 模块测试共同使用的临时进程装置，不包含验收场景。"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from contract import encode_json
from test_support import fixture


class RelayHTTPFixture(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name)
        self.fixture_path = self.path / "fixture.json"
        self.fixture_path.write_bytes(encode_json(self.fixture_value()))
        self.fixture_path.chmod(0o600)
        self.process = None
        self.prepare_runtime()
        self.start()

    def fixture_value(self):
        return fixture()

    def prepare_runtime(self):
        pass

    def tearDown(self):
        self.stop()
        self.directory.cleanup()

    def start(self, controls=True, verifier=None, receipt_signer=None, receipt_key=None):
        command = [sys.executable, "-B", str(Path(__file__).with_name("server.py")), "--database", str(self.path / "relay.sqlite3"),
                   "--fixture", str(self.fixture_path), "--port", "0"]
        if controls:
            command.append("--enable-test-controls")
        if verifier is not None:
            command.extend(["--permission-verifier", str(verifier)])
        if receipt_signer is not None:
            command.extend(["--receipt-signer", str(receipt_signer), "--receipt-key", str(receipt_key)])
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        line = self.process.stdout.readline()
        self.assertTrue(line, self.process.stderr.read() if self.process.poll() is not None else "missing ready")
        ready = json.loads(line)
        self.assertEqual(ready["status"], "ready")
        self.url = ready["url"]

    def stop(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
            self.process.communicate(timeout=5)
            self.process = None

    def request(self, operation, value, token="synthetic-A1-token", control=False):
        route = "/_test/control" if control else f"/v1/{operation}"
        request = Request(self.url + route, data=encode_json(value), headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
        try:
            with urlopen(request, timeout=8) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            with error:
                return error.code, json.load(error)

    def control(self, value):
        status, body = self.request("", value, "synthetic-controller-token", True)
        self.assertEqual(status, 200, body)
        return body["result"]

