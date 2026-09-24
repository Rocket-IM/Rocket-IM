"""一致性检查点的真实 HTTP 回归；两个显式启用的用例调用真实 Rust 签名器。

其余用例复用合成签名替身。真实签名的端侧独立验签由 Rust/HTTP 联调覆盖；
这里核对真实签名器输出、固定公钥与 HTTP 声明字节，不另写密码验证实现。
"""

import copy
import json
import os
import subprocess
import unittest
from pathlib import Path

from contract import encode_json
from http_test_support import RelayHTTPFixture
from receipt_contract import validate_consistency_head
from receipt_signer import ReceiptSigner
from receipt_test_support import ReceiptHTTPFixture, receipt_fixture

REQUEST = {"service_id": "S1", "conversation_id": "G1", "challenge": "c" * 64}


class ConsistencyHTTPTests(ReceiptHTTPFixture):
    def test_request_shape_context_and_token_cannot_inject_identity_or_checkpoint(self):
        for change in ({"challenge": "A" * 64}, {"challenge": "1" * 63}, {"challenge": 1},
                       {"actor": {"account_id": "B", "device_id": "B1"}}, {"checkpoint": {}}):
            status, body = self.request("get_consistency_head", {**REQUEST, **change})
            self.assertEqual((status, body["error"]["code"]), (400, "invalid_envelope"))
        for name in ("service_id", "conversation_id"):
            status, body = self.request("get_consistency_head", {**REQUEST, name: "OTHER"})
            self.assertEqual((status, body["error"]["code"]), (403, "permission_denied"))
        status, body = self.request("get_consistency_head", REQUEST, "invalid")
        self.assertEqual((status, body["error"]["code"]), (401, "unauthenticated"))
        status, body = self.request("get_consistency_head", REQUEST, "synthetic-A2-token")
        self.assertEqual(status, 200, body)
        self.assertEqual(validate_consistency_head(body["result"]["head"])["actor"], {"account_id": "A", "device_id": "A2"})

    def test_committed_permission_and_restart_return_current_checkpoint_and_deny_removed(self):
        status, body = self.request("submit_permission_change", {"service_id": "S1", "conversation_id": "G1", "change": self.change})
        self.assertEqual(status, 200, body)
        status, body = self.request("get_consistency_head", REQUEST)
        self.assertEqual(status, 200, body)
        head = validate_consistency_head(body["result"]["head"])
        self.assertEqual(head["checkpoint"]["authorization_version"], "2")
        self.assertEqual([m["device_id"] for m in head["checkpoint"]["members"]], ["A1", "A2", "A3"])
        self.stop()
        self.start()
        self.assertEqual(self.request("get_consistency_head", REQUEST), (status, body))
        status, body = self.request("get_consistency_head", REQUEST, "synthetic-B1-token")
        self.assertEqual((status, body["error"]["code"]), (403, "permission_denied"))

    def test_runtime_signer_failure_is_typed_and_recoverable(self):
        self.key_path.unlink()
        status, body = self.request("get_consistency_head", REQUEST)
        self.assertEqual((status, body["error"]["code"]), (503, "receipt_signer_unavailable"))
        self.assertEqual(body["error"]["outcome"], "not_recorded")
        self.key_path.write_text(receipt_fixture()["relay_receipt_key"])
        self.assertEqual(self.request("get_consistency_head", REQUEST)[0], 200)


class UnsignedConsistencyHTTPTests(RelayHTTPFixture):
    def test_unsigned_instance_explicitly_refuses_head(self):
        status, body = self.request("get_consistency_head", REQUEST)
        self.assertEqual((status, body["error"]["code"]), (409, "receipt_not_enabled"))


class RealConsistencyHTTPTests(RelayHTTPFixture):
    @classmethod
    def setUpClass(cls):
        fixture = os.environ.get("RIM_HISTORY_TRANSFER_PUBLIC_FIXTURE")
        cls.signer_executable = os.environ.get("RIM_RECEIPT_SIGNER")
        cls.verifier_executable = os.environ.get("RIM_PERMISSION_VERIFIER")
        if not all((fixture, cls.signer_executable, cls.verifier_executable)):
            raise unittest.SkipTest("真实 HTTP 签名检查需要显式公开 fixture、Rust 验证器与签名器路径")
        public = json.loads(Path(fixture).read_text())
        if set(public) != {"checkpoint", "request", "package", "receipt"}:
            raise ValueError("真实 HTTP 装置只能读取合成公开历史证据")
        cls.checkpoint = public["checkpoint"]

    def fixture_value(self):
        value = receipt_fixture()
        value["permission_checkpoint"] = copy.deepcopy(self.checkpoint)
        value["service_id"] = self.checkpoint["service_id"]
        value["devices"] = [{**member, "token": f"synthetic-{member['device_id']}-token"} for member in self.checkpoint["members"]]
        value["conversation"] = {"conversation_id": self.checkpoint["conversation_id"],
                                 "authorization_version": self.checkpoint["authorization_version"],
                                 "crypto_state_ref": self.checkpoint["crypto_state_ref"],
                                 "members": [{name: m[name] for name in ("account_id", "device_id")} for m in self.checkpoint["members"]]}
        return value

    def initialize_key(self, path):
        result = subprocess.run([self.signer_executable], input=encode_json({"operation": "init", "key_path": str(path)}),
                                capture_output=True, timeout=5, check=True)
        value = json.loads(result.stdout)
        self.assertIs(value["ok"], True)
        return value["result"]["signature_key"]

    def prepare_runtime(self):
        self.key_path = self.path / "synthetic-service-seed"
        self.public_key = self.initialize_key(self.key_path)
        fixture = self.fixture_value()
        fixture["relay_receipt_key"] = self.public_key
        self.fixture_path.write_bytes(encode_json(fixture))
        member = self.checkpoint["members"][0]
        self.actor = {name: member[name] for name in ("account_id", "device_id")}
        self.token = f"synthetic-{member['device_id']}-token"
        self.head_request = {"service_id": self.checkpoint["service_id"], "conversation_id": self.checkpoint["conversation_id"],
                             "challenge": os.urandom(32).hex()}

    def start(self, controls=True, verifier=None):
        super().start(controls, self.verifier_executable, self.signer_executable, self.key_path)

    def test_real_signer_http_binds_challenge_full_checkpoint_actor_and_durable_key(self):
        status, body = self.request("get_consistency_head", self.head_request, self.token)
        self.assertEqual(status, 200, body)
        head = body["result"]["head"]
        statement = validate_consistency_head(head)
        self.assertEqual(statement["checkpoint"], self.checkpoint)
        self.assertEqual(statement["actor"], self.actor)
        self.assertEqual(statement["challenge"], self.head_request["challenge"])
        signer = ReceiptSigner(self.signer_executable, self.key_path)
        signer.signature_key = self.public_key
        self.assertEqual(signer.sign(statement), head)
        new_request = {**self.head_request, "challenge": os.urandom(32).hex()}
        status, changed = self.request("get_consistency_head", new_request, self.token)
        self.assertEqual(status, 200, changed)
        self.assertNotEqual(changed["result"]["head"]["signature_bytes"], head["signature_bytes"])
        self.stop()
        self.start()
        self.assertEqual(self.request("get_consistency_head", self.head_request, self.token), (200, body))

    def test_real_signer_replacement_key_cannot_sign_under_persisted_pin(self):
        replacement = self.path / "synthetic-other-seed"
        self.assertNotEqual(self.initialize_key(replacement), self.public_key)
        self.key_path.write_bytes(replacement.read_bytes())
        status, body = self.request("get_consistency_head", self.head_request, self.token)
        self.assertEqual((status, body["error"]["code"]), (503, "receipt_signer_unavailable"))
        self.assertEqual(body["error"]["outcome"], "not_recorded")


if __name__ == "__main__":
    unittest.main()
