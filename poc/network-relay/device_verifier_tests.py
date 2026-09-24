"""可选择运行的真实 Rust 公共验证器用例；输入只有合成公开证据，无客户端秘密。

RIM_DEVICE_JOIN_PUBLIC_FIXTURE 指向联调产出的 {checkpoint,change,join}；
RIM_PERMISSION_VERIFIER 指向已构建的公开验证器。最终验收日志必须实际运行。
"""

import base64
import copy
import json
import os
import unittest
from pathlib import Path

from contract import ProtocolError
from permission_contract import validate_proof
from permission_verifier import PermissionVerifier


class RealDeviceVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = os.environ.get("RIM_DEVICE_JOIN_PUBLIC_FIXTURE")
        executable = os.environ.get("RIM_PERMISSION_VERIFIER")
        if not fixture or not executable:
            raise unittest.SkipTest("真实 public helper 验收需要显式公开 fixture 和已构建验证器路径")
        cls.value = json.loads(Path(fixture).read_text())
        if set(cls.value) != {"checkpoint", "change", "join"}:
            raise ValueError("真实验证装置只能包含公开 checkpoint/change/join")
        cls.verifier = PermissionVerifier(executable)
        if validate_proof(cls.value["change"])["action"]["kind"] != "add_device":
            raise ValueError("真实装置必须是 AddDevice")

    def verify(self, value):
        return self.verifier.verify(value["checkpoint"], value["change"], validate_proof(value["change"]), value["join"])

    def assert_code(self, code, value):
        with self.assertRaises(ProtocolError) as error:
            self.verify(value)
        self.assertEqual(error.exception.code, code)

    def test_real_device_signature_key_package_and_checkpoint_derivation(self):
        result = self.verify(self.value)
        statement = validate_proof(self.value["change"])
        self.assertEqual(result["checkpoint"]["authorization_version"], statement["authorization_version"])
        self.assertIn(statement["action"]["member"], result["checkpoint"]["members"])
        self.assertEqual(statement["actor"]["account_id"], statement["action"]["member"]["account_id"])

    def test_real_verifier_rejects_changed_device_signature(self):
        value = copy.deepcopy(self.value)
        signature = bytearray(base64.b64decode(value["change"]["signature_bytes"]))
        signature[0] ^= 1
        value["change"]["signature_bytes"] = base64.b64encode(signature).decode()
        self.assert_code("permission_signature", value)

    def test_real_verifier_rejects_changed_join_key_package(self):
        value = copy.deepcopy(self.value)
        raw = bytearray(base64.b64decode(value["join"]["key_package"]))
        raw[-1] ^= 1
        value["join"]["key_package"] = base64.b64encode(raw).decode()
        self.assert_code("join_material_mismatch", value)

    def test_real_verifier_rejects_untrusted_actor_key(self):
        value = copy.deepcopy(self.value)
        actor = validate_proof(value["change"])["actor"]
        member = next(m for m in value["checkpoint"]["members"] if (m["account_id"], m["device_id"]) == (actor["account_id"], actor["device_id"]))
        other = next(m for m in value["checkpoint"]["members"] if m is not member)
        member["signature_key"], other["signature_key"] = other["signature_key"], member["signature_key"]
        self.assert_code("permission_signature", value)


if __name__ == "__main__":
    unittest.main()
