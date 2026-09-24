"""可选真实 Rust 公共验证器回归；只读取合成公开请求和密文，不访问端侧秘密。"""

import base64
import copy
import json
import os
import unittest
from pathlib import Path

from contract import ProtocolError
from history_contract import package_digest, request_digest, validate_history_receipt
from permission_verifier import PermissionVerifier


class RealHistoryTransferVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path, executable = os.environ.get("RIM_HISTORY_TRANSFER_PUBLIC_FIXTURE"), os.environ.get("RIM_PERMISSION_VERIFIER")
        if not path or not executable:
            raise unittest.SkipTest("真实历史迁移验证需要显式公开fixture及已构建验证器路径")
        cls.value = json.loads(Path(path).read_text())
        if set(cls.value) != {"checkpoint", "request", "package", "receipt"}:
            raise ValueError("历史验收装置只能包含公开checkpoint/request/package/receipt")
        cls.verifier = PermissionVerifier(executable)

    def verify(self, value):
        return self.verifier.verify_history_transfer(value["checkpoint"], value["request"], value["package"])

    def assert_code(self, code, value):
        with self.assertRaises(ProtocolError) as error:
            self.verify(value)
        self.assertEqual(error.exception.code, code)

    def test_real_target_source_signatures_and_digests_match_service_receipt(self):
        verified = self.verify(self.value)
        receipt = validate_history_receipt(self.value["receipt"])
        self.assertEqual(verified["request_sha256"], request_digest(self.value["request"]))
        self.assertEqual(verified["package_sha256"], package_digest(self.value["package"]))
        self.assertEqual(receipt["request_sha256"], verified["request_sha256"])
        self.assertEqual(receipt["package_sha256"], verified["package_sha256"])

    def test_real_helper_rejects_changed_target_signature(self):
        value = copy.deepcopy(self.value)
        raw = bytearray(base64.b64decode(value["request"]["signature_bytes"])); raw[0] ^= 1
        value["request"]["signature_bytes"] = base64.b64encode(raw).decode()
        self.assert_code("history_signature", value)

    def test_real_helper_rejects_changed_source_signature(self):
        value = copy.deepcopy(self.value)
        raw = bytearray(base64.b64decode(value["package"]["signature_bytes"])); raw[0] ^= 1
        value["package"]["signature_bytes"] = base64.b64encode(raw).decode()
        self.assert_code("history_signature", value)

    def test_real_helper_rejects_replaced_ciphertext(self):
        value = copy.deepcopy(self.value)
        raw = bytearray(base64.b64decode(value["package"]["ciphertext"])); raw[-1] ^= 1
        value["package"]["ciphertext"] = base64.b64encode(raw).decode()
        self.assert_code("history_context", value)


if __name__ == "__main__":
    unittest.main()
