"""真实Rust公共PoP验签回归；只消费公开proof，不加载客户端秘密。

RIM_REGISTRATION_PUBLIC_FIXTURE 为 {proof:SignedRecord}，RIM_PERMISSION_VERIFIER
为本轮构建的公共验证器；未提供时整类跳过，不能算运行通过。
"""

import base64
import copy
import json
import os
import unittest
from pathlib import Path

from contract import ProtocolError, encode_json
from permission_verifier import PermissionVerifier
from registration_contract import proof as validate_proof


class RealRegistrationVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = os.environ.get("RIM_REGISTRATION_PUBLIC_FIXTURE")
        executable = os.environ.get("RIM_PERMISSION_VERIFIER")
        if not path or not executable:
            raise unittest.SkipTest("真实注册验签需要显式公开proof和已构建Rust验证器")
        value = json.loads(Path(path).read_text())
        if set(value) != {"proof"}:
            raise ValueError("注册验签装置只能包含公开proof")
        cls.proof = value["proof"]
        cls.statement = validate_proof(cls.proof)
        cls.verifier = PermissionVerifier(executable)

    def rejected(self, code, value):
        with self.assertRaises(ProtocolError) as caught:
            self.verifier.verify_device_registration(value)
        self.assertEqual(caught.exception.code, code)

    def test_real_registration_signature_verifies_exact_statement(self):
        self.assertEqual(self.verifier.verify_device_registration(self.proof), {"statement": self.statement})

    def test_real_verifier_rejects_copied_public_key_without_signature(self):
        changed = {**self.proof, "signature_bytes": base64.b64encode(bytes(64)).decode()}
        self.rejected("registration_signature", changed)

    def test_real_verifier_rejects_modified_original_even_when_json_semantics_match(self):
        raw = base64.b64decode(self.proof["statement_bytes"])
        changed = {**self.proof, "statement_bytes": base64.b64encode(raw + b" ").decode()}
        self.rejected("registration_signature", changed)

    def test_real_verifier_rejects_another_context_key_or_nonce_under_original_signature(self):
        for field, value in (("account_id", "different_account"), ("registration_id", "another_registration"),
                             ("challenge_nonce", base64.b64encode(bytes([99]) * 32).decode())):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.statement)
                changed[field] = value
                self.rejected("registration_signature", {**self.proof,
                    "statement_bytes": base64.b64encode(encode_json(changed)).decode()})

    def test_real_verifier_rejects_weak_identity_key_and_cross_purpose(self):
        for field, value in (("signature_key", base64.b64encode(bytes(32)).decode()), ("purpose", "another_purpose")):
            with self.subTest(field=field):
                changed = {**self.statement, field: value}
                self.rejected("registration_invalid", {**self.proof,
                    "statement_bytes": base64.b64encode(encode_json(changed)).decode()})
