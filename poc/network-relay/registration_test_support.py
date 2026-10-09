"""注册模块测试装置；替身仅核对约定标记，不提供密码学验签证据。"""

import base64
import json

from contract import ProtocolError
from quota_test_support import QuotaFixture
from registration_contract import proof as validate_proof

SYNTHETIC_SIGNATURE = base64.b64encode(bytes([7]) * 64).decode()


def encoded(raw):
    return base64.b64encode(raw).decode()


def request(registration_id="R1", key_byte=11):
    return {"service_id": "S1", "registration_id": registration_id,
            "signature_key": encoded(bytes([key_byte]) * 32)}


def proof(challenge):
    return {"statement_bytes": challenge["challenge_bytes"], "signature_bytes": SYNTHETIC_SIGNATURE}


class TransactionVerifier:
    """只隔离密码调用以验证原Store/DISPATCH事务；禁止作为真实PoP通过证据。"""

    def __init__(self):
        self.calls = 0

    def verify_device_registration(self, value):
        self.calls += 1
        statement = validate_proof(value)
        if value["signature_bytes"] != SYNTHETIC_SIGNATURE:
            raise ProtocolError("registration_signature", "测试替身拒绝签名标记", status=403)
        return {"statement": statement}


class RegistrationFixture(QuotaFixture):
    def setUp(self):
        super().setUp()
        self.verifier = TransactionVerifier()
        self.store.permission_verifier = self.verifier

    def begin(self, value=None, token="synthetic-A1-token"):
        return self.call("begin_device_registration", value or request(), token)

    def complete(self, challenge, token="synthetic-A1-token"):
        return self.call("complete_device_registration", {"service_id": "S1", "proof": proof(challenge)}, token)

    def reject(self, code, operation, value, token="synthetic-A1-token"):
        before = self.snapshot()
        with self.assertRaises(ProtocolError) as caught:
            self.call(operation, value, token)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(self.snapshot(), before)

    @staticmethod
    def statement(value):
        return json.loads(base64.b64decode(value["challenge_bytes"]))
