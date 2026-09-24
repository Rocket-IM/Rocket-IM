"""首次入群事务的合成装置；不实现或替代 KeyPackage/Welcome 密码验证。"""

import base64
import hashlib
import json
import time

from contract import encode_json
from permission_tests import proof
from receipt_test_support import ReceiptHTTPFixture, VerifiedCloseFixture, receipt_fixture


def join_fixture():
    fixture = receipt_fixture()
    fixture["devices"] = [d for d in fixture["devices"] if d["device_id"] != "A3"]
    for name in ("conversation", "permission_checkpoint"):
        fixture[name]["members"] = [m for m in fixture[name]["members"] if m["device_id"] != "A3"]
    for index, account in enumerate(("D", "E")):
        fixture["devices"].append({"account_id": account, "device_id": account + "1", "token": f"synthetic-{account}1-token",
                                   "signature_key": base64.b64encode(bytes([17 + index]) * 32).decode()})
    return fixture


def join_request(change_id="J1", version="1", account="D", key_package=None, welcome=b"fixture-welcome", commit=b"fixture-add-commit", nonce="c" * 64, current_time=False):
    device = next(d for d in join_fixture()["devices"] if d["account_id"] == account)
    member = {key: device[key] for key in ("account_id", "device_id", "signature_key")}
    key_package = key_package or f"fixture-key-package-{account}".encode()
    action = {"kind": "add_member", "member": member, "history_policy": "from_join",
              "key_package_sha256": hashlib.sha256(key_package).hexdigest(), "welcome_sha256": hashlib.sha256(welcome).hexdigest()}
    change = proof(change_id, version, nonce, action, commit)
    if current_time:
        statement = json.loads(base64.b64decode(change["statement_bytes"]))
        statement.update(issued_at_unix_secs=str(int(time.time())), expires_at_unix_secs=str(int(time.time()) + 300))
        change["statement_bytes"] = base64.b64encode(encode_json(statement)).decode()
    return {"service_id": "S1", "conversation_id": "G1", "change": change,
            "join": {"key_package": base64.b64encode(key_package).decode(), "welcome": base64.b64encode(welcome).decode()}}


def change_action(request, **updates):
    statement = json.loads(base64.b64decode(request["change"]["statement_bytes"]))
    statement["action"].update(updates)
    request["change"]["statement_bytes"] = base64.b64encode(encode_json(statement)).decode()


class VerifiedJoinFixture(VerifiedCloseFixture):
    def __init__(self):
        self.joins = []

    def verify(self, checkpoint, change, statement, join=None):
        if statement["action"]["kind"] not in {"add_member", "add_device"}:
            return super().verify(checkpoint, change, statement)
        assert join is not None, "Service首次Add必须把真实材料传给公共验证器"
        self.joins.append(join)
        members = sorted([*checkpoint["members"], statement["action"]["member"]], key=lambda m: (m["account_id"], m["device_id"]))
        return {"statement": statement, "checkpoint": {**checkpoint, "members": members,
                "authorization_version": statement["authorization_version"], "crypto_state_ref": statement["to_state_ref"]}}


class JoinHTTPFixture(ReceiptHTTPFixture):
    def fixture_value(self):
        return join_fixture()

    def submit_join(self, request=None):
        return self.request("submit_permission_change", request or join_request(current_time=True))

    def material(self, change_id="J1", token="synthetic-D1-token"):
        return self.request("get_join_material", {"service_id": "S1", "conversation_id": "G1", "change_id": change_id}, token)
