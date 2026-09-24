"""同账号新设备的合成业务装置；密码学证据由独立 Rust helper 验证。"""

import base64
import json

from contract import encode_json
from join_test_support import JoinHTTPFixture, join_fixture, join_request


def device_join_fixture():
    value = join_fixture()
    for device in value["devices"]:
        if device["account_id"] in {"D", "E"}:
            account = "B" if device["account_id"] == "D" else "A"
            device.update(account_id=account, device_id=account + "3", token=f"synthetic-{account}3-token")
    return value


def edit_statement(request, **updates):
    statement = json.loads(base64.b64decode(request["change"]["statement_bytes"]))
    statement.update(updates)
    request["change"]["statement_bytes"] = base64.b64encode(encode_json(statement)).decode()


def device_join_request(change_id="D1", version="1", account="B", actor=None, **kwargs):
    request = join_request(change_id, version, **kwargs)
    member = next(d for d in device_join_fixture()["devices"] if d["device_id"] == account + "3")
    statement = json.loads(base64.b64decode(request["change"]["statement_bytes"]))
    statement["action"].update(kind="add_device", member={k: member[k] for k in ("account_id", "device_id", "signature_key")})
    edit_statement(request, action=statement["action"], actor=actor or {"account_id": account, "device_id": account + "1"})
    return request


class DeviceJoinHTTPFixture(JoinHTTPFixture):
    def fixture_value(self):
        return device_join_fixture()

    def submit_device(self, request=None, token="synthetic-B1-token"):
        return self.request("submit_permission_change", request or device_join_request(current_time=True), token)

    def device_material(self, change_id="D1", token="synthetic-B3-token"):
        return self.material(change_id, token)
