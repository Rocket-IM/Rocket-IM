"""Relay 模块测试用合成数据；字节载荷不代表有效 MLS 密文。"""

import base64

from contract import encode_json


def fixture():
    return {"service_id": "S1", "controller_token": "synthetic-controller-token",
            "devices": [{"account_id": "A", "device_id": "A1", "token": "synthetic-A1-token"},
                        {"account_id": "A", "device_id": "A2", "token": "synthetic-A2-token"},
                        {"account_id": "B", "device_id": "B1", "token": "synthetic-B1-token"},
                        {"account_id": "B", "device_id": "B2", "token": "synthetic-B2-token"}],
            "conversation": {"conversation_id": "G1", "authorization_version": "1", "crypto_state_ref": "a" * 64,
                             "members": [{"account_id": "A", "device_id": "A1"}, {"account_id": "A", "device_id": "A2"},
                                         {"account_id": "B", "device_id": "B1"}]}}


def envelope(logical_id="M1", attempt_id="P1", payload=b"opaque-fixture", **changes):
    header = {"protocol_version": "rim-poc-1", "service_id": "S1", "conversation_id": "G1",
              "sender": {"account_id": "A", "device_id": "A1"}, "logical_message_id": logical_id,
              "attempt_id": attempt_id, "security_mode": "e2ee", "crypto_profile": "mls-poc",
              "authorization_version": "1", "crypto_state_ref": "a" * 64,
              "recipients": [{"account_id": "A", "device_id": "A2"}, {"account_id": "B", "device_id": "B1"}]}
    header.update(changes)
    return {"header_bytes": base64.b64encode(encode_json(header)).decode(), "payload_bytes": base64.b64encode(payload).decode()}


def key(logical_id="M1", attempt_id="P1"):
    return {"service_id": "S1", "conversation_id": "G1", "logical_message_id": logical_id, "attempt_id": attempt_id}
