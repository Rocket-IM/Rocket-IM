"""目标专属历史迁移的字段与域分离摘要；不处理明文或自研密码算法。"""

import hashlib

from contract import (decode_bytes, fields, invalid, parse_u64, validate_id,
                      validate_state_ref)
from receipt_contract import signed_statement

REQUEST_FIELDS = ("statement_bytes", "signature_bytes")
PACKAGE_FIELDS = (*REQUEST_FIELDS, "kem_output", "ciphertext")
MAX_CIPHERTEXT = 256 * 1024 + 16


def exact_bytes(value, name, size):
    if len(decode_bytes(value, name, size)) != size:
        invalid(f"{name} 必须为 {size} 字节")


def identity(value):
    fields(value, ("account_id", "device_id"))
    for name in ("account_id", "device_id"):
        validate_id(value[name], name)


def validate_history_request(value):
    statement = signed_statement(value)
    fields(statement, ("protocol_version", "transfer_id", "service_id", "conversation_id", "source", "target",
                       "authorization_version", "crypto_state_ref", "recipient_key", "selection", "nonce",
                       "issued_at_unix_secs", "expires_at_unix_secs"))
    if statement["protocol_version"] != "rim-history-request-1":
        invalid("不支持此历史迁移请求版本")
    for name in ("transfer_id", "service_id", "conversation_id"):
        validate_id(statement[name], name)
    for name in ("source", "target"):
        identity(statement[name])
    for name in ("authorization_version", "issued_at_unix_secs", "expires_at_unix_secs"):
        parse_u64(statement[name], name)
    for name in ("crypto_state_ref", "nonce"):
        validate_state_ref(statement[name])
    exact_bytes(statement["recipient_key"], "recipient_key", 32)
    selection = statement["selection"]
    if not isinstance(selection, list) or not 1 <= len(selection) <= 16:
        invalid("历史选择须包含 1—16 项")
    ids = []
    for item in selection:
        fields(item, ("acceptance_id", "envelope_sha256"))
        ids.append(validate_id(item["acceptance_id"], "acceptance_id"))
        validate_state_ref(item["envelope_sha256"])
    if ids != sorted(set(ids)):
        invalid("历史选择须按 acceptance_id 排序且唯一")
    if not 1 <= int(statement["expires_at_unix_secs"]) - int(statement["issued_at_unix_secs"]) <= 300:
        invalid("迁移请求有效期须为 1—300 秒")
    return statement


def validate_history_package(value):
    fields(value, PACKAGE_FIELDS)
    statement = signed_statement({name: value[name] for name in REQUEST_FIELDS})
    fields(statement, ("protocol_version", "transfer_id", "request_sha256", "ciphertext_sha256"))
    if statement["protocol_version"] != "rim-history-package-1":
        invalid("不支持此历史迁移包版本")
    validate_id(statement["transfer_id"], "transfer_id")
    for name in ("request_sha256", "ciphertext_sha256"):
        validate_state_ref(statement[name])
    exact_bytes(value["kem_output"], "kem_output", 32)
    if len(decode_bytes(value["ciphertext"], "ciphertext", MAX_CIPHERTEXT)) < 16:
        invalid("迁移密文缺少认证标签")
    return statement


def history_digest(purpose, value, names):
    digest = hashlib.sha256(f"Rockets-IM/POC/{purpose}/v1\0".encode())
    for name in names:
        raw = decode_bytes(value[name], name, MAX_CIPHERTEXT)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def request_digest(value):
    return history_digest("history-request-digest", value, REQUEST_FIELDS)


def package_digest(value):
    return history_digest("history-package-digest", value, PACKAGE_FIELDS)


def ciphertext_digest(value):
    return history_digest("history-ciphertext", value, ("kem_output", "ciphertext"))


def validate_history_receipt(value):
    statement = signed_statement(value)
    fields(statement, ("protocol_version", "service_id", "conversation_id", "transfer_id", "request_sha256",
                       "package_sha256", "authorization_version", "crypto_state_ref", "accepted_at_unix_ms",
                       "expires_at_unix_secs"))
    if statement["protocol_version"] != "rim-history-receipt-1":
        invalid("不支持此历史迁移回执版本")
    for name in ("service_id", "conversation_id", "transfer_id"):
        validate_id(statement[name], name)
    for name in ("request_sha256", "package_sha256", "crypto_state_ref"):
        validate_state_ref(statement[name])
    for name in ("authorization_version", "accepted_at_unix_ms", "expires_at_unix_secs"):
        parse_u64(statement[name], name)
    return statement


def validate_history_operation(operation, value):
    names = ("service_id", "conversation_id") + (("request", "package") if operation == "submit_history_transfer" else ("transfer_id",))
    fields(value, names)
    for name in ("service_id", "conversation_id"):
        validate_id(value[name], name)
    if operation == "submit_history_transfer":
        validate_history_request(value["request"])
        validate_history_package(value["package"])
    else:
        validate_id(value["transfer_id"], "transfer_id")
    return value
