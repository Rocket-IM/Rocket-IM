"""权限终态与消息接受凭证；摘要按独立域绑定原始字节。"""

import hashlib

from contract import (MAX_HEADER_BYTES, MAX_PAYLOAD_BYTES, decode_bytes, fields,
                      invalid, parse_json, parse_u64, validate_id, validate_state_ref)
from permission_contract import PROOF_FIELDS, validate_checkpoint

PROOF_DOMAIN = b"Rockets-IM/POC/permission-proof/v1\0"
MESSAGE_ENVELOPE_DOMAIN = b"Rockets-IM/POC/message-envelope/v1\0"


def proof_digest(change):
    digest = hashlib.sha256(PROOF_DOMAIN)
    for name, limit in zip(PROOF_FIELDS, (MAX_HEADER_BYTES, 64, MAX_PAYLOAD_BYTES)):
        raw = decode_bytes(change[name], name, limit)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def signed_statement(value):
    fields(value, ("statement_bytes", "signature_bytes"))
    raw = decode_bytes(value["statement_bytes"], "statement_bytes", MAX_HEADER_BYTES)
    if len(decode_bytes(value["signature_bytes"], "signature_bytes", 64)) != 64:
        invalid("签名必须为 64 字节")
    return parse_json(raw)


def validate_terminal_statement(statement, receipt=False):
    names = ("protocol_version", "service_id", "conversation_id", "actor", "change_id", "proof_sha256")
    fields(statement, names + (("outcome", "authorization_version", "crypto_state_ref") if receipt else ()))
    expected_version = "rim-permission-receipt-1" if receipt else "rim-permission-close-1"
    if statement["protocol_version"] != expected_version:
        invalid("不支持此权限终态凭证版本")
    for name in ("service_id", "conversation_id", "change_id"):
        validate_id(statement[name], name)
    fields(statement["actor"], ("account_id", "device_id"))
    for name in ("account_id", "device_id"):
        validate_id(statement["actor"][name], name)
    validate_state_ref(statement["proof_sha256"])
    if receipt:
        if statement["outcome"] not in ("accepted", "closed"):
            invalid("权限凭证只能表示 accepted 或 closed")
        parse_u64(statement["authorization_version"], "authorization_version")
        validate_state_ref(statement["crypto_state_ref"])
    return statement


def validate_close(value):
    return validate_terminal_statement(signed_statement(value))


def validate_receipt(value):
    return validate_terminal_statement(signed_statement(value), receipt=True)


def terminal_statement(statement, change, checkpoint, outcome):
    return {"protocol_version": "rim-permission-receipt-1", "service_id": statement["service_id"],
            "conversation_id": statement["conversation_id"], "actor": statement["actor"], "change_id": statement["change_id"],
            "proof_sha256": proof_digest(change), "outcome": outcome,
            "authorization_version": checkpoint["authorization_version"], "crypto_state_ref": checkpoint["crypto_state_ref"]}


def message_envelope_digest(header_raw, payload_raw):
    digest = hashlib.sha256(MESSAGE_ENVELOPE_DOMAIN)
    for raw in (header_raw, payload_raw):
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def validate_message_acceptance_statement(statement):
    fields(statement, ("protocol_version", "service_id", "conversation_id", "acceptance_id",
                       "envelope_sha256", "authorization_version", "crypto_state_ref"))
    if statement["protocol_version"] != "rim-message-acceptance-1":
        invalid("不支持此消息接受凭证版本")
    for name in ("service_id", "conversation_id", "acceptance_id"):
        validate_id(statement[name], name)
    for name in ("envelope_sha256", "crypto_state_ref"):
        validate_state_ref(statement[name])
    parse_u64(statement["authorization_version"], "authorization_version")
    return statement


def validate_message_acceptance(value):
    return validate_message_acceptance_statement(signed_statement(value))


def message_acceptance_statement(header, header_raw, payload_raw, acceptance_id):
    return {"protocol_version": "rim-message-acceptance-1", "service_id": header["service_id"],
            "conversation_id": header["conversation_id"], "acceptance_id": acceptance_id,
            "envelope_sha256": message_envelope_digest(header_raw, payload_raw),
            "authorization_version": header["authorization_version"], "crypto_state_ref": header["crypto_state_ref"]}


def message_closure_statement(req, sender, closure_id):
    """NULL 封口仅绑定鉴权发送者提供的摘要；不声称核对未收到的密文。"""
    return {"protocol_version": "rim-message-closure-1", "service_id": req["service_id"],
            "conversation_id": req["conversation_id"], "sender": sender,
            "logical_message_id": req["logical_message_id"], "attempt_id": req["attempt_id"],
            "envelope_sha256": req["envelope_sha256"], "replaces_attempt_id": req.get("replaces_attempt_id"),
            "predecessor_closure_id": req.get("closure_id"), "closure_id": closure_id,
            "outcome": "cancelled_before_accept"}


def validate_message_terminal(statement, version, outcome, extra=()):
    fields(statement, ("protocol_version", "service_id", "conversation_id", "sender", "logical_message_id",
                       "attempt_id", "envelope_sha256", "replaces_attempt_id", "predecessor_closure_id",
                       "closure_id", "outcome") + extra)
    if statement["protocol_version"] != version or statement["outcome"] != outcome:
        invalid("不支持此消息终态凭证版本或结果")
    for name in ("service_id", "conversation_id", "logical_message_id", "attempt_id", "closure_id"):
        validate_id(statement[name], name)
    fields(statement["sender"], ("account_id", "device_id"))
    for name in ("account_id", "device_id"):
        validate_id(statement["sender"][name], name)
    validate_state_ref(statement["envelope_sha256"])
    if (statement["replaces_attempt_id"] is None) != (statement["predecessor_closure_id"] is None):
        invalid("封口前驱须同时为 null 或有效标识")
    for name in ("replaces_attempt_id", "predecessor_closure_id"):
        if statement[name] is not None:
            validate_id(statement[name], name)
    if statement["replaces_attempt_id"] == statement["attempt_id"]:
        invalid("消息封口不能将当前尝试用作前驱")
    if statement["predecessor_closure_id"] == statement["closure_id"]:
        invalid("消息封口不能将当前封口标识用作前驱")
    return statement


def validate_message_closure(value):
    return validate_message_terminal(signed_statement(value), "rim-message-closure-1", "cancelled_before_accept")


def validate_message_rejection(value):
    statement = validate_message_terminal(signed_statement(value), "rim-message-rejection-1", "rejected_final",
                                          ("code", "required_authorization_version", "required_crypto_state_ref"))
    if statement["code"] != "state_stale":
        invalid("签名消息拒绝仅支持 state_stale")
    parse_u64(statement["required_authorization_version"], "required_authorization_version")
    validate_state_ref(statement["required_crypto_state_ref"])
    return statement


def message_rejection_statement(header, header_raw, payload_raw, req, closure_id, conv):
    return {"protocol_version": "rim-message-rejection-1", "service_id": header["service_id"],
            "conversation_id": header["conversation_id"], "sender": header["sender"],
            "logical_message_id": header["logical_message_id"], "attempt_id": header["attempt_id"],
            "envelope_sha256": message_envelope_digest(header_raw, payload_raw),
            "replaces_attempt_id": req.get("replaces_attempt_id"), "predecessor_closure_id": req.get("closure_id"),
            "closure_id": closure_id, "outcome": "rejected_final", "code": "state_stale",
            "required_authorization_version": conv["authorization_version"],
            "required_crypto_state_ref": conv["crypto_state_ref"]}


def validate_consistency_head(value):
    """只验证签名声明结构；签名可信性由固定公钥的接收端独立验证。"""
    statement = signed_statement(value)
    fields(statement, ("protocol_version", "service_id", "conversation_id", "actor", "challenge", "checkpoint"))
    if statement["protocol_version"] != "rim-consistency-head-1":
        invalid("不支持此一致性检查点凭证版本")
    for name in ("service_id", "conversation_id"):
        validate_id(statement[name], name)
    fields(statement["actor"], ("account_id", "device_id"))
    for name in ("account_id", "device_id"):
        validate_id(statement["actor"][name], name)
    validate_state_ref(statement["challenge"])
    checkpoint = validate_checkpoint(statement["checkpoint"])
    if any(statement[name] != checkpoint[name] for name in ("service_id", "conversation_id")):
        invalid("一致性声明与完整权限检查点的上下文不一致")
    if not any(all(member[name] == statement["actor"][name] for name in ("account_id", "device_id"))
               for member in checkpoint["members"]):
        invalid("一致性声明接收设备不在权限检查点中")
    return statement
