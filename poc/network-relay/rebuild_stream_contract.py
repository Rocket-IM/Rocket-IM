"""重建设备流的有界公开契约；签名真实性由固定公钥的 Rust 验证器判断。"""

import hashlib

from contract import decode_bytes, fields, invalid, parse_u64, validate_id, validate_state_ref
from permission_contract import validate_proof
from receipt_contract import signed_statement, validate_receipt
from rebuild_stream_storage import scope, validate_trust

SIGNED_DOMAIN = b"Rockets-IM/POC/rebuild-stream-signed-digest/v1\0"
MAX_PAGE_BYTES = 740 * 1024


def signed_digest(value):
    fields(value, ("statement_bytes", "signature_bytes"))
    digest = hashlib.sha256(SIGNED_DOMAIN)
    for name, limit in (("statement_bytes", 16 * 1024), ("signature_bytes", 64)):
        raw = decode_bytes(value[name], name, limit)
        if name == "signature_bytes" and len(raw) != 64:
            invalid("重建设备流签名必须为64字节")
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def validate_plan(plan):
    fields(plan, ("protocol_version", "rebuild_id", "old_scope", "old_head", "old_txn", "old_revision",
                  "old_conversation_id", "old_group_id", "anchor_public_key", "successor_scope", "successor_head",
                  "successor_client_public_key", "key_package_sha256", "trust"))
    if plan["protocol_version"] != "rim-anchor-rebuild-1":
        invalid("重建计划版本无效")
    validate_trust({name: plan[name] for name in ("old_scope", "anchor_public_key", "trust")})
    scope(plan["successor_scope"])
    for name in ("rebuild_id", "old_head", "old_txn", "successor_head", "successor_client_public_key", "key_package_sha256"):
        validate_state_ref(plan[name])
    parse_u64(plan["old_revision"], "old_revision")
    validate_id(plan["old_conversation_id"], "old_conversation_id")
    decode_bytes(plan["old_group_id"], "old_group_id", 128)
    return plan


def validate_registration(value):
    fields(value, ("plan", "approval", "anchor_request", "anchor_response", "request", "join_record"))
    validate_plan(value["plan"])
    for name in ("approval", "anchor_request", "anchor_response"):
        signed_statement(value[name])
    validate_stream_request(signed_statement(value["request"]))
    record = value["join_record"]
    fields(record, ("change", "receipt"))
    validate_proof(record["change"])
    validate_receipt(record["receipt"])
    return value


def validate_stream_request(statement, binding=False):
    names = ("protocol_version", "plan_sha256", "successor_scope", "conversation_id", "stream_id", "initial_cursor", "join_proof_sha256")
    fields(statement, names + (("request_sha256",) if binding else ()))
    expected = "rim-rebuild-stream-binding-1" if binding else "rim-rebuild-stream-request-1"
    if statement["protocol_version"] != expected or statement["initial_cursor"] != "0":
        invalid("重建设备流版本或初始游标无效")
    scope(statement["successor_scope"])
    validate_id(statement["conversation_id"], "conversation_id")
    for name in ("plan_sha256", "stream_id", "join_proof_sha256") + (("request_sha256",) if binding else ()):
        validate_state_ref(statement[name])
    return statement


def validate_pull(statement, page=False):
    names = ("protocol_version", "service_id", "conversation_id", "successor_scope", "stream_id", "binding_sha256", "after_seq", "limit", "challenge")
    fields(statement, names + (("request_sha256", "page_sha256") if page else ()))
    expected = "rim-rebuild-stream-page-1" if page else "rim-rebuild-stream-pull-1"
    if statement["protocol_version"] != expected:
        invalid("重建设备流分页协议版本无效")
    successor = scope(statement["successor_scope"])
    for name in ("service_id", "conversation_id"):
        validate_id(statement[name], name)
    if statement["service_id"] != successor["service"]:
        invalid("分页服务实例与后继范围不一致")
    for name in ("stream_id", "binding_sha256", "challenge") + (("request_sha256", "page_sha256") if page else ()):
        validate_state_ref(statement[name])
    parse_u64(statement["after_seq"], "after_seq")
    if not 1 <= parse_u64(statement["limit"], "limit") <= 100:
        invalid("重建设备流分页大小须为1—100")
    return statement


def validate_binding(value):
    return validate_stream_request(signed_statement(value), binding=True)


def validate_page_receipt(value):
    return validate_pull(signed_statement(value), page=True)


def validate_operation(operation, value):
    fields(value, ("service_id", "registration" if operation == "register_rebuild_stream" else "request"))
    validate_id(value["service_id"], "service_id")
    if operation == "register_rebuild_stream":
        validate_registration(value["registration"])
    else:
        validate_pull(signed_statement(value["request"]))
    return value
