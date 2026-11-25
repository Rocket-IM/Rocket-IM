"""恢复原件的字节边界；签名与语义由共享 Rust 验证器核验。"""
import hashlib
from contract import fields, decode_bytes, parse_json, validate_id, invalid


def signed(proof):
    fields(proof, ("statement_bytes", "signature_bytes"))
    if len(decode_bytes(proof["signature_bytes"], "signature_bytes", 64)) != 64:
        invalid("恢复签名长度不符")
    return parse_json(decode_bytes(proof["statement_bytes"], "statement_bytes", 16384))


def proof(value):
    fields(value, ("statement_bytes", "signature_bytes", "commit_bytes"))
    signed({k: value[k] for k in ("statement_bytes", "signature_bytes")})
    decode_bytes(value["commit_bytes"], "commit_bytes", 524288)


def bundle(value):
    fields(value, ("intent", "claim", "allocation", "change", "key_package", "welcome"))
    for name in ("intent", "claim", "allocation"): signed(value[name])
    proof(value["change"])
    decode_bytes(value["key_package"], "key_package", 8192)
    decode_bytes(value["welcome"], "welcome", 524288)


def validate_request(value):
    kind = value.get("kind") if isinstance(value, dict) else None
    if kind in ("claim", "close"):
        fields(value, ("kind", "intent", "proof"))
        signed(value["intent"]); signed(value["proof"])
    elif kind == "accept":
        fields(value, ("kind", "bundle")); bundle(value["bundle"])
    elif kind == "get":
        fields(value, ("kind", "service_id", "conversation_id", "recovery_id"))
        for name in ("service_id", "conversation_id", "recovery_id"): validate_id(value[name])
    else: invalid("不支持恢复动作")


def digest(domain, parts):
    value = hashlib.sha256(b"Rocket-IM/POC/" + domain.encode() + b"/v1\0")
    for encoded, limit in parts:
        raw = decode_bytes(encoded, "recovery_bytes", limit)
        value.update(len(raw).to_bytes(8, "big")); value.update(raw)
    return value.hexdigest()


def signed_digest(value):
    return digest("recovery-signed-record", [(value["statement_bytes"], 16384), (value["signature_bytes"], 64)])


def candidate_digest(value):
    return digest("recovery-candidate", [(value["statement_bytes"], 16384), (value["signature_bytes"], 64), (value["commit_bytes"], 524288)])


def admission_ref(change, receipt):
    statement = parse_json(decode_bytes(change["statement_bytes"], "statement_bytes", 16384))
    return {"change_id": statement["change_id"], "record_sha256": digest("admission-record", [
        (change["statement_bytes"], 16384), (change["signature_bytes"], 64), (change["commit_bytes"], 524288),
        (receipt["statement_bytes"], 16384), (receipt["signature_bytes"], 64)])}


def receipt_record(record):
    # Rust 签名器已执行严格结构验证；这里再核对原字节返回，禁止重排后验签。
    value = signed(record)
    if value.get("protocol_version") not in {"rim-recovery-receipt-1", "rim-recovery-receipt-2"}:
        invalid("恢复回执版本错误")
    return value
