"""新实验协议的严格字段边界；真实密码验证仍由 Rust 公共验证器完成。"""
import hashlib
from contract import (fields, decode_bytes, parse_json, parse_u64, validate_id,
                      validate_state_ref, invalid, encode_json)
from permission_contract import validate_member

LIMIT = 49152
def digest(record):
    return hashlib.sha256(encode_json({k: record[k] for k in ("statement_bytes", "signature_bytes")})).hexdigest()

def signed(record):
    fields(record, ("statement_bytes", "signature_bytes"))
    if len(decode_bytes(record["signature_bytes"], "signature_bytes", 64)) != 64:
        invalid("签名长度不符")
    return parse_json(decode_bytes(record["statement_bytes"], "statement_bytes", LIMIT))

def request(proof):
    value = signed(proof)
    fields(value, ("protocol_version", "service_id", "request_id", "actor", "action"))
    if value["protocol_version"] != "rim-key-package-request-1":
        invalid("生命周期协议版本不支持")
    validate_id(value["service_id"]); validate_id(value["request_id"]); validate_member(value["actor"])
    action = value["action"]
    if not isinstance(action, dict):
        invalid("动作格式无效")
    kind = action.get("kind")
    if kind == "directory":
        fields(action, ("kind", "account_id", "challenge"))
        validate_id(action["account_id"]); validate_state_ref(action["challenge"])
    elif kind == "publish":
        fields(action, ("kind", "packages"))
        if not isinstance(action["packages"], list) or not 1 <= len(action["packages"]) <= 4:
            invalid("发布批次须为1—4份")
        raw = [decode_bytes(p, "key_package", 8192) for p in action["packages"]]
        if len(set(raw)) != len(raw):
            invalid("批次重复材料")
    elif kind == "claim":
        fields(action, ("kind", "target", "conversation_id", "join_kind", "change_id",
                        "directory_version", "directory_sha256", "authorization_version", "crypto_state_ref"))
        validate_member(action["target"])
        for name in ("conversation_id", "change_id"): validate_id(action[name])
        for name in ("directory_version", "authorization_version"): parse_u64(action[name])
        for name in ("directory_sha256", "crypto_state_ref"): validate_state_ref(action[name])
        if action["directory_version"] == "0" or action["join_kind"] not in ("add_member", "add_device"):
            invalid("领取版本或加入动作无效")
    elif kind == "retire":
        fields(action, ("kind", "key_package_sha256")); validate_state_ref(action["key_package_sha256"])
    else:
        invalid("不支持生命周期动作")
    return value

def validate_request(value):
    fields(value, ("proof",)); request(value["proof"])

def receipt(value):
    fields(value, ("protocol_version", "service_id", "request_sha256", "result"))
    if value["protocol_version"] != "rim-key-package-receipt-1": invalid("回执版本错误")
    validate_id(value["service_id"]); validate_state_ref(value["request_sha256"])
    result = value["result"]
    if not isinstance(result, dict): invalid("结果格式无效")
    kind = result.get("kind")
    if kind == "directory":
        fields(result, ("kind", "challenge", "snapshots")); validate_state_ref(result["challenge"])
        if not isinstance(result["snapshots"], list) or not 1 <= len(result["snapshots"]) <= 16:
            invalid("目录链长度无效")
        for snapshot in result["snapshots"]: decode_bytes(snapshot, "snapshot", 16384)
    else:
        extras = {"published": ("hashes",), "allocated": ("key_package", "key_package_sha256", "allocated_at_ms"),
                  "unavailable": (), "retired": ("key_package_sha256",)}.get(kind)
        if extras is None: invalid("结果种类无效")
        fields(result, ("kind", "inventory_version", *extras)); parse_u64(result["inventory_version"])
        if kind == "published":
            if not isinstance(result["hashes"], list) or not 1 <= len(result["hashes"]) <= 4: invalid("发布结果无效")
            for hash_value in result["hashes"]: validate_state_ref(hash_value)
        if "key_package_sha256" in result: validate_state_ref(result["key_package_sha256"])
        if kind == "allocated":
            raw = decode_bytes(result["key_package"], "key_package", 8192)
            if hashlib.sha256(raw).hexdigest() != result["key_package_sha256"]: invalid("领取材料摘要错误")
            parse_u64(result["allocated_at_ms"])
    if len(encode_json(value)) > LIMIT: invalid("回执原件超限")
    return value
