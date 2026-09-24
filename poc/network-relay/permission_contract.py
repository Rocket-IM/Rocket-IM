"""签名权限证据的严格字段边界；签名与授权判断由 Rust 公共验证器负责。"""

from contract import (MAX_HEADER_BYTES, MAX_PAYLOAD_BYTES, decode_bytes, fields,
                      invalid, parse_json, parse_u64, validate_id, validate_state_ref)

PROOF_FIELDS = ("statement_bytes", "signature_bytes", "commit_bytes")
JOIN_ACTIONS = ("add_member", "add_device")


def validate_member(value):
    fields(value, ("account_id", "device_id", "signature_key"))
    for name in ("account_id", "device_id"):
        validate_id(value[name], name)
    if len(decode_bytes(value["signature_key"], "signature_key", 32)) != 32:
        invalid("设备签名公钥必须为 32 字节")
    return value


def validate_checkpoint(value):
    fields(value, ("service_id", "conversation_id", "authorization_version", "crypto_state_ref", "owner_account_id", "members"))
    for name in ("service_id", "conversation_id", "owner_account_id"):
        validate_id(value[name], name)
    parse_u64(value["authorization_version"], "authorization_version")
    validate_state_ref(value["crypto_state_ref"])
    if not isinstance(value["members"], list) or not 2 <= len(value["members"]) <= 6:
        invalid("权限检查点必须包含 2—6 个设备")
    identities, keys = [], set()
    for member in value["members"]:
        validate_member(member)
        identities.append((validate_id(member["account_id"], "account_id"), validate_id(member["device_id"], "device_id")))
        key = decode_bytes(member["signature_key"], "signature_key", 32)
        if key in keys:
            invalid("不同设备不能复用签名公钥")
        keys.add(key)
        if len(key) != 32:
            invalid("设备签名公钥必须为 32 字节")
    if identities != sorted(set(identities)) or value["owner_account_id"] not in {identity[0] for identity in identities}:
        invalid("检查点成员须排序、唯一且包含所有者账号")
    return value


def validate_statement(statement):
    fields(statement, ("protocol_version", "change_id", "service_id", "conversation_id", "actor",
                       "previous_authorization_version", "authorization_version", "from_state_ref", "to_state_ref",
                       "action", "commit_sha256", "nonce", "issued_at_unix_secs", "expires_at_unix_secs"))
    if statement["protocol_version"] != "rim-permission-1":
        invalid("不支持此权限证据版本")
    for name in ("change_id", "service_id", "conversation_id"):
        validate_id(statement[name], name)
    fields(statement["actor"], ("account_id", "device_id"))
    for name in ("account_id", "device_id"):
        validate_id(statement["actor"][name], name)
    for name in ("previous_authorization_version", "authorization_version", "issued_at_unix_secs", "expires_at_unix_secs"):
        parse_u64(statement[name], name)
    for name in ("from_state_ref", "to_state_ref", "commit_sha256", "nonce"):
        validate_state_ref(statement[name])
    action = statement["action"]
    if not isinstance(action, dict):
        invalid("权限操作必须为对象")
    if action.get("kind") == "remove_member":
        fields(action, ("kind", "account_id"))
    elif action.get("kind") == "revoke_device":
        fields(action, ("kind", "account_id", "device_id"))
        validate_id(action["device_id"], "device_id")
    elif action.get("kind") in JOIN_ACTIONS:
        fields(action, ("kind", "member", "key_package_sha256", "welcome_sha256", "history_policy"))
        validate_member(action["member"])
        for name in ("key_package_sha256", "welcome_sha256"):
            validate_state_ref(action[name])
        if action["history_policy"] != "from_join":
            invalid("本轮入群仅支持 from_join 历史策略")
        return statement
    else:
        invalid("不支持此权限操作")
    validate_id(action["account_id"], "account_id")
    return statement


def validate_proof(change):
    fields(change, PROOF_FIELDS)
    raw = decode_bytes(change["statement_bytes"], "statement_bytes", MAX_HEADER_BYTES)
    if len(decode_bytes(change["signature_bytes"], "signature_bytes", 64)) != 64:
        invalid("权限签名必须为 64 字节")
    decode_bytes(change["commit_bytes"], "commit_bytes", MAX_PAYLOAD_BYTES)
    return validate_statement(parse_json(raw))


def validate_permission_request(operation, value):
    if operation in {"submit_permission_change", "close_permission_change"}:
        names = ("service_id", "conversation_id", "change") + (("close",) if operation == "close_permission_change" else ())
        fields(value, names, ("join",) if operation == "submit_permission_change" else ())
        statement = validate_proof(value["change"])
        if operation == "submit_permission_change":
            if (statement["action"]["kind"] in JOIN_ACTIONS) != ("join" in value):
                invalid("仅 Add 必须提供 join 材料；其他操作禁止附加")
            if "join" in value:
                validate_join(value["join"])
        if operation == "close_permission_change":
            from receipt_contract import validate_close
            validate_close(value["close"])
    elif operation == "get_join_material":
        fields(value, ("service_id", "conversation_id", "change_id"))
        validate_id(value["change_id"], "change_id")
    else:
        fields(value, ("service_id", "conversation_id", "after_version", "limit"))
        parse_u64(value["after_version"], "after_version")
        if not 1 <= parse_u64(value["limit"], "limit") <= 32:
            invalid("权限证据分页大小须为 1—32")
    validate_id(value["service_id"], "service_id")
    validate_id(value["conversation_id"], "conversation_id")
    return value


def validate_join(value):
    fields(value, ("key_package", "welcome"))
    return tuple(decode_bytes(value[name], name, MAX_PAYLOAD_BYTES) for name in ("key_package", "welcome"))
