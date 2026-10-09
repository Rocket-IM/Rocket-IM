"""阶段 0 HTTP POC 的输入边界；不包含鉴权、持久化或密码验证。"""

import base64
import binascii
import json
import math
import re

MAX_REQUEST_BYTES = 1024 * 1024
MAX_HEADER_BYTES = 16 * 1024
MAX_PAYLOAD_BYTES = 512 * 1024
MAX_U64 = (1 << 64) - 1
PROTOCOL_VERSION = "rim-poc-1"
ID_PATTERN = r"[A-Za-z0-9_-]{1,64}"
STATE_PATTERN = r"[0-9a-f]{64}"
OPERATIONS = frozenset({
    "submit_message", "get_attempt", "close_attempt", "pull_events", "pull_events_signed",
    "report_delivery", "report_read", "get_crypto_dependencies",
    "submit_permission_change", "get_permission_changes", "close_permission_change", "get_permission_records", "get_join_material",
    "submit_history_transfer", "get_history_transfer", "get_consistency_head",
    "register_rebuild_stream", "pull_rebuild_events",
    "confirm_reclaim", "finish_reclaim",
    "begin_device_registration", "complete_device_registration",
})


class ProtocolError(Exception):
    """可公开的固定错误说明，不附带输入内容或秘密。"""

    def __init__(self, code, message, *, outcome="not_recorded", status=400, **details):
        super().__init__(message)
        self.code = code
        self.message = message
        self.outcome = outcome
        self.status = status
        self.details = details


def invalid(message):
    raise ProtocolError("invalid_envelope", message)


def encode_json(value):
    """仅用于首次生成或普通响应；不得重新序列化替代已保存的认证头。"""
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":")).encode("utf-8")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            invalid("JSON 不允许重复字段")
        result[key] = value
    return result


def _reject_constant(_value):
    invalid("JSON 不允许非有限数值")


def parse_json(raw):
    """解析完整 UTF-8 JSON 对象；在解码前执行字节限额。"""
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_REQUEST_BYTES:
        invalid("请求必须为 1 字节至 1 MiB 的 UTF-8 JSON")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                           parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        invalid("请求不是有效 UTF-8 JSON")
    if not isinstance(value, dict):
        invalid("请求顶层必须为对象")
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 32:
            invalid("JSON 嵌套超过 32 层")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, float) and not math.isfinite(item):
            invalid("JSON 数值超出有限表示范围")
    return value


def fields(value, required, optional=()):
    if not isinstance(value, dict):
        invalid("字段必须为对象")
    present = set(value)
    if not set(required) <= present or present - set(required) - set(optional):
        invalid("对象存在缺失或未定义字段")


def validate_id(value, name="id"):
    if not isinstance(value, str) or re.fullmatch(ID_PATTERN, value) is None:
        invalid(f"{name} 必须是 1 至 64 位 ASCII 标识")
    return value


def parse_u64(value, name="value"):
    if not isinstance(value, str) or re.fullmatch(r"0|[1-9][0-9]{0,19}", value) is None:
        invalid(f"{name} 必须是无前导零的 u64 十进制字符串")
    result = int(value)
    if result > MAX_U64:
        invalid(f"{name} 超过 u64 范围")
    return result


def validate_state_ref(value):
    if not isinstance(value, str) or re.fullmatch(STATE_PATTERN, value) is None:
        invalid("状态引用必须是公共检查点的 64 位小写十六进制摘要")
    return value


def decode_bytes(value, name, max_bytes):
    if not isinstance(value, str) or not value or len(value) > 4 * ((max_bytes + 2) // 3):
        invalid(f"{name} 不是有界非空 Base64 字符串")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        invalid(f"{name} 不是标准带填充 Base64")
    if not raw or len(raw) > max_bytes or base64.b64encode(raw).decode("ascii") != value:
        invalid(f"{name} 非规范 Base64 或解码长度超限")
    return raw


def _identity(value):
    fields(value, ("account_id", "device_id"))
    return (validate_id(value["account_id"], "account_id"),
            validate_id(value["device_id"], "device_id"))


def validate_header_bytes(encoded):
    raw = decode_bytes(encoded, "header_bytes", MAX_HEADER_BYTES)
    header = parse_json(raw)
    fields(header, (
        "protocol_version", "service_id", "conversation_id", "sender",
        "logical_message_id", "attempt_id", "security_mode", "crypto_profile",
        "authorization_version", "crypto_state_ref", "recipients",
    ))
    if any(not isinstance(header[name], str)
           for name in ("protocol_version", "security_mode", "crypto_profile")):
        invalid("协议版本、模式和密码配置必须为字符串")
    if header["protocol_version"] != PROTOCOL_VERSION:
        raise ProtocolError("unsupported_version", "不支持此实验协议版本")
    if header["security_mode"] != "e2ee":
        raise ProtocolError("unsupported_mode", "本实验仅实现 e2ee 模式")
    if header["crypto_profile"] != "mls-poc":
        raise ProtocolError("unsupported_crypto_profile", "不支持此密码实验配置")
    for name in ("service_id", "conversation_id", "logical_message_id", "attempt_id"):
        validate_id(header[name], name)
    sender = _identity(header["sender"])
    parse_u64(header["authorization_version"], "authorization_version")
    validate_state_ref(header["crypto_state_ref"])
    recipients = header["recipients"]
    if not isinstance(recipients, list) or not 1 <= len(recipients) <= 5:
        invalid("目标设备必须为 1 至 5 项数组")
    identities = [_identity(recipient) for recipient in recipients]
    if identities != sorted(set(identities)) or sender in identities:
        invalid("目标必须排序、唯一且不包含发送设备")
    return header, raw


def validate_envelope(value):
    fields(value, ("header_bytes", "payload_bytes"))
    header, raw = validate_header_bytes(value["header_bytes"])
    payload = decode_bytes(value["payload_bytes"], "payload_bytes", MAX_PAYLOAD_BYTES)
    return header, raw, payload


def _limit(value, maximum):
    if not 1 <= parse_u64(value, "limit") <= maximum:
        invalid("分页大小超出范围")


def _replacement(value):
    if ("replaces_attempt_id" in value) != ("closure_id" in value):
        invalid("替代参数必须同时提供")
    for name in ("replaces_attempt_id", "closure_id"):
        if name in value:
            validate_id(value[name], name)


def validate_request(operation, value):
    """验证操作形状，不改变数据或建立尝试终态；身份以 Bearer 主体为准。"""
    if operation not in OPERATIONS:
        raise ProtocolError("unsupported_operation", "不支持此操作", status=404)
    if operation in {"begin_device_registration", "complete_device_registration"}:
        from registration_contract import validate_request as validate_registration_request
        return validate_registration_request(operation, value)
    if operation in {"confirm_reclaim", "finish_reclaim"}:
        from reclamation_contract import validate_reclamation_request
        return validate_reclamation_request(operation, value)
    if operation in {"register_rebuild_stream", "pull_rebuild_events"}:
        from rebuild_stream_contract import validate_operation
        return validate_operation(operation, value)
    if operation in {"submit_permission_change", "get_permission_changes", "close_permission_change", "get_permission_records", "get_join_material"}:
        from permission_contract import validate_permission_request
        return validate_permission_request(operation, value)
    if operation in {"submit_history_transfer", "get_history_transfer"}:
        from history_contract import validate_history_operation
        return validate_history_operation(operation, value)
    if operation == "get_consistency_head":
        fields(value, ("service_id", "conversation_id", "challenge"))
        validate_id(value["service_id"], "service_id")
        validate_id(value["conversation_id"], "conversation_id")
        if not isinstance(value["challenge"], str) or re.fullmatch(STATE_PATTERN, value["challenge"]) is None:
            invalid("challenge 必须是 32 字节随机值的 64 位小写十六进制表示")
        return value
    if operation == "submit_message":
        fields(value, ("envelope",), ("replaces_attempt_id", "closure_id"))
        validate_envelope(value["envelope"])
        _replacement(value)
        return value
    if operation in ("get_attempt", "close_attempt"):
        fields(value, ("service_id", "conversation_id", "logical_message_id", "attempt_id"),
               ("replaces_attempt_id", "closure_id", "envelope_sha256") if operation == "close_attempt" else ())
        if operation == "close_attempt":
            _replacement(value)
        for name, item in value.items():
            if name == "envelope_sha256":
                validate_state_ref(item)
            else:
                validate_id(item, name)
    elif operation in {"pull_events", "pull_events_signed"}:
        fields(value, ("service_id", "after_seq", "limit"), ("stream_id",))
        parse_u64(value["after_seq"], "after_seq")
        if "stream_id" in value:
            validate_id(value["stream_id"], "stream_id")
        elif value["after_seq"] != "0":
            invalid("仅初始游标 0 可以省略流标识")
        _limit(value["limit"], 100)
    elif operation == "report_delivery":
        fields(value, ("service_id", "acceptance_id", "attempt_id", "event_id"))
        for name, item in value.items():
            validate_id(item, name)
    elif operation == "report_read":
        fields(value, ("service_id", "acceptance_ids"))
        ids = value["acceptance_ids"]
        if not isinstance(ids, list) or not 1 <= len(ids) <= 100:
            invalid("已读列表必须包含 1 至 100 个接受标识")
        for item in ids:
            validate_id(item, "acceptance_id")
        if len(set(ids)) != len(ids):
            invalid("已读列表不允许重复标识")
    else:
        fields(value, ("service_id", "conversation_id", "from_state_ref", "to_state_ref", "limit"),
               ("after_control_id",))
        validate_id(value["conversation_id"], "conversation_id")
        validate_state_ref(value["from_state_ref"])
        validate_state_ref(value["to_state_ref"])
        if "after_control_id" in value:
            validate_id(value["after_control_id"], "after_control_id")
        _limit(value["limit"], 32)
    validate_id(value["service_id"], "service_id")
    return value
