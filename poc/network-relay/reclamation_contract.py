"""有限显式回收许可和设备流缺口声明；不授权跳过未处理事件。"""

from contract import fields, invalid, parse_u64, validate_id, validate_state_ref
from receipt_contract import signed_statement


def validate_scope(statement):
    for name in ("service_id", "account_id", "device_id", "stream_id"):
        validate_id(statement[name], name)


def validate_reclaim_receipt(value):
    statement = signed_statement(value)
    fields(statement, ("protocol_version", "service_id", "conversation_id", "plan_id", "account_id",
                       "device_id", "stream_id", "processed_seq", "messages"))
    if statement["protocol_version"] != "rim-message-reclaim-1":
        invalid("回收许可版本无效")
    validate_scope(statement)
    for name in ("conversation_id", "plan_id"):
        validate_id(statement[name], name)
    parse_u64(statement["processed_seq"], "processed_seq")
    messages = statement["messages"]
    if not isinstance(messages, list) or not 1 <= len(messages) <= 16:
        invalid("回收选择须为1—16项")
    ids = []
    for item in messages:
        fields(item, ("acceptance_id", "envelope_sha256", "availability", "recipients"))
        ids.append(validate_id(item["acceptance_id"], "acceptance_id"))
        validate_state_ref(item["envelope_sha256"])
        if not isinstance(item["availability"], str) or item["availability"] not in {"deleted", "expired"}:
            invalid("回收仅接受已有删除或到期终态")
        if not isinstance(item["recipients"], list) or not 1 <= len(item["recipients"]) <= 5:
            invalid("回收目标集合无效")
        pairs = []
        for recipient in item["recipients"]:
            fields(recipient, ("account_id", "device_id"))
            pairs.append(tuple(validate_id(recipient[name], name) for name in ("account_id", "device_id")))
        if pairs != sorted(set(pairs)):
            invalid("回收目标须有序且唯一")
    if ids != sorted(set(ids)):
        invalid("回收选择须按接受标识排序且唯一")
    return statement


def validate_retention_receipt(value):
    statement = signed_statement(value)
    fields(statement, ("protocol_version", "service_id", "account_id", "device_id", "stream_id",
                       "after_seq", "limit", "floor", "watermark"))
    if statement["protocol_version"] != "rim-stream-retention-1":
        invalid("设备流回收边界版本无效")
    validate_scope(statement)
    after, floor, high = (parse_u64(statement[name], name) for name in ("after_seq", "floor", "watermark"))
    if not after < floor <= high or not 1 <= parse_u64(statement["limit"], "limit") <= 100:
        invalid("设备流回收边界或原请求无效")
    return statement


def validate_reclamation_request(operation, value):
    common = ("service_id", "conversation_id", "plan_id")
    fields(value, common + (("stream_id", "processed_seq", "acceptance_ids") if operation == "confirm_reclaim" else ("receipt",)))
    for name in common:
        validate_id(value[name], name)
    if operation == "finish_reclaim":
        validate_reclaim_receipt(value["receipt"])
        return
    validate_id(value["stream_id"], "stream_id")
    parse_u64(value["processed_seq"], "processed_seq")
    ids = value["acceptance_ids"]
    if not isinstance(ids, list) or not 1 <= len(ids) <= 16:
        invalid("回收选择须为1—16项")
    for acceptance_id in ids:
        validate_id(acceptance_id, "acceptance_id")
    if ids != sorted(set(ids)):
        invalid("回收选择须排序且唯一")
