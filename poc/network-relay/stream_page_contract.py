"""普通设备流原始页的签名声明；真实性由固定 Service 公钥的 Rust 验证器判断。"""

from contract import fields, invalid, parse_u64, validate_id, validate_state_ref
from receipt_contract import signed_statement

MAX_PAGE_BYTES = 740 * 1024
PROTOCOL_VERSION = "RIM-STREAM-PAGE-POC-1"


def validate_stream_page_receipt(value):
    statement = signed_statement(value)
    fields(statement, ("protocol_version", "service_id", "account_id", "device_id",
                       "stream_id", "after_seq", "limit", "page_sha256"))
    if statement["protocol_version"] != PROTOCOL_VERSION:
        invalid("普通设备流分页协议版本无效")
    for name in ("service_id", "account_id", "device_id", "stream_id"):
        validate_id(statement[name], name)
    parse_u64(statement["after_seq"], "after_seq")
    if not 1 <= parse_u64(statement["limit"], "limit") <= 100:
        invalid("普通设备流分页大小须为1—100")
    validate_state_ref(statement["page_sha256"])
    return statement
