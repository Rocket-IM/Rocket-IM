"""仅保存设备定向密文包；每次释放前重新检查整份原消息选择的当前权限。"""

import json
import time

from contract import ProtocolError, encode_json
from history_contract import package_digest, request_digest, validate_history_request
from permission_records import require_receipts
from receipt_contract import message_envelope_digest
from rebuild_stream_storage import row_for
from storage import now_ms, public_subject, subject

MAX_TRANSFERS = 128
MAX_RESPONSE_BYTES = 900 * 1024
HISTORY_SCHEMA = """
CREATE TABLE history_transfers (transfer_id TEXT PRIMARY KEY, nonce TEXT UNIQUE NOT NULL,
    source_account TEXT NOT NULL, source_device TEXT NOT NULL,
    target_account TEXT NOT NULL, target_device TEXT NOT NULL,
    request TEXT NOT NULL, package TEXT NOT NULL, receipt TEXT NOT NULL,
    FOREIGN KEY(source_account,source_device) REFERENCES devices(account,device),
    FOREIGN KEY(target_account,target_device) REFERENCES devices(account,device));
"""


def check_access(store, db, device, statement, service_id, conversation_id):
    require_receipts(store)
    if not store.permission_enabled:
        raise ProtocolError("permission_not_enabled", "历史迁移需要已固定签名权限检查点", status=409)
    conv = store.context(db, device, service_id, conversation_id)
    if statement["service_id"] != service_id or statement["conversation_id"] != conversation_id:
        raise ProtocolError("history_context", "迁移请求上下文不匹配", status=409)
    source, target = subject(statement["source"]), subject(statement["target"])
    if source[0] != target[0] or source == target:
        raise ProtocolError("history_denied", "历史迁移仅限同账号不同设备", status=403)
    for pair in (source, target):
        if row_for(db, pair) is not None:
            raise ProtocolError("history_denied", "重建后继不能作为历史迁移源或目标", status=403)
        row = db.execute("SELECT revoked FROM devices WHERE account=? AND device=?", pair).fetchone()
        if row is None or row["revoked"] or pair not in store.members(db):
            raise ProtocolError("history_denied", "迁移源或目标已无当前访问权限", status=403)
    if any(statement[name] != conv[name] for name in ("authorization_version", "crypto_state_ref")):
        raise ProtocolError("history_context", "群状态已经变化，须重新发起迁移", status=409)
    if not int(statement["issued_at_unix_secs"]) <= int(time.time()) < int(statement["expires_at_unix_secs"]):
        raise ProtocolError("history_expired", "迁移请求不在有效期内", status=409)
    for item in statement["selection"]:
        check_original(db, source, service_id, conversation_id, item)


def check_original(db, source, service_id, conversation_id, item):
    row = db.execute("SELECT header,payload,result,outcome,availability FROM attempts WHERE acceptance_id=?", (item["acceptance_id"],)).fetchone()
    if row is None or row["outcome"] != "accepted" or row["availability"] != "available":
        raise ProtocolError("history_unavailable", "选择中的原消息不可迁移", status=403)
    header, accepted = json.loads(row["header"]), json.loads(row["result"])
    if (header["service_id"] != service_id or header["conversation_id"] != conversation_id
            or "acceptance_receipt" not in accepted
            or int(accepted["expires_at_unix_ms"]) <= now_ms()
            or message_envelope_digest(row["header"], row["payload"]) != item["envelope_sha256"]):
        raise ProtocolError("history_unavailable", "原消息身份、接受证明、摘要或保留期限不符", status=403)
    # 发送方没有给自己的 message 事件；原接受记录已经绑定准确发送设备。
    if subject(header["sender"]) == source:
        return
    if public_subject(source) not in header["recipients"]:
        raise ProtocolError("history_unavailable", "源设备不是原发送设备或原收件设备", status=403)
    event = db.execute("SELECT availability,content FROM events WHERE account=? AND device=? AND acceptance_id=? AND json_extract(content,'$.type')='message'", (*source, item["acceptance_id"])).fetchone()
    if event is None or event["availability"] != "available":
        raise ProtocolError("history_unavailable", "源设备的原收件事件不可访问", status=403)


def result(row):
    return {name: json.loads(row[name]) for name in ("request", "package", "receipt")}


def submit_history_transfer(store, db, device, req):
    statement = validate_history_request(req["request"])
    if subject(statement["source"]) != (device["account"], device["device"]):
        raise ProtocolError("history_denied", "只能由请求中原源设备提交迁移包", status=403)
    check_access(store, db, device, statement, req["service_id"], req["conversation_id"])
    encoded = {name: encode_json(req[name]).decode() for name in ("request", "package")}
    row = db.execute("SELECT request,package,receipt FROM history_transfers WHERE transfer_id=?", (statement["transfer_id"],)).fetchone()
    if row is not None:
        if any(json.loads(row[name]) != req[name] for name in encoded):
            raise ProtocolError("history_conflict", "同一迁移标识不可改变请求或包的原字节", status=409)
        return result(row)
    if db.execute("SELECT 1 FROM history_transfers WHERE nonce=?", (statement["nonce"],)).fetchone():
        raise ProtocolError("history_conflict", "迁移请求 nonce 已被使用", status=409)
    if db.execute("SELECT COUNT(*) FROM history_transfers").fetchone()[0] >= MAX_TRANSFERS:
        raise ProtocolError("resource_exhausted", "迁移记录已达 128 个实验上限", status=429)
    if store.permission_verifier is None:
        raise ProtocolError("permission_verifier_unavailable", "缺少公共验证器", status=503)
    from permissions import checkpoint_record
    _, checkpoint = checkpoint_record(db)
    store.permission_verifier.verify_history_transfer(checkpoint, req["request"], req["package"])
    receipt = store.receipt_signer.sign({"protocol_version": "rim-history-receipt-1",
        **{name: statement[name] for name in ("service_id", "conversation_id", "transfer_id", "authorization_version", "crypto_state_ref", "expires_at_unix_secs")},
        "request_sha256": request_digest(req["request"]), "package_sha256": package_digest(req["package"]), "accepted_at_unix_ms": str(now_ms())})
    value = {"request": req["request"], "package": req["package"], "receipt": receipt}
    if len(encode_json({"ok": True, "result": value})) > MAX_RESPONSE_BYTES:
        raise ProtocolError("resource_exhausted", "完整迁移响应超过 900 KiB", status=429)
    # 有界公共验证与签名也会耗时；提交前再核对请求和原消息的时间窗口。
    check_access(store, db, device, statement, req["service_id"], req["conversation_id"])
    db.execute("INSERT INTO history_transfers VALUES (?,?,?,?,?,?,?,?,?)", (statement["transfer_id"], statement["nonce"],
               *subject(statement["source"]), *subject(statement["target"]), encoded["request"], encoded["package"], encode_json(receipt).decode()))
    return value


def get_history_transfer(store, db, device, req):
    store.context(db, device, req["service_id"], req["conversation_id"])
    row = db.execute("SELECT target_account,target_device,request,package,receipt FROM history_transfers WHERE transfer_id=?", (req["transfer_id"],)).fetchone()
    if row is None or (row["target_account"], row["target_device"]) != (device["account"], device["device"]):
        raise ProtocolError("history_denied", "迁移包仅原目标设备可以领取", status=403)
    value = result(row)
    statement = validate_history_request(value["request"])
    check_access(store, db, device, statement, req["service_id"], req["conversation_id"])
    return value
