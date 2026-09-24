"""同一权限候选的唯一持久终态；封口不修改已接受的业务权限。"""

import json

from contract import ProtocolError, encode_json
from permission_contract import PROOF_FIELDS, validate_proof
from receipt_contract import proof_digest, terminal_statement, validate_close
from storage import subject

MAX_PERMISSION_RECORDS = 10000


def proof_json(change):
    return encode_json({name: change[name] for name in PROOF_FIELDS}).decode()


def require_receipts(store):
    if not store.receipt_enabled:
        raise ProtocolError("receipt_not_enabled", "此实验实例未固定 Service 终态凭证公钥", status=409)
    if store.receipt_signer is None:
        raise ProtocolError("receipt_signer_unavailable", "Service 终态凭证签名器不可用", status=503)


def existing_resolution(store, db, device, change, statement):
    if not store.receipt_enabled:
        return None
    row = db.execute("SELECT actor_account,actor_device,proof,outcome,receipt FROM permission_resolutions WHERE change_id=?", (statement["change_id"],)).fetchone()
    if row is None:
        return None
    if (row["actor_account"], row["actor_device"]) != (device["account"], device["device"]):
        raise ProtocolError("permission_denied", "凭证与原权限候选发起设备不一致", status=403)
    if row["proof"] != proof_json(change):
        raise ProtocolError("idempotency_conflict", "同一权限候选不可改变证据字节", status=409)
    return row


def check_record_capacity(db):
    count = db.execute("SELECT (SELECT COUNT(*) FROM permission_changes)+(SELECT COUNT(*) FROM permission_resolutions WHERE outcome='closed')").fetchone()[0]
    if count >= MAX_PERMISSION_RECORDS:
        raise ProtocolError("resource_exhausted", "权限候选终态总量已达实验上限", status=429, retry_after_ms="1000")


def save_resolution(store, db, change, statement, checkpoint, outcome):
    require_receipts(store)
    signed = store.receipt_signer.sign(terminal_statement(statement, change, checkpoint, outcome))
    db.execute("INSERT INTO permission_resolutions VALUES (?,?,?,?,?,?)", (statement["change_id"],
               statement["actor"]["account_id"], statement["actor"]["device_id"], proof_json(change), outcome, encode_json(signed).decode()))
    return signed


def close_permission_change(store, db, device, req):
    from permissions import checkpoint_record
    store.context(db, device, req["service_id"], req["conversation_id"])
    _, checkpoint = checkpoint_record(db)
    require_receipts(store)
    statement = validate_proof(req["change"])
    close = validate_close(req["close"])
    expected = {"protocol_version": "rim-permission-close-1", "service_id": req["service_id"],
                "conversation_id": req["conversation_id"], "actor": statement["actor"], "change_id": statement["change_id"],
                "proof_sha256": proof_digest(req["change"])}
    if subject(close["actor"]) != (device["account"], device["device"]):
        raise ProtocolError("permission_denied", "凭证与封口发起设备不一致", status=403)
    if close != expected:
        raise ProtocolError("permission_context", "封口声明与请求上下文或权限候选不一致", status=403)
    row = existing_resolution(store, db, device, req["change"], statement)
    if row is not None:
        return {"change": json.loads(row["proof"]), "receipt": json.loads(row["receipt"])}
    if db.execute("SELECT 1 FROM permission_changes WHERE change_id=?", (statement["change_id"],)).fetchone():
        raise ProtocolError("permission_conflict", "已接受记录缺少同事务保存的终态凭证", status=409)
    if store.permission_verifier is None:
        raise ProtocolError("permission_verifier_unavailable", "未配置公共权限验证器", status=503)
    store.permission_verifier.verify_close(checkpoint, req["change"], req["close"])
    if int(statement["previous_authorization_version"]) > int(checkpoint["authorization_version"]):
        raise ProtocolError("permission_version", "不能在候选前驱版本之前签发恢复封口凭证", status=409)
    check_record_capacity(db)
    receipt = save_resolution(store, db, req["change"], statement, checkpoint, "closed")
    return {"change": json.loads(proof_json(req["change"])), "receipt": receipt}
