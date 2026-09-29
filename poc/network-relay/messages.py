"""不可变尝试、封口和一次性接受；调用方事务共同覆盖事件扇出。"""

import base64
import hashlib
import json

from contract import ProtocolError, encode_json, validate_envelope
from receipt_contract import (message_acceptance_statement, message_closure_statement,
                              message_rejection_statement, validate_message_closure, validate_message_rejection)
from permission_contract import validate_checkpoint
from receipt_signer import unavailable
from storage import MAX_ATTEMPTS, RETENTION_MS, identifier, logical_key, now_ms, public_subject, subject


def result(row):
    value = json.loads(row["result"])
    if value["outcome"] == "accepted":
        value["availability"] = row["availability"]
    return value


def find_attempt(db, key, attempt_id):
    return db.execute("SELECT * FROM attempts WHERE logical_key=? AND attempt_id=?", (key, attempt_id)).fetchone()


def accepted_result(db, key, chain):
    return result(find_attempt(db, key, chain["accepted_attempt"]))


def check_capacity(db):
    if db.execute("SELECT COUNT(*) FROM attempts WHERE compacted=0").fetchone()[0] >= MAX_ATTEMPTS:
        raise ProtocolError("resource_exhausted", "实验尝试总量已达上限", status=429, retry_after_ms="1000")


def insert_attempt(db, key, attempt_id, header, payload, value):
    db.execute("INSERT INTO attempts(logical_key,attempt_id,header,payload,outcome,closure_id,result,acceptance_id) VALUES (?,?,?,?,?,?,?,?)",
               (key, attempt_id, header, payload, value["outcome"], value.get("closure_id"),
                encode_json(value).decode(), value.get("acceptance_id")))


def rejected_error(value):
    details = {name: value[name] for name in ("logical_message_id", "attempt_id", "closure_id")}
    if "rejection_receipt" in value:
        details["rejection_receipt"] = value["rejection_receipt"]
    return ProtocolError(value["code"], "该尝试已被终态拒绝", outcome="rejected_final", status=409, **details)


def return_attempt(row):
    value = result(row)
    if value["outcome"] == "rejected_final":
        raise rejected_error(value)
    if value["outcome"] == "cancelled_before_accept":
        raise ProtocolError("attempt_closed", "尝试已封口", outcome="cancelled_before_accept", status=409,
                            logical_message_id=value["logical_message_id"], attempt_id=value["attempt_id"], closure_id=value["closure_id"])
    return value


def sign_stale_rejection(store, db, header, header_raw, payload_raw, req, closure_id, conv):
    from permissions import checkpoint_record
    if store.receipt_signer is None:
        raise unavailable()
    try:
        _, checkpoint = checkpoint_record(db)
        validate_checkpoint(checkpoint)
        if (any(checkpoint[name] != header[name] for name in ("service_id", "conversation_id"))
                or any(checkpoint[name] != conv[name] for name in ("authorization_version", "crypto_state_ref"))
                or [(member["account_id"], member["device_id"]) for member in checkpoint["members"]] != store.members(db)):
            raise unavailable()
    except (ProtocolError, ValueError, KeyError, TypeError):
        raise unavailable() from None
    return store.receipt_signer.sign(message_rejection_statement(header, header_raw, payload_raw, req, closure_id, conv))


def check_predecessor(db, key, chain, replacement, closure_id):
    if chain is None:
        if replacement is not None:
            raise ProtocolError("attempt_chain_conflict", "替代前驱不存在", status=409)
        return
    old = find_attempt(db, key, chain["tail"])
    if replacement != chain["tail"] or old["closure_id"] != closure_id or old["successor"] is not None:
        raise ProtocolError("attempt_chain_conflict", "替代必须持有当前链尾的封口证明", status=409)


def submit(store, db, device, req):
    header, header_raw, payload_raw = validate_envelope(req["envelope"])
    conv = store.context(db, device, header["service_id"], header["conversation_id"])
    if subject(header["sender"]) != (device["account"], device["device"]):
        raise ProtocolError("permission_denied", "凭证与发送设备不一致", status=403)
    key = logical_key(header["service_id"], conv["id"], device, header["logical_message_id"])
    attempt_id = header["attempt_id"]
    previous = find_attempt(db, key, attempt_id)
    if previous is not None:
        payload_matches = (previous["payload_size"] == len(payload_raw)
                           and previous["payload_sha256"] == hashlib.sha256(payload_raw).hexdigest()) if previous["compacted"] else previous["payload"] == payload_raw
        if previous["header"] is not None and (previous["header"] != header_raw or not payload_matches):
            raise ProtocolError("idempotency_conflict", "同一尝试不可改变头或密文字节", status=409,
                                logical_message_id=header["logical_message_id"], attempt_id=attempt_id)
        saved = result(previous)
        if "rejection_receipt" in saved:
            statement = validate_message_rejection(saved["rejection_receipt"])
            if (statement["replaces_attempt_id"], statement["predecessor_closure_id"]) != (req.get("replaces_attempt_id"), req.get("closure_id")):
                raise ProtocolError("idempotency_conflict", "同一签名拒绝不可改变前驱绑定", status=409)
        return return_attempt(previous)
    chain = db.execute("SELECT tail,accepted_attempt FROM logical_messages WHERE key=?", (key,)).fetchone()
    if chain and chain["accepted_attempt"]:
        raise ProtocolError("logical_message_already_accepted", "该逻辑消息已经接受", outcome="accepted", status=409,
                            logical_message_id=header["logical_message_id"], attempt_id=attempt_id,
                            acceptance=accepted_result(db, key, chain))
    replacement = req.get("replaces_attempt_id")
    check_predecessor(db, key, chain, replacement, req.get("closure_id"))
    check_capacity(db)
    if chain is None:
        db.execute("INSERT INTO logical_messages VALUES (?,?,NULL)", (key, attempt_id))
    else:
        db.execute("UPDATE attempts SET successor=? WHERE logical_key=? AND attempt_id=?", (attempt_id, key, replacement))
        db.execute("UPDATE logical_messages SET tail=? WHERE key=?", (attempt_id, key))
    expected = [public_subject(m) for m in store.members(db) if m != (device["account"], device["device"])]
    code = None
    if header["authorization_version"] != conv["authorization_version"]:
        code = "state_stale"
    elif header["crypto_state_ref"] != conv["crypto_state_ref"]:
        code = "state_conflict"
    elif header["recipients"] != expected:
        code = "recipient_set_mismatch"
    if code:
        value = {"outcome": "rejected_final", "code": code, "logical_message_id": header["logical_message_id"],
                 "attempt_id": attempt_id, "closure_id": identifier()}
        if store.receipt_enabled and code == "state_stale" and int(header["authorization_version"]) < int(conv["authorization_version"]):
            value["rejection_receipt"] = sign_stale_rejection(store, db, header, header_raw, payload_raw, req, value["closure_id"], conv)
        insert_attempt(db, key, attempt_id, header_raw, payload_raw, value)
        # 终态先随事务提交；HTTP 层随后将其表达为错误响应。
        return value
    accepted_at = now_ms()
    value = {"outcome": "accepted", "acceptance_id": identifier(), "logical_message_id": header["logical_message_id"],
             "attempt_id": attempt_id, "accepted_at_unix_ms": str(accepted_at),
             "expires_at_unix_ms": str(accepted_at + RETENTION_MS), "recipients": expected, "availability": "available"}
    if store.receipt_enabled:
        value["acceptance_receipt"] = store.receipt_signer.sign(
            message_acceptance_statement(header, header_raw, payload_raw, value["acceptance_id"]))
    insert_attempt(db, key, attempt_id, header_raw, payload_raw, value)
    db.execute("UPDATE logical_messages SET accepted_attempt=? WHERE key=?", (attempt_id, key))
    envelope = {"header_bytes": base64.b64encode(header_raw).decode(), "payload_bytes": base64.b64encode(payload_raw).decode()}
    event = {"type": "message", "acceptance_id": value["acceptance_id"], "envelope": envelope}
    if "acceptance_receipt" in value:
        event["acceptance_receipt"] = value["acceptance_receipt"]
    for recipient in expected:
        store.append_event(db, subject(recipient), event, value["acceptance_id"])
    return value


def get_attempt(store, db, device, req):
    store.context(db, device, req["service_id"], req["conversation_id"])
    key = logical_key(req["service_id"], req["conversation_id"], device, req["logical_message_id"])
    row = find_attempt(db, key, req["attempt_id"])
    if row is None:
        return {"outcome": "not_found", "logical_message_id": req["logical_message_id"], "attempt_id": req["attempt_id"]}
    return result(row)


def close_attempt(store, db, device, req):
    store.context(db, device, req["service_id"], req["conversation_id"])
    key = logical_key(req["service_id"], req["conversation_id"], device, req["logical_message_id"])
    chain = db.execute("SELECT tail,accepted_attempt FROM logical_messages WHERE key=?", (key,)).fetchone()
    if chain and chain["accepted_attempt"]:
        return accepted_result(db, key, chain)
    row = find_attempt(db, key, req["attempt_id"])
    previous = result(row) if row is not None else None
    # 已有拒绝不能变成另一种终态；已接受逻辑在上方始终优先返回。
    if previous is not None and previous["outcome"] == "rejected_final":
        return previous
    signed = "envelope_sha256" in req
    if signed and (not store.receipt_enabled or store.receipt_signer is None):
        raise ProtocolError("receipt_signer_unavailable", "签名封口需要已配置的Service凭证签名器", status=503)
    if row is not None:
        if "closure_receipt" in previous:
            expected = message_closure_statement(req, public_subject((device["account"], device["device"])),
                                                 previous["closure_id"]) if signed else None
            if expected != validate_message_closure(previous["closure_receipt"]):
                raise ProtocolError("idempotency_conflict", "同一签名封口不可改变摘要或前驱绑定", status=409)
        # 旧无证明的封口保留原结果，不能追认其未保存的请求绑定。
        return previous
    check_predecessor(db, key, chain, req.get("replaces_attempt_id"), req.get("closure_id"))
    check_capacity(db)
    value = {"outcome": "cancelled_before_accept", "logical_message_id": req["logical_message_id"],
             "attempt_id": req["attempt_id"], "closure_id": identifier()}
    if chain is None:
        db.execute("INSERT INTO logical_messages VALUES (?,?,NULL)", (key, req["attempt_id"]))
    else:
        db.execute("UPDATE attempts SET successor=? WHERE logical_key=? AND attempt_id=?", (req["attempt_id"], key, chain["tail"]))
        db.execute("UPDATE logical_messages SET tail=? WHERE key=?", (req["attempt_id"], key))
    if signed:
        statement = message_closure_statement(req, public_subject((device["account"], device["device"])), value["closure_id"])
        value["closure_receipt"] = store.receipt_signer.sign(statement)
    insert_attempt(db, key, req["attempt_id"], None, None, value)
    return value
