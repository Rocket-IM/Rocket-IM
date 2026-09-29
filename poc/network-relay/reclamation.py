"""参与者显式同意、逐设备签名许可和完成确认；全部完成后才回收Relay载荷。"""

import hashlib
import json

from contract import ProtocolError, encode_json, parse_u64
from reclamation_checks import check_scope, conflict, denied, pending, required_processed, selection
from reclamation_contract import validate_reclaim_receipt
from reclamation_storage import MAX_PLAN_BYTES, MAX_PLAN_TOTAL_BYTES, MAX_PLANS, advance_floor, watermarks


def check_plan_bytes(db, plan_id):
    total = 0
    for plan in db.execute("SELECT * FROM reclamation_plans"):
        # 发许可前预留完成状态的字节，避免 ready→complete 多3B令已同意的finish越额或卡住。
        reserved = dict(plan)
        reserved["status"] = "complete"
        size = len(encode_json(reserved))
        for row in db.execute("SELECT * FROM reclamation_participants WHERE plan_id=?", (plan["plan_id"],)):
            size += len(encode_json(dict(row)))
        for row in db.execute("SELECT * FROM reclamation_selection WHERE plan_id=?", (plan["plan_id"],)):
            size += len(encode_json(dict(row)))
        if size > MAX_PLAN_BYTES:
            raise ProtocolError("resource_exhausted", "回收单计划字节预算已满", status=429)
        total += size
    if total > MAX_PLAN_TOTAL_BYTES:
        raise ProtocolError("resource_exhausted", "回收计划字节预算已满", status=429)


def participant(db, plan_id, device):
    row = db.execute("SELECT * FROM reclamation_participants WHERE plan_id=? AND account=? AND device=?",
                     (plan_id, device["account"], device["device"])).fetchone()
    if row is None:
        raise denied("当前设备不是选择的原参与者")
    return row


def confirm_reclaim(store, db, device, req):
    check_scope(store, db, device, req)
    if req["stream_id"] != device["stream_id"]:
        raise conflict("确认不属于当前设备流")
    plan_id, ids = req["plan_id"], req["acceptance_ids"]
    encoded = encode_json(req).decode()
    plan = db.execute("SELECT * FROM reclamation_plans WHERE plan_id=?", (plan_id,)).fetchone()
    if plan is None:
        messages, participants = selection(store, db, ids)
        if (device["account"], device["device"]) not in participants:
            raise denied("当前设备不是选择的原参与者")
        if db.execute("SELECT COUNT(*) FROM reclamation_plans").fetchone()[0] >= MAX_PLANS:
            raise ProtocolError("resource_exhausted", "累计回收计划预算已满", status=429)
        if any(db.execute("SELECT 1 FROM reclamation_selection WHERE acceptance_id=?", (item,)).fetchone() for item in ids):
            raise conflict("选择已归属另一回收计划")
        db.execute("INSERT INTO reclamation_plans VALUES (?,?,?,'pending')", (plan_id, encode_json(ids).decode(), encode_json(messages).decode()))
        db.executemany("INSERT INTO reclamation_participants(plan_id,account,device) VALUES (?,?,?)", [(plan_id, *pair) for pair in sorted(participants)])
        db.executemany("INSERT INTO reclamation_selection VALUES (?,?)", [(item, plan_id) for item in ids])
    elif json.loads(plan["selection"]) != ids:
        raise conflict("同一计划不能改变选择")
    own = participant(db, plan_id, device)
    if own["request"] is not None and own["request"] != encoded:
        raise conflict("同一设备确认不能改变原游标或请求")
    if own["request"] is None:
        messages, _ = selection(store, db, ids)
        plan = db.execute("SELECT * FROM reclamation_plans WHERE plan_id=?", (plan_id,)).fetchone()
        if messages != json.loads(plan["messages"]):
            raise conflict("选择的持久终态发生冲突")
        processed = parse_u64(req["processed_seq"])
        marks = watermarks(db, (device["account"], device["device"]))
        if not max(marks["floor"], required_processed(db, (device["account"], device["device"]), ids)) <= processed <= marks["high_watermark"]:
            raise pending("确认未覆盖原消息和终态通知或超过已提交水位")
        db.execute("UPDATE reclamation_participants SET request=? WHERE plan_id=? AND account=? AND device=?",
                   (encoded, plan_id, device["account"], device["device"]))
    if db.execute("SELECT 1 FROM reclamation_participants WHERE plan_id=? AND request IS NULL", (plan_id,)).fetchone():
        check_plan_bytes(db, plan_id)
        return {"status": "pending", "plan_id": plan_id}
    # 所有参与者明确确认后，同一事务为每个固定请求保存唯一许可。
    plan = db.execute("SELECT * FROM reclamation_plans WHERE plan_id=?", (plan_id,)).fetchone()
    for row in db.execute("SELECT * FROM reclamation_participants WHERE plan_id=? AND receipt IS NULL", (plan_id,)).fetchall():
        original = json.loads(row["request"])
        statement = {"protocol_version": "rim-message-reclaim-1", "service_id": req["service_id"],
                     "conversation_id": req["conversation_id"], "plan_id": plan_id,
                     "account_id": row["account"], "device_id": row["device"], "stream_id": original["stream_id"],
                     "processed_seq": original["processed_seq"], "messages": json.loads(plan["messages"])}
        if len(encode_json(statement)) > 16 * 1024:
            raise ProtocolError("resource_exhausted", "回收许可声明超过16KiB", status=429)
        receipt = store.receipt_signer.sign(statement)
        if validate_reclaim_receipt(receipt) != statement:
            raise conflict("签名器返回不同回收许可")
        db.execute("UPDATE reclamation_participants SET receipt=? WHERE plan_id=? AND account=? AND device=?",
                   (encode_json(receipt).decode(), plan_id, row["account"], row["device"]))
    db.execute("UPDATE reclamation_plans SET status='ready' WHERE plan_id=? AND status='pending'", (plan_id,))
    check_plan_bytes(db, plan_id)
    return {"status": "ready", "plan_id": plan_id, "receipt": json.loads(participant(db, plan_id, device)["receipt"])}


def compact(db, ids):
    for acceptance_id in ids:
        key = db.execute("SELECT logical_key FROM attempts WHERE acceptance_id=?", (acceptance_id,)).fetchone()[0]
        for row in db.execute("SELECT attempt_id,payload FROM attempts WHERE logical_key=? AND compacted=0", (key,)).fetchall():
            payload = row["payload"]
            db.execute("UPDATE attempts SET compacted=1,payload=NULL,payload_sha256=?,payload_size=? WHERE logical_key=? AND attempt_id=?",
                       (hashlib.sha256(payload).hexdigest() if payload is not None else None,
                        len(payload) if payload is not None else None, key, row["attempt_id"]))
        for row in db.execute("SELECT account,device,seq,content FROM events WHERE acceptance_id=? AND compacted=0", (acceptance_id,)).fetchall():
            content = json.loads(row["content"])
            if content["type"] == "message":
                content.pop("envelope")
            db.execute("UPDATE events SET content=?,compacted=1 WHERE account=? AND device=? AND seq=?",
                       (encode_json(content).decode(), row["account"], row["device"], row["seq"]))


def finish_reclaim(store, db, device, req):
    check_scope(store, db, device, req)
    own = participant(db, req["plan_id"], device)
    if own["receipt"] is None:
        raise pending("全部参与者尚未确认，未签发回收许可")
    if json.loads(own["receipt"]) != req["receipt"]:
        raise conflict("完成确认没有携带本设备原许可")
    statement = validate_reclaim_receipt(req["receipt"])
    if statement["stream_id"] != device["stream_id"]:
        raise conflict("完成确认所属设备流已经改变")
    plan = db.execute("SELECT * FROM reclamation_plans WHERE plan_id=?", (req["plan_id"],)).fetchone()
    if plan["status"] == "complete":
        return {"status": "complete", "plan_id": req["plan_id"]}
    ids = json.loads(plan["selection"])
    messages, _ = selection(store, db, ids)
    if messages != json.loads(plan["messages"]):
        raise conflict("完成前原终态与许可不一致")
    db.execute("UPDATE reclamation_participants SET finished=1 WHERE plan_id=? AND account=? AND device=?",
               (req["plan_id"], device["account"], device["device"]))
    if db.execute("SELECT 1 FROM reclamation_participants WHERE plan_id=? AND finished=0", (req["plan_id"],)).fetchone():
        return {"status": "pending", "plan_id": req["plan_id"]}
    compact(db, ids)
    for row in db.execute("SELECT account,device FROM reclamation_participants WHERE plan_id=?", (req["plan_id"],)):
        advance_floor(db, (row["account"], row["device"]))
    db.execute("UPDATE reclamation_plans SET status='complete' WHERE plan_id=?", (req["plan_id"],))
    return {"status": "complete", "plan_id": req["plan_id"]}
