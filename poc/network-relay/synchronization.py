"""独立设备流、可用性投影、回执和有界密码依赖查询。"""

import json

from contract import ProtocolError, encode_json, parse_u64
from message_lifecycle import set_availability
from messages import result
from storage import now_ms, public_subject
from reclamation_storage import pending_selection, watermarks

MAX_PAGE_BYTES = 900 * 1024 - 512


def project_expiration(db):
    current_time = now_ms()
    rows = db.execute("SELECT acceptance_id,result FROM attempts WHERE outcome='accepted' AND availability='available'").fetchall()
    for row in rows:
        if int(json.loads(row["result"])["expires_at_unix_ms"]) <= current_time:
            set_availability(db, row["acceptance_id"], "expired")


def pull_events(store, db, device, req):
    from rebuild_stream_storage import authorize_operation
    authorize_operation(db, device, "pull_events")
    return event_page(store, db, device, req)


def event_page(store, db, device, req, max_bytes=MAX_PAGE_BYTES):
    """调用者先完成设备流授权；分页只投影同一事务内的连续事件。"""
    store.context(db, device, req["service_id"])
    stream_id = device["stream_id"]
    if req.get("stream_id", stream_id) != stream_id:
        raise ProtocolError("cursor_invalid", "游标不属于当前设备流", status=409)
    pair = (device["account"], device["device"])
    after = parse_u64(req["after_seq"], "after_seq")
    marks = watermarks(db, pair)
    watermark = marks["high_watermark"]
    if after < marks["floor"]:
        from permission_records import require_receipts
        require_receipts(store)
        statement = {"protocol_version": "rim-stream-retention-1", "service_id": req["service_id"],
                     "account_id": pair[0], "device_id": pair[1], "stream_id": stream_id,
                     "after_seq": req["after_seq"], "limit": req["limit"],
                     "floor": str(marks["floor"]), "watermark": str(watermark)}
        raise ProtocolError("cursor_reclaimed", "请求游标早于已确认回收前缀，禁止自动跳过", status=409,
                            retention_receipt=store.receipt_signer.sign(statement))
    if after > watermark:
        raise ProtocolError("cursor_invalid", "游标超过已提交水位", status=409)
    # 游标先按请求前的已提交水位校验，过期追加完成后再固定本页水位。
    project_expiration(db)
    watermark = watermarks(db, pair)["high_watermark"]
    limit = parse_u64(req["limit"], "limit")
    rows = db.execute("SELECT seq,event_id,content,availability FROM events WHERE account=? AND device=? AND seq>? AND seq<=? ORDER BY seq LIMIT ?",
                      (*pair, after, watermark, limit))
    events, page_size = [], 0
    for row in rows:
        event = {"stream_id": stream_id, "event_seq": str(row["seq"]), "event_id": row["event_id"], "availability": row["availability"]}
        if row["availability"] == "available":
            event["event"] = json.loads(row["content"])
        event_size = len(encode_json(event))
        if events and page_size + event_size > max_bytes:
            break
        events.append(event)
        page_size += event_size
    next_after = int(events[-1]["event_seq"]) if events else after
    return {"stream_id": stream_id, "events": events, "next_after_seq": str(next_after), "watermark": str(watermark), "has_more": next_after < watermark}


def receipt_target(store, db, device, acceptance_id):
    conv = store.context(db, device, store.meta(db, "service_id"))
    row = db.execute("SELECT * FROM attempts WHERE acceptance_id=?", (acceptance_id,)).fetchone()
    pair = (device["account"], device["device"])
    if row is None:
        raise ProtocolError("permission_denied", "目标接受记录不可访问", status=403)
    value = result(row)
    member = pair in store.members(db)
    if public_subject(pair) not in value["recipients"] or not member:
        raise ProtocolError("permission_denied", "仅原目标且仍有权限的设备可以报告", status=403)
    return row, value, conv


def save_receipt(store, db, device, row, value, read):
    pair = (device["account"], device["device"])
    existing = db.execute("SELECT delivered,is_read FROM receipts WHERE acceptance_id=? AND account=? AND device=?", (value["acceptance_id"], *pair)).fetchone()
    was_delivered = bool(existing and existing["delivered"])
    was_read = bool(existing and existing["is_read"])
    is_read = read or was_read
    if pending_selection(db, value["acceptance_id"]) and (not was_delivered or (read and not was_read)):
        raise ProtocolError("reclamation_conflict", "回收计划已固定终态，不能新增迟到回执", status=409)
    db.execute("INSERT INTO receipts VALUES (?,?,?,?,?) ON CONFLICT(acceptance_id,account,device) DO UPDATE SET delivered=1,is_read=excluded.is_read",
               (value["acceptance_id"], *pair, 1, int(is_read)))
    # 状态通知仅给原消息涉及且当前仍有权的设备；后来加入者不获得旧元数据。
    header = json.loads(row["header"])
    original = {(m["account_id"], m["device_id"]) for m in value["recipients"]}
    original.add((header["sender"]["account_id"], header["sender"]["device_id"]))
    changes = ([] if was_delivered else ["delivery"]) + (["read"] if read and not was_read else [])
    for kind in changes:
        event = {"type": kind, "acceptance_id": value["acceptance_id"], "attempt_id": value["attempt_id"], "device": public_subject(pair)}
        for target in sorted(original.intersection(store.members(db))):
            store.append_event(db, target, event, value["acceptance_id"])
    return {"acceptance_id": value["acceptance_id"], "attempt_id": value["attempt_id"], "device": public_subject(pair), "delivered": True, "read": is_read}


def report_delivery(store, db, device, req):
    store.context(db, device, req["service_id"])
    row, value, _ = receipt_target(store, db, device, req["acceptance_id"])
    event = db.execute("SELECT content,acceptance_id FROM events WHERE account=? AND device=? AND event_id=?",
                       (device["account"], device["device"], req["event_id"])).fetchone()
    if event is None or event["acceptance_id"] != req["acceptance_id"] or json.loads(event["content"])["type"] != "message" or value["attempt_id"] != req["attempt_id"]:
        raise ProtocolError("permission_denied", "设备事件与尝试不匹配", status=403)
    return save_receipt(store, db, device, row, value, False)


def report_read(store, db, device, req):
    store.context(db, device, req["service_id"])
    rows = [receipt_target(store, db, device, acceptance_id) for acceptance_id in req["acceptance_ids"]]
    return {"receipts": [save_receipt(store, db, device, row, value, True) for row, value, _ in rows]}


def get_crypto_dependencies(store, db, device, req):
    store.context(db, device, req["service_id"], req["conversation_id"])
    if store.permission_enabled:
        raise ProtocolError("permission_chain_required", "请取得并独立验证签名权限证据链，不能使用合成控制材料恢复", status=409)
    current, target = req["from_state_ref"], req["to_state_ref"]
    chain, seen = [], set()
    pair = public_subject((device["account"], device["device"]))
    while current != target:
        if current in seen or len(chain) >= 128:
            raise ProtocolError("state_conflict", "依赖链循环或超过实验上限", status=409)
        seen.add(current)
        row = db.execute("SELECT control_id,from_ref,to_ref,payload,recipients FROM controls WHERE from_ref=?", (current,)).fetchone()
        if row is None:
            raise ProtocolError("dependency_missing", "指定检查点之间缺少控制材料", status=409)
        if pair not in json.loads(row["recipients"]):
            raise ProtocolError("permission_denied", "设备无权取得该历史控制材料", status=403)
        chain.append({"control_id": row["control_id"], "from_state_ref": row["from_ref"], "to_state_ref": row["to_ref"], "payload_bytes": row["payload"]})
        current = row["to_ref"]
    offset = 0
    after = req.get("after_control_id")
    if after is not None:
        matches = [i for i, control in enumerate(chain) if control["control_id"] == after]
        if not matches:
            raise ProtocolError("cursor_invalid", "控制材料游标不在指定链中", status=409)
        offset = matches[0] + 1
    controls, page_size = [], 0
    for control in chain[offset:offset + parse_u64(req["limit"], "limit")]:
        control_size = len(encode_json(control))
        if controls and page_size + control_size > MAX_PAGE_BYTES:
            break
        controls.append(control)
        page_size += control_size
    return {"conversation_id": req["conversation_id"], "from_state_ref": req["from_state_ref"], "to_state_ref": target,
            "controls": controls, "next_after_control_id": controls[-1]["control_id"] if controls else after,
            "has_more": offset + len(controls) < len(chain)}
