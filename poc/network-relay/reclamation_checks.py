"""回收选择的来源、终态、迁移及参与者检查；先拒绝不支持范围。"""

import base64
import json

from contract import ProtocolError, validate_envelope
from lifecycle_backfill_auth import authority
from receipt_contract import message_acceptance_statement, validate_message_acceptance
from reclamation_storage import capacity
from storage import subject


def denied(message):
    return ProtocolError("reclamation_denied", message, status=403)


def conflict(message):
    return ProtocolError("reclamation_conflict", message, status=409)


def pending(message):
    return ProtocolError("reclamation_pending", message, status=409)


def check_scope(store, db, device, req):
    store.context(db, device, req["service_id"], req["conversation_id"])
    if not store.permission_enabled or not store.receipt_enabled or store.receipt_signer is None:
        raise denied("回收仅支持已固定Service回执钥的签名权限普通流")
    if db.execute("SELECT 1 FROM rebuild_streams WHERE account=? AND device=?", (device["account"], device["device"])).fetchone():
        raise denied("重建后继流不在本轮回收范围")


def selection(store, db, ids):
    authority(store, db)
    selected = set(ids)
    for row in db.execute("SELECT request FROM history_transfers"):
        from history_contract import validate_history_request
        if selected.intersection(item["acceptance_id"] for item in validate_history_request(json.loads(row["request"]))["selection"]):
            raise denied("选择包含已参与历史迁移的消息")
    messages, participants = [], None
    for acceptance_id in ids:
        row = db.execute("SELECT * FROM attempts WHERE acceptance_id=?", (acceptance_id,)).fetchone()
        if row is None or row["outcome"] != "accepted" or row["compacted"]:
            raise denied("原接受记录不存在或已经回收")
        if row["availability"] not in {"deleted", "expired"}:
            raise pending("仅允许已持久保存的删除或到期终态")
        accepted = json.loads(row["result"])
        header, raw, payload = validate_envelope({"header_bytes": base64.b64encode(row["header"]).decode(),
                                                 "payload_bytes": base64.b64encode(row["payload"]).decode()})
        receipt = accepted.get("acceptance_receipt")
        if receipt is None or validate_message_acceptance(receipt) != message_acceptance_statement(header, raw, payload, acceptance_id):
            raise denied("原接受记录缺少一致的签名来源")
        if any(accepted.get(name) != header[name] for name in ("logical_message_id", "attempt_id", "recipients")):
            raise conflict("原接受结果与信封身份不一致")
        if db.execute("SELECT 1 FROM lifecycle_backfill WHERE acceptance_id=? AND status='pending'", (acceptance_id,)).fetchone():
            raise pending("历史终态回填尚未完成")
        targets = {subject(value) for value in header["recipients"]}
        for pair in targets:
            original = db.execute("SELECT seq,event_id,content,availability FROM events WHERE account=? AND device=? "
                                  "AND acceptance_id=? AND json_extract(content,'$.type')='message'", (*pair, acceptance_id)).fetchall()
            if len(original) != 1 or original[0]["availability"] != row["availability"]:
                raise conflict("原消息目标槽或终态不一致")
            event = json.loads(original[0]["content"])
            _, event_header, event_payload = validate_envelope(event["envelope"])
            if event_header != raw or event_payload != payload or event.get("acceptance_receipt") != receipt:
                raise conflict("原消息槽信封或接受证明不一致")
            notifications = db.execute("SELECT content FROM events WHERE account=? AND device=? AND acceptance_id=? "
                                       "AND json_extract(content,'$.type')='message_availability'", (*pair, acceptance_id)).fetchall()
            expected = {"type": "message_availability", "target_event_seq": str(original[0]["seq"]),
                        "target_event_id": original[0]["event_id"], "acceptance_id": acceptance_id,
                        "attempt_id": header["attempt_id"], "availability": row["availability"]}
            if len(notifications) != 1 or json.loads(notifications[0]["content"]) != expected:
                raise pending("原目标缺少唯一精确终态通知")
        current_participants = targets | {subject(header["sender"]) }
        if participants is not None and participants != current_participants:
            raise denied("首轮回收批次必须具有相同原参与者集合")
        participants = current_participants
        messages.append({"acceptance_id": acceptance_id,
                         "envelope_sha256": validate_message_acceptance(receipt)["envelope_sha256"],
                         "availability": row["availability"], "recipients": header["recipients"]})
    members = set(store.members(db))
    for pair in participants:
        device = db.execute("SELECT revoked FROM devices WHERE account=? AND device=?", pair).fetchone()
        if pair not in members or device is None or device["revoked"]:
            raise denied("原参与者已无当前权限，不能代其同意回收")
        if db.execute("SELECT 1 FROM rebuild_streams WHERE account=? AND device=?", pair).fetchone():
            raise denied("选择包含重建后继流")
    reserved = selected | {row[0] for row in db.execute("SELECT s.acceptance_id FROM reclamation_selection s "
                                                       "JOIN reclamation_plans p ON p.plan_id=s.plan_id WHERE p.status!='complete'")}
    keys = {db.execute("SELECT logical_key FROM attempts WHERE acceptance_id=?", (item,)).fetchone()[0] for item in reserved}
    attempt_count = sum(db.execute("SELECT COUNT(*) FROM attempts WHERE logical_key=? AND compacted=0", (key,)).fetchone()[0] for key in keys)
    event_count = sum(db.execute("SELECT COUNT(*) FROM events WHERE acceptance_id=? AND compacted=0", (item,)).fetchone()[0] for item in reserved)
    capacity(db, attempt_count, event_count)
    from reclamation_budget import check_proof_bytes
    check_proof_bytes(db, keys, reserved)
    return messages, participants


def required_processed(db, pair, ids):
    required = 0
    for acceptance_id in ids:
        required = max(required, db.execute("SELECT COALESCE(MAX(seq),0) FROM events WHERE account=? AND device=? AND acceptance_id=?",
                                           (*pair, acceptance_id)).fetchone()[0])
    return required
