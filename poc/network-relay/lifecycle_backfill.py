"""升级时冻结历史原消息槽，显式控制器事务内补齐至多一次终态通知。"""

import json

from contract import ProtocolError, fields, parse_u64, validate_envelope, validate_id
from lifecycle_backfill_auth import authority, lost_access, untrusted
from receipt_contract import message_acceptance_statement, validate_message_acceptance
from storage import Store, public_subject

VERSION = "rim-lifecycle-backfill-1"
SCHEMA = """
CREATE TABLE lifecycle_backfill (
    account TEXT NOT NULL, device TEXT NOT NULL, target_seq INTEGER NOT NULL CHECK(target_seq>0),
    target_event_id TEXT NOT NULL UNIQUE, acceptance_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
    availability TEXT NOT NULL CHECK(availability IN ('deleted','expired')),
    status TEXT NOT NULL CHECK(status IN ('pending','appended','existing','skipped')),
    notification_event_id TEXT,
    PRIMARY KEY(account,device,target_seq),
    CHECK((status IN ('appended','existing')) = (notification_event_id IS NOT NULL)))
"""


def install(db):
    """只由 schema 1..5→6 迁移调用；不发事件、不改变原业务事实。"""
    db.execute(SCHEMA)
    db.execute("INSERT INTO meta VALUES ('lifecycle_backfill_version',?)", (VERSION,))
    db.execute("INSERT INTO lifecycle_backfill SELECT e.account,e.device,e.seq,e.event_id,a.acceptance_id,"
               "a.attempt_id,a.availability,'pending',NULL FROM events e JOIN attempts a ON a.acceptance_id=e.acceptance_id "
               "WHERE a.outcome='accepted' AND a.availability IN ('deleted','expired') "
               "AND json_extract(e.content,'$.type')='message'")


def validate_schema(db):
    marker = db.execute("SELECT value FROM meta WHERE key='lifecycle_backfill_version'").fetchone()
    table = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='lifecycle_backfill'").fetchone()
    if marker is None or marker["value"] != VERSION or table is None:
        raise ValueError("历史回填版本或固定范围缺失，不能重新生成范围")


def conflict():
    return ProtocolError("lifecycle_backfill_conflict", "历史原槽、终态或已有通知绑定不一致", status=409)


def summary(db):
    counts = {status: 0 for status in ("pending", "appended", "existing", "skipped")}
    for row in db.execute("SELECT status,COUNT(*) AS count FROM lifecycle_backfill GROUP BY status"):
        counts[row["status"]] = row["count"]
    return {"version": VERSION, "scope_count": str(sum(counts.values())),
            **{status + "_count": str(count) for status, count in counts.items()}}


def original(db, target, checkpoint, refs):
    """原信封/回执仍保存于旧槽；回填只引用，不能修补或重签这些接受事实。"""
    row = db.execute("SELECT event_id,content,acceptance_id,availability FROM events WHERE account=? AND device=? AND seq=?",
                     (target["account"], target["device"], target["target_seq"])).fetchone()
    attempt = db.execute("SELECT attempt_id,header,payload,outcome,result,availability FROM attempts WHERE acceptance_id=?",
                         (target["acceptance_id"],)).fetchone()
    if (row is None or attempt is None or attempt["outcome"] != "accepted"
            or row["event_id"] != target["target_event_id"] or row["acceptance_id"] != target["acceptance_id"]
            or attempt["attempt_id"] != target["attempt_id"] or attempt["availability"] != target["availability"]
            or row["availability"] not in (target["availability"], "access_removed")):
        raise conflict()
    try:
        event, result = json.loads(row["content"]), json.loads(attempt["result"])
        fields(event, ("type", "acceptance_id", "envelope", "acceptance_receipt"))
        header, raw, payload = validate_envelope(event["envelope"])
        version = int(header["authorization_version"])
        receipt = validate_message_acceptance(event["acceptance_receipt"])
        if (event["type"] != "message" or event["acceptance_id"] != target["acceptance_id"]
                or raw != attempt["header"] or payload != attempt["payload"]
                or header["attempt_id"] != target["attempt_id"]
                or any(header[name] != checkpoint[name] for name in ("service_id", "conversation_id"))
                or refs.get(version) != header["crypto_state_ref"]
                or public_subject((target["account"], target["device"])) not in header["recipients"]
                or result.get("outcome") != "accepted" or result.get("acceptance_id") != target["acceptance_id"]
                or any(result.get(name) != header[name] for name in ("attempt_id", "logical_message_id", "recipients"))
                or event["acceptance_receipt"] != result.get("acceptance_receipt")
                or receipt != message_acceptance_statement(header, raw, payload, target["acceptance_id"])):
            raise untrusted()
    except (ProtocolError, ValueError, KeyError, TypeError):
        raise untrusted() from None
    return row, version


def notifications(db):
    """按原槽 ID 和同设备序号索引，避免对每个历史目标重新扫描整张事件表。"""
    by_id, by_slot = {}, {}
    for row in db.execute("SELECT account,device,seq,event_id,content,acceptance_id,availability FROM events "
                          "WHERE json_extract(content,'$.type')='message_availability'"):
        try:
            event = json.loads(row["content"])
            fields(event, ("type", "target_event_seq", "target_event_id", "acceptance_id", "attempt_id", "availability"))
            sequence = parse_u64(event["target_event_seq"])
            for name in ("target_event_id", "acceptance_id", "attempt_id"):
                validate_id(event[name], name)
            target = db.execute("SELECT content,acceptance_id,availability FROM events WHERE account=? AND device=? AND seq=? AND event_id=?",
                                (row["account"], row["device"], sequence, event["target_event_id"])).fetchone()
            if (sequence == 0 or sequence >= row["seq"] or target is None or event["availability"] not in ("deleted", "expired")
                    or row["acceptance_id"] != event["acceptance_id"] or target["acceptance_id"] != event["acceptance_id"]
                    or json.loads(target["content"]).get("type") != "message"
                    or target["availability"] not in (event["availability"], "access_removed")):
                raise conflict()
            by_id.setdefault(event.get("target_event_id"), []).append((row, event))
            key = (row["account"], row["device"], event.get("target_event_seq"))
            by_slot.setdefault(key, []).append((row, event))
        except (ProtocolError, ValueError, TypeError):
            raise conflict() from None
    return by_id, by_slot


def existing_notification(index, target, expected):
    pair = target["account"], target["device"]
    matches = {row["event_id"]: (row, event) for row, event in
               index[0].get(target["target_event_id"], []) + index[1].get((*pair, str(target["target_seq"])), [])}
    if not matches:
        return None
    if len(matches) != 1:
        raise conflict()
    row, event = next(iter(matches.values()))
    if ((row["account"], row["device"]) != pair or row["seq"] <= target["target_seq"] or event != expected
            or row["acceptance_id"] != target["acceptance_id"] or row["availability"] not in ("available", "access_removed")):
        raise conflict()
    return row["event_id"]


def backfill(store, db, req):
    fields(req, ("action", "version"))
    if req["version"] != VERSION:
        raise ProtocolError("unsupported_version", "不支持此历史生命周期回填版本", status=409)
    if Store.meta(db, "lifecycle_backfill_version") != VERSION:
        raise conflict()
    pending = db.execute("SELECT * FROM lifecycle_backfill WHERE status='pending' ORDER BY account,device,target_seq").fetchall()
    if not pending:
        return summary(db)
    checkpoint, refs, statements = authority(store, db)
    index = notifications(db)
    members = set(Store.members(db))
    devices = {(row["account"], row["device"]): row["revoked"]
               for row in db.execute("SELECT account,device,revoked FROM devices")}
    for target in pending:
        row, version = original(db, target, checkpoint, refs)
        pair = target["account"], target["device"]
        event = {"type": "message_availability", "target_event_seq": str(target["target_seq"]),
                 "target_event_id": target["target_event_id"], "acceptance_id": target["acceptance_id"],
                 "attempt_id": target["attempt_id"], "availability": target["availability"]}
        notification = existing_notification(index, target, event)
        if notification is not None:
            status = "existing"
        elif (pair not in members or devices.get(pair, 1) or row["availability"] == "access_removed"
              or lost_access(statements, version, pair)):
            status = "skipped"
        else:
            Store.append_event(db, pair, event, target["acceptance_id"])
            notification = db.execute("SELECT event_id FROM events WHERE account=? AND device=? ORDER BY seq DESC LIMIT 1", pair).fetchone()[0]
            status = "appended"
        db.execute("UPDATE lifecycle_backfill SET status=?,notification_event_id=? WHERE account=? AND device=? AND target_seq=?",
                   (status, notification, *pair, target["target_seq"]))
    return summary(db)
