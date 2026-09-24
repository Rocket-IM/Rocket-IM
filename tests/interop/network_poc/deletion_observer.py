"""M11.d 测试专用只读观察：保留接受事实与槽位摘要，不导出密文或秘密。"""

from contextlib import closing
from copy import deepcopy
import hashlib
import json
import sqlite3

from .fixture import check


def _bytes_digest(value):
    return None if value is None else hashlib.sha256(value).hexdigest()


def relay_records(lab):
    """在同一显式只读事务中观察合成 Relay；不供 SDK 或业务调用。"""
    uri = (lab.directory / "relay.sqlite").resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, isolation_level=None)) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        try:
            logical_messages = [dict(row) for row in db.execute(
                "SELECT key,tail,accepted_attempt FROM logical_messages ORDER BY key")]
            attempts = []
            for row in db.execute(
                    "SELECT logical_key,attempt_id,header,payload,outcome,acceptance_id,"
                    "availability,closure_id,successor,result FROM attempts "
                    "ORDER BY logical_key,attempt_id"):
                item = dict(row)
                item["header_sha256"] = _bytes_digest(item.pop("header"))
                item["payload_sha256"] = _bytes_digest(item.pop("payload"))
                # 原 result 不随可用性投影改写，用于区分接受事实与当前展示状态。
                item["result"] = json.loads(item["result"])
                attempts.append(item)
            events = []
            watermarks = {}
            for row in db.execute(
                    "SELECT account,device,seq,event_id,content,acceptance_id,availability "
                    "FROM events ORDER BY account,device,seq"):
                item = dict(row)
                content = item.pop("content")
                item["type"] = json.loads(content)["type"]
                item["content_sha256"] = hashlib.sha256(content.encode("utf-8")).hexdigest()
                watermarks[(item["account"], item["device"])] = item["seq"]
                item["seq"] = str(item["seq"])
                events.append(item)
            receipts = [dict(row) for row in db.execute(
                "SELECT acceptance_id,account,device,delivered,is_read FROM receipts "
                "ORDER BY acceptance_id,account,device")]
            streams = [{**dict(row), "watermark": str(watermarks.get(
                (row["account"], row["device"]), 0))} for row in db.execute(
                    "SELECT account,device,stream_id FROM devices ORDER BY account,device")]
            db.commit()
        except BaseException:
            db.rollback()
            raise
    return {"logical_messages": logical_messages, "attempts": attempts, "events": events,
            "receipts": receipts, "streams": streams,
            "counts": {"attempts": len(attempts), "logical_messages": len(logical_messages),
                       "accepted": sum(row["outcome"] == "accepted" for row in attempts),
                       "events": len(events),
                       "message_events": sum(row["type"] == "message" for row in events),
                       "receipts": len(receipts)}}


def assert_terminal_transition(before, after, acceptance_id, availability):
    """本矩阵所有原目标仍有权：只许终态投影与每个原消息槽各一次通知。"""
    expected = deepcopy(before)
    attempts = [row for row in expected["attempts"] if row["acceptance_id"] == acceptance_id]
    check(len(attempts) == 1 and attempts[0]["outcome"] == "accepted"
          and attempts[0]["availability"] == "available", "删除前必须存在唯一可用接受记录")
    attempts[0]["availability"] = availability
    events = [row for row in expected["events"] if row["acceptance_id"] == acceptance_id
              and row["availability"] == "available"]
    check(any(row["type"] == "message" for row in events), "删除前必须存在可用消息槽")
    original_messages = [deepcopy(row) for row in events if row["type"] == "message"]
    for row in events:
        row["availability"] = availability
    original_ids = {row["event_id"] for row in before["events"]}
    notifications = [row for row in after["events"] if row["event_id"] not in original_ids]
    check(len(notifications) == len(original_messages), "终态通知少发、重复或扩散给非原目标")
    for original in original_messages:
        pair = (original["account"], original["device"])
        stream = next(row for row in expected["streams"] if (row["account"], row["device"]) == pair)
        sequence = int(stream["watermark"]) + 1
        candidates = [row for row in notifications if (row["account"], row["device"], row["seq"]) == (*pair, str(sequence))]
        check(len(candidates) == 1, "原消息目标没有精确连续的新通知")
        notification = candidates[0]
        event = {"type": "message_availability", "target_event_seq": original["seq"],
                 "target_event_id": original["event_id"], "acceptance_id": acceptance_id,
                 "attempt_id": attempts[0]["attempt_id"], "availability": availability}
        content_hash = hashlib.sha256(json.dumps(event, ensure_ascii=True, allow_nan=False,
                                                separators=(",", ":")).encode()).hexdigest()
        expected_notification = {"account": pair[0], "device": pair[1], "seq": str(sequence),
            "event_id": notification["event_id"], "acceptance_id": acceptance_id, "availability": "available",
            "type": "message_availability", "content_sha256": content_hash}
        check(notification == expected_notification, "新通知未绑定原消息槽、接受记录、尝试或终态")
        expected["events"].append(expected_notification)
        stream["watermark"] = str(sequence)
    expected["events"].sort(key=lambda row: (row["account"], row["device"], int(row["seq"])))
    expected["counts"]["events"] += len(notifications)
    check(after == expected, "终态改变了允许投影/通知之外的接受事实、密文、槽位或回执")


def assert_deleted_transition(before, after, acceptance_id):
    assert_terminal_transition(before, after, acceptance_id, "deleted")
