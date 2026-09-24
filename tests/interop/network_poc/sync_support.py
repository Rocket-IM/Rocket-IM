"""M03逐设备页/处理断言及已提交回执观察，不实现产品同步worker。"""

from contextlib import closing
import hashlib
import json
import sqlite3

from .fixture import ACCOUNTS, check, identity
from .message_cases import header

TARGETS = ("a2", "b1", "c1")


def add_messages(lab, packets, start=0, stop=20):
    for index in range(start, stop):
        logical = f"m03_message_{index:02}"
        saved = lab.prepare(logical, payload="synthetic-M03-" + logical)
        accepted = lab.submit(saved)
        check(accepted["recipients"] == [identity(d) for d in TARGETS], "接受目标集合不完整")
        packets[logical] = (saved, accepted)
    lab.case_evidence["accepted"] = {logical: accepted for logical, (_, accepted) in packets.items()}


class Receiver:
    def __init__(self, lab, device, packets):
        self.lab, self.device, self.packets = lab, device, packets
        self.slots, self.seen, self.processed = {}, set(), set()
        self.cursor = 0
        self.trace = []
        lab.case_evidence.setdefault("targets", {})[device] = {"trace": self.trace}

    def download(self, page, after, limit, *, high):
        events = page["events"]
        next_seq = int(page["next_after_seq"])
        check(page["stream_id"] == self.lab.streams[self.device] and int(page["watermark"]) == high,
              "HTTP页流归属或已提交水位错误")
        check(len(events) <= limit and [int(s["event_seq"]) for s in events]
              == list(range(after + 1, after + 1 + len(events))), "HTTP页跳过槽位或超限")
        check(next_seq == after + len(events) and page["has_more"] is (next_seq < high),
              "HTTP下一游标不对应已返回前缀")
        for slot in events:
            seq = int(slot["event_seq"])
            check(slot["stream_id"] == page["stream_id"] and slot["availability"] == "available", "槽位身份错误")
            event = slot["event"]
            if event["type"] == "message":
                logical = header({"envelope": event["envelope"]})["logical_message_id"]
                check(logical in self.packets, "取得非本轮接受消息")
                saved, accepted = self.packets[logical]
                check(event["envelope"] == saved["envelope"] and event["acceptance_id"] == accepted["acceptance_id"],
                      "目标槽原信封或接受ID变化")
            else:
                check(event["type"] == "delivery", "未显式阅读却出现read或未知事件")
            if seq in self.slots:
                check(slot == self.slots[seq], "重复/交叠槽位改变身份或正文")
        result = self.lab.download(self.device, page)
        check(result["status"] == "downloaded" and result["sync"]["download_cursor"] == str(next_seq),
              "下载未推进到实际完整前缀")
        duplicate = self.lab.download(self.device, page)
        check(duplicate == result, "同页重复改变下载结果")
        self.slots.update({int(slot["event_seq"]): slot for slot in events})
        self.cursor = next_seq
        self.trace.append({"operation": "download_twice", "after": str(after), "limit": str(limit),
                           "next": str(next_seq), "watermark": str(high), "has_more": page["has_more"],
                           "slots": [{k: s[k] for k in ("event_seq", "event_id")} for s in events],
                           "page_sha256": hashlib.sha256(json.dumps(page, sort_keys=True).encode()).hexdigest(),
                           "sync": result["sync"]})

    def candidates(self):
        return [{"acceptance_id": self.slots[seq]["event"]["acceptance_id"], "attempt_id": "P1",
                 "event_id": self.slots[seq]["event_id"]} for seq in sorted(self.processed)
                if self.slots[seq]["event"]["type"] == "message"]

    def process(self):
        value = self.lab.rust(self.device, "wire_process")
        expected_seqs = sorted(set(self.slots) - self.processed)
        check([int(item["event_seq"]) for item in value["results"]] == expected_seqs,
              "处理遗漏新槽或再次发布已处理槽")
        for item in value["results"]:
            seq = int(item["event_seq"])
            slot = self.slots[seq]
            check(item["event_id"] == slot["event_id"], "处理事件归属改变")
            event, result = slot["event"], item["result"]
            if event["type"] == "message":
                check(result["status"] == "valid" and result["acceptance_id"] == event["acceptance_id"],
                      "合法消息被隔离/等待或接受归属改变")
                message = result["message"]
                logical = header({"envelope": event["envelope"]})["logical_message_id"]
                check(logical not in self.seen and message["logical_message_id"] == logical
                      and message["attempt_id"] == "P1" and message["duplicate"] is False
                      and message["payload_sha256"] == hashlib.sha256(("synthetic-M03-" + logical).encode()).hexdigest(),
                      "消息重复交付或MLS真实解密结果错误")
                self.seen.add(logical)
            else:
                check(result == {"status": "receipt_recorded"}, "回执槽没有形成独立处理结果")
            self.processed.add(seq)
        check(value["deliveries"] == self.candidates(), "持久送达候选遗漏或重复/错归属")
        check(value["sync"]["download_cursor"] == value["sync"]["processed_cursor"] == str(self.cursor)
              and value["sync"]["pending_count"] == value["sync"]["quarantined_count"] == 0,
              "合法事件处理后双游标或队列不完整")
        again = self.lab.rust(self.device, "wire_process")
        check(again["results"] == [] and again["deliveries"] == self.candidates()
              and again["sync"] == value["sync"], "新CLI重复处理改变业务或送达候选")
        state = self.lab.rust(self.device, "wire_inspect")
        check(state["inbox_count"] == len(self.seen) and not state["sync"]["halted"], "持久业务去重不符")
        self.trace.append({"operation": "process_twice", "new_sequences": [str(s) for s in expected_seqs],
                           "logical_ids": sorted(self.seen), "deliveries": value["deliveries"], "state": state})
        return value

    def reject(self, page, reason):
        path = self.lab.directory / self.device / "state.enc"
        before = path.read_bytes()
        error = self.lab.download(self.device, page, expected_exit=1)
        check(error["code"] == "cursor_invalid" and path.read_bytes() == before,
              "非法迟到/越缺口页没有明确拒绝或改变快照")
        self.trace.append({"operation": "rejected_page", "reason": reason, "page": page,
                           "error": error, "snapshot_unchanged": True,
                           "snapshot_sha256": hashlib.sha256(before).hexdigest()})


def relay_receipts(lab):
    """一次显式只读事务观察全部已提交回执/事件；不触碰端侧存储。"""
    uri = (lab.directory / "relay.sqlite").resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, isolation_level=None)) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        try:
            receipts = db.execute("SELECT acceptance_id,account,device,delivered,is_read FROM receipts ORDER BY acceptance_id,account,device").fetchall()
            events = db.execute("SELECT account,device,seq,event_id,content,availability FROM events ORDER BY account,device,seq").fetchall()
            db.commit()
        except BaseException:
            db.rollback()
            raise
    return {"receipts": [{"acceptance_id": r[0], "device": {"account_id": r[1], "device_id": r[2]},
                           "delivered": bool(r[3]), "read": bool(r[4])} for r in receipts],
            "events": [{"account": r[0], "device": r[1], "seq": str(r[2]), "event_id": r[3],
                        "event": json.loads(r[4]), "availability": r[5]} for r in events]}


def verify_receipts(rows, reports):
    check(len(rows["receipts"]) == len(reports), "已提交回执行数错误")
    expected = {(report["acceptance_id"], device) for device, report in reports}
    actual = {(row["acceptance_id"], row["device"]["device_id"]) for row in rows["receipts"]}
    check(actual == expected and all(row["delivered"] and not row["read"] for row in rows["receipts"]),
          "确认被扩大为其他设备或隐式阅读")
    check(all(row["device"] == identity(row["device"]["device_id"]) for row in rows["receipts"]),
          "回执行的账号与设备归属不匹配")
    delivery = [e for e in rows["events"] if e["event"]["type"] == "delivery"]
    check(len(delivery) == len(reports) * len(ACCOUNTS), "确认状态通知出现重复/部分扇出")
    check(all(e["event"]["type"] in ("message", "delivery") for e in rows["events"]), "出现隐式read事件")
    for target in ACCOUNTS:
        own = [e for e in rows["events"] if e["device"] == target]
        check([e["seq"] for e in own] == [str(i) for i in range(1, len(own) + 1)], "确认通知造成序号空洞")
        actual_events = [e["event"] for e in own if e["event"]["type"] == "delivery"]
        expected_events = [{"type": "delivery", "acceptance_id": report["acceptance_id"],
                            "attempt_id": report["attempt_id"], "device": identity(device)}
                           for device, report in reports]
        check(actual_events == expected_events, "确认通知顺序或设备/尝试归属错误")
