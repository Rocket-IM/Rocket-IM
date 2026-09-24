"""M11.g：原签名消息追加为两个真实槽，逐槽处理、业务去重与回执幂等。"""

from functools import partial

from .fixture import ACCOUNTS, SERVICE, check, identity
from .slot_support import (check_message_result, check_message_slot, check_sync,
                           delivery_for, digest, inspect_slot, publish)
from .sync_support import TARGETS, relay_receipts, verify_receipts


def process_messages(lab, device, slots, new_sequences, logical, payload_hash):
    result = lab.rust(device, "wire_process")
    check([r["event_seq"] for r in result["results"]] == [str(s) for s in new_sequences], "处理遗漏新槽或重复发布旧槽")
    for item in result["results"]:
        seq = int(item["event_seq"])
        check(item["event_id"] == slots[seq - 1]["event_id"], "处理结果事件ID错误")
        check_message_result(item["result"], slots[seq - 1], logical, payload_hash, seq == 2)
    check(result["deliveries"] == [delivery_for(s) for s in slots], "两合法槽没有形成各自可重报候选")
    check_sync(result["sync"], len(slots), len(slots))
    state = lab.rust(device, "wire_inspect")
    check(state["inbox_count"] == 1, "同一合法消息在不同槽产生重复业务记录")
    return result


def report(lab, device, candidate):
    result = lab.http(device, "report_delivery", {"service_id": SERVICE, **candidate})
    check(result == {"acceptance_id": candidate["acceptance_id"], "attempt_id": "P1",
                     "device": identity(device), "delivered": True, "read": False},
          "送达回执扩大设备范围或隐式标记已读")
    return result


def drain_receipts(lab, targets):
    for device in ACCOUNTS:
        after = "0" if device == "a1" else "2"
        page = lab.pull(device, after)
        check(len(page["events"]) == 3 and all(s["event"]["type"] == "delivery" for s in page["events"]),
              "每个涉及设备应只取得三条送达通知")
        lab.download(device, page)
        value = lab.rust(device, "wire_process")
        check([r["event_seq"] for r in value["results"]] == [s["event_seq"] for s in page["events"]]
              and all(r["result"] == {"status": "receipt_recorded"} for r in value["results"]),
              "送达通知没有逐槽处理")
        candidates = [] if device == "a1" else targets[device]["deliveries"]
        check(value["deliveries"] == candidates, "处理通知改动原消息送达候选")
        cursor = 3 if device == "a1" else 5
        check_sync(value["sync"], cursor, cursor)
        state = lab.rust(device, "wire_inspect")
        check(state["inbox_count"] == (0 if device == "a1" else 1), "处理通知产生额外业务消息")
        again = lab.rust(device, "wire_process")
        check(again["results"] == [] and again["deliveries"] == candidates, "通知重放重复发布结果")
        lab.case_evidence.setdefault("after_receipts", {})[device] = state
        if device != "a1":
            for seq in (1, 2):
                inspect_slot(lab, device, seq, targets[device]["stored_slots"][seq - 1])


def duplicate(lab, *, schedule, reverse):
    logical = "legitimate_two_slots"
    packet, accepted, payload_hash = publish(lab, logical)
    first_pages = {device: lab.pull(device) for device in TARGETS}
    lab.case_evidence.update(schedule=schedule, receipt_order="reverse" if reverse else "forward", targets={})
    for device, page in first_pages.items():
        check(len(page["events"]) == 1, "原接受应给每目标一个槽")
        check_message_slot(page["events"][0], packet, accepted, 1)
        if schedule != "together":
            lab.download(device, page)
            if schedule == "split":
                process_messages(lab, device, page["events"], (1,), logical, payload_hash)
            else:
                pending = inspect_slot(lab, device, 1)
                check(pending["slot"] == page["events"][0] and pending["result"] is None,
                      "待处理重启基线错误")
        lab.duplicate(device, page["events"][0]["event_id"])
    if schedule != "together":
        lab.restart()

    targets = lab.case_evidence["targets"]
    full_pages = {}
    for device in TARGETS:
        full = lab.pull(device)
        check(len(full["events"]) == 2 and full["watermark"] == full["next_after_seq"] == "2"
              and not full["has_more"], "追加槽不在真实连续设备流内")
        slots = full["events"]
        for seq, slot in enumerate(slots, 1):
            check_message_slot(slot, packet, accepted, seq)
            check(slot["stream_id"] == full["stream_id"], "两槽流代际不一致")
        check(slots[0] == first_pages[device]["events"][0]
              and slots[0]["event_id"] != slots[1]["event_id"]
              and slots[0]["event"] == slots[1]["event"], "装置未保留原槽或不是原消息异槽重复")
        page = full if schedule == "together" else lab.pull(device, "1", "1")
        lab.download(device, page)
        sequences = (2,) if schedule == "split" else (1, 2)
        value = process_messages(lab, device, slots, sequences, logical, payload_hash)
        stored = [inspect_slot(lab, device, seq) for seq in (1, 2)]
        for seq, observed in enumerate(stored, 1):
            check(observed["found"] and observed["slot"] == slots[seq - 1] and not observed["waiting"],
                  "独立重载的原槽内容不完整")
            check_message_result(observed["result"], slots[seq - 1], logical, payload_hash, seq == 2)
        for _ in range(2):
            lab.download(device, full)
            replay = process_messages(lab, device, slots, (), logical, payload_hash)
            check(replay["sync"] == value["sync"], "重放改变双游标")
        targets[device] = {"stored_slots": stored, "stored_sha256": [digest(s) for s in stored],
                           "deliveries": value["deliveries"], "sync": value["sync"], "inbox_count": 1}
        full_pages[device] = full
    check(lab.control("stats")["accepted"] == "1"
          and lab.control("stats")["message_events"] == "6", "异槽装置额外接受消息或遗漏目标")

    lab.restart()
    restored = {}
    for device in TARGETS:
        check(lab.pull(device) == full_pages[device], "重启改变已提交原消息槽")
        slots = full_pages[device]["events"]
        value = process_messages(lab, device, slots, (), logical, payload_hash)
        check(value["deliveries"] == targets[device]["deliveries"], "重启未恢复两个原事件候选")
        restored[device] = value["deliveries"]
    # 首个确认会向全部设备追加通知；先核对所有原页，再开始报告。
    reports = []
    for device in TARGETS:
        candidates = restored[device]
        ordered = list(reversed(candidates)) if reverse else candidates
        first = report(lab, device, ordered[0])
        rows = relay_receipts(lab)
        check(report(lab, device, ordered[1]) == first and relay_receipts(lab) == rows,
              "另一真实槽报告导致重复回执或再次扇出")
        reports.append((device, ordered[0]))
        targets[device]["receipt"] = first
        targets[device]["both_candidates_idempotent"] = True
    rows = relay_receipts(lab)
    verify_receipts(rows, reports)
    check(len(rows["events"]) == 18, "六消息槽加十二通知槽的总数错误")
    drain_receipts(lab, targets)
    final_pages = {device: lab.pull(device) for device in ACCOUNTS}
    lab.restart()
    for device in ACCOUNTS:
        check(lab.pull(device) == final_pages[device], "最终重启改变原流内容")
    for device in TARGETS:
        value = lab.rust(device, "wire_process")
        check(value["results"] == [] and value["deliveries"] == targets[device]["deliveries"],
              "最终重启重复处理消息或改变候选")
        check_sync(value["sync"], 5, 5)
        for candidate in value["deliveries"]:
            check(report(lab, device, candidate) == targets[device]["receipt"], "重启后重报回执结果不稳定")
        for seq in (1, 2):
            inspect_slot(lab, device, seq, targets[device]["stored_slots"][seq - 1])
    check(relay_receipts(lab) == rows and lab.attempt(logical) == accepted,
          "重报制造新的接受/槽位/回执或隐式已读")
    lab.case_evidence["final_relay"] = {"receipts": rows["receipts"], "event_count": len(rows["events"]),
                                        "committed_view_sha256": digest(rows), "unchanged_after_restart_reports": True}


CASES = [(f"M11.duplicate.{schedule}.{order}", partial(duplicate, schedule=schedule, reverse=order == "reverse"))
         for schedule in ("together", "split", "queued_restart") for order in ("forward", "reverse")]
