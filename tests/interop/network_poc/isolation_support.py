"""双实例各自合法收发、接受绑定及恢复断言；不引入另一个客户端同步实现。"""

import hashlib

from .fixture import ACCOUNTS, check, identity
from .isolation_fixture import client_view, relay_view
from .slot_support import check_message_result, check_message_slot, check_sync, delivery_for, inspect_slot
from .sync_support import TARGETS


def publish_and_receive(pair, label, logical):
    lab = pair.labs[label]
    payload = "synthetic-" + lab.service + "-" + logical
    packet = lab.prepare(logical, payload=payload)
    accepted = lab.submit(packet)
    check(accepted["recipients"] == [identity(d) for d in TARGETS] and bool(accepted["acceptance_receipt"]),
          "真实签名接受目标不完整")
    check(lab.attempt(logical) == accepted, "同名逻辑消息未返回本实例自己的接受事实")
    receipt_fields = {"logical_message_id": logical, "attempt_id": "P1", "acceptance_receipt": accepted["acceptance_receipt"]}
    ack = lab.rust("a1", "wire_accept", **receipt_fields)
    check(ack["status"] == "accepted" and not ack["duplicate"] and ack["acceptance_id"] == accepted["acceptance_id"],
          "本实例发送方未验证并保存真实接受")
    check(lab.rust("a1", "wire_accept", **receipt_fields)["duplicate"], "原接受回执未幂等")
    expected_count = len(pair.records[label]) + 1
    slots = {}
    payload_hash = hashlib.sha256(payload.encode()).hexdigest()
    for device in TARGETS:
        before = lab.rust(device, "wire_inspect")
        page = lab.pull(device, before["sync"]["download_cursor"])
        check(len(page["events"]) == 1, "新一轮每目标应只有一条新消息")
        slot = page["events"][0]
        seq = int(before["sync"]["download_cursor"]) + 1
        check_message_slot(slot, packet, accepted, seq)
        lab.download(device, page)
        result = lab.rust(device, "wire_process")
        check(len(result["results"]) == 1 and result["results"][0]["event_seq"] == str(seq), "新消息未逐槽处理")
        check_message_result(result["results"][0]["result"], slot, logical, payload_hash, False)
        check_sync(result["sync"], seq, seq)
        check(result["deliveries"][-1] == delivery_for(slot) and len(result["deliveries"]) == expected_count,
              "本实例持久送达候选丢失或串入外实例")
        observed = inspect_slot(lab, device, seq)
        check(observed["slot"] == slot and observed["result"] == result["results"][0]["result"], "原槽落盘不完整")
        check(lab.rust(device, "wire_inspect")["inbox_count"] == expected_count, "业务消息跨实例或重复")
        slots[device] = slot
    # 原消息三个目标各自确认，通知应只扇出至本实例四设备。
    for device, slot in slots.items():
        value = lab.http(device, "report_delivery", {"service_id": lab.service, **delivery_for(slot)})
        check(value == {"acceptance_id": accepted["acceptance_id"], "attempt_id": "P1",
                        "device": identity(device), "delivered": True, "read": False}, "送达回执归属错误")
    final = {}
    for device in ACCOUNTS:
        before = lab.rust(device, "wire_inspect")
        page = lab.pull(device, before["sync"]["download_cursor"])
        check(len(page["events"]) == 3 and all(s["event"]["type"] == "delivery" for s in page["events"]),
              "本轮通知有遗漏、重复或隐式阅读")
        check([s["event"] for s in page["events"]] == [
            {"type": "delivery", "acceptance_id": accepted["acceptance_id"], "attempt_id": "P1",
             "device": identity(target)} for target in TARGETS], "通知接受事实、尝试、设备归属或顺序错误")
        lab.download(device, page)
        value = lab.rust(device, "wire_process")
        check([r["event_seq"] for r in value["results"]] == [s["event_seq"] for s in page["events"]]
              and all(r["result"] == {"status": "receipt_recorded"} for r in value["results"]), "通知进度未完整保存")
        cursor = expected_count * (3 if device == "a1" else 4)
        check_sync(value["sync"], cursor, cursor)
        again = lab.rust(device, "wire_process")
        check(again["results"] == [] and again["deliveries"] == value["deliveries"], "重载重复发布旧结果")
        final[device] = lab.rust(device, "wire_inspect")
        check(final[device]["inbox_count"] == (0 if device == "a1" else expected_count), "通知改变业务记录数")
    stats = lab.control("stats")
    check(stats["accepted"] == str(expected_count) and stats["message_events"] == str(expected_count * 3)
          and stats["receipts"] == str(expected_count * 3), "本实例接受或回执数量错误")
    record = {"packet": packet, "accepted": accepted, "slots": slots, "payload_sha256": payload_hash, "final": final}
    pair.records[label][logical] = record
    pair.evidence.setdefault("rounds", []).append({"service": label, "logical": logical, **record})


def round_trip(pair, logical):
    for label, lab in pair.labs.items():
        other_label = "S2" if label == "S1" else "S1"
        other = pair.labs[other_label]
        before = {"clients": client_view(other), "relay": relay_view(other)}
        publish_and_receive(pair, label, logical)
        check(before == {"clients": client_view(other), "relay": relay_view(other)}, "本实例合法操作污染另一实例")
        pair.evidence.setdefault("independent_rounds", []).append({"operated": label, "unchanged": other_label})
    first, second = [pair.records[label][logical] for label in pair.labs]
    check(first["packet"]["envelope"] != second["packet"]["envelope"]
          and first["accepted"]["acceptance_id"] != second["accepted"]["acceptance_id"]
          and first["payload_sha256"] != second["payload_sha256"], "同名消息没有独立身份与内容")
    for device in TARGETS:
        check(first["slots"][device]["stream_id"] != second["slots"][device]["stream_id"]
              and first["slots"][device]["event_id"] != second["slots"][device]["event_id"], "跨实例流或事件ID相同")


def reject_http(pair, lab, device, operation, fields, *, status, code, label, token=None):
    before = pair.capture()
    error = lab.http(device, operation, fields, expected=status, token=token)
    check(error["code"] == code, "HTTP跨实例错误码不符: " + label)
    pair.unchanged(before, label)
    pair.evidence.setdefault("rejections", []).append({"label": label, "http_status": status, "error": error})


def reject_rust(pair, lab, device, operation, fields, *, code, label):
    before = pair.capture()
    error = lab.rust(device, operation, expected_exit=1, **fields)
    check(error["code"] == code, "Rust跨实例错误码不符: " + label)
    pair.unchanged(before, label)
    pair.evidence.setdefault("rejections", []).append({"label": label, "error": error})
