"""M03回执提交窗口：真实丢响应/退出，重启从持久候选原样重报。"""

from functools import partial
import hashlib
import http.client
import json

from .fixture import ACCOUNTS, SERVICE, check, identity
from .sync_cases import receive_notifications
from .sync_support import Receiver, TARGETS, add_messages, relay_receipts, verify_receipts


def observed(rows):
    return {"sha256": hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest(),
            "receipts": rows["receipts"], "event_count": len(rows["events"]),
            "event_ids": [{k: e[k] for k in ("account", "device", "seq", "event_id")} for e in rows["events"]]}


def result_for(device, report):
    return {"acceptance_id": report["acceptance_id"], "attempt_id": report["attempt_id"],
            "device": identity(device), "delivered": True, "read": False}


def lost_confirmation(lab, receiver, report, confirmed, *, hook):
    device = receiver.device
    before = relay_receipts(lab)
    verify_receipts(before, confirmed)
    lab.control("hook", hook=hook)
    try:
        lab.http(device, "report_delivery", {"service_id": SERVICE, **report})
        raise AssertionError("故障点未丢弃设备确认应答")
    except (http.client.RemoteDisconnected, ConnectionResetError):
        pass
    if hook == "drop_after_commit":
        check(lab.process.poll() is None, "丢应答意外退出服务")
    else:
        check(lab.process.wait(timeout=10) == (86 if hook == "before_commit_exit" else 87),
              "Relay没有在指定提交边界真实退出")
    after = relay_receipts(lab)
    committed = hook != "before_commit_exit"
    verify_receipts(after, confirmed + ([(device, report)] if committed else []))
    if committed:
        check(len(after["events"]) == len(before["events"]) + 4, "确认提交没有完整通知四个原设备")
        before_ids = {e["event_id"]: e for e in before["events"]}
        check(all(e == before_ids[e["event_id"]] for e in after["events"] if e["event_id"] in before_ids),
              "新确认改动了原槽位")
    else:
        check(after == before, "提交前退出留下部分确认或设备事件")
    lab.restart()
    check(relay_receipts(lab) == after, "重启改变故障点真实持久结果")
    rebuilt = receiver.process()
    check(report in rebuilt["deliveries"], "重启CLI后无法从持久结果恢复原确认候选")
    reply = lab.http(device, "report_delivery", {"service_id": SERVICE, **report})
    check(reply == result_for(device, report), "重报未返回精确原设备/尝试状态")
    confirmed.append((device, report))
    verify_receipts(relay_receipts(lab), confirmed)
    if committed:
        check(relay_receipts(lab) == after, "已提交确认重报新增或改变了状态通知")
    lab.case_evidence.setdefault("failpoints", []).append({
        "device": device, "report": report, "hook": hook, "response_lost": True,
        "committed_before_restart": committed, "before": observed(before), "after": observed(after),
        "retry_response": reply, "recovered_candidates": rebuilt["deliveries"]})


def finish_receipt_streams(lab, packets, receivers, confirmed):
    rows = relay_receipts(lab)
    verify_receipts(rows, confirmed)
    check(len(rows["receipts"]) == 60 and len(rows["events"]) == 300, "最终确认或全流事件总数错误")
    check(sum(e["event"]["type"] == "message" for e in rows["events"]) == 60, "确认重试产生新消息槽")
    receivers["a1"] = Receiver(lab, "a1", packets)
    pages = {}
    for device in ACCOUNTS:
        receiver = receivers[device]
        high = 60 if device == "a1" else 80
        while receiver.cursor < high:
            after = max(0, receiver.cursor - 2)
            page = lab.pull(device, str(after), "17")
            receiver.download(page, after, 17, high=high)
            receiver.process()
        check(len(receiver.seen) == (0 if device == "a1" else 20), "确认槽改变有效消息数量")
        full = lab.pull(device)
        check(full["events"] == [receiver.slots[i] for i in range(1, high + 1)], "完整设备流与已处理槽不符")
        pages[device] = full
    lab.restart()
    check(relay_receipts(lab) == rows, "最终重启改变持久回执或槽位")
    for device, receiver in receivers.items():
        page = lab.pull(device)
        check(page == pages[device], "最终重启改变完整设备页")
        high = 60 if device == "a1" else 80
        receiver.download(page, 0, 100, high=high)
        receiver.process()
        for report in receiver.candidates():
            check(lab.http(device, "report_delivery", {"service_id": SERVICE, **report}) == result_for(device, report),
                  "最终全量候选重报响应改变")
    check(relay_receipts(lab) == rows, "全量60次重报产生重复回执/通知")
    for logical, (saved, accepted) in packets.items():
        check(lab.attempt(logical) == accepted and lab.submit(saved) == accepted, "回执重试改变原消息接受")
    stats = lab.control("stats")
    check(stats["accepted"] == stats["attempts"] == "20" and stats["message_events"] == "60"
          and stats["receipts"] == "60" and stats["events"] == "300", "最终接受、确认、投递计数错误")
    lab.case_evidence.update(final_stats=stats, final_rows=observed(rows), final_pages=pages)


def confirmation_recovery(lab, *, hook, position):
    packets = {}
    add_messages(lab, packets)
    receivers = receive_notifications(lab, packets, limit=7, overlap=3, process_every=2, restart_midway=False)
    confirmed = []
    for device in TARGETS:
        receiver = receivers[device]
        for index, report in enumerate(receiver.candidates()):
            if index == position:
                lost_confirmation(lab, receiver, report, confirmed, hook=hook)
            else:
                reply = lab.http(device, "report_delivery", {"service_id": SERVICE, **report})
                check(reply == result_for(device, report), "普通确认结果归属错误")
                confirmed.append((device, report))
    finish_receipt_streams(lab, packets, receivers, confirmed)
    lab.case_evidence.update(hook=hook, fault_message_ordinal=position + 1)


CASES = [(f"M03.delivery.{hook}.message_{position + 1:02}",
          partial(confirmation_recovery, hook=hook, position=position))
         for hook in ("drop_after_commit", "before_commit_exit", "after_commit_exit")
         for position in (0, 9, 19)]
