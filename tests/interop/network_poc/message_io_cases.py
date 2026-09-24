"""M06：普通快照提交边界与已有独立锚的未决暂停分别验收。"""

import hashlib
import json
from functools import partial

from .anchor_fixture import sha256
from .fixture import SERVICE, check

OPERATIONS = ("wire_send", "wire_receive", "wire_download", "wire_process")
FAULTS = ("write", "file_sync", "rename", "directory_sync")
PAYLOAD = "synthetic-M06-消息"


def setup(lab, operation):
    stable = lab.prepare("m06_saved", payload="synthetic-M06-saved")
    if operation == "wire_send":
        return "a1", {"logical_message_id": "m06_target", "attempt_id": "P1", "payload": PAYLOAD}, None, stable
    packet = lab.prepare("m06_target", payload=PAYLOAD)
    accepted = lab.submit(packet)
    page = lab.pull("b1")
    slot = page["events"][0]
    receipt = {"acceptance_id": accepted["acceptance_id"], "attempt_id": "P1", "event_id": slot["event_id"]}
    data = {"packet": packet, "page": page, "receipt": receipt}
    if operation == "wire_receive":
        fields = packet["envelope"]
    elif operation == "wire_download":
        fields = page
    else:
        lab.download("b1", page)
        fields = {}
    return "b1", fields, data, stable


def compare_saved(lab, device, operation, before, committed):
    after = lab.rust(device, "wire_inspect")
    if not committed:
        check(after == before, "失败改变了旧密码状态/消息/双游标")
    else:
        for key in ("crypto_state_ref", "epoch", "group_id", "active", "configuration"):
            check(after[key] == before[key], "提交改变了非本次操作的身份或群状态")
        if operation == "wire_send":
            check(after["outbox_count"] == before["outbox_count"] + 1, "提交后缺少完整发送记录")
        elif operation in ("wire_receive", "wire_process"):
            check(after["inbox_count"] == 1, "提交后消息/去重不完整")
        if operation in ("wire_download", "wire_process"):
            sync = after["sync"]
            check(sync["download_cursor"] == "1" and sync["slot_count"] == 1,
                  "原始事件和下载游标没有共同提交")
            check(sync["processed_cursor"] == ("1" if operation == "wire_process" else "0"),
                  "处理游标和下载进度混淆")
    lab.case_evidence["after_observed_restart"] = after


def recover(lab, device, operation, fields, data, stable, committed):
    if operation == "wire_send":
        if not committed:
            # 普通入口没有独立预约，不能把重新加密同一失败意图当作安全恢复。
            cached = lab.prepare("m06_saved", payload="synthetic-M06-saved")
            check(cached["reused"] and cached["envelope"] == stable["envelope"], "已存原密文丢失或被重算")
            lab.case_evidence["recovery"] = "old_snapshot_and_existing_outbox_only_unsaved_intent_not_reexecuted"
            return
        packet = lab.rust(device, operation, **fields)
        check(packet["reused"], "已提交但应答失败的发送被重新加密")
        again = lab.rust(device, operation, **fields)
        check(again["reused"] and again["envelope"] == packet["envelope"], "重启未复用精确密文")
        first = lab.submit(packet)
        check(lab.submit(again) == first and lab.control("stats")["accepted"] == "1", "重试重复接受")
        received = lab.receive("b1", packet)
        check(received["payload_sha256"] == hashlib.sha256(PAYLOAD.encode()).hexdigest(), "恢复密文不可解密")
        lab.case_evidence["recovery"] = "observed_committed_outbox_reused_not_power_loss_proof"
        return
    if operation == "wire_receive":
        result = lab.rust(device, operation, **fields)
        check(result["duplicate"] is committed, "接收去重与实际提交边界不符")
        check(result["payload_sha256"] == hashlib.sha256(PAYLOAD.encode()).hexdigest(), "接收正文摘要错误")
        check(lab.rust(device, operation, **fields)["duplicate"], "已保存接收被重复处理")
        deliveries = [data["receipt"]]
    else:
        if operation == "wire_download":
            lab.rust(device, operation, **fields)
            lab.rust(device, operation, **fields)
        result = lab.rust(device, "wire_process")
        expected_results = 0 if operation == "wire_process" and committed else 1
        check(len(result["results"]) == expected_results, "重新处理丢失或重复业务结果")
        if result["results"]:
            message = result["results"][0]["result"]["message"]
            check(message["payload_sha256"] == hashlib.sha256(PAYLOAD.encode()).hexdigest(), "落盘原件不可恢复")
        deliveries = result["deliveries"]
        check(deliveries == [data["receipt"]], "持久结果的送达归属错误")
        again = lab.rust(device, "wire_process")
        check(again["results"] == [] and again["deliveries"] == deliveries, "重启后重复业务结果")
        current = lab.rust(device, "wire_inspect")
        check(current["sync"]["download_cursor"] == current["sync"]["processed_cursor"] == "1", "恢复双游标不一致")
    for receipt in deliveries:
        first = lab.http(device, "report_delivery", {"service_id": SERVICE, **receipt})
        check(lab.http(device, "report_delivery", {"service_id": SERVICE, **receipt}) == first,
              "恢复后的设备确认不幂等")
    check(lab.control("stats")["receipts"] == "1", "恢复出现重复回执")
    check(lab.rust(device, "wire_inspect")["inbox_count"] == 1, "恢复出现重复业务记录")
    lab.case_evidence["recovery"] = "persisted_message_dedup_cursors_and_repeatable_receipt"


def io_failure(lab, operation, fault, anchored=False):
    device, fields, data, stable = setup(lab, operation)
    before = lab.rust(device, "wire_inspect")
    if anchored:
        lab.enable(device)
    old = sha256(lab.snapshot(device))
    stats = lab.control("stats")
    lab.case_evidence.update(operation=operation, fault=fault, anchored=anchored,
                             before=before, before_snapshot_sha256=old, relay_before=stats,
                             input_sha256=hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest())
    reply = lab.fault(device, operation, fault, **fields)
    lab.dispatch(reply, operation, data["receipt"] if data else None)
    check(lab.control("stats") == stats, "保存失败却提交了消息或送达确认")
    saved = sha256(lab.snapshot(device))
    committed = fault == "directory_sync"
    check((old != saved) is committed, "实际快照与系统错误窗口不符")
    lab.case_evidence.update(after_snapshot_sha256=saved, relay_after_failure=lab.control("stats"),
                             durability="unknown" if committed else "old_snapshot_preserved")
    lab.restart()
    if anchored:
        lab.paused_after_restart(device, operation, fields)
        check(lab.control("stats") == stats, "未决暂停产生消息或送达")
    else:
        compare_saved(lab, device, operation, before, committed)
        recover(lab, device, operation, fields, data, stable, committed)
    lab.case_evidence["final_stats"] = lab.control("stats")


def crash_window(lab, operation, point, code):
    device, fields, data, stable = setup(lab, operation)
    before = lab.rust(device, "wire_inspect")
    old = sha256(lab.snapshot(device))
    stats = lab.control("stats")
    result = lab.raw_rust(device, operation, failpoint=point, **fields)
    lab.case_evidence.update(operation=operation, point=point, exit_code=result.returncode,
                             before=before, before_snapshot_sha256=old, relay_before=stats)
    check(result.returncode == code and not result.stdout.strip(), "受控退出泄漏成功输出或窗口错误")
    check(lab.control("stats") == stats, "未交付结果却生成消息/回执")
    committed = point == "after_save"
    check((sha256(lab.snapshot(device)) != old) is committed, "退出后快照不符合提交边界")
    lab.restart()
    compare_saved(lab, device, operation, before, committed)
    recover(lab, device, operation, fields, data, stable, committed)
    lab.case_evidence["final_stats"] = lab.control("stats")


def exact_anchor_recovery(lab, operation):
    device, fields, data, _ = setup(lab, operation)
    lab.enable(device)
    stats = lab.control("stats")
    result = lab.raw_rust(device, operation, env={"RIM_ANCHOR_FAILPOINT": "after_journal"}, **fields)
    check(result.returncode == 87 and not result.stdout.strip(), "未在完整日志后退出")
    check(lab.control("stats") == stats, "恢复前有成功投递")
    saved = sha256(lab.snapshot(device))
    lab.resume(device)
    check(sha256(lab.snapshot(device)) == saved, "完整日志恢复重算了密码")
    recovered = lab.rust(device, operation, **fields)
    if operation == "wire_send":
        check(recovered["reused"], "已保存发送没有精确复用")
    else:
        check(recovered["results"] == [] and recovered["deliveries"] == [data["receipt"]], "处理结果没有精确恢复")
        current = lab.rust(device, "wire_inspect")
        check(current["inbox_count"] == 1, "完整日志恢复丢失业务消息")
        check(current["sync"]["download_cursor"] == current["sync"]["processed_cursor"] == "1",
              "完整日志恢复丢失双游标")
        duplicate = lab.receive(device, data["packet"])
        check(duplicate["duplicate"] and duplicate["payload_sha256"] == hashlib.sha256(PAYLOAD.encode()).hexdigest(),
              "完整日志恢复丢失原消息或去重状态")
    first = lab.dispatch({"ok": True, "result": recovered}, operation)
    check(lab.dispatch({"ok": True, "result": recovered}, operation) == first, "恢复后重复提交响应变化")
    after = lab.control("stats")
    check(after["accepted"] == "1", "完整日志恢复产生重复接受")
    if operation == "wire_send":
        check(after["message_events"] == "3" and after["receipts"] == "0", "恢复发送扇出错误")
        received = lab.receive("b1", recovered)
        check(received["payload_sha256"] == hashlib.sha256(PAYLOAD.encode()).hexdigest(), "完整日志恢复密文不可解密")
    else:
        check(after["receipts"] == "1", "完整日志恢复送达不幂等")
    lab.case_evidence.update(operation=operation, recovery="complete_journal_exact_resume",
                             saved_sha256=saved, final_stats=lab.control("stats"))


CASES = []
for operation in OPERATIONS:
    short = operation.removeprefix("wire_")
    for fault in FAULTS:
        for anchored in (False, True):
            ident = f"M06.{short}.{fault}.{'anchor' if anchored else 'ordinary'}"
            CASES.append((ident, partial(io_failure, operation=operation, fault=fault, anchored=anchored)))
    for point, code in (("before_save", 83), ("before_rename", 84), ("after_save", 85)):
        CASES.append((f"M06.{short}.{point}", partial(crash_window, operation=operation, point=point, code=code)))
for operation in ("wire_send", "wire_process"):
    CASES.append((f"M06.{operation.removeprefix('wire_')}.exact_resume", partial(exact_anchor_recovery, operation=operation)))
