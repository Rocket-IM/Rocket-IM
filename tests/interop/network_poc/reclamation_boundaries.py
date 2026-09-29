"""显式回收的内容、范围和依赖负例；拒绝必须保留原快照与Relay载荷。"""

import base64
from copy import deepcopy
import json

from .fixture import check, identity
from .reclamation_cases import compacted
from .reclamation_fixture import (DEVICES, apply, approve, database, finish, prepare_requests,
                                  publish, snapshot, synchronize, terminal_candidate)


def reject(lab, device, operation, code, **fields):
    before, rows = snapshot(lab, device), database(lab)
    error = lab.rust(device, operation, expected_exit=1, **fields)
    check(error["code"] == code and snapshot(lab, device) == before and database(lab) == rows,
          f"拒绝应为{code}并保留状态，实际{error}")
    lab.case_evidence.setdefault("rejections", []).append({"device": device, "operation": operation,
        "error": error, "snapshot_before": before, "snapshot_after": snapshot(lab, device)})
    return error


def available(lab):
    record = publish(lab, "still-available")
    synchronize(lab, "b1", report_delivery=True)
    synchronize(lab, "b1")
    reject(lab, "b1", "wire_reclaim_request", "reclaim_target_invalid", plan_id="not-terminal",
           acceptance_ids=[record["accepted"]["acceptance_id"]])
    check(database(lab)["attempts"][0]["payload_bytes"] > 0, "仍可用消息被清理")
    lab.case_evidence["progress"] = "AVAILABLE_CONTENT_BLOCKED_NO_RECLAMATION"


def pending_read(lab):
    record = publish(lab, "pending-read")
    for device in DEVICES[1:]:
        synchronize(lab, device, report_delivery=True)
    for device in DEVICES:
        synchronize(lab, device)
    slot = lab.rust("b1", "wire_slot_inspect", event_seq="1")["slot"]
    marked = lab.rust("b1", "wire_read", event_ids=[slot["event_id"]])
    check(marked["pending_count"] == 1, "没有建立真实未完成阅读意图")
    lab.control("set_availability", acceptance_id=record["accepted"]["acceptance_id"], availability="deleted")
    synchronize(lab, "b1")
    reject(lab, "b1", "wire_reclaim_request", "reclaim_dependency", plan_id="pending-read-plan",
           acceptance_ids=[record["accepted"]["acceptance_id"]])
    check(lab.rust("b1", "wire_read_inspect")["pending_count"] == 1, "拒绝回收清除了待确认阅读")
    lab.case_evidence["progress"] = "PENDING_READING_BLOCKED_AND_PRESERVED"


def unconfirmed_delivery(lab):
    record = publish(lab, "delivery-unconfirmed")
    synchronize(lab, "b1")
    lab.control("set_availability", acceptance_id=record["accepted"]["acceptance_id"], availability="deleted")
    synchronize(lab, "b1")
    reject(lab, "b1", "wire_reclaim_request", "reclaim_dependency", plan_id="without-delivery",
           acceptance_ids=[record["accepted"]["acceptance_id"]])
    lab.case_evidence["progress"] = "MISSING_DELIVERY_CONFIRMATION_BLOCKED"


def incomplete_participants(lab):
    record = terminal_candidate(lab)
    requests = prepare_requests(lab, [record])
    for device in DEVICES[:-1]:
        result = lab.http(device, "confirm_reclaim", requests[device])
        check(result["status"] == "pending" and "receipt" not in result,
              "原参与者尚未全部确认却发放许可")
    waiting = database(lab)
    lab.restart()
    check(database(lab) == waiting, "重启清除了离线参与者要求")
    check(lab.http("b1", "confirm_reclaim", requests["b1"])["status"] == "pending"
          and database(lab) == waiting, "重复确认替代了另一台原设备")
    lab.http("c1", "confirm_reclaim", requests["c1"])
    receipts = {device: lab.http(device, "confirm_reclaim", requests[device])["receipt"]
                for device in DEVICES}
    results = apply(lab, receipts)
    for device in DEVICES[:-1]:
        result = lab.http(device, "finish_reclaim", results[device]["finish_request"])
        check(result["status"] == "pending", "有设备尚未本机完成却先清Relay载荷")
    partial = database(lab)
    check(partial["attempts"][0]["payload_bytes"] > 0 and partial["attempts"][0]["compacted"] == 0,
          "未完成设备仍需的Relay载荷已提前删除")
    lab.restart()
    result = lab.http("c1", "finish_reclaim", results["c1"]["finish_request"])
    check(result["status"] == "complete", "最后设备完成后未恢复合法回收")
    compacted(lab, [record])
    lab.case_evidence.update(progress="MISSING_CONFIRM_OR_FINISH_BLOCKS_THEN_EXPLICITLY_RECOVERS",
                            before_final_confirmation=waiting, before_final_finish=partial)


def invalid_permits(lab):
    record = terminal_candidate(lab)
    receipts = approve(lab, prepare_requests(lab, [record]))
    reject(lab, "b1", "wire_reclaim", "reclaim_conflict", receipt=receipts["a2"])
    broken = deepcopy(receipts["b1"])
    signature = bytearray(base64.b64decode(broken["signature_bytes"]))
    signature[-1] ^= 1
    broken["signature_bytes"] = base64.b64encode(signature).decode()
    reject(lab, "b1", "wire_reclaim", "reclaim_signature", receipt=broken)
    finish(lab, apply(lab, receipts))
    compacted(lab, [record])
    lab.case_evidence["progress"] = "CROSS_ACCOUNT_AND_SIGNATURE_REJECTED_VALID_PERMIT_RECOVERS"


def migration_reference(lab):
    record = terminal_candidate(lab)
    accepted = record["accepted"]
    fact = json.loads(base64.b64decode(accepted["acceptance_receipt"]["statement_bytes"]))
    request = lab.rust("a1", "history_request", transfer_id="selected-history", source=identity("a2"),
        selection=[{"acceptance_id": accepted["acceptance_id"], "envelope_sha256": fact["envelope_sha256"]}])
    check("request" in request, "没有建立真实定向迁移选择")
    for cancelled in (False, True):
        if cancelled:
            lab.rust("a1", "history_cancel", transfer_id="selected-history")
        reject(lab, "a1", "wire_reclaim_request", "reclaim_dependency", plan_id="migration-blocked",
               acceptance_ids=[accepted["acceptance_id"]])
    lab.case_evidence["progress"] = "EVER_SELECTED_MIGRATION_BLOCKS_EVEN_AFTER_CANCELLATION"


def old_requests(lab):
    record = terminal_candidate(lab)
    receipts = approve(lab, prepare_requests(lab, [record]))
    finish(lab, apply(lab, receipts))
    rows = compacted(lab, [record])
    wires = {device: lab.rust(device, "wire_inspect") for device in DEVICES}
    repeated = lab.rust("a1", "wire_send", logical_message_id=record["logical"], attempt_id="P1", payload=record["payload"])
    check(repeated["payload_reclaimed"] and repeated["status"] == "accepted" and "envelope" not in repeated,
          "已清发送请求重建了旧密文或隐藏内容不可用")
    reject(lab, "a1", "wire_send", "idempotency_conflict", logical_message_id=record["logical"],
           attempt_id="P1", payload="changed-original")
    reject(lab, "a1", "wire_send", "acceptance_conflict", logical_message_id=record["logical"],
           attempt_id="P2", payload=record["payload"])
    duplicate = lab.rust("b1", "wire_receive", **record["packet"]["envelope"],
        acceptance_id=record["accepted"]["acceptance_id"],
        acceptance_receipt=record["accepted"]["acceptance_receipt"])
    check(duplicate["duplicate"] and duplicate["payload_reclaimed"]
          and duplicate["payload_sha256"] == record["payload_sha256"] and "payload" not in duplicate,
          "已清收件重复输入重新交付正文或丢失原摘要")
    late = lab.rust("a1", "wire_accept", logical_message_id=record["logical"], attempt_id="P1",
                    acceptance_receipt=record["accepted"]["acceptance_receipt"])
    check(late["duplicate"] and late["payload_reclaimed"], "迟到原接受证明复活已清原件")
    reject(lab, "b1", "wire_read", "payload_reclaimed",
           event_ids=[record["old_page"]["events"][0]["event_id"]])
    reject(lab, "b1", "wire_download_signed", "cursor_invalid", **record["old_page"].signed_input())
    late_read = lab.http("b1", "report_read", {"service_id": lab.service,
        "acceptance_ids": [record["accepted"]["acceptance_id"]]}, expected=409)
    check(late_read["code"] == "reclamation_conflict", "迟到首次阅读改变已固定回收终态")
    gap = lab.pull("b1", after="0", limit="100", expected=409)
    check(gap["code"] == "cursor_reclaimed" and "retention_receipt" in gap,
          "旧HTTP游标没有返回签名缺口证明")
    before_retention = snapshot(lab, "b1")
    retained = lab.rust("b1", "wire_retention", receipt=gap["retention_receipt"], after_seq="0", limit="100")
    check(retained["status"] == "recovery_required" and snapshot(lab, "b1") == before_retention,
          "签名缺口处理错误跳过本机游标或改写快照")
    reject(lab, "a2", "wire_retention", "retention_conflict", receipt=gap["retention_receipt"], after_seq="0", limit="100")
    reject(lab, "b1", "wire_retention", "retention_conflict", receipt=gap["retention_receipt"], after_seq="0", limit="99")
    for operation in ("get_attempt", "close_attempt"):
        result = lab.attempt(record["logical"], operation=operation)
        check(result["acceptance_id"] == record["accepted"]["acceptance_id"] and result["outcome"] == "accepted",
              "旧终态查询或封口改变了接受事实")
    result = lab.submit(record["packet"])
    check(result["acceptance_id"] == record["accepted"]["acceptance_id"] and result["outcome"] == "accepted",
          "Relay原密文重试产生第二次接受")
    check(database(lab) == rows and wires == {device: lab.rust(device, "wire_inspect") for device in DEVICES},
          "旧请求改变回收计数、密码或Relay终态")
    lab.case_evidence.update(progress="OLD_EXACT_REQUESTS_REMAIN_COMPACT_AND_CONFLICTS_REFUSE",
        repeated_send=repeated, duplicate_receive=duplicate, late_acceptance=late,
        late_read_error=late_read, cursor_gap=gap, local_gap_result=retained)


CASES = [("M12.reclaim.available_blocked", available),
         ("M12.reclaim.pending_read_blocked", pending_read),
         ("M12.reclaim.delivery_unconfirmed", unconfirmed_delivery),
         ("M12.reclaim.incomplete_participants", incomplete_participants),
         ("M12.reclaim.invalid_permits", invalid_permits),
         ("M12.reclaim.migration_reference", migration_reference),
         ("M12.reclaim.old_requests", old_requests)]
