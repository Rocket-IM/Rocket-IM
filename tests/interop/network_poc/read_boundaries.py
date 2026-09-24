"""M13 显式阅读的认证来源、消息目标、删除、撤销与旧程序兼容边界。"""

import base64
from copy import deepcopy
import hashlib
import json
import subprocess

from .deletion_observer import relay_records
from .deletion_support import check_deleted_slot, delete
from .fixture import check, identity
from .permission_cases import prepare as prepare_permission, submit as submit_permission
from .read_support import (finish, inspect, load_messages, mark, pending, publish,
                           refuse, report, snapshot, synchronize)


def final_boundary(lab, progress, *, device="b1"):
    state, exported, rows = inspect(lab, device), pending(lab, device), relay_records(lab)
    lab.restart()
    check(inspect(lab, device) == state and pending(lab, device) == exported and relay_records(lab) == rows,
          "重启改变阅读边界的原持久事实")
    lab.case_evidence.update(final_relay=rows, final_read_state=state, final_pending=exported,
                            progress=progress)


def source_required(lab):
    records = publish(lab)
    page = lab.pull("b1")
    ident = page["events"][0]["event_id"]
    refuse(lab, [ident], code="read_source_required")
    received = lab.receive("b1", records[0]["packet"])
    state = lab.rust("b1", "wire_inspect")
    check(not received["duplicate"] and received["payload_sha256"] == records[0]["payload_sha256"]
          and state["inbox_count"] == 1 and not state["sync"]["source_verified"],
          "直接接收没有真实收件，或被当作签名普通流来源")
    refuse(lab, [ident], code="read_source_required")
    check(inspect(lab)["records"] == [] and relay_records(lab)["receipts"] == [], "直接收件产生隐式阅读")
    lab.case_evidence["direct_receive_without_stream"] = {"signed_page_not_downloaded": page.wrapper,
        "received": received, "wire_state": state}
    final_boundary(lab, "NO_READ_INTENT_WITHOUT_AUTHENTICATED_STREAM")


def downloaded_not_processed(lab):
    publish(lab)
    page = lab.pull("b1")
    downloaded = lab.download("b1", page)
    state = lab.rust("b1", "wire_inspect")
    check(state["inbox_count"] == 0 and state["sync"]["source_verified"]
          and state["sync"]["download_cursor"] == "1" and state["sync"]["processed_cursor"] == "0",
          "下载阶段已产生成功收件或错误推进处理游标")
    refuse(lab, [page["events"][0]["event_id"]], code="read_target_invalid")
    lab.case_evidence["download_without_processing"] = {"signed_page": page.wrapper,
        "downloaded": downloaded, "wire_state": state}
    check(inspect(lab)["records"] == [] and relay_records(lab)["receipts"] == [], "仅下载产生阅读或回执")
    final_boundary(lab, "DOWNLOADED_MESSAGE_IS_NOT_YET_READABLE")


def exact_targets_and_atomic_batch(lab):
    records = publish(lab)
    ids = load_messages(lab, records)
    foreign = lab.pull("a2")["events"][0]["event_id"]
    check(foreign != ids[0], "不同设备意外共用消息事件 ID")
    refuse(lab, ["missing-read-event"], code="read_target_not_found")
    refuse(lab, [foreign], code="read_target_not_found")
    refuse(lab, [ids[0], "missing-read-event"], code="read_target_not_found")
    delivered = lab.http("b1", "report_delivery", {"service_id": lab.service,
        "acceptance_id": records[0]["accepted"]["acceptance_id"], "attempt_id": "P1", "event_id": ids[0]})
    check(delivered["delivered"] and not delivered["read"], "送达被转换为隐式阅读")
    synchronize(lab)
    receipt = lab.rust("b1", "wire_slot_inspect", event_seq="2")
    check(receipt["slot"]["event"]["type"] == "delivery" and receipt["result"] == {"status": "receipt_recorded"},
          "目标负例不是实际已处理的回执槽")
    refuse(lab, [receipt["slot"]["event_id"]], code="read_target_invalid")
    rows = relay_records(lab)
    check(inspect(lab)["records"] == [] and not any(row["is_read"] for row in rows["receipts"])
          and not any(row["type"] == "read" for row in rows["events"]), "错误批次或送达回执创建阅读事实")
    lab.case_evidence["target_boundaries"] = {"foreign_message_event_id": foreign,
        "delivery_response": delivered, "receipt_slot": receipt}
    final_boundary(lab, "INVALID_TARGETS_AND_BATCH_CREATE_ZERO_INTENTS")


def rejected_page_and_quarantine(lab):
    publish(lab)
    original = lab.pull("b1")
    tampered = original.signed_input()
    signature = bytearray(base64.b64decode(tampered["receipt"]["signature_bytes"], validate=True))
    signature[0] ^= 1
    tampered["receipt"]["signature_bytes"] = base64.b64encode(signature).decode()
    before, rows = snapshot(lab), relay_records(lab)
    error = lab.rust("b1", "wire_download_signed", expected_exit=1, **tampered)
    check(error["code"] == "stream_page_signature" and snapshot(lab) == before and relay_records(lab) == rows,
          "坏页签名未拒绝或写入端侧状态")
    refuse(lab, [original["events"][0]["event_id"]], code="read_source_required")
    bad = deepcopy(original)
    payload = bytearray(base64.b64decode(bad["events"][0]["event"]["envelope"]["payload_bytes"], validate=True))
    payload[-1] ^= 1
    bad["events"][0]["event"]["envelope"]["payload_bytes"] = base64.b64encode(payload).decode()
    # 明确合成 Service 作恶夹具：只重签传输页，保留原消息接受证明以触发精确密文绑定拒绝。
    signed_bad = lab.sign_test_page(bad)
    downloaded = lab.download("b1", signed_bad)
    processed = lab.rust("b1", "wire_process")
    check(processed["results"] == [{"event_seq": "1", "event_id": original["events"][0]["event_id"],
          "result": {"status": "quarantined", "code": "acceptance_conflict"}}]
          and processed["deliveries"] == [] and lab.rust("b1", "wire_inspect")["inbox_count"] == 0,
          "带坏消息的签页未隔离，或产生收件/送达候选")
    refuse(lab, [original["events"][0]["event_id"]], code="read_target_invalid")
    check(relay_records(lab) == rows and inspect(lab)["records"] == [], "坏页或坏消息产生阅读/Relay 回执")
    lab.case_evidence["malicious_page_fixture"] = {"scope": "synthetic Service re-signing fixture; Relay retains original ciphertext",
        "original_signed_page": original.wrapper, "tampered_signature_input": tampered,
        "signature_error": error, "snapshot_sha256_before_bad_signature": before,
        "snapshot_unchanged_after_bad_signature": True, "signed_bad_message_page": signed_bad.wrapper,
        "downloaded": downloaded, "processed": processed}
    final_boundary(lab, "UNAUTHENTICATED_OR_QUARANTINED_MESSAGES_CREATE_ZERO_INTENTS")


def project_deleted(lab, record):
    original = lab.pull("b1")
    before = inspect(lab)
    delete(lab, record["accepted"])
    page = lab.pull("b1")
    check_deleted_slot(page["events"][0], original["events"][0])
    downloaded = lab.download("b1", page)
    processed = lab.rust("b1", "wire_process")
    check(processed["results"] == [] and inspect(lab) == before, "删除重发已处理消息或改变既有阅读意图")
    slot = lab.rust("b1", "wire_slot_inspect", event_seq="1")
    check(slot["slot"]["availability"] == "deleted" and slot["result"]["status"] == "valid",
          "删除投影未保留原成功处理事实")
    lab.case_evidence["overlapping_deletion_page"] = {"signed_page": page.wrapper,
        "downloaded": downloaded, "processed": processed, "stored_slot": slot}


def deleted_before_mark(lab):
    records = publish(lab)
    ids = load_messages(lab, records)
    project_deleted(lab, records[0])
    refuse(lab, ids, code="read_target_invalid")
    check(inspect(lab)["records"] == [] and relay_records(lab)["receipts"] == [], "已观察删除仍允许首次阅读")
    final_boundary(lab, "OBSERVED_DELETION_BLOCKS_FIRST_READ_INTENT")


def deleted_after_mark(lab):
    records = publish(lab)
    ids = load_messages(lab, records)
    check(mark(lab, ids)["marked_count"] == 1, "没有实际保存删除前阅读意图")
    state, exported = inspect(lab), pending(lab)
    check(state["pending_count"] == 1 and state["confirmed_count"] == 0, "删除前意图被提前确认")
    project_deleted(lab, records[0])
    before = snapshot(lab)
    repeated = mark(lab, ids)
    check(repeated["marked_count"] == 0 and repeated["duplicate_count"] == 1
          and snapshot(lab) == before and inspect(lab) == state and pending(lab) == exported,
          "删除清空已有意图或重复标记重写了快照")
    check(relay_records(lab)["receipts"] == [], "仅本地阅读意图产生服务回执")
    final_boundary(lab, "PERSISTED_PENDING_READ_SURVIVES_OBSERVED_DELETION")


def revoked_device_pending(lab):
    device = "a2"
    records = publish(lab)
    ids = load_messages(lab, records, device=device)
    check(mark(lab, ids, device=device)["marked_count"] == 1, "撤销前没有保存真实阅读意图")
    state, exported = inspect(lab, device), pending(lab, device)
    check(state["pending_count"] == 1 and state["confirmed_count"] == 0, "撤销前意图被提前确认")
    # 原权限契约只允许同账号旧设备撤销其他设备；a1 实际撤销 alice/a2。
    change = prepare_permission(lab, "revoke_pending_reader",
        {"kind": "revoke_device", **identity(device)})["change"]
    accepted = submit_permission(lab, change)
    record = {"change": change, "receipt": accepted["receipt"]}
    recovered = lab.rust(device, "permission_recover", record=record)
    permissions = lab.rust(device, "permission_inspect")
    check(accepted["outcome"] == "accepted" and permissions["access_removed"]
          and permissions["recovery_status"] == "access_removed",
          "撤销未经过真实接受与本设备签名恢复")
    refuse(lab, ids, device=device, code="access_removed")
    before, rows = snapshot(lab, device), relay_records(lab)
    error = lab.http(device, "report_read", exported["request"], expected=403)
    check(error["code"] == "device_revoked" and snapshot(lab, device) == before and relay_records(lab) == rows
          and inspect(lab, device) == state and pending(lab, device) == exported, "撤销后的拒绝报告清空意图或改变服务回执")
    lab.case_evidence["signed_reader_revocation"] = {"reader_device": device, "record_from_actual_submit_response": record,
        "accepted": accepted, "permission_recover": recovered, "permission_state": permissions, "http_error": error,
        "proof_transport": "captured original accepted record supplied to removed fixture device"}
    final_boundary(lab, "ACCESS_REMOVED_BLOCKS_REPORTING_WITH_PENDING_INTENT_RETAINED", device=device)


def old_program(lab, phase, enabled):
    before = snapshot(lab)
    request = {"directory": str(lab.directory / "b1"), "service": lab.service,
               "account": identity("b1")["account_id"], "device": "b1", "operation": "wire_inspect"}
    try:
        output = subprocess.run([str(lab.old_binary)], input=json.dumps(request), text=True,
                                capture_output=True, timeout=30)
    finally:
        lab.process_count += 1
    after, reply = snapshot(lab), json.loads(output.stdout)
    item = {"phase": phase, "exit_code": output.returncode, "reply": reply,
        "snapshot_sha256_before": before, "snapshot_sha256_after": after,
        "stderr_sha256": hashlib.sha256(output.stderr.encode()).hexdigest(), "stderr_bytes": len(output.stderr.encode())}
    lab.case_evidence.setdefault("old_program_compatibility", []).append(item)
    check(before == after, "旧程序改写新阅读快照")
    if enabled:
        check(output.returncode == 1 and reply.get("ok") is False and reply["error"]["code"] == "state_decoding"
              and "wire_reads" in reply["error"]["message"], "旧程序未明确拒绝新阅读字段")
    else:
        current = lab.rust("b1", "wire_inspect")
        check(output.returncode == 0 and reply.get("ok") is True and reply["result"] == current,
              "未建立阅读意图时旧程序失去读取兼容")


def old_binary_markers(lab):
    records = publish(lab)
    ids = load_messages(lab, records)
    old_program(lab, "before_read_marker", False)
    check(mark(lab, ids)["marked_count"] == 1, "没有首次持久阅读 marker")
    old_program(lab, "pending_read_marker", True)
    report(lab)
    synchronize(lab)
    check(inspect(lab)["confirmed_count"] == 1, "签名普通流未确认已读")
    old_program(lab, "confirmed_read_marker", True)
    finish(lab, records)


CASES = [("M13.boundary.source_required", source_required),
         ("M13.boundary.downloaded_not_processed", downloaded_not_processed),
         ("M13.boundary.exact_targets_and_atomic_batch", exact_targets_and_atomic_batch),
         ("M13.boundary.rejected_page_and_quarantine", rejected_page_and_quarantine),
         ("M13.boundary.deleted_before_mark", deleted_before_mark),
         ("M13.boundary.deleted_after_mark", deleted_after_mark),
         ("M13.boundary.revoked_device_pending", revoked_device_pending),
         ("M13.boundary.old_binary_markers", old_binary_markers)]
