"""M04 终态取证：保存公开结果与字节摘要，不导出正文、凭证或密码秘密。"""

import base64
import copy
import hashlib
import json

from .deletion_observer import relay_records
from .deletion_support import capture, unchanged
from .fixture import check
from .isolation_fixture import client_view
from .message_cases import changed_header, header
from .permission_cases import prepare as prepare_permission, submit as submit_permission, version
from .retry_support import committed_fact
from .slot_support import check_sync, digest


def input_summary(packet):
    envelope = packet["envelope"]
    raw_header = base64.b64decode(envelope["header_bytes"], validate=True)
    payload = base64.b64decode(envelope["payload_bytes"], validate=True)
    return {"header": header(packet), "header_sha256": hashlib.sha256(raw_header).hexdigest(),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "header_length": len(raw_header), "payload_length": len(payload)}


def prepare_original(lab, logical, payload, terminal):
    original = lab.prepare(logical, payload=payload)
    check(original["reused"] is False, "必须从原 Rust 发送入口新建唯一真实 MLS 密文")
    packet = original
    preparation = {"kind": "original_rust_mls", "permission_r1_applied": False}
    if terminal == "state_stale":
        change = prepare_permission(lab, "m04_remove_before_submit")["change"]
        accepted = submit_permission(lab, change)
        check(accepted["outcome"] == "accepted" and accepted["authorization_version"] == "2"
              and version(lab, "a1") == "1", "真实签名 R0 未形成服务端 2 / 发送端 1 的边界")
        preparation.update(kind="original_rust_mls_after_real_signed_r0", permission_acceptance=accepted,
                           permission_change_sha256=digest(change))
    elif terminal == "state_conflict":
        old_ref = header(original)["crypto_state_ref"]
        different_ref = ("0" if old_ref[0] != "0" else "1") + old_ref[1:]
        packet = changed_header(original, crypto_state_ref=different_ref)
        preparation.update(kind="synthetic_http_header_negative", changed_field="crypto_state_ref")
    elif terminal == "recipient_set_mismatch":
        recipients = header(original)["recipients"]
        check(len(recipients) == 3, "初始真实消息必须包含三个目标")
        remaining = recipients[:-1]
        subjects = [(item["account_id"], item["device_id"]) for item in remaining]
        check(bool(remaining) and subjects == sorted(set(subjects))
              and header(original)["sender"] not in remaining, "目标负例必须保留非空、排序唯一且无发送者的集合")
        packet = changed_header(original, recipients=remaining)
        preparation.update(kind="synthetic_http_header_negative", changed_field="recipients")
    else:
        check(terminal == "accepted", "未知原终态")
    check(packet["envelope"]["payload_bytes"] == original["envelope"]["payload_bytes"],
          "终态准备不得重新加密或替换原 Rust 密文")
    lab.case_evidence.update(preparation=preparation, rust_original=input_summary(original),
                             submitted_original=input_summary(packet))
    return packet


def changed_packet(original, mutation):
    changed = copy.deepcopy(original)
    original_header = header(original)
    if mutation == "semantic_header":
        check(original_header["authorization_version"] != "9", "负例版本必须不同于原版本")
        changed = changed_header(original, authorization_version="9")
        check({k for k in original_header if original_header[k] != header(changed)[k]}
              == {"authorization_version"}, "语义头负例改变了多个字段")
    elif mutation == "raw_header":
        changed["envelope"]["header_bytes"] = base64.b64encode(
            json.dumps(original_header, sort_keys=True, indent=1).encode()).decode()
        check(header(changed) == original_header, "原始字节负例不应改变头语义")
    else:
        check(mutation == "ciphertext", "未知异字节类型")
        payload = bytearray(base64.b64decode(changed["envelope"]["payload_bytes"], validate=True))
        check(bool(payload), "不能构造空密文翻位负例")
        payload[-1] ^= 1
        changed["envelope"]["payload_bytes"] = base64.b64encode(payload).decode()
    for field in ("service_id", "conversation_id", "sender", "logical_message_id", "attempt_id"):
        check(header(changed)[field] == original_header[field], "异字节请求改变了原逻辑键或尝试")
    same_header = changed["envelope"]["header_bytes"] == original["envelope"]["header_bytes"]
    same_payload = changed["envelope"]["payload_bytes"] == original["envelope"]["payload_bytes"]
    check((same_header, same_payload) == ((True, False) if mutation == "ciphertext" else (False, True)),
          "负例没有只改变指定原始字节域")
    return changed


def establish_terminal(lab, packet, terminal):
    clients = client_view(lab)
    response = lab.submit(packet, expected=200 if terminal == "accepted" else 409)
    check(client_view(lab) == clients, "首次 HTTP 提交改变客户端快照")
    if terminal == "accepted":
        value, rows = committed_fact(lab)
        check(response == value, "首次 HTTP 完整接受结果与持久事实不同")
    else:
        rows = relay_records(lab)
        check(rows["counts"] == {"attempts": 1, "logical_messages": 1, "accepted": 0,
              "events": 0, "message_events": 0, "receipts": 0}, "终态拒绝产生接受或部分扇出")
        value = rows["attempts"][0]["result"]
        expected_fields = {"outcome", "code", "logical_message_id", "attempt_id", "closure_id"}
        if terminal == "state_stale":
            expected_fields.add("rejection_receipt")
        check(set(value) == expected_fields
              and value["outcome"] == "rejected_final" and value["code"] == terminal
              and bool(value["closure_id"]), "原拒绝终态未保存完整封口标识")
        check(set(response) == set(value) | {"message"} and isinstance(response["message"], str)
              and bool(response["message"]) and {k: response[k] for k in value} == value,
              "首次 HTTP 错误没有对应完整持久终态")
        check(all(stream["watermark"] == "0" for stream in rows["streams"]), "拒绝推进了设备流水位")
    saved = rows["attempts"][0]
    summary = input_summary(packet)
    check(saved["header_sha256"] == summary["header_sha256"]
          and saved["payload_sha256"] == summary["payload_sha256"]
          and value["logical_message_id"] == summary["header"]["logical_message_id"]
          and saved["outcome"] == value["outcome"] and saved["successor"] is None,
          "原尝试摘要不属于实际提交字节或出现额外后继")
    chain = rows["logical_messages"][0]
    check(chain["tail"] == value["attempt_id"] == saved["attempt_id"] == "P1"
          and chain["accepted_attempt"] == ("P1" if terminal == "accepted" else None)
          and saved["closure_id"] == value.get("closure_id")
          and saved["acceptance_id"] == value.get("acceptance_id"), "逻辑链或原终态字段不一致")
    lab.case_evidence.update(original_response=response, original_terminal=value, original_relay=rows)
    return response, value, rows


def exact_operations(lab, packet, response, terminal, label):
    replies = {}
    for operation in ("submit_message", "get_attempt", "close_attempt"):
        before = capture(lab)
        if operation == "submit_message":
            reply = lab.submit(packet, expected=200 if terminal["outcome"] == "accepted" else 409)
            check(reply == response, "原提交未返回完整相同 HTTP 结果")
        else:
            reply = lab.attempt(terminal["logical_message_id"], operation=operation)
            check(reply == terminal, "查询或封口改写原完整终态")
        unchanged(lab, before, label + "_" + operation)
        replies[operation] = reply
    lab.case_evidence.setdefault("terminal_responses", []).append({"label": label, "responses": replies})


def reject_mutation(lab, packet, terminal, label, previous=None):
    before = capture(lab)
    error = lab.submit(packet, expected=409)
    check(set(error) == {"code", "message", "outcome", "logical_message_id", "attempt_id"}
          and error["code"] == "idempotency_conflict" and error["outcome"] == "not_recorded"
          and error["logical_message_id"] == terminal["logical_message_id"]
          and error["attempt_id"] == terminal["attempt_id"] and bool(error["message"]),
          "异字节未明确冲突，或覆盖了原接受/封口结果")
    if previous is not None:
        check(error == previous, "相同异字节冲突的完整 HTTP 错误变化")
    unchanged(lab, before, label)
    lab.case_evidence.setdefault("conflict_responses", []).append({"label": label, "response": error})
    return error


def signed_page_summary(page):
    wrapper = page.signed_input()
    return {"stream_id": page["stream_id"], "next_after_seq": page["next_after_seq"],
            "watermark": page["watermark"], "has_more": page["has_more"],
            "event_ids": [slot["event_id"] for slot in page["events"]],
            "event_seqs": [slot["event_seq"] for slot in page["events"]],
            "page_bytes_sha256": hashlib.sha256(base64.b64decode(wrapper["page_bytes"], validate=True)).hexdigest(),
            "receipt": wrapper["receipt"], "signed_wrapper_sha256": digest(wrapper)}


def receive_empty(lab, device, page, rows):
    stream = next(s for s in rows["streams"] if s["device"] == device)
    check(page["stream_id"] == stream["stream_id"] and page["events"] == []
          and page["watermark"] == page["next_after_seq"] == "0" and not page["has_more"],
          "终态拒绝新增了目标消息或改变空流")
    downloaded = lab.download(device, page)
    check(downloaded["status"] == "downloaded", "原始空签页未被验证和保存")
    check_sync(downloaded["sync"], 0, 0)
    processed = lab.rust(device, "wire_process")
    check(processed["results"] == processed["deliveries"] == [], "拒绝的尝试交付了业务结果或送达候选")
    check_sync(processed["sync"], 0, 0)
    state = lab.rust(device, "wire_inspect")
    check(state["inbox_count"] == state["outbox_count"] == state["sync"]["slot_count"] == 0
          and state["sync"]["source_verified"] and state["sync"] == processed["sync"],
          "拒绝后的端侧出现消息或隐藏槽位")
    return {"downloaded": downloaded, "processed": processed, "state": state}
