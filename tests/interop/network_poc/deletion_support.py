"""M11.d 原接受事实、删除投影与本机状态观察；不读取客户端明文。"""

import base64
import copy
import json

from .deletion_observer import assert_deleted_transition, relay_records
from .fixture import ACCOUNTS, check
from .isolation_fixture import client_view
from .slot_support import digest


def capture(lab):
    return {"clients": client_view(lab), "relay": relay_records(lab)}


def unchanged(lab, before, label):
    after = capture(lab)
    check(after == before, "只读/拒绝/重启改变已提交状态: " + label)
    lab.case_evidence.setdefault("unchanged_checks", []).append({
        "label": label, "before_sha256": digest(before), "after_sha256": digest(after)})


def restart(lab, label):
    before = capture(lab)
    lab.restart()
    unchanged(lab, before, label)


def deleted_result(accepted):
    return {**accepted, "availability": "deleted"}


def delete(lab, accepted):
    before = relay_records(lab)
    clients = client_view(lab)
    ident = accepted["acceptance_id"]
    reply = lab.control("set_availability", acceptance_id=ident, availability="deleted")
    check(reply == {"acceptance_id": ident, "availability": "deleted"}, "没有直接进入deleted")
    after = relay_records(lab)
    assert_deleted_transition(before, after, ident)
    check(client_view(lab) == clients, "删除控制器擅自修改了端侧状态")
    lab.case_evidence["deletion_transition"] = {"before": before, "after": after}
    before_repeat = capture(lab)
    check(lab.control("set_availability", acceptance_id=ident, availability="deleted") == reply,
          "重复删除响应不稳定")
    unchanged(lab, before_repeat, "repeat_delete_without_new_events")


def retry_deleted(lab, packet, accepted, label):
    """原包/查询/封口不制造接受；HTTP异字节负例不冒充新的合法MLS发送。"""
    logical = accepted["logical_message_id"]
    expected = deleted_result(accepted)
    before = capture(lab)
    for operation in ("submit_message", "get_attempt", "close_attempt"):
        value = lab.submit(packet) if operation == "submit_message" else lab.attempt(logical, operation=operation)
        check(value == expected, "删除后完整接受事实变化: " + operation)
    changed = copy.deepcopy(packet)
    payload = bytearray(base64.b64decode(changed["envelope"]["payload_bytes"]))
    payload[-1] ^= 1
    changed["envelope"]["payload_bytes"] = base64.b64encode(payload).decode()
    check(lab.submit(changed, expected=409)["code"] == "idempotency_conflict",
          "删除后同尝试异密文获得新的接受")
    changed = copy.deepcopy(packet)
    header = json.loads(base64.b64decode(changed["envelope"]["header_bytes"]))
    header["attempt_id"] = "P2"
    changed["envelope"]["header_bytes"] = base64.b64encode(json.dumps(header, separators=(",", ":")).encode()).decode()
    error = lab.submit(changed, expected=409)
    check(error["code"] == "logical_message_already_accepted" and error["acceptance"] == expected,
          "新尝试绕过原逻辑接受事实或恢复available")
    unchanged(lab, before, label)
    lab.case_evidence.setdefault("retry_results", []).append({"label": label, "result": expected,
        "changed_ciphertext": "idempotency_conflict", "new_attempt": "logical_message_already_accepted"})


def check_deleted_slot(slot, original):
    expected = {k: original[k] for k in ("stream_id", "event_seq", "event_id")}
    expected["availability"] = "deleted"
    check(slot == expected, "删除投影改变槽身份、未省略载荷或不是deleted")


def check_availability_notice(slot, original, accepted, availability, sequence):
    check(slot["stream_id"] == original["stream_id"] and slot["event_seq"] == str(sequence)
          and slot["event_id"] != original["event_id"] and slot["availability"] == "available",
          "终态通知流、序号、独立身份或可用性不正确")
    check(slot["event"] == {"type": "message_availability", "target_event_seq": original["event_seq"],
          "target_event_id": original["event_id"], "acceptance_id": accepted["acceptance_id"],
          "attempt_id": accepted["attempt_id"], "availability": availability}, "终态通知未绑定原消息与精确接受事实")


def check_notice_result(result, slot):
    check(result == {"event_seq": slot["event_seq"], "event_id": slot["event_id"],
                     "result": {"status": "availability_recorded"}}, "终态通知被当作正文、送达或阅读")


def final_relay(lab, expected_messages):
    rows = relay_records(lab)
    counts = rows["counts"]
    check(counts["attempts"] == counts["logical_messages"] == counts["accepted"] == expected_messages
          and counts["message_events"] == expected_messages * 3, "接受、逻辑记录或消息槽重复/丢失")
    lab.case_evidence["final_relay"] = rows
    return rows


def observe_clients(lab):
    return {device: lab.rust(device, "wire_inspect") for device in ACCOUNTS}
