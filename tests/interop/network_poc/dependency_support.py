"""M10联合验证的状态、原槽和回执断言；不实现控制应用或同步业务。"""

import base64
import copy
import hashlib

from .deletion_observer import relay_records
from .fixture import check, identity


def record(lab, operation, **values):
    lab.case_evidence.setdefault("trace", []).append({"operation": operation, **values})


def state(lab, label, *, downloaded, processed, pending, quarantined, inbox, applied):
    value = lab.rust("b1", "wire_inspect")
    sync = value["sync"]
    expected = {"download_cursor": str(downloaded), "processed_cursor": str(processed),
                "pending_count": pending, "quarantined_count": quarantined,
                "slot_count": downloaded, "applied_control_count": applied,
                "pending_limit": 1, "halted": False, "source_verified": False}
    check(all(sync[key] == item for key, item in expected.items())
          and value["inbox_count"] == inbox, label + "：持久队列、双游标或消息数量不符")
    record(lab, label, state=value)
    return value


def corrupt(packet):
    changed = copy.deepcopy(packet)
    raw = bytearray(base64.b64decode(changed["envelope"]["payload_bytes"], validate=True))
    raw[-1] ^= 1
    changed["envelope"]["payload_bytes"] = base64.b64encode(raw).decode()
    return changed


def one_page(lab, after, expected_type):
    page = lab.pull("b1", str(after), "1")
    check(len(page["events"]) == 1 and page["next_after_seq"] == str(after + 1)
          and page["events"][0]["event"]["type"] == expected_type,
          "真实HTTP页未返回紧接的预期槽位")
    record(lab, "http_page", page=page)
    return page


def process_slot(lab, slot, status, *, duplicate=None, plaintext=None):
    result = lab.rust("b1", "wire_process")
    check(len(result["results"]) == 1, "本次应只处理一个槽位")
    item = result["results"][0]
    check(item["event_seq"] == slot["event_seq"] and item["event_id"] == slot["event_id"]
          and item["result"]["status"] == status, "处理结果丢失原槽归属或状态不符")
    if duplicate is not None:
        check(item["result"]["duplicate"] is duplicate, "控制重复应用标记错误")
    if plaintext is not None:
        message = item["result"]["message"]
        check(message["duplicate"] is False
              and message["payload_sha256"] == hashlib.sha256(plaintext.encode()).hexdigest(),
              "真实MLS消息解密不符或重复插入")
    stored = lab.rust("b1", "wire_slot_inspect", event_seq=slot["event_seq"])
    check(stored["found"] and stored["slot"] == slot and stored["result"] == item["result"]
          and stored["waiting"] == (status == "waiting_dependency"), "新CLI未读取到原槽和完整处理结果")
    record(lab, "process_and_reload_slot", result=result, stored=stored)
    return result


def candidates(lab, result, good_slot, bad_slots):
    expected = [] if good_slot is None else [{"acceptance_id": good_slot["event"]["acceptance_id"],
                                            "attempt_id": "P1", "event_id": good_slot["event_id"]}]
    check(result["deliveries"] == expected, "送达候选遗漏、重复或带入控制/坏槽")
    for slot in bad_slots:
        check(all(item["event_id"] != slot["event_id"]
                  and item["acceptance_id"] != slot["event"]["acceptance_id"] for item in result["deliveries"]),
              "坏槽进入持久送达候选")
    record(lab, "candidate_check", expected=expected,
           bad_event_ids=[slot["event_id"] for slot in bad_slots])
    return expected


def restart(lab, label):
    before_state = lab.rust("b1", "wire_inspect")
    before_rows = relay_records(lab)
    lab.restart()
    check(lab.rust("b1", "wire_inspect") == before_state and relay_records(lab) == before_rows,
          "正常Relay重启或新CLI改变已保存状态/记录")
    record(lab, label, state=before_state, relay=before_rows)


def report_and_repeat(lab, good_slot, bad_slots, current, applied_state):
    result = lab.rust("b1", "wire_process")
    check(result["results"] == [], "已处理消息在新CLI再次产生处理结果")
    expected = candidates(lab, result, good_slot, bad_slots)
    before = relay_records(lab)
    check(before["receipts"] == [], "未显式报告前产生了回执")
    request = {"service_id": lab.service, **expected[0]}
    first = lab.http("b1", "report_delivery", request)
    once = relay_records(lab)
    again = lab.http("b1", "report_delivery", request)
    check(first == again and relay_records(lab) == once, "重复报告追加了回执或通知")
    check(once["receipts"] == [{"acceptance_id": good_slot["event"]["acceptance_id"],
                               "account": "bob", "device": "b1", "delivered": 1, "is_read": 0}],
          "回执归属错误或坏消息产生回执")
    notifications = [event for event in once["events"] if event["type"] == "delivery"]
    check(len(notifications) == 3 and {e["device"] for e in notifications} == {"a1", "a2", "b1"}
          and all(e["acceptance_id"] == good_slot["event"]["acceptance_id"] for e in notifications),
          "送达通知不是唯一合法消息的三个当前有权目标")
    record(lab, "report_delivery_twice", response=first, committed=once)
    page = one_page(lab, current, "delivery")
    check(page["events"][0]["event"] == {"type": "delivery", **{k: request[k] for k in ("acceptance_id", "attempt_id")},
                                         "device": identity("b1")}, "回执通知内容错误")
    lab.download("b1", page)
    result = process_slot(lab, page["events"][0], "receipt_recorded")
    candidates(lab, result, good_slot, bad_slots)
    final = state(lab, "receipt_processed", downloaded=current + 1, processed=current + 1,
                  pending=0, quarantined=len(bad_slots), inbox=1, applied=1)
    check((final["epoch"], final["crypto_state_ref"]) == applied_state, "控制之后公共密码状态再次推进")
    full = lab.pull("b1")
    check([s["event_seq"] for s in full["events"]] == [str(i) for i in range(1, current + 2)],
          "完整补拉遗漏或重复槽位")
    saved_slots = [lab.rust("b1", "wire_slot_inspect", event_seq=s["event_seq"]) for s in full["events"]]
    check(all(saved["slot"] == slot for saved, slot in zip(saved_slots, full["events"])), "HTTP原槽与端侧保存不一致")
    restart(lab, "restart_after_receipt")
    for _ in range(2):
        repeated = lab.pull("b1")
        check(repeated == full, "重复HTTP补拉改写原槽/水位")
        lab.download("b1", repeated)
        result = lab.rust("b1", "wire_process")
        check(result["results"] == [] and lab.rust("b1", "wire_inspect") == final,
              "重复页面引发二次处理或改变游标/密码引用")
        candidates(lab, result, good_slot, bad_slots)
        check([lab.rust("b1", "wire_slot_inspect", event_seq=s["event_seq"]) for s in full["events"]] == saved_slots,
              "重复页面改写原槽处理摘要")
        check(lab.http("b1", "report_delivery", request) == first and relay_records(lab) == once,
              "重启后原送达确认不幂等")
        record(lab, "repeat_full_http_page_and_receipt", page=repeated, state=final, process=result)
    lab.case_evidence.update(final_state=final, final_relay=once, bad_slots=bad_slots,
                             successful_candidate=expected[0], ordinary_control_applied_once=True)
