"""M09权限边界的逐目标证据；仅消费公开HTTP/Rust入口。"""

import hashlib
import json

from .attempt_support import key, message_rows, retry_packet
from .fixture import CONVERSATION, SERVICE, check, identity


def permission_fields(change):
    return {"service_id": SERVICE, "conversation_id": CONVERSATION, "change": change}


def accepted_from_rows(rows):
    accepted = [entry["result"] for entry in rows["attempts"] if entry["outcome"] == "accepted"]
    check(len(accepted) == 1, "独立已提交视图应只有一个接受结果")
    value = accepted[0]
    check(bool(value.get("acceptance_receipt")), "接受结果缺少真实Service签名回执")
    return value


def assert_fanout(lab, saved, accepted, targets):
    rows = message_rows(lab)
    check(accepted_from_rows(rows) == accepted, "完整接受结果与独立已提交视图不同")
    check(accepted["recipients"] == [identity(device) for device in targets], "原接受目标集合不完整或被改写")
    events = rows["events"]
    check(len(events) == len(targets), "扇出槽位总量错误")
    for device in targets:
        own = [entry for entry in events if entry["device"] == device]
        check(len(own) == 1 and own[0]["seq"] == "1", "目标槽位不唯一或序号不连续")
        event = own[0]["event"]
        check(own[0]["account"] == identity(device)["account_id"] and event["type"] == "message"
              and event["acceptance_id"] == accepted["acceptance_id"]
              and event["envelope"] == saved["envelope"]
              and event["acceptance_receipt"] == accepted["acceptance_receipt"],
              "已存目标槽位的归属、原信封或接受回执改变")
    lab.case_evidence["message_rows"] = rows
    return rows


def consume(lab, device, saved, accepted, logical, *, duplicate=False):
    page = lab.pull(device)
    check(page["watermark"] == page["next_after_seq"] == "1" and not page["has_more"],
          "目标没有恰好一个完整消息槽位")
    check(len(page["events"]) == 1, "目标槽位数量错误")
    slot = page["events"][0]
    check(slot["availability"] == "available" and slot["event_seq"] == "1"
          and slot["stream_id"] == page["stream_id"], "目标槽位身份/可用性错误")
    event = slot["event"]
    check(event["type"] == "message" and event["envelope"] == saved["envelope"]
          and event["acceptance_id"] == accepted["acceptance_id"]
          and event["acceptance_receipt"] == accepted["acceptance_receipt"],
          "目标取得的原密文或完整接受证据改变")
    prior = lab.case_evidence.setdefault("targets", {}).get(device)
    if prior:
        check(prior["page"] == page, "重启或重试改变了目标stream/event/seq/原信封")
    lab.download(device, page)
    lab.download(device, page)
    result = lab.rust(device, "wire_process")
    check(len(result["results"]) == (0 if duplicate else 1), "业务处理重复或遗漏")
    if not duplicate:
        message = result["results"][0]["result"]["message"]
        expected = hashlib.sha256(("synthetic-M09-" + logical).encode()).hexdigest()
        check(message["logical_message_id"] == logical and message["payload_sha256"] == expected
              and message["attempt_id"] == accepted["attempt_id"] and message["duplicate"] is False,
              "独立Rust设备真实解密结果错误")
    delivery = [{"acceptance_id": accepted["acceptance_id"], "attempt_id": accepted["attempt_id"],
                 "event_id": slot["event_id"]}]
    check(result["deliveries"] == delivery, "送达候选未绑定唯一接受、尝试和目标事件")
    again = lab.rust(device, "wire_process")
    check(again["results"] == [] and again["deliveries"] == delivery,
          "重复处理再次交付业务结果或改变持久送达候选")
    state = lab.rust(device, "wire_inspect")
    check(state["inbox_count"] == 1 and state["sync"]["download_cursor"] == "1"
          and state["sync"]["processed_cursor"] == "1", "重启CLI后去重/双游标未持久化")
    lab.case_evidence["targets"][device] = {
        "page": page, "page_sha256": hashlib.sha256(json.dumps(page, sort_keys=True).encode()).hexdigest(),
        "state": state, "duplicate_after_restart": duplicate,
    }


def removed_projection(lab, rows, device="c1"):
    page = lab.pull(device)
    originals = [entry for entry in rows["events"] if entry["device"] == device]
    check(len(originals) == len(page["events"]), "访问移除投影删除或新增了槽位")
    for original, slot in zip(originals, page["events"]):
        check(slot["event_id"] == original["event_id"] and slot["event_seq"] == original["seq"]
              and slot["stream_id"] == page["stream_id"] and slot["availability"] == "access_removed"
              and "event" not in slot, "被移除者取得了载荷或槽位身份改变")
    check(page["next_after_seq"] == page["watermark"] == str(len(originals)) and not page["has_more"],
          "移除投影水位错误")
    prior = lab.case_evidence.setdefault("removed_targets", {}).get(device)
    if prior:
        check(prior == page, "重启改变访问移除投影")
    lab.case_evidence["removed_targets"][device] = page
    lab.case_evidence["removed_old_key_decryption"] = "NOT_EXECUTED_ACCESS_RESTRICTED"


def accepted_operations(lab, saved, logical, accepted, *, attempt="P1", device="a1", **proof):
    again = retry_packet(lab, saved, logical, attempt, device, **proof)
    responses = {
        "get": lab.http(device, "get_attempt", key(logical, attempt)),
        "submit": lab.submit(again, device=device, **proof),
        "close": lab.http(device, "close_attempt", key(logical, attempt)),
    }
    check(all(value == accepted for value in responses.values()),
          "get/submit/close未返回完整相等的原接受结果")
    lab.case_evidence.setdefault("accepted_operations", []).append(responses)


def terminal_operations(lab, saved, logical, terminal):
    check(lab.http("a1", "get_attempt", key(logical)) == terminal
          and lab.http("a1", "close_attempt", key(logical)) == terminal, "终态查询或封口不稳定")
    result = lab.submit(saved, expected=409)
    check(all(result.get(field) == terminal[field] for field in
              ("outcome", "code", "logical_message_id", "attempt_id", "closure_id")),
          "旧首次提交终态在重试后改变")


def no_message_events(lab):
    rows = message_rows(lab)
    check(not rows["events"] and not any(row["outcome"] == "accepted" for row in rows["attempts"]),
          "终态拒绝仍生成了接受记录或目标消息事件")
    pages = {device: lab.pull(device) for device in ("a2", "b1", "c1")}
    check(all(not page["events"] and page["watermark"] == page["next_after_seq"] == "0"
              and not page["has_more"] for page in pages.values()), "某一目标新增了消息槽位")
    if "empty_targets" in lab.case_evidence:
        check(lab.case_evidence["empty_targets"] == pages, "重启改变空目标设备流身份或水位")
    lab.case_evidence.update(message_rows=rows, empty_targets=pages)
    return rows
