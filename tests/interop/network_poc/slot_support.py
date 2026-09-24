"""M11单槽持久观察与真实接受记录断言；不读取客户端明文或密码状态。"""

import hashlib
import json

from .fixture import check, identity
from .sync_support import TARGETS


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def publish(lab, logical):
    payload = "synthetic-M11-" + logical
    packet = lab.prepare(logical, payload=payload)
    accepted = lab.submit(packet)
    check(accepted["recipients"] == [identity(d) for d in TARGETS], "真实接受目标集合不完整")
    check(bool(accepted["acceptance_receipt"]), "本轮必须使用真实签名接受回执")
    lab.case_evidence.setdefault("accepted", {})[logical] = accepted
    return packet, accepted, hashlib.sha256(payload.encode()).hexdigest()


def inspect_slot(lab, device, seq, expected=None):
    path = lab.directory / device / "state.enc"
    before = path.read_bytes()
    value = lab.rust(device, "wire_slot_inspect", event_seq=str(seq))
    check(path.read_bytes() == before, "健康或已halted普通流的观察改变快照")
    check(value["event_seq"] == str(seq), "观察返回错误序号")
    if expected is not None:
        check(value == expected, "重载后原槽、处理结果或waiting发生改变")
    return value


def check_message_slot(slot, packet, accepted, seq):
    check(slot["event_seq"] == str(seq) and slot["availability"] == "available", "消息槽序号或可用性不符")
    event = slot["event"]
    check(event["type"] == "message" and event["envelope"] == packet["envelope"]
          and event["acceptance_id"] == accepted["acceptance_id"]
          and event["acceptance_receipt"] == accepted["acceptance_receipt"], "原密文或签名接受事实被改写")


def check_message_result(result, slot, logical, payload_hash, duplicate):
    check(result["status"] == "valid" and result["event_id"] == slot["event_id"]
          and result["acceptance_id"] == slot["event"]["acceptance_id"], "槽结果不是原事件的合法接受")
    message = result["message"]
    check(message["logical_message_id"] == logical and message["attempt_id"] == "P1"
          and message["payload_sha256"] == payload_hash and message["duplicate"] is duplicate,
          "真实解密摘要、逻辑去重或尝试归属错误")


def check_sync(sync, download, processed, pending=0, halted=False):
    check(sync["download_cursor"] == str(download) and sync["processed_cursor"] == str(processed)
          and sync["pending_count"] == pending and sync["quarantined_count"] == 0
          and sync["halted"] is halted, "持久双游标、队列或停流状态错误")


def delivery_for(slot):
    return {"acceptance_id": slot["event"]["acceptance_id"], "attempt_id": "P1", "event_id": slot["event_id"]}
