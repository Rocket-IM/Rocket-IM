"""M02 非秘密取证：原尝试恢复、接受事实和逐目标消息槽，不观察密码秘密。"""

import base64
import hashlib
import http.client

from .deletion_observer import relay_records
from .fixture import check, identity
from .isolation_fixture import client_view
from .slot_support import check_message_result, check_message_slot, check_sync, delivery_for, inspect_slot
from .sync_support import TARGETS


def observe_send(lab, label, logical, payload, *, reused, original=None):
    before = lab.rust("a1", "wire_inspect")
    before_file = client_view(lab)["a1"]["state.enc"]
    packet = lab.prepare(logical, payload=payload)
    observation = lab.encryption_observations[-1]
    check(observation["operation"] == "wire_send" and packet["reused"] is reused,
          "未通过原wire_send入口恢复尝试")
    if lab.probe_enabled:
        check(observation["calls"] == ("0" if reused else "1"), "消息创建调用次数不符")
    if original is not None:
        check(packet == {**original, "reused": True}, "新CLI没有返回完整原信封与尝试身份")
    after = lab.rust("a1", "wire_inspect")
    if reused:
        check(after == before, "恢复原尝试改变可观察业务/公共密码状态")
    else:
        check(before["outbox_count"] == 0 and after["outbox_count"] == 1, "首次发送没有保存唯一尝试")
    lab.case_evidence.setdefault("send_observations", []).append({
        "label": label, "observation": observation, "reused": reused,
        "header_sha256": hashlib.sha256(base64.b64decode(packet["envelope"]["header_bytes"])).hexdigest(),
        "ciphertext_sha256": hashlib.sha256(base64.b64decode(packet["envelope"]["payload_bytes"])).hexdigest(),
        "snapshot_sha256_before": before_file, "snapshot_sha256_after": client_view(lab)["a1"]["state.enc"],
        "snapshot_scope": "wire_send may save a newly wrapped snapshot; not a message encryption count",
        "sender_before": before, "sender_after": after})
    return packet


def committed_fact(lab):
    rows = relay_records(lab)
    check(rows["counts"] == {"attempts": 1, "logical_messages": 1, "accepted": 1,
          "events": 3, "message_events": 3, "receipts": 0}, "接受丢响应未留下唯一完整扇出")
    attempt = rows["attempts"][0]
    accepted = attempt["result"]
    check(accepted["outcome"] == "accepted" and accepted["availability"] == attempt["availability"] == "available"
          and accepted["recipients"] == [identity(d) for d in TARGETS]
          and accepted["acceptance_id"] == attempt["acceptance_id"]
          and int(accepted["expires_at_unix_ms"]) - int(accepted["accepted_at_unix_ms"]) == 30 * 24 * 60 * 60 * 1000,
          "原接受事实、完整目标或默认期限不正确")
    check(all(e["acceptance_id"] == accepted["acceptance_id"] and e["seq"] == "1"
              and e["availability"] == "available" for e in rows["events"]), "原目标槽位不完整")
    check([(e["account"], e["device"]) for e in rows["events"]]
          == [(identity(d)["account_id"], d) for d in TARGETS], "原接受扇出到错误设备")
    check(len({e["event_id"] for e in rows["events"]}) == 3, "事件身份不唯一")
    return accepted, rows


def lose_response(lab, packet, hook, label, *, expected_rows=None):
    clients = client_view(lab)
    lab.control("hook", hook=hook)
    try:
        lab.submit(packet)
        raise AssertionError("指定窗口没有丢失接受响应")
    except (http.client.RemoteDisconnected, ConnectionResetError) as error:
        error_type = type(error).__name__
    if hook == "after_commit_exit":
        check(lab.process.wait(timeout=10) == 87, "Relay没有在提交后真实退出87")
        exit_code = 87
    else:
        check(hook == "drop_after_commit" and lab.process.poll() is None, "丢ACK时服务状态不符")
        exit_code = None
    check(client_view(lab) == clients, "HTTP提交擅自修改客户端持久状态")
    accepted, rows = committed_fact(lab)
    attempt = rows["attempts"][0]
    check(attempt["header_sha256"] == hashlib.sha256(base64.b64decode(packet["envelope"]["header_bytes"])).hexdigest()
          and attempt["payload_sha256"] == hashlib.sha256(base64.b64decode(packet["envelope"]["payload_bytes"])).hexdigest(),
          "首次接受的原尝试头/密文摘要与实际提交不符")
    if expected_rows is not None:
        check(rows == expected_rows, "重试再丢ACK新增或改写原接受及槽位")
    lab.case_evidence.setdefault("lost_responses", []).append({
        "label": label, "hook": hook, "exception": error_type, "relay_exit_code": exit_code,
        "committed_fact": accepted, "committed_rows": rows, "clients_unchanged": True})
    return accepted, rows


def check_page(page, device, packet, accepted, rows):
    event = next(e for e in rows["events"] if e["device"] == device)
    stream = next(s for s in rows["streams"] if s["device"] == device)
    check(page["stream_id"] == stream["stream_id"] and page["next_after_seq"] == page["watermark"] == "1"
          and not page["has_more"] and len(page["events"]) == 1, "签页流或水位改变")
    slot = page["events"][0]
    check(slot["stream_id"] == stream["stream_id"] and slot["event_id"] == event["event_id"],
          "重试改变逐目标stream/seq/event身份")
    check_message_slot(slot, packet, accepted, 1)


def receive_once(lab, device, page, accepted, payload, *, already_processed=False):
    lab.download(device, page)
    value = lab.rust(device, "wire_process")
    if already_processed:
        check(value["results"] == [], "已处理原消息再次发布有效结果")
    else:
        check(len(value["results"]) == 1 and value["results"][0]["event_seq"] == "1"
              and value["results"][0]["event_id"] == page["events"][0]["event_id"], "消息结果数量/身份不符")
        check_message_result(value["results"][0]["result"], page["events"][0],
                             accepted["logical_message_id"], hashlib.sha256(payload.encode()).hexdigest(), False)
    check(value["deliveries"] == [delivery_for(page["events"][0])], "缺少唯一原送达候选")
    check_sync(value["sync"], 1, 1)
    check(value["sync"]["slot_count"] == 1, "重试造成隐藏重复槽")
    state = lab.rust(device, "wire_inspect")
    check(state["inbox_count"] == 1 and state["outbox_count"] == 0 and state["sync"]["source_verified"],
          "目标没有唯一有效消息或来源未经认证")
    slot = inspect_slot(lab, device, 1)
    lab.download(device, page)
    repeated = lab.rust(device, "wire_process")
    check(repeated["results"] == [] and repeated["deliveries"] == value["deliveries"]
          and repeated["sync"] == value["sync"], "原签页重放不幂等")
    inspect_slot(lab, device, 1, slot)
    return {"sync": value["sync"], "deliveries": value["deliveries"],
            "inbox_count": 1, "slot": slot}
