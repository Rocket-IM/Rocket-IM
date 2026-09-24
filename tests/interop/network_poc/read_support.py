"""M13真实消息、显式意图和本设备签页确认的公共取证；不模拟阅读者认知。"""

import hashlib

from .deletion_observer import relay_records
from .fixture import check, identity
from .slot_support import check_message_slot

DEVICES = ("a1", "a2", "b1", "c1")


def snapshot(lab, device="b1"):
    return hashlib.sha256((lab.directory / device / "state.enc").read_bytes()).hexdigest()


def inspect(lab, device="b1"):
    before = snapshot(lab, device)
    result = lab.rust(device, "wire_read_inspect")
    check(snapshot(lab, device) == before, "阅读诊断重写原快照")
    check(result["pending_count"] + result["confirmed_count"] == len(result["records"]), "阅读记录计数不一致")
    return result


def pending(lab, device="b1"):
    before = snapshot(lab, device)
    result = lab.rust(device, "wire_read_pending")
    check(snapshot(lab, device) == before, "导出阅读报告重写原快照")
    if result["request"] is not None:
        ids = result["request"]["acceptance_ids"]
        check(result["request"]["service_id"] == lab.service and 1 <= len(ids) <= 100
              and ids == sorted(set(ids)), "报告未按本人稳定待办导出")
    else:
        check(result["pending_count"] == 0 and not result["has_more"], "非空阅读待办静默丢失")
    return result


def publish(lab, count=1):
    records = []
    for index in range(1, count + 1):
        logical, payload = f"M{index}", f"synthetic-explicit-read-{index}"
        packet = lab.prepare(logical, payload=payload)
        accepted = lab.submit(packet)
        check(accepted["recipients"] == [identity(d) for d in DEVICES[1:]], "初始消息目标不正确")
        lab.rust("a1", "wire_accept", logical_message_id=logical, attempt_id="P1",
                 acceptance_receipt=accepted["acceptance_receipt"])
        records.append({"logical_message_id": logical, "packet": packet, "accepted": accepted,
                        "payload_sha256": hashlib.sha256(payload.encode()).hexdigest()})
    lab.case_evidence["messages"] = records
    return records


def synchronize(lab, device="b1"):
    processed = []
    while True:
        cursor = lab.rust(device, "wire_inspect")["sync"]["download_cursor"]
        page = lab.pull(device, after=cursor)
        downloaded = lab.download(device, page)
        result = lab.rust(device, "wire_process")
        lab.case_evidence.setdefault("synchronization", []).append({"device": device,
            "signed_page": page.wrapper, "downloaded": downloaded, "processed": result})
        processed.append(result)
        if not page["has_more"]:
            break
    return processed


def load_messages(lab, records, device="b1"):
    results = synchronize(lab, device)
    valid = [v for p in results for v in p["results"] if v["result"]["status"] == "valid"]
    check(len(valid) == len(records), "真实消息没有全部解密成功")
    ids = []
    for item, record in zip(valid, records):
        result = item["result"]
        slot = lab.rust(device, "wire_slot_inspect", event_seq=item["event_seq"])["slot"]
        check_message_slot(slot, record["packet"], record["accepted"], int(item["event_seq"]))
        check(result["acceptance_id"] == record["accepted"]["acceptance_id"]
              and result["event_id"] == slot["event_id"]
              and result["message"]["logical_message_id"] == record["logical_message_id"]
              and result["message"]["payload_sha256"] == record["payload_sha256"], "消息结果不属于原密文")
        ids.append(slot["event_id"])
    state = inspect(lab, device)
    check(state == {"pending_count": 0, "confirmed_count": 0, "records": []}, "后台接收自动创建了阅读意图")
    lab.case_evidence.setdefault("decrypted", []).append({"device": device, "message_event_ids": ids,
        "results": valid, "read_state": state})
    return ids


def mark(lab, event_ids, device="b1", **options):
    before = snapshot(lab, device)
    result = lab.rust(device, "wire_read", event_ids=event_ids, **options)
    lab.case_evidence.setdefault("reading_commands", []).append({"device": device, "event_ids": event_ids,
        "result": result, "snapshot_sha256_before": before, "snapshot_sha256_after": snapshot(lab, device)})
    return result


def refuse(lab, event_ids, *, device="b1", code, **options):
    before, state, rows = snapshot(lab, device), inspect(lab, device), relay_records(lab)
    result = mark(lab, event_ids, device=device, expected_exit=1, **options)
    after = snapshot(lab, device)
    current = inspect(lab, device)
    check(result["code"] == code and before == after and current == state and relay_records(lab) == rows,
          "无效阅读请求未拒绝或改变已提交状态")
    lab.case_evidence.setdefault("rejected_reading", []).append({"device": device, "error": result,
        "snapshot_sha256_before": before, "snapshot_sha256_after": after, "state_before": state, "state_after": current})
    return result


def report(lab, device="b1"):
    exported = pending(lab, device)
    check(exported["request"] is not None, "没有已持久阅读意图却发送报告")
    before, state = snapshot(lab, device), inspect(lab, device)
    response = lab.http(device, "report_read", exported["request"])
    check(before == snapshot(lab, device) and state == inspect(lab, device), "HTTP成功被宿主直接当成本地签名确认")
    expected = [{"acceptance_id": ident, "attempt_id": "P1", "device": identity(device),
                 "delivered": True, "read": True} for ident in exported["request"]["acceptance_ids"]]
    check(response == {"receipts": expected}, "已读报告响应错误归属")
    rows = relay_records(lab)
    check(lab.http(device, "report_read", exported["request"]) == response and relay_records(lab) == rows,
          "重复已读报告产生新状态或通知")
    lab.case_evidence.setdefault("read_reports", []).append({"device": device,
        "exported": exported, "response": response, "local_before_confirmation": state, "relay": rows})
    return response


def assert_confirmed(lab, records, device="b1"):
    state = inspect(lab, device)
    expected = {r["accepted"]["acceptance_id"] for r in records}
    check(state["pending_count"] == 0 and state["confirmed_count"] == len(expected)
          and {v["acceptance_id"] for v in state["records"]} == expected
          and all(v["status"] == "confirmed" and v["confirmation"] is not None
                  and v["service_id"] == lab.service and v["conversation_id"] == "G1"
                  and v["account_id"] == identity(device)["account_id"] and v["device_id"] == device
                  for v in state["records"]), "本设备签名已读没有精确确认持久意图")
    check(pending(lab, device) == {"request": None, "pending_count": 0, "has_more": False}, "已确认阅读仍被重复导出")
    return state


def finish(lab, records, *, readers=("b1",)):
    states = {d: assert_confirmed(lab, records, d) for d in readers}
    rows = relay_records(lab)
    expected = {(r["accepted"]["acceptance_id"], identity(d)["account_id"], d) for d in readers for r in records}
    check({(r["acceptance_id"], r["account"], r["device"]) for r in rows["receipts"] if r["is_read"]} == expected,
          "已读被扩大到未阅读设备或漏掉目标")
    check(all(r["delivered"] == 1 for r in rows["receipts"] if r["is_read"]), "已读缺少本人送达")
    read_events = [r for r in rows["events"] if r["type"] == "read"]
    check(len(read_events) == len(expected) * 4 and rows["counts"]["accepted"] == len(records)
          and rows["counts"]["message_events"] == len(records) * 3, "重复已读通知或改变接受/消息扇出")
    lab.restart()
    check(relay_records(lab) == rows, "重启改变已读和消息记录")
    for device, state in states.items():
        check(inspect(lab, device) == state, "新Rust进程没有保留阅读确认")
        synchronize(lab, device)
        check(inspect(lab, device) == state, "空增量重放改变已读事实")
    lab.case_evidence.update(final_relay=rows, confirmed_states=states, confirmed_read_intents=len(expected),
                            read_notification_events=len(read_events), real_decryptions=sum(len(v["results"]) for v in lab.case_evidence["decrypted"]))
