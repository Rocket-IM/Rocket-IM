"""后继尝试的真实签页、解密、送达与重启重放核对。"""

import hashlib

from .deletion_observer import relay_records
from .fixture import check, identity
from .slot_support import check_message_slot, check_sync, inspect_slot


def receive(lab, records):
    """records 为 (logical, attempt, payload, packet, accepted)，不把P1写死为成功尝试。"""
    targets = lab.case_evidence.setdefault("targets", {})
    for device in ("a2", "b1", "c1"):
        page = lab.pull(device)
        check(len(page["events"]) == len(records) and page["watermark"] == str(len(records)),
              "封口产生消息或后继接受丢失目标槽")
        for seq, (slot, record) in enumerate(zip(page["events"], records), 1):
            check_message_slot(slot, record[3], record[4], seq)
        lab.download(device, page)
        processed = lab.rust(device, "wire_process")
        targets[device] = {"signed_page": page.wrapper, "process": processed}
        check(len(processed["results"]) == len(records), "后继处理漏槽")
        candidates = []
        for seq, (item, slot, record) in enumerate(zip(processed["results"], page["events"], records), 1):
            logical, attempt, payload, _, accepted = record
            value = item["result"]
            check(item["event_seq"] == str(seq) and item["event_id"] == slot["event_id"]
                  and value["event_id"] == slot["event_id"]
                  and value["status"] == "valid" and value["acceptance_id"] == accepted["acceptance_id"]
                  and value["message"]["logical_message_id"] == logical
                  and value["message"]["attempt_id"] == attempt
                  and value["message"]["payload_sha256"] == hashlib.sha256(payload.encode()).hexdigest()
                  and value["message"]["duplicate"] is False, "后继解密或逻辑归属错误")
            candidates.append({"acceptance_id": accepted["acceptance_id"], "attempt_id": attempt,
                               "event_id": slot["event_id"]})
            saved = inspect_slot(lab, device, seq)
            check(saved["slot"] == slot and saved["result"] == value, "新进程未保存原后继槽")
        check(processed["deliveries"] == candidates and processed["sync"]["quarantined_count"] == 0,
              "封口旧尝试成为送达候选或后继被隔离")
        check_sync(processed["sync"], len(records), len(records))
        state = lab.rust(device, "wire_inspect")
        check(state["sync"] == processed["sync"] and state["inbox_count"] == len(records),
              "后继游标与消息数量未共同持久保存")
        lab.download(device, page)
        replay = lab.rust(device, "wire_process")
        check(replay["results"] == [] and replay["deliveries"] == candidates
              and lab.rust(device, "wire_inspect") == state, "原签页重放再次发布后继")
        targets[device].update(candidates=candidates, replay=replay, state=state)
    before = relay_records(lab)
    lab.restart()
    check(relay_records(lab) == before, "Relay重启改变原封口或接受事实")
    for logical, attempt, _, _, accepted in records:
        check(lab.attempt(logical, attempt) == accepted, "重启查询改变接受证明")
    for device, value in targets.items():
        value["delivery_reports"] = []
        for candidate in value["candidates"]:
            result = lab.http(device, "report_delivery", {"service_id": lab.service, **candidate})
            check(result == {"acceptance_id": candidate["acceptance_id"],
                             "attempt_id": candidate["attempt_id"], "device": identity(device),
                             "delivered": True, "read": False}, "送达确认绑定错误")
            rows = relay_records(lab)
            check(lab.http(device, "report_delivery", {"service_id": lab.service, **candidate}) == result
                  and relay_records(lab) == rows, "重复送达产生新记录")
            value["delivery_reports"].append(result)
    final = relay_records(lab)
    check(final["counts"]["accepted"] == len(records)
          and final["counts"]["message_events"] == final["counts"]["receipts"] == 3 * len(records),
          "封口和后继产生重复接受或错误回执")
    lab.case_evidence.update(accepted_messages=len(records), target_valid_results=3 * len(records),
                            target_quarantined_results=0, final_relay=final, delivery_restart_count=1)
