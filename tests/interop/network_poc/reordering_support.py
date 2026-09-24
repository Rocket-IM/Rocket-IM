"""M03 真实签页、逐槽隔离及仅成功消息送达证据。"""

from .fixture import ACCOUNTS, check
from .slot_duplicate_cases import report
from .slot_support import (check_message_result, check_message_slot, delivery_for,
                           digest, inspect_slot)
from .sync_support import TARGETS, relay_receipts, verify_receipts


def check_state(state, cursor, valid, quarantined):
    sync = state["sync"]
    check(state["inbox_count"] == valid and sync["slot_count"] == cursor
          and sync["download_cursor"] == sync["processed_cursor"] == str(cursor)
          and sync["pending_count"] == 0 and sync["quarantined_count"] == quarantined
          and sync["source_verified"] and not sync["halted"],
          "持久收件、双游标、隔离或签页来源状态错误")


def check_result(result, slot, record, quarantined):
    if quarantined:
        check(result == {"status": "quarantined", "code": "decryption_failed"},
              "超窗原消息没有明确隔离为解密失败")
    else:
        check_message_result(result, slot, record["logical"], record["payload_sha256"], False)


def receive_targets(lab, packets, order, page_limit, quarantined):
    targets = {}
    for device in TARGETS:
        cursor, slots, candidates, failed = 0, [], [], 0
        evidence = {"pages": []}
        lab.case_evidence["targets"][device] = evidence
        while cursor < len(order):
            page = lab.pull(device, str(cursor), str(page_limit))
            events = page["events"]
            end = min(cursor + page_limit, len(order))
            check(page["watermark"] == str(len(order)) and page["next_after_seq"] == str(end)
                  and page["has_more"] is (end < len(order))
                  and [s["event_seq"] for s in events] == [str(s) for s in range(cursor + 1, end + 1)],
                  "真实签页没有按接受顺序给出完整连续前缀")
            for seq, slot in enumerate(events, cursor + 1):
                record = packets[order[seq - 1]]
                check_message_slot(slot, record["packet"], record["accepted"], seq)
                check(slot["stream_id"] == page["stream_id"], "原消息槽流归属不符")
            downloaded = lab.download(device, page)
            result = lab.rust(device, "wire_process")
            # 在断言前保存实际处理，异常轮次仍保留诊断。
            evidence["pages"].append({"after_seq": str(cursor), "signed_page": page.wrapper,
                                      "download": downloaded, "process": result})
            check(downloaded["status"] == "downloaded" and
                  [r["event_seq"] for r in result["results"]] == [s["event_seq"] for s in events],
                  "处理漏槽或重复处理旧槽")
            for seq, (slot, item) in enumerate(zip(events, result["results"]), cursor + 1):
                index = order[seq - 1]
                is_failed = index in quarantined
                check(item["event_id"] == slot["event_id"], "处理改变原事件身份")
                check_result(item["result"], slot, packets[index], is_failed)
                if is_failed:
                    failed += 1
                else:
                    candidates.append(delivery_for(slot))
            slots.extend(events)
            cursor = end
            check(result["deliveries"] == candidates, "隔离槽产生送达候选或成功候选丢失")
            state = lab.rust(device, "wire_inspect")
            check_state(state, cursor, len(candidates), failed)
            check(result["sync"] == state["sync"], "逐槽处理状态未持久保存")
            evidence["pages"][-1]["state"] = state
        stored = [inspect_slot(lab, device, seq) for seq in range(1, len(order) + 1)]
        for seq, saved in enumerate(stored, 1):
            check(saved["found"] and saved["slot"] == slots[seq - 1] and not saved["waiting"],
                  "新 CLI 未加载到原槽及终态处理结果")
            index = order[seq - 1]
            check_result(saved["result"], saved["slot"], packets[index], index in quarantined)
        full = lab.pull(device, "0", "100")
        check(full["events"] == slots and not full["has_more"], "完整原签页与分批实际槽不符")
        targets[device] = {"state": state, "stored_slots": stored, "candidates": candidates, "full_page": full}
        evidence.update(state=state, stored_slots=stored, candidates=candidates,
                        signed_full_page_sha256=digest(full.wrapper))
    return targets


def report_successes(lab, packets, order, targets, quarantined):
    before = relay_receipts(lab)
    check(before["receipts"] == [], "解密或隔离本身产生了隐式回执")
    reports = []
    evidence = {"reports": [], "after_notifications": {}}
    lab.case_evidence["receipt_evidence"] = evidence
    for device, target in targets.items():
        for candidate in target["candidates"]:
            value = report(lab, device, candidate)
            reports.append((device, candidate))
            evidence["reports"].append({"device": device, "candidate": candidate, "result": value})
    rows = relay_receipts(lab)
    verify_receipts(rows, reports)
    rejected_ids = {packets[i]["accepted"]["acceptance_id"] for i in quarantined}
    check(not any(r["acceptance_id"] in rejected_ids for r in rows["receipts"]),
          "本轮成功候选流程为隔离消息提交了错误送达")
    for device, candidate in reports:
        report(lab, device, candidate)
    check(relay_receipts(lab) == rows, "重复成功回执产生新记录或通知")
    for device in ACCOUNTS:
        start = 0 if device == "a1" else len(order)
        page = lab.pull(device, str(start), "100")
        end = start + len(reports)
        check(len(page["events"]) == len(reports) and page["watermark"] == str(end)
              and page["next_after_seq"] == str(end) and not page["has_more"]
              and all(s["event"]["type"] == "delivery" for s in page["events"]),
              "送达通知数量或事件类型错误")
        lab.download(device, page)
        result = lab.rust(device, "wire_process")
        evidence["after_notifications"][device] = {"process": result, "signed_page_sha256": digest(page.wrapper)}
        candidates = [] if device == "a1" else targets[device]["candidates"]
        check([r["event_seq"] for r in result["results"]] == [s["event_seq"] for s in page["events"]]
              and all(r["result"] == {"status": "receipt_recorded"} for r in result["results"])
              and result["deliveries"] == candidates, "送达通知改变原消息处理或候选")
        state = lab.rust(device, "wire_inspect")
        check_state(state, end, len(candidates), 0 if device == "a1" else len(quarantined))
        check(result["sync"] == state["sync"], "回执处理状态没有持久保存")
        again = lab.rust(device, "wire_process")
        check(again["results"] == [] and again["deliveries"] == candidates and again["sync"] == state["sync"],
              "重复处理通知改变候选或隔离状态")
        evidence["after_notifications"][device].update(state=state, repeated_process=again)
        if device != "a1":
            for saved in targets[device]["stored_slots"]:
                inspect_slot(lab, device, saved["event_seq"], saved)
    check(relay_receipts(lab) == rows, "处理回执通知修改 Relay 记录")
    evidence.update(committed=rows, unique_successful_reports=len(reports),
                    repeated_reports=len(reports), quarantined_acceptance_ids=sorted(rejected_ids),
                    reporting_scope="only actual Rust success candidates; no test of a malicious client forging a delivery claim")
