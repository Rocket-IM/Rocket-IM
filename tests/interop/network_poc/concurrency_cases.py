"""M07：真实事务待锁期间并发HTTP，分别提交/回滚后逐目标完整补拉。"""

from concurrent.futures import ThreadPoolExecutor
from functools import partial
import hashlib
import json

from .fixture import SERVICE, check
from .message_cases import header

TARGETS = ("a2", "b1", "c1")


def page_slots(lab, device, page, after, limit, expected, processed):
    slots = page["events"]
    high, next_after = int(page["watermark"]), int(page["next_after_seq"])
    check(page["stream_id"] == lab.streams[device], "设备流身份变化")
    check(len(slots) <= limit and high >= after, "页大小超限或水位回退")
    check([int(slot["event_seq"]) for slot in slots] == list(range(after + 1, after + 1 + len(slots))),
          "分页越过了未返回的槽位")
    check(next_after == (after + len(slots)) and next_after <= high, "下一游标未指向实际连续前缀")
    check(page["has_more"] is (next_after < high), "has_more与已提交水位不符")
    for slot in slots:
        check(slot["stream_id"] == page["stream_id"] and slot["availability"] == "available", "槽位归属或可用性错误")
        event = slot["event"]
        check(event["type"] == "message", "产生了额外非消息事件")
        logical = header({"envelope": event["envelope"]})["logical_message_id"]
        check(logical in expected, "页中包含未接受或已回滚的消息")
        packet, accepted = expected[logical]
        check(event["envelope"] == packet["envelope"] and event["acceptance_id"] == accepted["acceptance_id"],
              "槽位信封/接受ID未保持原值")
    lab.download(device, page)
    lab.download(device, page)
    result = lab.rust(device, "wire_process")
    for item in result["results"]:
        message = item["result"]["message"]
        logical = message["logical_message_id"]
        check(logical in expected and logical not in processed, "出现重复或非已接受业务结果")
        check(message["payload_sha256"] == hashlib.sha256(("synthetic-network-" + logical).encode()).hexdigest(),
              "真实MLS解密正文摘要错误")
        processed.add(logical)
    check(lab.rust(device, "wire_process")["results"] == [], "重复处理再次交付业务结果")
    return slots


def concurrent_transactions(lab, *, decision, seeds, limit, launch_first):
    expected = {}
    collected, processed = {d: [] for d in TARGETS}, {d: set() for d in TARGETS}
    for i in range(seeds):
        logical = f"m07_seed_{i}"
        packet = lab.prepare(logical)
        expected[logical] = (packet, lab.submit(packet))
    for device in TARGETS:
        initial = lab.pull(device)
        collected[device].extend(page_slots(lab, device, initial, 0, 100, expected, processed[device]))
    first, second = lab.prepare("m07_tx1"), lab.prepare("m07_tx2")
    baseline = lab.committed_view()
    lab.case_evidence.update(decision=decision, seed_count=seeds, page_limit=limit,
                             launch_first=launch_first, committed_before=baseline)
    lab.probe("arm", labels=[{"label": "tx1", "hold_before_commit": True},
                              {"label": "tx2"}, {"label": "page"}])
    released = False
    with ThreadPoolExecutor(max_workers=3) as pool:
        one = pool.submit(lab.http, "a1", "submit_message", {"envelope": first["envelope"]},
                          label="tx1", expected=200 if decision == "commit" else 503)
        try:
            entered = lab.wait_for("tx1", "before_commit_waiting")
            lab.case_evidence["tx1_entered"] = entered
            pending = next(e["pending"] for e in entered["events"] if e["stage"] == "before_commit_waiting")
            check(pending["accepted"] == pending["attempts"] == str(seeds + 1)
                  and pending["message_events"] == str((seeds + 1) * 3), "Tx1暂停前没有写完接受与目标扇出")
            for stream in pending["streams"]:
                count = seeds + 1 if stream["device_id"] in TARGETS else 0
                check(stream["watermark"] == stream["events"] == str(count), "Tx1暂停前目标槽位不完整")
            def start(label):
                if label == "tx2":
                    return pool.submit(lab.http, "a1", "submit_message", {"envelope": second["envelope"]}, label=label)
                return pool.submit(lab.pull, "b1", str(seeds), str(limit), label=label)
            futures = {}
            for label in (launch_first, "page" if launch_first == "tx2" else "tx2"):
                futures[label] = start(label)
                lab.wait_for(label, "begin_requested")
            held = lab.probe("status")
            lab.case_evidence["held_timeline"] = held
            check(not any(e["stage"] in ("acquired", "responded") and e["label"] in ("tx2", "page")
                          for e in held["events"]), "Tx1持锁时等待者已经获得事务或应答")
            check(not one.done() and not any(f.done() for f in futures.values()), "未决窗口泄漏HTTP结果")
            observed = lab.committed_view()
            check(observed == baseline, "独立读取暴露了Tx1未提交接受或槽位")
            lab.case_evidence["committed_while_held"] = observed
            lab.probe("release", label="tx1", point="before_commit", decision=decision)
            released = True
            result1 = one.result(timeout=10)
            result2 = futures["tx2"].result(timeout=10)
            raced_page = futures["page"].result(timeout=10)
        finally:
            if not released:
                lab.probe("release", label="tx1", point="before_commit", decision="rollback")
    for label in ("tx1", "tx2", "page"):
        lab.wait_for(label, "responded")
    timeline = lab.probe("status")
    lab.case_evidence.update(timeline=timeline, tx1_result=result1, tx2_result=result2, raced_page=raced_page)
    stages = {label: [e["stage"] for e in timeline["events"] if e["label"] == label]
              for label in ("tx1", "tx2", "page")}
    check(("committed" if decision == "commit" else "rolled_back") in stages["tx1"], "Tx1终态不符合释放动作")
    if decision == "commit":
        expected["m07_tx1"] = (first, result1)
    else:
        check(result1["code"] == "test_transaction_rollback" and result1["outcome"] == "not_recorded", "没有明确测试回滚结果")
        check(lab.attempt("m07_tx1")["outcome"] == "not_found", "回滚事务残留尝试终态")
    expected["m07_tx2"] = (second, result2)
    acquired = [e["label"] for e in timeline["events"] if e["stage"] == "acquired"]
    check(acquired[0] == "tx1" and set(acquired) == {"tx1", "tx2", "page"}, "事务获取记录不完整")
    race_watermark = seeds + (decision == "commit") + (acquired.index("tx2") < acquired.index("page"))
    check(int(raced_page["watermark"]) == race_watermark, "分页水位不对应实际已提交前缀")
    total = len(expected)
    for device in TARGETS:
        cursor = seeds
        if device == "b1":
            collected[device].extend(page_slots(lab, device, raced_page, cursor, limit, expected, processed[device]))
            cursor = int(raced_page["next_after_seq"])
        # 两发送均终结后必须再拉一页，早先has_more=false也不代表未来无提交。
        while True:
            page = lab.pull(device, str(cursor), str(limit))
            check(int(page["watermark"]) == total, "最终水位遗漏已接受消息")
            collected[device].extend(page_slots(lab, device, page, cursor, limit, expected, processed[device]))
            cursor = int(page["next_after_seq"])
            if not page["has_more"]:
                break
        check(processed[device] == set(expected), "目标设备解密结果遗漏或包含回滚消息")
        check(len(collected[device]) == total, "目标槽位未恰好覆盖所有已接受消息")
    # 真实重启Relay与独立Rust CLI，再比较槽位完整内容及去重状态。
    lab.restart()
    for device in TARGETS:
        page = lab.pull(device)
        check(page["events"] == collected[device], "重启改变槽位ID/序号/接受归属或原信封")
        page_slots(lab, device, page, 0, 100, expected, processed[device])
        state = lab.rust(device, "wire_inspect")
        check(state["inbox_count"] == total and state["sync"]["download_cursor"] == str(total)
              and state["sync"]["processed_cursor"] == str(total), "重启后去重或双游标不完整")
        lab.case_evidence.setdefault("targets", {})[device] = {
            "logical_ids": sorted(processed[device]), "state": state,
            "slots_sha256": hashlib.sha256(json.dumps(page["events"], sort_keys=True).encode()).hexdigest(),
            "slots": [{k: slot[k] for k in ("stream_id", "event_seq", "event_id")} for slot in page["events"]]}
    for logical, (packet, accepted) in expected.items():
        check(lab.attempt(logical) == accepted and lab.submit(packet) == accepted, "重启后原接受结果不稳定或重复投递")
    if decision == "rollback":
        check(lab.attempt("m07_tx1")["outcome"] == "not_found", "重启复活回滚尝试")
    stats = lab.control("stats")
    check(stats["accepted"] == stats["attempts"] == str(total) and stats["message_events"] == str(total * 3)
          and stats["events"] == str(total * 3) and stats["receipts"] == "0", "最终接受/完整扇出或去重计数错误")
    lab.case_evidence.update(final_stats=stats, accepted_ids=sorted(expected), acquisition_order=acquired)


CASES = [(f"M07.{decision}.{name}", partial(concurrent_transactions, decision=decision,
           seeds=seeds, limit=limit, launch_first=first))
         for decision in ("commit", "rollback")
         for name, seeds, limit, first in (("empty_page_first", 0, 1, "page"),
                                           ("seeded_writer_first", 2, 1, "tx2"),
                                           ("seeded_page_two", 2, 2, "page"))]
