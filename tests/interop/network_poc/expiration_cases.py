"""实际到期判断的请求入口、毫秒边界与真实短保留期；共用原 Rust 签页处理。"""

import copy
from functools import partial
import time

from .deletion_observer import relay_records
from .deletion_support import capture, check_availability_notice, check_notice_result, restart, unchanged
from .expiration_support import (assert_expired_transition, check_expired_slot,
                                 observe_final, retry_expired, set_clock)
from .fixture import check
from .slot_support import (check_message_result, check_message_slot, check_sync,
                           delivery_for, inspect_slot, publish)
from .sync_support import TARGETS

PHASES = {"a2": "unfetched", "b1": "queued", "c1": "processed"}


def initial_clients(lab, records):
    pages = {d: lab.pull(d) for d in TARGETS}
    stored = {}
    for device in TARGETS:
        for seq, record in enumerate(records, 1):
            check_message_slot(pages[device]["events"][seq - 1], record[0], record[1], seq)
        if device != "a2":
            # 只下载首槽，使逐槽重叠页不落后于现有下载游标。
            lab.download(device, lab.pull(device, "0", "1"))
            if device == "c1":
                result = lab.rust(device, "wire_process")
                check(len(result["results"]) == 1, "过期前没有处理原消息")
                check_message_result(result["results"][0]["result"], pages[device]["events"][0],
                                     records[0][1]["logical_message_id"], records[0][2], False)
                check(result["deliveries"] == [delivery_for(pages[device]["events"][0])], "初始候选不符")
        stored[device] = inspect_slot(lab, device, 1)
    lab.case_evidence.update(phases=PHASES, before_slots=stored)
    return pages, stored


def consume_expiration(lab, records, pages, stored, pagination):
    message_count = len(records)
    total = message_count + 1
    expected_relay = relay_records(lab)
    final = {}
    for device in TARGETS:
        page = lab.pull(device)
        check(len(page["events"]) == total and page["next_after_seq"] == page["watermark"] == str(total)
              and not page["has_more"], "过期后的连续水位错误")
        check_expired_slot(page["events"][0], pages[device]["events"][0])
        check(page["events"][1:message_count] == pages[device]["events"][1:], "未到期后续消息改变")
        check_availability_notice(page["events"][-1], pages[device]["events"][0], records[0][1], "expired", total)
        if pagination == "single":
            for after in range(total):
                single = lab.pull(device, str(after), "1")
                check(single["events"] == [page["events"][after]]
                      and single["next_after_seq"] == str(after + 1)
                      and single["has_more"] is (after + 1 < total), "逐槽补拉丢失过期占位")
                lab.download(device, single)
        else:
            lab.download(device, page)
        expected_slot = copy.deepcopy(stored[device])
        if device == "a2":
            expected_slot = {"event_seq": "1", "found": True, "slot": page["events"][0],
                             "result": None, "waiting": False}
        else:
            expected_slot["slot"]["availability"] = "expired"
        inspect_slot(lab, device, 1, expected_slot)
        value = lab.rust(device, "wire_process")
        sequences = range(2 if device == "c1" else 1, total + 1)
        check([v["event_seq"] for v in value["results"]] == [str(n) for n in sequences],
              "TTL处理跳过或重复结果")
        for item in value["results"]:
            seq = int(item["event_seq"])
            check(item["event_id"] == page["events"][seq - 1]["event_id"], "结果改变原事件身份")
            if seq == 1:
                check(item["result"] == {"status": "unavailable", "availability": "expired"},
                      "已知过期仍处理正文")
            elif seq == total:
                check_notice_result(item, page["events"][-1])
            else:
                check_message_result(item["result"], pages[device]["events"][seq - 1],
                                     records[seq - 1][1]["logical_message_id"], records[seq - 1][2], False)
        valid = list(range(1 if device == "c1" else 2, message_count + 1))
        candidates = [delivery_for(pages[device]["events"][n - 1]) for n in valid]
        check(value["deliveries"] == candidates, "TTL错误生成或删除既有候选")
        check_sync(value["sync"], total, total)
        check(value["sync"]["slot_count"] == total, "TTL制造重复槽")
        check(lab.rust(device, "wire_inspect")["inbox_count"] == len(valid), "TTL复活/重复/清除有效本地消息")
        lab.download(device, page)
        repeat = lab.rust(device, "wire_process")
        check(repeat["results"] == [] and repeat["deliveries"] == candidates
              and repeat["sync"] == value["sync"], "重复过期页改变持久处理结果")
        final[device] = {"page": page, "slots": [inspect_slot(lab, device, n) for n in range(1, total + 1)],
                         "deliveries": candidates, "sync": value["sync"], "inbox_count": len(valid)}
    check(relay_records(lab) == expected_relay, "补拉/端侧处理改变了原接受记录")
    restart(lab, "after_expired_processing")
    retry_expired(lab, records[0][0], records[0][1], "expired_retry_after_processing_restart")
    for device in TARGETS:
        check(lab.pull(device) == final[device]["page"], "重启修改了投影页")
        lab.download(device, lab.pull(device))
        value = lab.rust(device, "wire_process")
        check(value["results"] == [] and value["deliveries"] == final[device]["deliveries"]
              and value["sync"] == final[device]["sync"], "重启后结果不幂等")
        for seq, slot in enumerate(final[device]["slots"], 1):
            inspect_slot(lab, device, seq, slot)
        tail = lab.pull(device, str(total), "1")
        check(tail["events"] == [] and tail["watermark"] == tail["next_after_seq"] == str(total)
              and not tail["has_more"], "过期重试产生新槽")
    check(relay_records(lab) == expected_relay, "最终重启/重试改变原持久记录")
    lab.case_evidence["targets"] = final
    observe_final(lab, message_count)


def request_boundary(lab, *, trigger, pagination):
    records = [publish(lab, "ttl_first")]
    first = records[0][1]
    deadline = lab.ttl_base_ms + lab.retention_ms
    check(first["accepted_at_unix_ms"] == str(lab.ttl_base_ms)
          and first["expires_at_unix_ms"] == str(deadline), "首次接受未使用受控时钟/保留期")
    set_clock(lab, lab.ttl_base_ms + 500)
    records.append(publish(lab, "ttl_later"))
    check(records[1][1]["expires_at_unix_ms"] == str(deadline + 500), "后续消息期限错误")
    pages, stored = initial_clients(lab, records)
    set_clock(lab, deadline - 1)
    before = capture(lab)
    for operation in ("submit_message", "get_attempt", "close_attempt"):
        value = lab.submit(records[0][0]) if operation == "submit_message" else lab.attempt(
            first["logical_message_id"], operation=operation)
        check(value == first, "deadline-1提前过期或重试续期")
    for device in TARGETS:
        check(lab.pull(device) == pages[device], "deadline-1页面已过期")
    unchanged(lab, before, "deadline_minus_one_all_available")
    restart(lab, "restart_before_deadline")
    set_clock(lab, deadline)
    restart(lab, "restart_at_deadline_before_request")
    before = relay_records(lab)
    expected = {**first, "availability": "expired"}
    if trigger == "pull_events_signed":
        check_expired_slot(lab.pull("a2")["events"][0], pages["a2"]["events"][0])
    else:
        value = lab.submit(records[0][0]) if trigger == "submit_message" else lab.attempt(
            first["logical_message_id"], operation=trigger)
        check(value == expected, "截止毫秒首次请求未返回完整过期接受事实")
    after = relay_records(lab)
    assert_expired_transition(before, after, first)
    lab.case_evidence.update(trigger=trigger, pagination=pagination, deadline_unix_ms=str(deadline),
                             expiration_transition={"before": before, "after": after})
    set_clock(lab, deadline + 1)
    retry_expired(lab, records[0][0], first, "deadline_plus_one_retry")
    consume_expiration(lab, records, pages, stored, pagination)


def wall_clock(lab):
    started_ms = time.time_ns() // 1_000_000
    records = [publish(lab, "ttl_wall_clock")]
    accepted = records[0][1]
    accepted_end_ms = time.time_ns() // 1_000_000
    accepted_ms, deadline = int(accepted["accepted_at_unix_ms"]), int(accepted["expires_at_unix_ms"])
    check(started_ms <= accepted_ms <= accepted_end_ms and deadline - accepted_ms == lab.retention_ms,
          "真实接受时间不在实测区间或保留期错误")
    pages, stored = initial_clients(lab, records)
    before = capture(lab)
    for operation in ("submit_message", "get_attempt", "close_attempt"):
        value = lab.submit(records[0][0]) if operation == "submit_message" else lab.attempt(
            accepted["logical_message_id"], operation=operation)
        check(value == accepted, "到期前接受事实变化")
    ready_ms = time.time_ns() // 1_000_000
    check(ready_ms < deadline, "真实时钟基线耗时超出保留期，不能声称验证到期前")
    unchanged(lab, before, "wall_clock_before_deadline")
    lab.stop()
    stopped_ms = time.time_ns() // 1_000_000
    check(stopped_ms < deadline, "Relay未在截止前退出")
    wait_start = time.monotonic()
    while time.time_ns() // 1_000_000 < deadline:
        check(time.monotonic() - wait_start < lab.retention_ms / 1000 + 10,
              "真实系统时钟未在有界窗口到期")
        time.sleep(0.05)
    observed_ms = time.time_ns() // 1_000_000
    wait_elapsed_ms = round((time.monotonic() - wait_start) * 1000)
    unchanged(lab, before, "wall_clock_elapsed_without_request")
    lab.start()
    unchanged(lab, before, "wall_clock_restart_does_not_extend_or_project")
    check(lab.attempt(accepted["logical_message_id"]) == {**accepted, "availability": "expired"},
          "真实期限后首查询未过期或重启延长期限")
    after = relay_records(lab)
    assert_expired_transition(before["relay"], after, accepted)
    lab.case_evidence.update(wall_clock={"submit_started_unix_ms": str(started_ms),
        "submit_finished_unix_ms": str(accepted_end_ms), "before_deadline_observed_unix_ms": str(ready_ms),
        "relay_stopped_unix_ms": str(stopped_ms), "after_deadline_observed_unix_ms": str(observed_ms),
        "wait_elapsed_monotonic_ms": wait_elapsed_ms,
        "deadline_unix_ms": str(deadline), "injected_clock": False},
        expiration_transition={"before": before["relay"], "after": after})
    retry_expired(lab, records[0][0], accepted, "wall_clock_expired_retry")
    consume_expiration(lab, records, pages, stored, "whole")


CASES = [(f"M11.expire.{trigger}.{pagination}", partial(request_boundary, trigger=trigger, pagination=pagination))
         for trigger in ("submit_message", "get_attempt", "close_attempt", "pull_events_signed")
         for pagination in ("whole", "single")] + [("M11.expire.wall_clock", wall_clock)]
