"""删除后的真实回执、旧签页停流与尾游标通知；既有副本不会远程收回。"""

from functools import partial

from .deletion_observer import relay_records
from .deletion_support import (capture, check_availability_notice, check_deleted_slot, check_notice_result, delete, final_relay,
                               restart, retry_deleted, unchanged)
from .fixture import ACCOUNTS, check, identity
from .slot_support import check_message_result, check_sync, delivery_for, inspect_slot, publish
from .sync_support import TARGETS


def report(lab, device, candidate):
    value = lab.http(device, "report_delivery", {"service_id": lab.service, **candidate})
    check(value == {"acceptance_id": candidate["acceptance_id"], "attempt_id": "P1",
                   "device": identity(device), "delivered": True, "read": False}, "送达结果范围或阅读状态错误")
    return value


def receipt_lifecycle(lab, *, timing):
    packet, accepted, payload_hash = publish(lab, "delete_receipts")
    pages, candidates = {}, {}
    for device in TARGETS:
        pages[device] = lab.pull(device)
        lab.download(device, pages[device])
        value = lab.rust(device, "wire_process")
        check_message_result(value["results"][0]["result"], pages[device]["events"][0],
                             accepted["logical_message_id"], payload_hash, False)
        candidates[device] = delivery_for(pages[device]["events"][0])
        check(value["deliveries"] == [candidates[device]], "处理前未形成真实持久候选")
    if timing == "before_delete":
        for device in TARGETS:
            report(lab, device, candidates[device])
    delete(lab, accepted)
    retry_deleted(lab, packet, accepted, "receipt_case_deleted_attempt")
    restart(lab, "receipt_case_restart_deleted")
    for device in ACCOUNTS:
        page = lab.pull(device)
        expected_count = (3 if timing == "before_delete" else 0) + 2 * int(device != "a1")
        projected = page["events"] if device == "a1" else page["events"][:-1]
        check(len(page["events"]) == expected_count
              and all(s["availability"] == "deleted" and "event" not in s for s in projected),
              "删除未投影当时已有消息/通知槽")
        if device != "a1":
            check_deleted_slot(page["events"][0], pages[device]["events"][0])
            check_availability_notice(page["events"][-1], pages[device]["events"][0], accepted, "deleted", expected_count)
        lab.download(device, page)
        result = lab.rust(device, "wire_process")
        new_slots = page["events"] if device == "a1" else page["events"][1:]
        check([(v["event_seq"], v["event_id"]) for v in result["results"]]
              == [(s["event_seq"], s["event_id"]) for s in new_slots], "删除通知占位进度或身份不符")
        receipt_results = result["results"] if device == "a1" else result["results"][:-1]
        check(len(receipt_results) == (3 if timing == "before_delete" else 0)
              and all(v["result"] == {"status": "unavailable", "availability": "deleted"} for v in receipt_results),
              "已删除的旧通知槽未形成占位或重复处理原消息")
        if device != "a1":
            check_notice_result(result["results"][-1], page["events"][-1])
        check(result["deliveries"] == ([] if device == "a1" else [candidates[device]]),
              "删除旧通知改变了既有成功候选")
        check_sync(result["sync"], expected_count, expected_count)
        check(result["sync"]["slot_count"] == expected_count, "投影后有隐藏重复通知槽")
    prior = relay_records(lab)
    replies = {}
    for device in TARGETS:
        replies[device] = report(lab, device, candidates[device])
    after = relay_records(lab)
    check(after["counts"]["message_events"] == 3 and after["counts"]["events"] == 18
          and after["counts"]["receipts"] == 3, "回执重建了消息或重复生成通知")
    check(after["receipts"] == [{"acceptance_id": accepted["acceptance_id"],
          "account": identity(d)["account_id"], "device": d, "delivered": 1, "is_read": 0}
          for d in TARGETS], "回执主体不符或产生隐式阅读")
    if timing == "before_delete":
        check(after == prior, "已有回执重报改变了持久事实")
    else:
        # 删除后新通知可见，但原消息槽仍deleted；这是元数据通知而非密文恢复。
        check(sum(e["type"] == "delivery" and e["availability"] == "available" for e in after["events"]) == 12
              and all(e["availability"] == "deleted" for e in after["events"] if e["type"] == "message"),
              "新回执可用性与删除的原消息混淆")
        for device in ACCOUNTS:
            page = lab.pull(device, "0" if device == "a1" else "2")
            check(len(page["events"]) == 3 and all(s["event"]["type"] == "delivery" for s in page["events"]),
                  "未取得三条新回执通知")
            check([s["event"] for s in page["events"]] == [{"type": "delivery",
                  "acceptance_id": accepted["acceptance_id"], "attempt_id": "P1", "device": identity(d)}
                  for d in TARGETS], "新通知接受事实、报告设备或顺序错误")
            lab.download(device, page)
            value = lab.rust(device, "wire_process")
            check([v["result"] for v in value["results"]] == [{"status": "receipt_recorded"}] * 3,
                  "新回执通知被误当消息或不可用槽")
    restart(lab, "receipt_case_final_restart")
    before_repeat = capture(lab)
    for device in TARGETS:
        check(report(lab, device, candidates[device]) == replies[device], "重启后的回执重报不幂等")
    unchanged(lab, before_repeat, "receipt_repeat_after_restart")
    for device in ACCOUNTS:
        value = lab.rust(device, "wire_process")
        check(value["results"] == [] and value["deliveries"] == ([] if device == "a1" else [candidates[device]]),
              "最终处理重复发布结果或丢失历史成功")
        check_sync(value["sync"], 3 if device == "a1" else 5, 3 if device == "a1" else 5)
        check(value["sync"]["slot_count"] == (3 if device == "a1" else 5), "最终槽数不符")
        check(lab.rust(device, "wire_inspect")["inbox_count"] == int(device != "a1"), "通知复活或复制了正文")
    retry_deleted(lab, packet, accepted, "receipt_case_final_retry")
    final_relay(lab, 1)
    lab.case_evidence.update(receipt_timing=timing, candidates=candidates,
                            boundary="delivery metadata may remain reportable; accepted message stays deleted")


def old_available_replay(lab):
    packet, accepted, _ = publish(lab, "delete_old_page")
    pages = {device: lab.pull(device) for device in TARGETS}
    phases = {"a2": "unfetched", "b1": "queued", "c1": "processed"}
    for device in ("b1", "c1"):
        lab.download(device, pages[device])
    lab.rust("c1", "wire_process")
    delete(lab, accepted)
    projected = {}
    for device in TARGETS:
        # 仅下载旧槽的新投影，通知留在下一页；旧页水位尚未低于本机游标，独立检验同槽冲突。
        page = lab.pull(device, "0", "1")
        check(page["watermark"] == "2" and page["has_more"], "删除未追加后续通知")
        check_deleted_slot(page["events"][0], pages[device]["events"][0])
        lab.download(device, page)
        value = lab.rust(device, "wire_process")
        if device == "c1":
            check(value["results"] == [] and len(value["deliveries"]) == 1, "删除重处理原成功消息")
        else:
            check(value["results"][0]["result"] == {"status": "unavailable", "availability": "deleted"}
                  and value["deliveries"] == [], "占位产生了成功送达")
        projected[device] = inspect_slot(lab, device, 1)
        result = lab.download(device, pages[device])
        check(result["status"] == "stream_conflict", "旧available签页复活了deleted槽")
        check_sync(result["sync"], 1, 1, halted=True)
        check(result["sync"]["slot_count"] == 1, "旧页重放增加槽位")
        inspect_slot(lab, device, 1, projected[device])
    restart(lab, "old_available_halt_restart")
    for device in TARGETS:
        before = capture(lab)
        page = lab.pull(device)
        check(lab.download(device, page, expected_exit=1)["code"] == "stream_conflict", "重启丢失停流状态")
        check(lab.rust(device, "wire_process", expected_exit=1)["code"] == "stream_conflict", "停流后仍自动处理")
        unchanged(lab, before, "persistent_halt_" + device)
        inspect_slot(lab, device, 1, projected[device])
    retry_deleted(lab, packet, accepted, "old_page_retry_still_deleted")
    final_relay(lab, 1)
    lab.case_evidence.update(phases=phases, stored_deleted_slots=projected,
                            old_signed_available="stream_conflict; persistent halt, no slot overwrite")


def incremental_local_copy(lab):
    packet, accepted, payload_hash = publish(lab, "delete_incremental_boundary")
    originals = {device: lab.pull(device) for device in TARGETS}
    for device in TARGETS:
        lab.download(device, originals[device])
    delete(lab, accepted)
    restart(lab, "incremental_boundary_restart")
    stored = {}
    for device in TARGETS:
        # c1 在获知删除之前仍能处理旧副本；另外两个设备先同步终态，不能再解密。
        candidates = []
        if device == "c1":
            before_notice = lab.rust(device, "wire_process")
            check_message_result(before_notice["results"][0]["result"], originals[device]["events"][0],
                                 accepted["logical_message_id"], payload_hash, False)
            candidates = [delivery_for(originals[device]["events"][0])]
            check(before_notice["deliveries"] == candidates, "未知删除的既有副本结果错误")
        page = lab.pull(device, "1")
        check(len(page["events"]) == 1 and page["watermark"] == page["next_after_seq"] == "2"
              and not page["has_more"], "尾游标未取得唯一删除通知")
        check_availability_notice(page["events"][0], originals[device]["events"][0], accepted, "deleted", 2)
        lab.download(device, page)
        queued = inspect_slot(lab, device, 1)
        check(queued["slot"] == {**originals[device]["events"][0], "availability": "deleted"}
              and (queued["result"] is None) is (device != "c1"), "增量通知未投影原槽或清除了成功事实")
        value = lab.rust(device, "wire_process")
        expected_sequences = ["2"] if device == "c1" else ["1", "2"]
        check([item["event_seq"] for item in value["results"]] == expected_sequences, "删除增量遗漏或重处理槽")
        if device != "c1":
            check(value["results"][0]["result"] == {"status": "unavailable", "availability": "deleted"},
                  "已知删除的排队副本仍被解密")
        check_notice_result(value["results"][-1], page["events"][0])
        check(value["deliveries"] == candidates, "删除通知产生新送达或丢失既有结果")
        check_sync(value["sync"], 2, 2)
        check(value["sync"]["slot_count"] == 2, "增量通知槽数错误")
        overlap = lab.pull(device)
        check_deleted_slot(overlap["events"][0], originals[device]["events"][0])
        lab.download(device, overlap)
        repeat = lab.rust(device, "wire_process")
        check(repeat["results"] == [] and repeat["deliveries"] == value["deliveries"]
              and lab.rust(device, "wire_inspect")["inbox_count"] == int(device == "c1"),
              "观察删除后重复处理或错误声称远程清除本地副本")
        check_sync(repeat["sync"], 2, 2)
        check(repeat["sync"]["slot_count"] == 2, "重叠删除页增加了槽位")
        stored[device] = [inspect_slot(lab, device, seq) for seq in (1, 2)]
    restart(lab, "incremental_boundary_after_projection_restart")
    for device in TARGETS:
        value = lab.rust(device, "wire_process")
        expected = [delivery_for(originals[device]["events"][0])] if device == "c1" else []
        check(value["results"] == [] and value["deliveries"] == expected
              and lab.rust(device, "wire_inspect")["inbox_count"] == int(device == "c1"), "重启改变了既有副本边界")
        check_sync(value["sync"], 2, 2)
        check(value["sync"]["slot_count"] == 2, "重启增加终态槽")
        for seq in (1, 2):
            inspect_slot(lab, device, seq, stored[device][seq - 1])
    retry_deleted(lab, packet, accepted, "incremental_boundary_original_stays_deleted")
    final_relay(lab, 1)
    lab.case_evidence.update(stored_slots=stored, incremental_result="verified_tail_notice_projects_queued_target_before_processing",
        boundary="c1 processed its prior copy before learning deletion; verified notification preserves that success and does not erase it")


CASES = [("M11.delete.receipts." + timing, partial(receipt_lifecycle, timing=timing))
         for timing in ("before_delete", "after_delete")] + [
    ("M11.delete.old_available_replay", old_available_replay),
    ("M11.delete.incremental_local_copy_boundary", incremental_local_copy),
]
