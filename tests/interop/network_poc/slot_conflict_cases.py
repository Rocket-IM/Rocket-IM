"""M11.e/f：只改变一个判定维度，直接读回原槽并核对持久停流。"""

import base64
import copy
from functools import partial

from .fixture import check
from .slot_support import check_message_result, check_message_slot, check_sync, digest, inspect_slot, publish
from .sync_support import TARGETS, relay_receipts


def conflict(lab, *, change, processed):
    logical = "slot_conflict_original"
    packet, accepted, payload_hash = publish(lab, logical)
    originals = {}
    lab.case_evidence.update(change=change, original_processed=processed, targets={})
    for device in TARGETS:
        page = lab.pull(device)
        check(len(page["events"]) == 1, "独立基线必须只有原消息槽")
        slot = page["events"][0]
        check_message_slot(slot, packet, accepted, 1)
        lab.download(device, page)
        if processed:
            result = lab.rust(device, "wire_process")
            check(len(result["results"]) == 1, "原槽未单独处理")
            check_message_result(result["results"][0]["result"], slot, logical, payload_hash, False)
        original = inspect_slot(lab, device, 1)
        check(original["found"] and original["slot"] == slot and not original["waiting"], "原槽未完整落盘")
        check((original["result"] is not None) is processed, "原槽处理基线不符")
        state = lab.rust(device, "wire_inspect")
        check_sync(state["sync"], 1, int(processed), int(not processed))
        check(state["inbox_count"] == int(processed), "原业务消息基线错误")
        originals[device] = (original, state)

    # 冲突页带后续真实合法槽：不能在发现冲突前后留下部分页写入。
    second, second_accepted, _ = publish(lab, "slot_conflict_suffix")
    rows_before = relay_receipts(lab)
    pages = {}
    for device in TARGETS:
        page = lab.pull(device)
        check(len(page["events"]) == 2, "冲突页缺少真实后续槽")
        check_message_slot(page["events"][1], second, second_accepted, 2)
        corrupted = copy.deepcopy(page)
        slot = corrupted["events"][0]
        if change == "event_id":
            slot["event_id"] = "m11_conflicting_event"
            check(slot["event_id"] != page["events"][0]["event_id"], "异ID装置没有改变ID")
            check(slot["event"] == page["events"][0]["event"], "异ID装置改了正文")
        else:
            raw = bytearray(base64.b64decode(slot["event"]["envelope"]["payload_bytes"], validate=True))
            raw[-1] ^= 1
            slot["event"]["envelope"]["payload_bytes"] = base64.b64encode(raw).decode()
            restored = copy.deepcopy(slot)
            restored["event"]["envelope"]["payload_bytes"] = page["events"][0]["event"]["envelope"]["payload_bytes"]
            check(restored == page["events"][0], "异内容装置改变了stream/seq/event_id或其他字段")
        # 明确模拟持有实验 Service 钥的作恶签发者；传输篡改不能进入槽冲突分支。
        corrupted = lab.sign_test_page(corrupted)
        result = lab.download(device, corrupted)
        check(result["status"] == "stream_conflict", "同槽冲突未显式停流")
        check_sync(result["sync"], 1, int(processed), int(not processed), halted=True)
        original, before = originals[device]
        after = lab.rust(device, "wire_inspect")
        expected = copy.deepcopy(before)
        expected["sync"]["halted"] = True
        check(after == expected, "冲突除了持久停流还改变了原业务/同步状态")
        inspect_slot(lab, device, 1, original)
        missing = inspect_slot(lab, device, 2)
        check(missing == {"event_seq": "2", "found": False, "slot": None, "result": None, "waiting": False},
              "冲突页部分保存了后续槽")
        lab.case_evidence["targets"][device] = {
            "original": original, "original_sha256": digest(original), "conflicting_slot": slot,
            "conflict": result, "state_before": before, "state_after": after,
            "suffix_missing": missing, "original_readback_equal": True,
        }
        pages[device] = page

    lab.restart()
    for device in TARGETS:
        page = lab.pull(device)
        check(page == pages[device], "客户端合成冲突改变了Relay原记录")
        original, _ = originals[device]
        snapshot = (lab.directory / device / "state.enc").read_bytes()
        for operation in ("download", "process"):
            error = (lab.download(device, page, expected_exit=1) if operation == "download"
                     else lab.rust(device, "wire_process", expected_exit=1))
            check(error["code"] == "stream_conflict", "重启后的正确页/处理绕过停流")
            check((lab.directory / device / "state.enc").read_bytes() == snapshot, "停流拒绝路径改写快照")
        inspect_slot(lab, device, 1, original)
        lab.case_evidence["targets"][device]["restart_rejected_without_write"] = True
    check(relay_receipts(lab) == rows_before, "冲突或观察意外产生服务端回执/事件")
    check(lab.control("stats")["message_events"] == "6", "两条消息真实扇出不完整")
    lab.case_evidence["relay_committed_view_sha256"] = digest(rows_before)


CASES = [(f"M11.conflict.{change}.{state}", partial(conflict, change=change, processed=state == "processed"))
         for change in ("event_id", "content") for state in ("pending", "processed")]
