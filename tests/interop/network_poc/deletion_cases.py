"""真实直接删除→原包重试→重启签页补拉→Rust占位/既有结果的三状态矩阵。"""

import copy
from functools import partial

from .deletion_observer import relay_records
from .deletion_support import (check_availability_notice, check_deleted_slot, check_notice_result, delete, final_relay,
                               observe_clients, restart, retry_deleted)
from .fixture import check
from .slot_support import (check_message_result, check_message_slot, check_sync,
                           delivery_for, inspect_slot, publish)
from .sync_support import TARGETS


def check_processed(lab, device, phase, originals, records, new_sequences):
    value = lab.rust(device, "wire_process")
    check([r["event_seq"] for r in value["results"]] == [str(s) for s in new_sequences],
          "处理跳过槽位或重复发布旧结果")
    for item in value["results"]:
        seq = int(item["event_seq"])
        check(item["event_id"] == originals[seq - 1]["event_id"], "处理结果槽身份错误")
        if seq == 3:
            check_notice_result(item, originals[2])
        elif seq == 2 and phase != "processed":
            check(item["result"] == {"status": "unavailable", "availability": "deleted"},
                  "已观察删除的未处理槽仍解密成功")
        else:
            packet, accepted, payload_hash = records[seq - 1 if seq < 3 else 2]
            check_message_result(item["result"], originals[seq - 1], accepted["logical_message_id"], payload_hash, False)
    valid = (1, 2, 4) if phase == "processed" else (1, 4)
    check(value["deliveries"] == [delivery_for(originals[seq - 1]) for seq in valid],
          "删除制造/清除既有送达结果或产生新候选")
    check_sync(value["sync"], 4, 4)
    check(value["sync"]["slot_count"] == 4, "存在隐藏重复槽")
    state = lab.rust(device, "wire_inspect")
    check(state["inbox_count"] == len(valid) and state["sync"]["source_verified"],
          "删除后重复建立业务消息或来源未认证")
    return value


def direct_deletion(lab, *, phase, pagination):
    records = [publish(lab, "delete_prefix"), publish(lab, "delete_target")]
    packet, accepted, _ = records[1]
    originals = {device: lab.pull(device) for device in TARGETS}
    before_slots = {}
    lab.case_evidence.update(phase=phase, pagination=pagination, targets={})
    for device, page in originals.items():
        check(len(page["events"]) == 2, "删除基线不是两条真实消息")
        for seq, record in enumerate(records, 1):
            check_message_slot(page["events"][seq - 1], record[0], record[1], seq)
        if phase != "unfetched":
            lab.download(device, page)
            if phase == "processed":
                result = lab.rust(device, "wire_process")
                check([v["event_seq"] for v in result["results"]] == ["1", "2"], "删除前没有实际处理两条消息")
                for seq, item in enumerate(result["results"], 1):
                    check_message_result(item["result"], page["events"][seq - 1], records[seq - 1][1]["logical_message_id"],
                                         records[seq - 1][2], False)
                check(result["deliveries"] == [delivery_for(s) for s in page["events"]], "删除前候选缺失")
        before_slots[device] = inspect_slot(lab, device, 2)
    delete(lab, accepted)
    retry_deleted(lab, packet, accepted, "retry_before_restart")
    restart(lab, "restart_after_delete")
    retry_deleted(lab, packet, accepted, "retry_after_restart")
    records.append(publish(lab, "delete_suffix"))
    expected_relay = relay_records(lab)
    check(expected_relay["counts"]["receipts"] == 0, "未报告却产生了设备回执")

    deleted_pages, stored = {}, {}
    for device in TARGETS:
        full = lab.pull(device)
        check(len(full["events"]) == 4 and full["watermark"] == full["next_after_seq"] == "4"
              and not full["has_more"], "删除使连续流出现空洞")
        check_deleted_slot(full["events"][1], originals[device]["events"][1])
        check(full["events"][0] == originals[device]["events"][0], "删除改变前一消息")
        check_availability_notice(full["events"][2], originals[device]["events"][1], accepted, "deleted", 3)
        check_message_slot(full["events"][3], records[2][0], records[2][1], 4)
        original_slots = [*originals[device]["events"], *full["events"][2:]]
        if pagination == "whole":
            lab.download(device, full)
        else:
            # 原游标为2时从1重叠读取删除槽；不能用已落后游标的单槽首页覆盖进度。
            start = 0 if phase == "unfetched" else 1
            for after in range(start, 4):
                page = lab.pull(device, str(after), "1")
                check(page["events"] == [full["events"][after]] and page["next_after_seq"] == str(after + 1)
                      and page["has_more"] is (after < 3), "单槽分页跳过删除占位")
                lab.download(device, page)
        queued = inspect_slot(lab, device, 2)
        expected_slot = copy.deepcopy(before_slots[device])
        if phase == "unfetched":
            expected_slot = {"event_seq": "2", "found": True, "slot": full["events"][1], "result": None, "waiting": False}
        else:
            expected_slot["slot"]["availability"] = "deleted"
        check(queued == expected_slot, "删除投影未保留原槽/结果或错误清除了已下载事件")
        result = check_processed(lab, device, phase, original_slots, records,
                                 (3, 4) if phase == "processed" else (1, 2, 3, 4))
        lab.download(device, full)
        repeated = check_processed(lab, device, phase, original_slots, records, ())
        check(repeated["deliveries"] == result["deliveries"], "删除页重放改变送达候选")
        stored[device] = [inspect_slot(lab, device, seq) for seq in (1, 2, 3, 4)]
        deleted_pages[device] = full
        lab.case_evidence["targets"][device] = {"before_target": before_slots[device], "after_projection": queued,
            "stored_slots": stored[device], "final_sync": result["sync"], "deliveries": result["deliveries"],
            "inbox_count": 3 if phase == "processed" else 2}
    check(relay_records(lab) == expected_relay, "端侧处理或补拉改变服务端接受/槽位")
    restart(lab, "restart_after_processing")
    retry_deleted(lab, packet, accepted, "retry_after_processing_restart")
    for device in TARGETS:
        full = lab.pull(device)
        check(full == deleted_pages[device], "重启恢复了已删除载荷或改写页")
        lab.download(device, full)
        original_slots = [*originals[device]["events"], *full["events"][2:]]
        check_processed(lab, device, phase, original_slots, records, ())
        for seq in (1, 2, 3, 4):
            inspect_slot(lab, device, seq, stored[device][seq - 1])
        tail = lab.pull(device, "4", "1")
        check(tail["events"] == [] and tail["next_after_seq"] == tail["watermark"] == "4"
              and not tail["has_more"], "删除/重试重新扇出消息槽")
    check(relay_records(lab) == expected_relay, "最终重试、重启或补拉制造重复记录")
    final_relay(lab, 3)
    lab.case_evidence["final_clients"] = observe_clients(lab)


CASES = [(f"M11.delete.{phase}.{pagination}", partial(direct_deletion, phase=phase, pagination=pagination))
         for phase in ("unfetched", "queued", "processed") for pagination in ("whole", "single")]
