"""M10.c：独立HTTP控制保存后，再经真实普通设备流到达的三条恢复路径。"""

import base64
import hashlib

from .dependency_support import (candidates, corrupt, one_page, process_slot,
                                 record, report_and_repeat, restart, state)
from .fixture import CONVERSATION, check, identity


def recover(lab, variant):
    lab.case_evidence.update(variant=variant, control_mode="legacy_synthetic",
                             ordinary_page_source="legacy_unverified")
    bad_slots = []
    prefix = 0
    if variant == "bad_before":
        damaged = corrupt(lab.prepare("bad_before_control"))
        accepted = lab.submit(damaged)
        page = one_page(lab, 0, "message")
        slot = page["events"][0]
        check(slot["event"]["acceptance_id"] == accepted["acceptance_id"]
              and slot["event"]["envelope"] == damaged["envelope"], "损坏消息未通过原HTTP保存与返回")
        lab.download("b1", page)
        bad_slots.append(slot)
        result = process_slot(lab, slot, "quarantined")
        check(result["results"][0]["result"]["code"] == "decryption_failed", "坏密文应在实际MLS解密处隔离")
        candidates(lab, result, None, bad_slots)
        prefix = 1
        state(lab, "bad_prefix_saved", downloaded=1, processed=1, pending=0,
              quarantined=1, inbox=0, applied=0)

    before = lab.rust("b1", "wire_inspect")
    removed = lab.rust("a1", "remove", id="m10_remove_c", member="c1")
    sender = lab.rust("a1", "wire_configure", conversation_id=CONVERSATION, authorization_version="2")
    current = sender["crypto_state_ref"]
    check(current != before["crypto_state_ref"] and int(sender["epoch"]) == int(before["epoch"]) + 1,
          "真实MLS移除未产生一个后继epoch")
    lab.control("set_state", authorization_version="2", crypto_state_ref=current,
                members=[identity(d) for d in ("a1", "a2", "b1")])
    control = {"control_id": "m10_remove_c", "from_state_ref": before["crypto_state_ref"],
               "to_state_ref": current, "payload_bytes": removed["commit"]}
    plaintext = "synthetic-M10-recovered-message"
    packet = lab.prepare("waiting_for_control", payload=plaintext)
    if variant == "bad_waiting":
        packet = corrupt(packet)
    accepted = lab.submit(packet)
    # 首次登记就追加真实控制事件；重复 add_control 不会给旧记录补事件。
    registered = lab.control("add_control", control=control, recipients=[identity("b1")], append_events=True)
    check(registered == {"control_id": control["control_id"], "reused": False}, "控制不是本轮首次登记")
    if variant == "bad_waiting":
        later = lab.prepare("good_after_waiting_bad", payload=plaintext)
        later_accepted = lab.submit(later)
    page = one_page(lab, prefix, "message")
    waiting_slot = page["events"][0]
    check(waiting_slot["event"]["envelope"] == packet["envelope"]
          and waiting_slot["event"]["acceptance_id"] == accepted["acceptance_id"], "等待槽不是原提交消息")
    lab.download("b1", page)
    waiting = process_slot(lab, waiting_slot, "waiting_dependency")
    check(waiting["results"][0]["result"]["code"] == "missing_crypto_state", "消息没有因缺真实控制而等待")
    candidates(lab, waiting, None, bad_slots)
    waiting_state = state(lab, "full_queue_waiting", downloaded=prefix + 1, processed=prefix,
                          pending=1, quarantined=len(bad_slots), inbox=0, applied=0)
    control_page = one_page(lab, prefix + 1, "crypto_control")
    control_slot = control_page["events"][0]
    check(control_slot["event"]["control"] == control, "普通流中的控制与真实Commit不同")
    snapshot = lab.directory / "b1/state.enc"
    prior = snapshot.read_bytes()
    rejected = lab.download("b1", control_page, expected_exit=1)
    check(rejected["code"] == "resource_exhausted" and snapshot.read_bytes() == prior
          and lab.rust("b1", "wire_inspect") == waiting_state, "满队列未拒绝普通控制或拒绝改变了状态")
    record(lab, "full_queue_rejected_control", error=rejected,
           snapshot_sha256=hashlib.sha256(prior).hexdigest(), snapshot_unchanged=True)

    request = {"service_id": lab.service, "conversation_id": CONVERSATION,
               "from_state_ref": control["from_state_ref"], "to_state_ref": current, "limit": "1"}
    fetched = lab.http("b1", "get_crypto_dependencies", request)
    check(fetched["controls"] == [control] and fetched["has_more"] is False,
          "满队列独立HTTP未取得完整精确控制")
    check(snapshot.read_bytes() == prior, "独立HTTP读取擅自修改了客户端状态")
    record(lab, "independent_http_control", response=fetched,
           payload_sha256=hashlib.sha256(base64.b64decode(control["payload_bytes"], validate=True)).hexdigest())
    applied = lab.rust("b1", "wire_apply_dependency", control=fetched["controls"][0])
    check(applied == {"status": "control_applied", "duplicate": False, "control_id": control["control_id"]},
          "独立控制没有首次成功应用")
    after_apply = state(lab, "independent_control_saved", downloaded=prefix + 1, processed=prefix,
                        pending=1, quarantined=len(bad_slots), inbox=0, applied=1)
    check(after_apply["crypto_state_ref"] == current and after_apply["epoch"] == sender["epoch"],
          "独立控制未保存真实后继公共密码状态")
    expected_sync = {**waiting_state["sync"], "applied_control_count": 1}
    check(after_apply["sync"] == expected_sync, "独立控制推进了设备流游标或改变了等待槽")
    restart(lab, "restart_after_independent_apply")
    again = lab.http("b1", "get_crypto_dependencies", request)
    check(again == fetched, "重启后独立控制材料变化")
    duplicate = lab.rust("b1", "wire_apply_dependency", control=again["controls"][0])
    check(duplicate == {**applied, "duplicate": True}
          and lab.rust("b1", "wire_inspect") == after_apply, "独立重复控制再次推进状态")
    record(lab, "independent_control_repeated", result=duplicate, state=after_apply)
    lab.rust("b1", "wire_configure", conversation_id=CONVERSATION, authorization_version="2", pending_limit=1)
    good_slot = None
    if variant == "bad_waiting":
        bad_slots.append(waiting_slot)
        recovered = process_slot(lab, waiting_slot, "quarantined")
        check(recovered["results"][0]["result"]["code"] == "decryption_failed", "依赖就绪后坏密文未隔离")
    else:
        good_slot = waiting_slot
        recovered = process_slot(lab, waiting_slot, "valid", plaintext=plaintext)
    candidates(lab, recovered, good_slot, bad_slots)
    state(lab, "waiting_slot_resolved", downloaded=prefix + 1, processed=prefix + 1,
          pending=0, quarantined=len(bad_slots), inbox=int(good_slot is not None), applied=1)

    later_control_page = one_page(lab, prefix + 1, "crypto_control")
    check(later_control_page == control_page, "重启及独立应用后真实普通控制页变化")
    lab.download("b1", later_control_page)
    restart(lab, "restart_after_control_download")
    processed = process_slot(lab, control_slot, "control_applied", duplicate=True)
    check(processed["results"][0]["result"] == duplicate, "普通控制槽未复用精确独立控制记录")
    candidates(lab, processed, good_slot, bad_slots)
    after_control = state(lab, "ordinary_control_duplicate_saved", downloaded=prefix + 2, processed=prefix + 2,
                          pending=0, quarantined=len(bad_slots), inbox=int(good_slot is not None), applied=1)
    public_state = (current, sender["epoch"])
    check((after_control["crypto_state_ref"], after_control["epoch"]) == public_state,
          "普通重复控制推进了公共密码状态")
    end = prefix + 2
    if variant == "bad_waiting":
        page = one_page(lab, end, "message")
        good_slot = page["events"][0]
        check(good_slot["event"]["envelope"] == later["envelope"]
              and good_slot["event"]["acceptance_id"] == later_accepted["acceptance_id"], "后继合法消息归属不符")
        lab.download("b1", page)
        processed = process_slot(lab, good_slot, "valid", plaintext=plaintext)
        candidates(lab, processed, good_slot, bad_slots)
        end += 1
    report_and_repeat(lab, good_slot, bad_slots, end, (sender["epoch"], current))


CASES = [("M10_clean", lambda lab: recover(lab, "clean")),
         ("M10_bad_before", lambda lab: recover(lab, "bad_before")),
         ("M10_bad_waiting", lambda lab: recover(lab, "bad_waiting"))]
