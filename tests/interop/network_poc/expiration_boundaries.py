"""受控时钟驱动原到期判断的事务、单向投影及本地副本边界。"""

import base64
import copy
import json

from .deletion_observer import relay_records
from .deletion_support import (capture, check_availability_notice, check_notice_result,
                               delete, restart, retry_deleted, unchanged)
from .expiration_support import (assert_expired_transition, check_expired_slot,
                                 observe_final, retry_expired, set_clock)
from .fixture import check
from .slot_support import check_message_result, check_sync, delivery_for, inspect_slot, publish
from .sync_support import TARGETS


def deadline(lab, accepted):
    check(accepted["accepted_at_unix_ms"] == str(lab.ttl_base_ms)
          and accepted["expires_at_unix_ms"] == str(lab.ttl_base_ms + lab.retention_ms),
          "接受时间或原完整保留截止并非受控时钟与保留期")
    return int(accepted["expires_at_unix_ms"])


def expire_by_get(lab, accepted, label):
    before = capture(lab)
    result = lab.attempt(accepted["logical_message_id"])
    check(result == {**accepted, "availability": "expired"}, "成功查询没有返回原接受事实与expired")
    after = capture(lab)
    assert_expired_transition(before["relay"], after["relay"], accepted)
    check(before["clients"] == after["clients"], "HTTP到期判断改写了端侧状态")
    lab.case_evidence.setdefault("expiration_transitions", []).append(
        {"label": label, "before": before["relay"], "after": after["relay"], "result": result})


def transaction_rollback(lab):
    packet, accepted, _ = publish(lab, "expiration_rollback")
    # 先取得合法流标识，错误游标才会进入事务内校验而非请求结构校验。
    lab.pull("a2")
    set_clock(lab, deadline(lab, accepted))
    baseline = capture(lab)
    replies = []
    error = lab.pull("a2", token="synthetic-invalid-token", expected=401)
    check(error["code"] == "unauthenticated", "无效凭证没有在认证处拒绝")
    unchanged(lab, baseline, "unauthenticated_before_expiration")
    replies.append({"operation": "unauthenticated_pull", "error": error})
    error = lab.pull("a2", "2", expected=409)
    check(error["code"] == "cursor_invalid", "超过原水位的游标未拒绝")
    unchanged(lab, baseline, "cursor_error_rolls_back_expiration")
    replies.append({"operation": "invalid_cursor", "error": error})
    changed = copy.deepcopy(packet)
    payload = bytearray(base64.b64decode(changed["envelope"]["payload_bytes"]))
    payload[-1] ^= 1
    changed["envelope"]["payload_bytes"] = base64.b64encode(payload).decode()
    error = lab.submit(changed, expected=409)
    check(error["code"] == "idempotency_conflict", "同尝试异密文未拒绝")
    unchanged(lab, baseline, "idempotency_error_rolls_back_expiration")
    replies.append({"operation": "changed_payload", "error": error})
    changed = copy.deepcopy(packet)
    header = json.loads(base64.b64decode(changed["envelope"]["header_bytes"]))
    header["attempt_id"] = "P2"
    changed["envelope"]["header_bytes"] = base64.b64encode(
        json.dumps(header, separators=(",", ":")).encode()).decode()
    error = lab.submit(changed, expected=409)
    check(error["code"] == "logical_message_already_accepted"
          and error["acceptance"] == {**accepted, "availability": "expired"},
          "P2拒绝未保留原接受事实或事务内到期视图")
    unchanged(lab, baseline, "accepted_conflict_rolls_back_expiration")
    replies.append({"operation": "new_attempt_same_logical", "error": error})
    check(relay_records(lab)["attempts"][0]["availability"] == "available",
          "事务内错误响应被误当作已提交到期状态")
    restart(lab, "rollback_before_successful_expiration")
    expire_by_get(lab, accepted, "first_successful_get_commits_expiration")
    retry_expired(lab, packet, accepted, "rollback_case_final_retry")
    observe_final(lab, 1)
    lab.case_evidence.update(rejected_requests=replies, pre_commit_relay=baseline["relay"],
        boundary="selected in-transaction errors roll back TTL; not a claim about every HTTP 409")


def deleted_precedence_and_clock_rollback(lab):
    deleted_packet, deleted, _ = publish(lab, "expiration_already_deleted")
    expired_packet, expired, _ = publish(lab, "expiration_after_deleted")
    check(deadline(lab, deleted) == deadline(lab, expired), "同一受控时钟未生成一致截止")
    originals = {device: lab.pull(device) for device in TARGETS}
    delete(lab, deleted)
    set_clock(lab, deadline(lab, expired))
    expire_by_get(lab, expired, "only_available_message_expires")
    stable = relay_records(lab)
    set_clock(lab, lab.ttl_base_ms)
    restart(lab, "clock_rollback_restart")
    retry_deleted(lab, deleted_packet, deleted, "clock_rollback_deleted_stays_deleted")
    retry_expired(lab, expired_packet, expired, "clock_rollback_expired_stays_expired")
    stored = {}
    for device in TARGETS:
        page = lab.pull(device)
        check(len(page["events"]) == 4 and page["watermark"] == page["next_after_seq"] == "4"
              and not page["has_more"], "回退时钟后槽位水位变化")
        expected_deleted = {key: originals[device]["events"][0][key]
                            for key in ("stream_id", "event_seq", "event_id")}
        check(page["events"][0] == {**expected_deleted, "availability": "deleted"},
              "TTL覆盖既有deleted或回退时钟恢复密文")
        check_expired_slot(page["events"][1], originals[device]["events"][1])
        check_availability_notice(page["events"][2], originals[device]["events"][0], deleted, "deleted", 3)
        check_availability_notice(page["events"][3], originals[device]["events"][1], expired, "expired", 4)
        lab.download(device, page)
        value = lab.rust(device, "wire_process")
        check([(item["event_seq"], item["event_id"], item["result"]) for item in value["results"]]
              == [(slot["event_seq"], slot["event_id"], {"status": "unavailable", "availability": state})
                  for slot, state in zip(page["events"][:2], ("deleted", "expired"))]
                  + [(slot["event_seq"], slot["event_id"], {"status": "availability_recorded"})
                     for slot in page["events"][2:]]
              and value["deliveries"] == [], "不可逆占位被解密或产生候选")
        check_sync(value["sync"], 4, 4)
        check(value["sync"]["slot_count"] == 4 and lab.rust(device, "wire_inspect")["inbox_count"] == 0,
              "不可逆投影产生隐藏槽或收件箱副本")
        stored[device] = [inspect_slot(lab, device, seq) for seq in (1, 2, 3, 4)]
    restart(lab, "clock_rollback_processed_restart")
    for device in TARGETS:
        value = lab.rust(device, "wire_process")
        check(value["results"] == [] and value["deliveries"] == [], "回退时钟后的重启重处理占位")
        check_sync(value["sync"], 4, 4)
        check(value["sync"]["slot_count"] == 4, "重启重复建立槽位")
        for seq in (1, 2, 3, 4):
            inspect_slot(lab, device, seq, stored[device][seq - 1])
    check(relay_records(lab) == stable, "回退时钟、重试或重启改写不可逆状态")
    observe_final(lab, 2)
    lab.case_evidence.update(stored_slots=stored, clock_rollback_to_unix_ms=str(lab.ttl_base_ms),
                            original_deadlines=[deleted["expires_at_unix_ms"], expired["expires_at_unix_ms"]])


def old_available_replay(lab):
    packet, accepted, payload_hash = publish(lab, "expiration_old_page")
    pages = {device: lab.pull(device) for device in TARGETS}
    phases = {"a2": "unfetched", "b1": "queued", "c1": "processed"}
    for device in ("b1", "c1"):
        lab.download(device, pages[device])
    processed = lab.rust("c1", "wire_process")
    check_message_result(processed["results"][0]["result"], pages["c1"]["events"][0],
                         accepted["logical_message_id"], payload_hash, False)
    check(processed["deliveries"] == [delivery_for(pages["c1"]["events"][0])], "基线缺少真实送达候选")
    before_slots = {device: inspect_slot(lab, device, 1) for device in TARGETS}
    set_clock(lab, deadline(lab, accepted))
    expire_by_get(lab, accepted, "expire_before_signed_page_replay")
    projected = {}
    for device in TARGETS:
        # 先只补拉旧槽投影，保留原同槽冲突路径；尾增量通知另由下方场景验证。
        page = lab.pull(device, "0", "1")
        check(page["watermark"] == "2" and page["has_more"], "到期未追加后续通知")
        check_expired_slot(page["events"][0], pages[device]["events"][0])
        lab.download(device, page)
        if device == "a2":
            expected = {"event_seq": "1", "found": True, "slot": page["events"][0],
                        "result": None, "waiting": False}
        else:
            expected = copy.deepcopy(before_slots[device])
            expected["slot"]["availability"] = "expired"
        inspect_slot(lab, device, 1, expected)
        value = lab.rust(device, "wire_process")
        deliveries = [delivery_for(pages[device]["events"][0])] if device == "c1" else []
        expected_results = [] if device == "c1" else [{"event_seq": "1",
            "event_id": page["events"][0]["event_id"], "result": {"status": "unavailable", "availability": "expired"}}]
        check(value["results"] == expected_results and value["deliveries"] == deliveries,
              "到期占位生成成功或重处理原已成功消息")
        check_sync(value["sync"], 1, 1)
        check(value["sync"]["slot_count"] == 1 and lab.rust(device, "wire_inspect")["inbox_count"] == int(device == "c1"),
              "到期投影改变了正确收件箱数量或增加槽位")
        projected[device] = inspect_slot(lab, device, 1)
        result = lab.download(device, pages[device])
        check(result["status"] == "stream_conflict", "旧available签页复活了expired槽")
        check_sync(result["sync"], 1, 1, halted=True)
        check(result["sync"]["slot_count"] == 1, "旧页重放增加槽位")
        inspect_slot(lab, device, 1, projected[device])
    restart(lab, "expired_old_page_halt_restart")
    for device in TARGETS:
        before = capture(lab)
        page = lab.pull(device)
        check(lab.download(device, page, expected_exit=1)["code"] == "stream_conflict", "重启丢失停流状态")
        check(lab.rust(device, "wire_process", expected_exit=1)["code"] == "stream_conflict", "停流后仍自动处理")
        unchanged(lab, before, "expiration_persistent_halt_" + device)
        inspect_slot(lab, device, 1, projected[device])
    retry_expired(lab, packet, accepted, "old_page_retry_still_expired")
    observe_final(lab, 1)
    lab.case_evidence.update(phases=phases, before_slots=before_slots, stored_expired_slots=projected,
                            old_signed_available="stream_conflict; persistent halt, no slot overwrite")


def incremental_local_copy(lab):
    packet, accepted, payload_hash = publish(lab, "expiration_incremental_boundary")
    originals = {device: lab.pull(device) for device in TARGETS}
    for device in TARGETS:
        lab.download(device, originals[device])
    set_clock(lab, deadline(lab, accepted))
    stored = {}
    for index, device in enumerate(TARGETS):
        candidates = []
        if device == "c1":
            # a2 的请求已提交过期；c1 尚未下载通知，仍能处理原有副本。
            before_notice = lab.rust(device, "wire_process")
            check_message_result(before_notice["results"][0]["result"], originals[device]["events"][0],
                                 accepted["logical_message_id"], payload_hash, False)
            candidates = [delivery_for(originals[device]["events"][0])]
            check(before_notice["deliveries"] == candidates, "未知到期的本地副本处理错误")
        before = capture(lab)
        page = lab.pull(device, "1")
        after = capture(lab)
        if index == 0:
            assert_expired_transition(before["relay"], after["relay"], accepted)
            check(before["clients"] == after["clients"], "到期请求擅自修改端侧副本")
            lab.case_evidence["expiration_transition"] = {"before": before["relay"], "after": after["relay"]}
        else:
            unchanged(lab, before, "expired_notification_page_" + device)
        check(len(page["events"]) == 1 and page["watermark"] == page["next_after_seq"] == "2"
              and not page["has_more"], "尾游标未返回精确一次到期通知")
        check_availability_notice(page["events"][0], originals[device]["events"][0], accepted, "expired", 2)
        lab.download(device, page)
        queued = inspect_slot(lab, device, 1)
        check(queued["slot"] == {**originals[device]["events"][0], "availability": "expired"}
              and (queued["result"] is None) is (device != "c1"), "增量通知未投影原槽或清除已有成功事实")
        value = lab.rust(device, "wire_process")
        expected_sequences = ["2"] if device == "c1" else ["1", "2"]
        check([item["event_seq"] for item in value["results"]] == expected_sequences, "到期通知遗漏或重复处理槽")
        if device != "c1":
            check(value["results"][0]["result"] == {"status": "unavailable", "availability": "expired"},
                  "已获知到期后仍解密排队副本")
        check_notice_result(value["results"][-1], page["events"][0])
        check(value["deliveries"] == candidates, "到期通知错误新增或清除成功候选")
        check_sync(value["sync"], 2, 2)
        check(value["sync"]["slot_count"] == 2, "到期通知槽数错误")
        prior = inspect_slot(lab, device, 1)
        overlap = lab.pull(device)
        check_expired_slot(overlap["events"][0], originals[device]["events"][0])
        lab.download(device, overlap)
        inspect_slot(lab, device, 1, prior)
        repeat = lab.rust(device, "wire_process")
        check(repeat["results"] == [] and repeat["deliveries"] == candidates
              and lab.rust(device, "wire_inspect")["inbox_count"] == int(device == "c1"),
              "观察过期后重复处理或错误清除既有本地副本")
        check_sync(repeat["sync"], 2, 2)
        check(repeat["sync"]["slot_count"] == 2, "重叠过期页增加了槽位")
        stored[device] = [inspect_slot(lab, device, seq) for seq in (1, 2)]
    restart(lab, "incremental_expiration_after_projection_restart")
    for device in TARGETS:
        value = lab.rust(device, "wire_process")
        expected = [delivery_for(originals[device]["events"][0])] if device == "c1" else []
        check(value["results"] == [] and value["deliveries"] == expected
              and lab.rust(device, "wire_inspect")["inbox_count"] == int(device == "c1"), "重启改变既有副本边界")
        check_sync(value["sync"], 2, 2)
        check(value["sync"]["slot_count"] == 2, "重启增加槽位")
        for seq in (1, 2):
            inspect_slot(lab, device, seq, stored[device][seq - 1])
    retry_expired(lab, packet, accepted, "incremental_boundary_original_stays_expired")
    observe_final(lab, 1)
    lab.case_evidence.update(stored_expired_slots=stored,
        incremental_result="verified_tail_notice_projects_queued_target_before_processing",
        boundary="c1 processed its copy before learning expiration; no remote erase of successful copies or shipped automatic worker")


CASES = [
    ("M11.expire.transaction_rollback", transaction_rollback),
    ("M11.expire.deleted_precedence_and_clock_rollback", deleted_precedence_and_clock_rollback),
    ("M11.expire.old_available_replay", old_available_replay),
    ("M11.expire.incremental_local_copy_boundary", incremental_local_copy),
]
