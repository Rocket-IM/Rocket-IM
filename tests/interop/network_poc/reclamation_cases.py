"""真实消息满快照后的显式回收；不改预算、设备快照或密码窗口。"""

from .fixture import check
from .reclamation_fixture import (DEVICES, PAYLOAD, apply, approve, database, digest, finish,
    prepare_requests, publish, raw_command, reject_old_binary, require_budget_error, snapshot, synchronize,
    terminal_candidate)


def receive(lab, record, device="b1"):
    result = lab.rust(device, "wire_receive", **record["packet"]["envelope"],
        acceptance_id=record["accepted"]["acceptance_id"],
        acceptance_receipt=record["accepted"]["acceptance_receipt"])
    check(not result["duplicate"] and result["payload_sha256"] == record["payload_sha256"],
          "回收后新消息没有且仅成功解密一次")
    return result


def compacted(lab, records):
    rows = database(lab)
    selected = {record["accepted"]["acceptance_id"] for record in records}
    attempts = [row for row in rows["attempts"] if row["acceptance_id"] in selected]
    check(len(attempts) == len(selected) and all(row["payload_is_null"] and row["payload_bytes"] == 0 and row["compacted"] == 1
                                               for row in attempts),
          "Relay未实际清理选定载荷或丢失终态身份")
    messages = [event for event in rows["message_events"] if event["acceptance_id"] in selected]
    check(len(messages) == 3 * len(selected)
          and all(event["compacted"] == 1 and not event["has_envelope"] for event in messages),
          "Relay的原目标Message槽仍保留密文副本")
    return rows


def roundtrip(lab):
    record = terminal_candidate(lab)
    requests = prepare_requests(lab, [record])
    receipts = approve(lab, requests)
    old_device = lab.backup("before-reclamation", lab.directory / "b1") if hasattr(lab, "configs") else None
    packet = lab.rust("a1", "wire_send", logical_message_id="following", attempt_id="P1",
                      payload="synthetic-following-reclamation")
    accepted = lab.submit(packet)
    before = database(lab)
    results = apply(lab, receipts)
    check(database(lab) == before, "仅本机完成就提前改变Relay载荷")
    after = finish(lab, results)
    compacted(lab, [record])
    if old_device is None:
        reject_old_binary(lab)
    error = lab.rust("a1", "wire_send", logical_message_id="must-remain-pending", attempt_id="P1",
                     payload="synthetic-unrelated", expected_exit=1)
    check(error["code"] == "send_order_pending", "回收选定原件错误释放了无关发送门")
    for device in DEVICES:
        wire = lab.rust(device, "wire_inspect")
        repeated = lab.rust(device, "wire_reclaim", receipt=receipts[device])
        check(repeated["duplicate"] and repeated["finish_request"] == results[device]["finish_request"],
              "相同许可重放没有返回原计划结果")
        check(lab.rust(device, "wire_inspect") == wire, "重复回收再次扣减或改变业务状态")
        repeated_finish = lab.http(device, "finish_reclaim", repeated["finish_request"])
        check(repeated_finish["status"] == "complete" and database(lab) == after,
              "完成回执重放改变Relay已提交事实")
    lab.restart()
    check(database(lab) == after, "Relay重启改变已完成回收")
    if old_device is not None:
        exact = lab.backup("after-reclamation", lab.directory / "b1")
        committed = snapshot(lab, "b1")
        lab.restore(old_device, lab.directory / "b1")
        for _ in range(2):
            anchor = lab.rust("b1", "anchor_inspect")
            check(anchor["status"] == "rollback_detected", "旧完整目录恢复未识别已完成回收回退")
            check(lab.blocked("b1", "wire_reclaim", receipt=receipts["b1"])["code"] == "anchor_paused",
                  "回退设备重新执行已完成回收")
            check(lab.blocked("b1", "anchor_resume")["code"] == "anchor_rollback",
                  "缺少当前快照却解除独立锚暂停")
            check(database(lab) == after, "回退检测改变Relay回收事实")
            lab.restart()
        lab.restore(exact, lab.directory / "b1")
        lab.resume("b1")
        check(snapshot(lab, "b1") == committed, "恢复精确副本改变已保存回收结果")
        lab.case_evidence["rollback"] = {"scope": "device_directory_only_authority_and_config_not_restored",
            "old_snapshot_sha256": digest((old_device / "state.enc").read_bytes()),
            "restored_snapshot": committed, "recovery": "exact_committed_device_directory_restored"}
    lab.rust("a1", "wire_accept", logical_message_id="following", attempt_id="P1",
             acceptance_receipt=accepted["acceptance_receipt"])
    following = {"payload_sha256": digest(b"synthetic-following-reclamation")}
    for device in DEVICES[1:]:
        outcomes = synchronize(lab, device, report_delivery=True)
        valid = [item["result"]["message"] for outcome in outcomes for item in outcome["results"]
                 if item["result"]["status"] == "valid"]
        check(len(valid) == 1 and valid[0]["payload_sha256"] == following["payload_sha256"],
              "回收后的新签页未成功解密或重复展示旧内容")
    final = database(lab)
    for old in after["watermarks"]:
        current = next(row for row in final["watermarks"] if (row["account"], row["device"])
                       == (old["account"], old["device"]))
        check(current["high_watermark"] > old["high_watermark"] and current["floor"] >= old["floor"],
              "回收后复用seq或回退连续保留边界")
    lab.case_evidence.update(progress="RECLAIMED_THEN_NEW_SEND_AND_SIGNED_STREAM_RECEIVE",
                            final_relay=final)
    if old_device is not None:
        legacy_anchor_downgrade(lab, receipts["b1"])


def legacy_anchor_downgrade(lab, receipt):
    # 旧程序先预约后解码；故意放在正常验证结束后，真实未决预约不得清除。
    before, rows = snapshot(lab, "b1"), database(lab)
    ready = lab.rust("b1", "anchor_inspect")
    reject_old_binary(lab)
    if lab.old_binary is None:
        return
    unresolved = lab.rust("b1", "anchor_inspect")
    check(ready["status"] == "ready" and ready["active_txn"] is None
          and unresolved["paused"] and unresolved["active_txn"] is not None,
          "旧程序降级拒绝的真实未决预约未被明确观察")
    for _ in range(2):
        check(lab.blocked("b1", "wire_inspect")["code"] == "anchor_paused",
              "旧程序未决预约被新程序诊断隐式解除")
        check(lab.blocked("b1", "wire_reclaim", receipt=receipt)["code"] == "anchor_paused",
              "旧程序未决预约允许再次回收")
        check(lab.blocked("b1", "anchor_resume")["code"] == "anchor_unresolved",
              "旧程序未保存精确日志却恢复了预约")
        lab.restart()
        current = lab.rust("b1", "anchor_inspect")
        check(current["active_txn"] == unresolved["active_txn"] and snapshot(lab, "b1") == before
              and database(lab) == rows, "旧程序降级后的拒绝或重启改变持久事实")
    lab.case_evidence["legacy_anchor_downgrade"] = {"status": "BLOCKED_UNRESOLVED",
        "before": ready, "after": unresolved, "snapshot": before,
        "meaning": "legacy_binary_reserved_before_rejecting_unknown_state; no journal, no reset, no capacity recovery"}


def _candidates(lab):
    # 两条已结算大消息提供真实维护空间；不保留任意生产 TTL 或偷偷扩配额。
    records = [terminal_candidate(lab, payload=PAYLOAD, logical=f"candidate-{index}", availability=availability)
               for index, availability in enumerate(("deleted", "expired"))]
    requests = prepare_requests(lab, records)
    return records, approve(lab, requests)


def sender_budget(lab):
    records, receipts = _candidates(lab)
    successful, pending, failed_logical = 0, None, None
    for index in range(1, 257):
        logical = f"full-send-{index}"
        reply = raw_command(lab, "a1", "wire_send", logical_message_id=logical,
                            attempt_id="P1", payload=PAYLOAD)
        if not reply["ok"]:
            require_budget_error(reply)
            failed_logical = logical
            break
        packet = reply["result"]
        accepted = lab.submit(packet)
        reply = raw_command(lab, "a1", "wire_accept", logical_message_id=logical, attempt_id="P1",
                            acceptance_receipt=accepted["acceptance_receipt"])
        if not reply["ok"]:
            require_budget_error(reply)
            pending = {"logical": logical, "packet": packet, "accepted": accepted}
            break
        successful += 1
        # 分散实际接收，避免另一台设备先满；每个接收者持续推进真实密码状态。
        receiver = DEVICES[1:][(index - 1) % 3]
        lab.rust(receiver, "wire_receive", **packet["envelope"],
                 acceptance_id=accepted["acceptance_id"], acceptance_receipt=accepted["acceptance_receipt"])
    else:
        raise AssertionError("256条64KiB发送未触及原快照预算")
    before = snapshot(lab, "a1")
    wire = lab.rust("a1", "wire_inspect")
    lab.case_evidence["full_snapshot"] = {"device": "a1", "snapshot": before,
        "successful_extra_messages": successful, "wire": wire,
        "failure_operation": "wire_accept" if pending else "wire_send"}
    lab.restart()
    check(snapshot(lab, "a1") == before and lab.rust("a1", "wire_inspect") == wire,
          "重启释放容量或改变发送状态")
    results = apply(lab, receipts)
    check(snapshot(lab, "a1")["bytes"] < before["bytes"], "合法候选回收未减少实际快照字节")
    finish(lab, results)
    compacted(lab, records)
    if pending:
        error = lab.rust("a1", "wire_send", logical_message_id="must-stay-pending", attempt_id="P1",
                         payload="synthetic", expected_exit=1)
        check(error["code"] == "send_order_pending", "回收其他内容释放了未决发送门")
        lab.rust("a1", "wire_accept", logical_message_id=pending["logical"], attempt_id="P1",
                 acceptance_receipt=pending["accepted"]["acceptance_receipt"])
    following = publish(lab, failed_logical or "after-full-send", PAYLOAD)
    decrypted = receive(lab, following)
    lab.case_evidence.update(progress="ACTUAL_SENDER_BYTE_LIMIT_RECLAIMED_NEW_MESSAGE_DECRYPTED",
        final_snapshot=snapshot(lab, "a1"), final_wire=lab.rust("a1", "wire_inspect"),
        following_acceptance_id=following["accepted"]["acceptance_id"], following_decryption=decrypted)


def receiver_budget(lab):
    records, receipts = _candidates(lab)
    successful, failed_page, failed_phase = 0, None, None
    for index in range(1, 257):
        sender = ("a1", "a2", "c1")[(index - 1) % 3]
        record = publish(lab, f"full-receive-{index}", PAYLOAD, sender)
        cursor = lab.rust("b1", "wire_inspect")["sync"]["download_cursor"]
        page = lab.pull("b1", after=cursor)
        reply = raw_command(lab, "b1", "wire_download_signed", **page.signed_input())
        if not reply["ok"]:
            require_budget_error(reply)
            failed_page, failed_phase = page, "wire_download_signed"
            break
        reply = raw_command(lab, "b1", "wire_process")
        if not reply["ok"]:
            require_budget_error(reply)
            failed_page, failed_phase = page, "wire_process"
            break
        valid = [item["result"]["message"] for item in reply["result"]["results"]
                 if item["result"]["status"] == "valid"]
        check(len(valid) == 1 and valid[0]["payload_sha256"] == record["payload_sha256"],
              "实际累计签页处理未成功解密")
        successful += 1
    else:
        raise AssertionError("256条64KiB签页接收未触及原快照预算")
    before, wire = snapshot(lab, "b1"), lab.rust("b1", "wire_inspect")
    lab.case_evidence["full_snapshot"] = {"device": "b1", "snapshot": before, "wire": wire,
        "successful_extra_messages": successful, "failure_operation": failed_phase,
        "accepted_pending_message": record["accepted"]["acceptance_id"]}
    lab.restart()
    check(snapshot(lab, "b1") == before and lab.rust("b1", "wire_inspect") == wire,
          "重启改变失败接收或双游标")
    results = apply(lab, receipts)
    check(snapshot(lab, "b1")["bytes"] < before["bytes"], "合法回收未减少实际接收快照字节")
    finish(lab, results)
    compacted(lab, records)
    if failed_phase == "wire_download_signed":
        lab.download("b1", failed_page)
    processed = lab.rust("b1", "wire_process")
    valid = [item["result"]["message"] for item in processed["results"] if item["result"]["status"] == "valid"]
    check(len(valid) == 1 and valid[0]["payload_sha256"] == record["payload_sha256"],
          "回收后未恢复原已接受但尚未成功收件的消息")
    duplicate = lab.rust("b1", "wire_receive", **record["packet"]["envelope"],
        acceptance_id=record["accepted"]["acceptance_id"],
        acceptance_receipt=record["accepted"]["acceptance_receipt"])
    check(duplicate["duplicate"], "恢复原接收后重复输入再次成功展示")
    following = publish(lab, "after-full-receive", "synthetic-next-message")
    outcomes = synchronize(lab, "b1")
    check(sum(item["result"]["status"] == "valid" for result in outcomes for item in result["results"]) == 1,
          "回收后下一条新签页未继续处理")
    lab.case_evidence.update(progress="ACTUAL_RECEIVER_BYTE_LIMIT_RECLAIMED_ORIGINAL_AND_NEW_MESSAGE",
        final_snapshot=snapshot(lab, "b1"), final_wire=lab.rust("b1", "wire_inspect"),
        restored_message=valid[0], following_acceptance_id=following["accepted"]["acceptance_id"])


def sender_no_candidate(lab):
    synchronize(lab, "a1")
    original = None
    for index in range(1, 257):
        logical = f"available-full-{index}"
        fields = {"logical_message_id": logical, "attempt_id": "P1", "payload": PAYLOAD}
        failed_operation = "wire_send"
        reply = raw_command(lab, "a1", failed_operation, **fields)
        if not reply["ok"]:
            require_budget_error(reply)
            break
        accepted = lab.submit(reply["result"])
        failed_operation = "wire_accept"
        fields = {"logical_message_id": logical, "attempt_id": "P1",
                  "acceptance_receipt": accepted["acceptance_receipt"]}
        reply = raw_command(lab, "a1", failed_operation, **fields)
        if not reply["ok"]:
            require_budget_error(reply)
            break
        if original is None:
            original = accepted
    else:
        raise AssertionError("全可用消息256条仍未触及原快照预算")
    check(original is not None, "没有实际可用记录")
    before, rows = snapshot(lab, "a1"), database(lab)
    check(all(row["availability"] == "available" and row["compacted"] == 0 for row in rows["attempts"]),
          "无候选负例出现了可回收终态")
    prepared = raw_command(lab, "a1", "wire_reclaim_request", plan_id="no-legal-candidate",
                           acceptance_ids=[original["acceptance_id"]])
    if prepared["ok"]:
        result = prepared["result"]
        check(result["status"] == "prepared" and not result["duplicate"], "首次准备状态错误")
        error = lab.http("a1", "confirm_reclaim", {}, raw=result["request_json"].encode(), expected=409)
        check(error["code"] == "reclamation_pending", "缺少终态的满额内容取得了回收许可")
    else:
        error = prepared["error"]
        check(error["code"] == "resource_exhausted" and snapshot(lab, "a1") == before,
              "准备配额失败没有保留原快照")
    blocked = snapshot(lab, "a1")
    check(database(lab) == rows, "缺少终态的满额内容被错误回收")
    lab.restart()
    require_budget_error(raw_command(lab, "a1", failed_operation, **fields))
    check(database(lab) == rows and snapshot(lab, "a1") == blocked, "重启或重复操作释放了不可回收容量")
    lab.case_evidence.update(progress="ACTUAL_FULL_AVAILABLE_CONTENT_REMAINS_BLOCKED",
        full_snapshot=before, accepted_messages=len(rows["attempts"]), failure_operation=failed_operation,
        reclamation_error=error, preparation_saved=prepared["ok"], blocked_snapshot=blocked,
        final_wire=lab.rust("a1", "wire_inspect"))


CASES = [("M12.reclaim.roundtrip", roundtrip), ("M12.reclaim.sender_budget", sender_budget),
         ("M12.reclaim.receiver_budget", receiver_budget),
         ("M12.reclaim.full_available_blocked", sender_no_candidate)]
