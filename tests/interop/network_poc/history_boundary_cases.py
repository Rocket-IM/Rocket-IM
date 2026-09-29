"""历史证据、密码完整性、访问变化和失败事务的交叉边界。"""

import base64
import copy

from .fixture import check
from .history_cases import advance, assert_valid, checkpoint, publish, receive_record, signed_for_packet
from .permission_cases import REVOKE_A2, reject_unchanged, version
from .permission_recovery_cases import communicate, recover


def signed_but_corrupt(lab):
    packet, accepted = publish(lab, "mls_integrity_after_r1")
    advance(lab, "change_before_integrity_check")
    corrupted = copy.deepcopy(packet)
    raw = bytearray(base64.b64decode(corrupted["envelope"]["payload_bytes"]))
    raw[-1] ^= 1
    corrupted["envelope"]["payload_bytes"] = base64.b64encode(raw).decode()
    receipt = signed_for_packet(lab, corrupted, accepted)
    error = reject_unchanged(lab, "b1", "wire_receive", **corrupted["envelope"],
                             acceptance_id=accepted["acceptance_id"], acceptance_receipt=receipt)
    check(error["code"] == "decryption_failed", "有效 Service 签名被误当成实际 MLS 完整性证明")
    check(not receive_record(lab, "b1", (packet, accepted))["duplicate"], "密码失败消耗了合法历史接收状态")
    communicate(lab, "current_after_mls_failure", sender="b1", receiver="a1")


def cached_removed_sender(lab):
    record = publish(lab, "received_before_sender_removal", "c1")
    check(not receive_record(lab, "b1", record)["duplicate"], "原消息初次接收被当作重复")
    advance(lab, "remove_already_received_sender")
    before = checkpoint(lab)
    check(receive_record(lab, "b1", record)["duplicate"], "已成功接收记录不能在撤销后复用原结果")
    packet, accepted = record
    forged_id = "different_acceptance_for_same_bytes"
    proof = signed_for_packet(lab, packet, accepted, acceptance_id=forged_id)
    reject_unchanged(lab, "b1", "wire_receive", **packet["envelope"],
                     acceptance_id=forged_id, acceptance_receipt=proof)
    lab.download("b1", lab.pull("b1"))
    result = lab.rust("b1", "wire_process")
    assert_valid(result, 1)
    check(result["results"][0]["result"]["message"]["duplicate"] and
          result["deliveries"][0]["acceptance_id"] == accepted["acceptance_id"], "历史重报借用了新的接受身份")
    check(checkpoint(lab) == before, "原结果重报回退了发送状态")


def missing_history_evidence(lab):
    publish(lab, "history_without_proof")
    advance(lab, "advance_before_unsigned_old_slot")
    page = lab.pull("b1")
    del page["events"][0]["event"]["acceptance_receipt"]
    # 页来源由实验 Service 显式重签；缺失的消息接受证明不补签或追认。
    page = lab.sign_test_page(page)
    lab.download("b1", page)
    result = lab.rust("b1", "wire_process")
    check(result["results"][0]["result"] == {"status": "quarantined", "code": "historical_acceptance_required"}
          and result["deliveries"] == [], "缺少历史接受证明没有明确隔离")
    state = lab.rust("b1", "wire_inspect")
    check(state["sync"]["pending_count"] == 0 and state["sync"]["processed_cursor"] == "1"
          and state["inbox_count"] == 0, "不可追认的旧事件永久等待或被记为成功")
    publish(lab, "valid_after_unproven_old")
    lab.download("b1", lab.pull("b1", "1"))
    valid = lab.rust("b1", "wire_process")
    assert_valid(valid, 1)
    check(valid["deliveries"][0]["acceptance_id"] != page["events"][0]["event"]["acceptance_id"],
          "隔离事件被错误报告送达")


def future_then_history(lab):
    oldest = publish(lab, "old_before_future")
    first = advance(lab, "future_step_one", devices=("a1", "a2"))
    middle = publish(lab, "middle_before_future")
    second = advance(lab, "future_step_two", REVOKE_A2, devices=("a1",))
    newest = publish(lab, "future_newest")
    # 先提交两步授权链之外的合法未来密文；它需要等待，不能误标历史丢失。
    packet, accepted = newest
    error = reject_unchanged(lab, "b1", "wire_receive", **packet["envelope"],
                             acceptance_id=accepted["acceptance_id"], acceptance_receipt=accepted["acceptance_receipt"])
    check(error["code"] == "missing_crypto_state", "真实未来消息没有保留依赖等待语义")
    recover(lab, first, "b1")
    recover(lab, second, "b1")
    for record in (newest, middle, oldest):
        receive_record(lab, "b1", record)
    check(version(lab, "b1") == "3" and lab.rust("b1", "wire_inspect")["inbox_count"] == 3,
          "补齐新状态后不能接收当前及合法历史")
    communicate(lab, "after_future_and_history", sender="b1", receiver="a1")


def revoked_receiver(lab):
    packet, accepted = publish(lab, "old_for_revoked_target")
    terminal = advance(lab, "revoke_historical_receiver", REVOKE_A2, devices=("a1", "b1"))
    recover(lab, terminal, "a2")
    lab.pull("a2", expected=403)
    error = reject_unchanged(lab, "a2", "wire_receive", **packet["envelope"],
                             acceptance_id=accepted["acceptance_id"], acceptance_receipt=accepted["acceptance_receipt"])
    check(error["code"] == "access_removed", "已撤销接收端通过旧消息证据恢复了访问")
    check(lab.rust("a2", "wire_inspect")["inbox_count"] == 0, "失权端成功记录了旧消息")
    communicate(lab, "remaining_after_target_revoked")


def message_signer_atomicity(lab):
    packet = lab.rust("a1", "wire_send", logical_message_id="message_signer_failure", attempt_id="P1",
                      payload="synthetic-history-signer")
    saved = lab.receipt_key.with_suffix(".saved")
    lab.receipt_key.rename(saved)
    try:
        error = lab.submit(packet, expected=503)
        check(error["code"] == "receipt_signer_unavailable", "消息接受签名失败没有明确失败")
        check(lab.attempt("message_signer_failure")["outcome"] == "not_found"
              and lab.control("stats")["message_events"] == "0", "消息签名失败留下了部分接受或投递")
    finally:
        saved.rename(lab.receipt_key)
    accepted = lab.submit(packet)
    lab.receipt_key.rename(saved)
    try:
        check(lab.submit(packet) == accepted, "精确重试依赖临时重新签名")
        check(lab.attempt("message_signer_failure") == accepted, "已有接受结果不能在签名器故障时重查")
    finally:
        saved.rename(lab.receipt_key)
    lab.restart()
    check(lab.submit(packet) == accepted, "重启后接受签名不是原字节")
    lab.rust("a1", "wire_accept", logical_message_id="message_signer_failure", attempt_id="P1",
             acceptance_receipt=accepted["acceptance_receipt"])
    advance(lab, "advance_after_message_acceptance")
    receive_record(lab, "b1", (packet, accepted))
    communicate(lab, "after_message_signer_restored")
