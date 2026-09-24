"""原发送者的接受证明与定向历史；消息与迁移均走既有公开入口。"""

import copy
import hashlib
import http.client
import sqlite3

from .device_join_cases import no_old_history
from .fixture import CONVERSATION, SERVICE, check
from .history_cases import publish, receive_record, signed_for_packet
from .join_cases import mutate_bytes
from .message_cases import header
from .migration_cases import get, joined, prepared, request, selection, submit
from .permission_cases import reject_unchanged


def ack(lab, record, device="b1", **fields):
    packet, accepted = record
    original = header(packet)
    return lab.rust(device, "wire_accept", **{"logical_message_id": original["logical_message_id"],
                    "attempt_id": original["attempt_id"], "acceptance_receipt": accepted["acceptance_receipt"], **fields})


def attempt(lab, logical, ident="P1", operation="get_attempt", device="b1", **options):
    return lab.http(device, operation, {"service_id": SERVICE, "conversation_id": CONVERSATION,
                    "logical_message_id": logical, "attempt_id": ident}, **options)


def sent(lab, name, save=True):
    record = publish(lab, name, "b1")
    if save:
        ack(lab, record)
    return record


def accepted_count(lab, device="b1"):
    return lab.rust(device, "wire_inspect")["accepted_outbox_count"]


def mixed_history(lab):
    own = [sent(lab, "sent_old_" + str(i)) for i in range(2)]
    inbound = publish(lab, "received_old_mixed")
    receive_record(lab, "b1", inbound)
    pending = lab.rust("b1", "wire_send", logical_message_id="not_submitted", attempt_id="P1", payload="synthetic-pending")
    joined(lab, count=0)
    for record in own:
        no_old_history(lab, record)
    state = lab.rust("b1", "history_inspect")
    check(state["exportable"] == selection([*own, inbound]) and state["sent_without_acceptance_count"] == 1,
          "未接受队列混入可迁移历史或遗漏真实收发副本")
    before = {d: lab.rust(d, "wire_inspect") for d in ("b1", "b2")}
    stats = lab.control("stats")
    accepted = submit(lab, prepared(lab, "mixed_sent_history", [own[0], inbound]))
    result = lab.rust("b2", "history_import", **get(lab, "mixed_sent_history"))
    copies = {item["logical_message_id"]: item for item in result["copies"]}
    check(result["imported_count"] == 2 and set(copies) == {"sent_old_0", "received_old_mixed"}
          and all(item["provenance"] == "source_authenticated_copy" for item in copies.values()),
          "混合迁移扩大了范围或冒充原作者独立验证")
    check(copies["sent_old_0"]["payload_sha256"] == hashlib.sha256(b"synthetic-history-sent_old_0").hexdigest(),
          "已发送副本正文与本机原发送内容不同")
    check(lab.control("stats") == stats and all(lab.rust(d, "wire_inspect") == before[d] for d in before),
          "历史导入改变原发送、接收、游标或密码状态")
    with sqlite3.connect(lab.directory / "relay.sqlite") as db:
        check(db.execute("SELECT COUNT(*) FROM events WHERE device='b1' AND acceptance_id=?",
                         (own[0][1]["acceptance_id"],)).fetchone()[0] == 0, "为原发送者伪造了自己的收件事件")
    check(lab.rust("b2", "history_import", **accepted)["imported_count"] == 0, "迁移重试重复生成副本")
    check(header(pending)["logical_message_id"] == "not_submitted" and accepted_count(lab) == 2, "迁移替用户提交了待发消息")
    receive_record(lab, "a1", publish(lab, "future_after_sent_copy", "b2"))


def lost_ack_and_superseded(lab):
    packet = lab.rust("b1", "wire_send", logical_message_id="late_ack", attempt_id="P1", payload="synthetic-late-ack")
    lab.control("hook", hook="drop_after_commit")
    try:
        lab.submit(packet, device="b1")
        raise AssertionError("消息接受丢响应装置未触发")
    except (http.client.RemoteDisconnected, ConnectionResetError):
        pass
    # 当前封口输入仍是可信实验调度器边界：故意给出矛盾假设以验证迟到真实接受事实优先。
    lab.rust("b1", "wire_send", logical_message_id="late_ack", attempt_id="P2", payload="synthetic-late-ack",
             replaces_attempt_id="P1", closure_id="synthetic_incorrect_closure")
    joined(lab, count=0)
    lab.restart()
    original = attempt(lab, "late_ack")
    check(original["outcome"] == "accepted" and accepted_count(lab) == 0, "普通查询被自动视作本机已验证接受")
    before = lab.rust("b1", "wire_inspect")
    result = ack(lab, (packet, original))
    after = lab.rust("b1", "wire_inspect")
    check(result["acceptance_id"] == original["acceptance_id"] and not result["duplicate"], "迟到证明未绑定原P1")
    check({k: v for k, v in before.items() if k != "accepted_outbox_count"}
          == {k: v for k, v in after.items() if k != "accepted_outbox_count"}, "迟到接受回退了当前密码或尝试状态")
    for ident, predecessor in (("P2", "P1"), ("P3", "P2")):
        reject_unchanged(lab, "b1", "wire_send", logical_message_id="late_ack", attempt_id=ident,
                         payload="synthetic-late-ack", replaces_attempt_id=predecessor, closure_id="synthetic_incorrect_closure")
    retry = lab.rust("b1", "wire_send", logical_message_id="late_ack", attempt_id="P1", payload="synthetic-late-ack")
    check(retry["envelope"] == packet["envelope"] and lab.submit(retry, device="b1") == original,
          "接受后原尝试重试重新加密或再次扇出")
    check(ack(lab, (packet, original))["duplicate"], "原接受证明重试没有去重")
    lab.rust("b2", "history_import", **submit(lab, prepared(lab, "late_accepted_history", [(packet, original)])))


def proof_binding(lab):
    first, second = sent(lab, "proof_first", save=False), sent(lab, "proof_second", save=False)
    joined(lab, count=0)
    packet, accepted = first
    fields = {"logical_message_id": "proof_first", "attempt_id": "P1", "acceptance_receipt": accepted["acceptance_receipt"]}
    bad = copy.deepcopy(fields)
    bad["acceptance_receipt"]["signature_bytes"] = mutate_bytes(bad["acceptance_receipt"]["signature_bytes"])
    reject_unchanged(lab, "b1", "wire_accept", **bad)
    for changes in ({"logical_message_id": "unknown"}, {"attempt_id": "P2"},
                    {"acceptance_receipt": second[1]["acceptance_receipt"]}, {"acceptance_receipt": accepted},
                    {"acceptance_receipt": None}):
        reject_unchanged(lab, "b1", "wire_accept", **{**fields, **changes})
    for device in ("a1", "a2", "b2", "c1"):
        reject_unchanged(lab, device, "wire_accept", **fields)
    for changed in ({"service_id": "other_service"}, {"conversation_id": "other_group"},
                    {"authorization_version": "9"}, {"crypto_state_ref": "0" * 64}):
        receipt = signed_for_packet(lab, packet, accepted, **changed)
        reject_unchanged(lab, "b1", "wire_accept", **{**fields, "acceptance_receipt": receipt})
    check(accepted_count(lab) == 0, "错误证明部分确认了发送记录")
    ack(lab, first)
    alternate = signed_for_packet(lab, packet, accepted, acceptance_id="different_acceptance")
    reject_unchanged(lab, "b1", "wire_accept", **{**fields, "acceptance_receipt": alternate})
    collision = signed_for_packet(lab, second[0], second[1], acceptance_id=accepted["acceptance_id"])
    reject_unchanged(lab, "b1", "wire_accept", logical_message_id="proof_second", attempt_id="P1", acceptance_receipt=collision)
    ack(lab, second)
    lab.rust("b2", "history_import", **submit(lab, prepared(lab, "correct_after_invalid_ack", [first, second])))


def closed_then_replaced(lab):
    first = lab.rust("b1", "wire_send", logical_message_id="closed_sent", attempt_id="P1", payload="synthetic-replaced")
    closed = attempt(lab, "closed_sent", operation="close_attempt")
    check(closed["outcome"] == "cancelled_before_accept", "未提交旧尝试未封口")
    reject_unchanged(lab, "b1", "wire_accept", logical_message_id="closed_sent", attempt_id="P1", acceptance_receipt=closed)
    lab.submit(first, device="b1", expected=409)
    second = lab.rust("b1", "wire_send", logical_message_id="closed_sent", attempt_id="P2", payload="synthetic-replaced",
                      replaces_attempt_id="P1", closure_id=closed["closure_id"])
    accepted = lab.submit(second, device="b1", replaces_attempt_id="P1", closure_id=closed["closure_id"])
    reject_unchanged(lab, "b1", "wire_accept", logical_message_id="closed_sent", attempt_id="P1",
                     acceptance_receipt=accepted["acceptance_receipt"])
    ack(lab, (second, accepted))
    stale = lab.rust("b1", "wire_send", logical_message_id="rejected_sent", attempt_id="P1", payload="synthetic-stale")
    joined(lab, count=0)
    rejected = lab.submit(stale, device="b1", expected=409)
    check(rejected["outcome"] == "rejected_final", "旧版本首次提交未终态拒绝")
    reject_unchanged(lab, "b1", "wire_accept", logical_message_id="rejected_sent", attempt_id="P1", acceptance_receipt=rejected)
    current = lab.rust("b1", "wire_send", logical_message_id="rejected_sent", attempt_id="P2", payload="synthetic-stale",
                       replaces_attempt_id="P1", closure_id=rejected["closure_id"])
    current_accepted = lab.submit(current, device="b1", replaces_attempt_id="P1", closure_id=rejected["closure_id"])
    ack(lab, (current, current_accepted))
    records = [(second, accepted), (current, current_accepted)]
    check(lab.rust("b1", "history_inspect")["exportable"] == selection(records), "封口或已拒绝的旧尝试混进已接受历史")
    result = lab.rust("b2", "history_import", **submit(lab, prepared(lab, "only_accepted_replacement", records)))
    check(result["imported_count"] == 2 and accepted_count(lab) == 2, "替代产生了额外已接受副本")


def native_received_copy(lab):
    joined(lab, count=0)
    own = sent(lab, "native_already_received")
    receive_record(lab, "b2", own)
    before = lab.rust("b2", "wire_inspect")
    result = lab.rust("b2", "history_import", **submit(lab, prepared(lab, "native_with_sent_copy", [own])))
    check(result["imported_count"] == 1 and lab.rust("b2", "wire_inspect") == before,
          "新增副本错误地替代正常收件或改成第二条聊天消息")
    check(receive_record(lab, "b2", own)["duplicate"], "迁移改变了普通消息去重")
