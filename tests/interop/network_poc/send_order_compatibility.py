"""真实旧程序留下的 outbox、隔离槽，以及默认门与首包的共同提交边界。"""

from functools import partial
import hashlib

from .deletion_observer import relay_records
from .fixture import check
from .reordering_recovery import recover
from .reordering_support import receive_targets, report_successes
from .send_order_support import enable, blocked, prepare, submit_and_accept, finish, snapshot
from .slot_support import digest


def reject_legacy_new(lab, label):
    before, state = snapshot(lab), lab.rust("a1", "wire_inspect")
    for operation, fields in (
        ("wire_send", dict(logical_message_id="new_blocked", attempt_id="P1", payload="test")),
        ("wire_send_order_enable", {}),
    ):
        error = lab.rust("a1", operation, expected_exit=1, **fields)
        check(error["code"] == "send_order_enable_conflict", "旧 outbox 被自动迁移或放行")
        check(snapshot(lab) == before and lab.rust("a1", "wire_inspect") == state,
              "旧 outbox 拒绝改变原状态")
        lab.case_evidence.setdefault("legacy_blocked", []).append(
            dict(label=label, operation=operation, error=error, snapshot_sha256=before, state=state))


def legacy_outbox(lab, accepted):
    current = lab.binary
    lab.binary = lab.legacy_binary
    original = lab.prepare("legacy")
    if accepted:
        fact = lab.submit(original)
        lab.rust("a1", "wire_accept", logical_message_id="legacy", attempt_id="P1",
                 acceptance_receipt=fact["acceptance_receipt"])
    lab.binary = current
    check("send_order" not in lab.rust("a1", "wire_inspect"), "旧程序意外启用发送门")
    reject_legacy_new(lab, "before_recovery")
    if not accepted:
        check(lab.attempt("legacy")["outcome"] == "not_found", "未提交原件已有服务终态")
        lab.restart()
        reject_legacy_new(lab, "unknown_after_restart")
    retried = lab.prepare("legacy")
    check(retried == {**original, "reused": True}, "新程序未复用旧密文")
    fact = lab.submit(retried)
    rows = relay_records(lab)
    for duplicate in (accepted, True):
        result = lab.rust("a1", "wire_accept", logical_message_id="legacy", attempt_id="P1",
                          acceptance_receipt=fact["acceptance_receipt"])
        check(result["duplicate"] == duplicate, "旧接受事实没有幂等持久保存")
        check(lab.submit(lab.prepare("legacy")) == fact and relay_records(lab) == rows,
              "旧原件重试产生重复接受")
    lab.restart()
    reject_legacy_new(lab, "all_accepted_still_not_migrated")
    payload = "synthetic-network-legacy"
    packets = {0: dict(logical="legacy", payload=payload, packet=original, accepted=fact,
                       payload_sha256=hashlib.sha256(payload.encode()).hexdigest())}
    lab.case_evidence["targets"] = {}
    targets = receive_targets(lab, packets, [0], 1, ())
    recover(lab, packets, [0], targets)
    report_successes(lab, packets, [0], targets, ())
    lab.case_evidence.update(original_envelope_sha256=digest(original["envelope"]),
                            accepted_messages=1, target_valid_results=3,
                            target_quarantined_results=0, migration="BLOCKED_NOT_AUTOMATIC")


def legacy_quarantine(lab):
    current = lab.binary
    lab.binary = lab.legacy_binary
    order = [0, 1, 4, 6, 3, 7, 5, 2, 8]
    packets = {}
    lab.case_evidence["targets"] = {}
    for index in range(9):
        logical = f"legacy_{index}"
        payload = "synthetic-network-" + logical
        packets[index] = dict(logical=logical, payload=payload, packet=lab.prepare(logical),
                              payload_sha256=hashlib.sha256(payload.encode()).hexdigest())
    for index in order:
        packets[index]["accepted"] = lab.submit(packets[index]["packet"])
    # 在旧进程中先形成真实隔离，再切换新进程重载、补拉和直接重试。
    targets = receive_targets(lab, packets, order, 1, (2,))
    lab.binary = current
    reject_legacy_new(lab, "old_multi_outbox")
    recover(lab, packets, order, targets)
    report_successes(lab, packets, order, targets, (2,))
    for record in packets.values():
        lab.rust("a1", "wire_accept", logical_message_id=record["logical"], attempt_id="P1",
                 acceptance_receipt=record["accepted"]["acceptance_receipt"])
    reject_legacy_new(lab, "nine_accepted_not_safe_to_adopt")
    lab.case_evidence.update(original_order=order, accepted_messages=9,
                            target_valid_results=24, target_quarantined_results=3,
                            quarantine_recovery="UNAVAILABLE_OLD_KEYS_NOT_RESTORED")


def first_send_crash(lab, point):
    enable(lab)
    before = snapshot(lab)
    code = {"before_save": 83, "before_rename": 84, "after_save": 85}[point]
    lab.rust("a1", "wire_send", logical_message_id="ordered_00", attempt_id="P1",
             payload="synthetic-order-ordered_00", failpoint=point, expected_exit=code)
    state = lab.rust("a1", "wire_inspect")
    committed = point == "after_save"
    check((snapshot(lab) != before) == committed, "首发快照提交边界错误")
    check(("send_order" in state) == committed and state["outbox_count"] == int(committed),
          "门标记和首份原件没有共同提交")
    lab.case_evidence["first_send_exit"] = dict(point=point, exit_code=code, state=state,
                                               snapshot_before=before, snapshot_after=snapshot(lab))
    if committed:
        blocked(lab, "first_send_committed_without_response")
        payload = "synthetic-order-ordered_00"
        packet = lab.prepare("ordered_00", payload=payload)
        check(packet["reused"], "提交后退出重新加密首包")
        first = dict(logical="ordered_00", payload=payload, packet=packet,
                     payload_sha256=hashlib.sha256(payload.encode()).hexdigest())
    else:
        first = prepare(lab, 0)
    submit_and_accept(lab, first, label="first_send_recovered")
    finish(lab, {0: first}, [0], 1)


DEFAULT_CASES = [("M03_default_first_send_" + point, partial(first_send_crash, point=point))
                 for point in ("before_save", "before_rename", "after_save")]
COMPATIBILITY_CASES = [
    ("M03_legacy_unknown", partial(legacy_outbox, accepted=False)),
    ("M03_legacy_accepted", partial(legacy_outbox, accepted=True)),
    ("M03_legacy_quarantine", legacy_quarantine),
]
