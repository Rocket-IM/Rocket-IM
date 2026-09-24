"""M09真实签名R0与旧尝试竞争、丢ACK、撤销设备及跨R1后继。"""

import http.client

from .attempt_support import held_race, key, message_rows, packet
from .attempt_permission_support import (
    accepted_from_rows, accepted_operations, assert_fanout, consume, no_message_events,
    permission_fields, removed_projection, terminal_operations,
)
from .fixture import check
from .message_cases import header
from .permission_cases import REVOKE_A2, prepare, submit, version
from .permission_recovery_cases import recover


def accept_before_r0(lab):
    logical = "m09_accept_before_r0"
    saved = packet(lab, logical)
    change = prepare(lab, "m09_remove_after_accept")["change"]
    results = held_race(lab, [
        ("old_submit", "a1", "submit_message", {"envelope": saved["envelope"]}, 200),
        ("signed_r0", "a1", "submit_permission_change", permission_fields(change), 200),
    ])
    accepted = results["old_submit"]
    check(results["signed_r0"]["authorization_version"] == "2", "真实R0未推进唯一权限版本")
    rows = assert_fanout(lab, saved, accepted, ("a2", "b1", "c1"))
    for device in ("a2", "b1"):
        consume(lab, device, saved, accepted, logical)
    removed_projection(lab, rows)
    recover(lab, {"change": change, "receipt": results["signed_r0"]["receipt"]}, "a1", "a2", "b1")
    accepted_operations(lab, saved, logical, accepted)
    lab.restart()
    accepted_operations(lab, saved, logical, accepted)
    check(message_rows(lab) == rows, "R0或重启重试重新扇出旧接受消息")
    for device in ("a2", "b1"):
        consume(lab, device, saved, accepted, logical, duplicate=True)
    removed_projection(lab, rows)


def r0_before_first_submit(lab):
    logical = "m09_r0_before_submit"
    saved = packet(lab, logical)
    change = prepare(lab, "m09_remove_before_submit")["change"]
    results = held_race(lab, [
        ("signed_r0", "a1", "submit_permission_change", permission_fields(change), 200),
        ("old_submit", "a1", "submit_message", {"envelope": saved["envelope"]}, 409),
    ])
    check(results["signed_r0"]["authorization_version"] == "2", "R0未成为已提交前驱")
    rejected = results["old_submit"]
    check(rejected["code"] == "state_stale" and rejected["outcome"] == "rejected_final",
          "旧状态首次提交未被终态拒绝")
    rows = no_message_events(lab)
    check(len(rows["attempts"]) == 1, "首次拒绝未持久化唯一尝试")
    terminal = rows["attempts"][0]["result"]
    terminal_operations(lab, saved, logical, terminal)
    recover(lab, {"change": change, "receipt": results["signed_r0"]["receipt"]}, "a1", "a2", "b1")
    lab.restart()
    terminal_operations(lab, saved, logical, terminal)
    check(no_message_events(lab) == rows, "重启复活旧状态请求或改变终态")
    lab.case_evidence["terminal"] = terminal


def lost_ack_across_r0(lab):
    logical = "m09_lost_ack_r0"
    saved = packet(lab, logical)
    lab.control("hook", hook="drop_after_commit")
    try:
        lab.submit(saved)
        raise AssertionError("真实drop_after_commit未丢弃接受响应")
    except (http.client.RemoteDisconnected, ConnectionResetError):
        pass
    # 此时业务发送者没有get/重提/封口；只用测试独立读事务保存已提交事实。
    before_r0 = message_rows(lab)
    accepted = accepted_from_rows(before_r0)
    check(assert_fanout(lab, saved, accepted, ("a2", "b1", "c1")) == before_r0,
          "R0前独立已提交视图不稳定")
    lab.case_evidence.update(ack_lost=True, sender_resolution_before_r0=False,
                             committed_ground_truth_before_r0=before_r0)
    change = prepare(lab, "m09_remove_during_unknown")["change"]
    r0 = submit(lab, change)
    check(r0["authorization_version"] == "2", "未知发送结果期间真实R0未成功")
    lab.case_evidence["permission_acceptance"] = r0
    rows = assert_fanout(lab, saved, accepted, ("a2", "b1", "c1"))
    for before, after in zip(before_r0["events"], rows["events"]):
        check({k: v for k, v in before.items() if k != "availability"}
              == {k: v for k, v in after.items() if k != "availability"}, "R0改变了原槽位或原密文")
    for device in ("a2", "b1"):
        consume(lab, device, saved, accepted, logical)
    removed_projection(lab, rows)
    recover(lab, {"change": change, "receipt": r0["receipt"]}, "a1", "a2", "b1")
    accepted_operations(lab, saved, logical, accepted)
    lab.restart()
    accepted_operations(lab, saved, logical, accepted)
    check(message_rows(lab) == rows, "跨R0丢ACK恢复新增了消息扇出")
    for device in ("a2", "b1"):
        consume(lab, device, saved, accepted, logical, duplicate=True)
    removed_projection(lab, rows)


def revoked_sender(lab):
    logical = "m09_revoked_sender"
    saved = packet(lab, logical, device="a2")
    accepted = lab.submit(saved, device="a2")
    rows = assert_fanout(lab, saved, accepted, ("a1", "b1", "c1"))
    for device in ("a1", "b1", "c1"):
        consume(lab, device, saved, accepted, logical)
    change = prepare(lab, "m09_revoke_sender", REVOKE_A2)["change"]
    r0 = submit(lab, change)
    check(r0["authorization_version"] == "2", "撤销发送设备的真实R0未提交")
    lab.case_evidence["permission_acceptance"] = r0
    recover(lab, {"change": change, "receipt": r0["receipt"]}, "a1", "b1", "c1")
    for restart in (False, True):
        if restart:
            lab.restart()
        rejected = {}
        for operation, fields in (("get_attempt", key(logical)), ("close_attempt", key(logical)),
                                  ("submit_message", {"envelope": saved["envelope"]})):
            error = lab.http("a2", operation, fields, expected=403)
            check(error["code"] == "device_revoked" and "acceptance_id" not in error
                  and "acceptance" not in error, "撤销发送者通过旧尝试取得接受事实")
            rejected[operation] = error
        lab.case_evidence.setdefault("revoked_sender_responses", []).append(rejected)
        check(message_rows(lab) == rows, "撤销发送者查询/封口/重试改变旧接受或扇出")
    for device in ("a1", "b1", "c1"):
        consume(lab, device, saved, accepted, logical, duplicate=True)


def closed_then_r1_successor(lab):
    logical = "m09_closed_r1_successor"
    old = packet(lab, logical)
    closed = lab.http("a1", "close_attempt", key(logical))
    check(closed["outcome"] == "cancelled_before_accept", "P1未持久封口")
    change = prepare(lab, "m09_remove_after_close")["change"]
    accepted_change = submit(lab, change)
    check(accepted_change["authorization_version"] == "2" and version(lab, "a1") == "1",
          "R0与端侧R1被混为同一步")
    recover(lab, {"change": change, "receipt": accepted_change["receipt"]}, "a1", "a2", "b1")
    check({version(lab, device) for device in ("a1", "a2", "b1")} == {"2"}, "R1未共同推进")
    proof = {"replaces_attempt_id": "P1", "closure_id": closed["closure_id"]}
    successor = packet(lab, logical, "P2", **proof)
    old_header, new_header = header(old), header(successor)
    check(old_header["authorization_version"] == "1" and new_header["authorization_version"] == "2"
          and old_header["crypto_state_ref"] != new_header["crypto_state_ref"]
          and old["envelope"]["payload_bytes"] != successor["envelope"]["payload_bytes"],
          "P2未使用真实R1的新密码状态生成新密文")
    accepted = lab.submit(successor, **proof)
    rows = assert_fanout(lab, successor, accepted, ("a2", "b1"))
    check(len(rows["attempts"]) == 2 and rows["attempts"][0]["successor"] == "P2",
          "封口前驱没有唯一后继")
    for restart in (False, True):
        if restart:
            lab.restart()
        error = lab.submit(old, expected=409)
        check(error["code"] == "attempt_closed" and error["closure_id"] == closed["closure_id"],
              "迟到P1复活或封口证据改变")
        check(lab.http("a1", "get_attempt", key(logical)) == closed, "旧前驱终态改变")
        check(lab.http("a1", "close_attempt", key(logical)) == accepted,
              "封口旧前驱未返回逻辑消息的唯一接受")
        accepted_operations(lab, successor, logical, accepted, attempt="P2", **proof)
        for device in ("a2", "b1"):
            consume(lab, device, successor, accepted, logical, duplicate=restart)
        removed_projection(lab, rows)
        check(message_rows(lab) == rows, "迟到前驱或重启造成第二接受/扇出")
    lab.case_evidence.update(predecessor=closed, permission_acceptance=accepted_change,
                             old_header=old_header, successor_header=new_header)


CASES = [
    ("M09.permission.accept_before_r0", accept_before_r0),
    ("M09.permission.r0_before_first_submit", r0_before_first_submit),
    ("M09.permission.lost_ack_across_r0", lost_ack_across_r0),
    ("M09.permission.revoked_sender", revoked_sender),
    ("M09.permission.closed_then_r1_successor", closed_then_r1_successor),
]
