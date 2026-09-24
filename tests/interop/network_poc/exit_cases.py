"""M08 接受、拒绝及封口在真实提交前后退出，离线读取并经原 HTTP 请求恢复。"""

from functools import partial

from .deletion_observer import relay_records
from .deletion_support import capture, unchanged
from .exit_support import (
    check_submit_reply, check_terminal, crash, exact_operations, mutations,
    reload_original, request, restart_after_exit,
)
from .fixture import ACCOUNTS, check
from .isolation_fixture import client_view
from .message_cases import header
from .retry_cases import record_acceptance
from .sync_support import TARGETS
from .terminal_cases import restart, targets
from .terminal_support import establish_terminal, input_summary, prepare_original, signed_page_summary


KINDS = ("accepted_first", "rejected_first_state_stale", "rejected_first_state_conflict",
         "rejected_first_recipient_set_mismatch", "closed_first", "closed_successor",
         "close_existing_accepted", "close_existing_rejected")


def prepare_case(lab, kind, logical, payload):
    reason = kind.removeprefix("rejected_first_") if kind.startswith("rejected_first_") else None
    if kind == "close_existing_rejected":
        reason = "state_stale"
    packet = prepare_original(lab, logical, payload, reason or "accepted")
    closed = kind in ("closed_first", "closed_successor")
    outcome = "cancelled_before_accept" if closed else "rejected_final" if reason else "accepted"
    proof, parent, existing = {}, None, None
    if kind.startswith("close_existing_"):
        response, terminal, rows = establish_terminal(lab, packet, reason or "accepted")
        existing = {"response": response, "terminal": terminal, "rows": rows}
    if kind == "closed_successor":
        first = request(lab, packet, "close_attempt", {})
        first_terminal, first_rows = check_terminal(lab, packet, "cancelled_before_accept")
        check(first == first_terminal, "P1 实际封口响应不同于已提交证明")
        parent = first_rows["attempts"][0]
        proof = {"replaces_attempt_id": "P1", "closure_id": first["closure_id"]}
        packet = lab.prepare(logical, "P2", payload=payload, **proof)
        check(packet["reused"] is False and packet["attempt_id"] == "P2",
              "未通过原 Rust 入口持实际 P1 closure 保存 P2")
        check(relay_records(lab) == first_rows, "端侧准备 P2 提前改变 Relay 链尾")
        lab.case_evidence.update(parent_terminal=first, parent_committed_rows=first_rows,
                                 successor_input=input_summary(packet), successor_proof=proof)
    operation = "close_attempt" if closed or kind.startswith("close_existing_") else "submit_message"
    lab.case_evidence.update(kind=kind, operation=operation, expected_outcome=outcome,
                             rejection_reason=reason, request_input=input_summary(packet), request_proof=proof)
    return packet, operation, proof, outcome, reason, parent, existing


def pages_before_exit(lab):
    pages = {}
    for device in TARGETS:
        before = capture(lab)
        pages[device] = lab.pull(device)
        unchanged(lab, before, "pre_exit_signed_pull_" + device)
    lab.case_evidence["pre_exit_pages"] = {device: signed_page_summary(page) for device, page in pages.items()}
    return pages


def recover_terminal(lab, packet, operation, proof, outcome, reason, parent, offline, payload, *, absent):
    before = capture(lab)
    queried = request(lab, packet, "get_attempt", {})
    unchanged(lab, before, "first_post_exit_query_without_creation")
    if absent:
        source = header(packet)
        check(queried == {"outcome": "not_found", "logical_message_id": source["logical_message_id"],
                           "attempt_id": source["attempt_id"]}, "提交前退出后查询没有保持 not_found")
    else:
        stored, rows = check_terminal(lab, packet, outcome, reason=reason, parent=parent)
        check(queried == stored and rows == offline["relay"], "查询没有返回离线观察的完整已提交事实")
    lab.case_evidence["first_recovery_query"] = queried
    # 仅恢复原接受包；state_stale 发送者仍有权限候选暂停，不调用 wire_send 绕过该门。
    if outcome == "accepted":
        packet = reload_original(lab, packet, payload, "after_actual_relay_exit")
    clients = client_view(lab)
    reply = request(lab, packet, operation, proof)
    check(client_view(lab) == clients, "恢复 HTTP 操作改变客户端持久状态")
    terminal, rows = check_terminal(lab, packet, outcome, reason=reason, parent=parent)
    if operation == "submit_message":
        check_submit_reply(reply, terminal)
    else:
        check(reply == terminal, "原封口请求未恢复完整已提交结果")
    if not absent:
        check(rows == offline["relay"], "重试写入、覆盖或再次扇出已提交事务")
    lab.case_evidence.update(recovery_response=reply, recovered_terminal=terminal, recovered_relay=rows)
    return packet, terminal, rows


def transaction_exit(lab, *, kind, hook):
    logical, payload = "m08_transaction_exit", "synthetic-M08-original-message"
    packet, operation, proof, outcome, reason, parent, existing = prepare_case(lab, kind, logical, payload)
    prior_pages = pages_before_exit(lab)
    before = capture(lab)
    offline = crash(lab, packet, operation, proof, hook, before)
    absent = hook == "before_commit_exit" and existing is None
    if hook == "before_commit_exit" or existing is not None:
        check(offline == before, "提交前退出或已有终态封口改写已提交记录、父链或客户端")
    if not absent:
        terminal, rows = check_terminal(lab, packet, outcome, reason=reason, parent=parent)
        check(rows == offline["relay"], "离线读取期间投影不稳定")
        if existing is not None:
            check(terminal == existing["terminal"] and rows == existing["rows"], "已有终态在封口退出时丢失")
    restart_after_exit(lab, offline)
    packet, terminal, rows = recover_terminal(lab, packet, operation, proof, outcome, reason,
                                              parent, offline, payload, absent=absent)
    replies = exact_operations(lab, packet, terminal, proof, "first_recovery", parent=parent)
    if existing is not None:
        check(replies["submit_message"] == existing["response"], "已有终态原完整 HTTP 响应跨退出变化")
    if outcome == "accepted":
        # 仅原 HTTP 路径实际返回的证明交给 wire_accept；离线记录不成为客户端输入。
        lab.case_evidence["sender_acceptance"] = record_acceptance(lab, replies["submit_message"], False)
    pages = prior_pages if existing is not None or outcome != "accepted" else {}
    first_targets = targets(lab, packet, terminal, rows, payload, pages,
                            repeated=False, label="after_exit_recovery")
    first_mutations = mutations(lab, packet, terminal, proof, "after_exit_recovery")
    exact_operations(lab, packet, terminal, proof, "after_altered_requests", parent=parent)
    check(relay_records(lab) == rows, "恢复、原包或异字节请求改变已提交消息相关记录")
    restart(lab, "final_normal_restart")
    final_replies = exact_operations(lab, packet, terminal, proof, "after_final_restart", parent=parent)
    check(final_replies == replies, "再次重启后原提交、查询或封口的完整响应变化")
    final_mutations = mutations(lab, packet, terminal, proof, "after_final_restart")
    check(final_mutations == first_mutations, "封口或异字节负例跨重启改变完整错误")
    last_targets = targets(lab, packet, terminal, rows, payload, pages,
                           repeated=True, label="after_final_restart")
    check(last_targets == first_targets and relay_records(lab) == rows,
          "再次重启丢失原签页、目标槽、去重、游标或终态")
    clients = {device: lab.rust(device, "wire_inspect") for device in ACCOUNTS}
    sender = clients["a1"]
    check(sender["outbox_count"] == (2 if parent is not None else 1) and sender["inbox_count"] == 0
          and sender["accepted_outbox_count"] == (1 if outcome == "accepted" else 0),
          "发送者出现重复接受、丢失原尝试或隐式处理消息")
    lab.case_evidence.update(final_terminal=terminal, final_relay=rows, final_clients=clients,
        actual_forced_exit_count=1, actual_relay_restart_count=2,
        altered_request_count=6, scope="message records and device stream projections; not full database bytes",
        encryption_measurement="NOT_INSTRUMENTED", old_key_decryption="NOT_EXECUTED_ACCESS_RESTRICTED")


CASES = [(f"M08.exit.{kind}.{hook}", partial(transaction_exit, kind=kind, hook=hook))
         for kind in KINDS for hook in ("before_commit_exit", "after_commit_exit")]
