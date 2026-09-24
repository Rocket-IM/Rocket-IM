"""M04 原终态 × 异字节 HTTP 负例；原 Rust 密文、精确结果及槽位跨重启保留。"""

from functools import partial

from .deletion_observer import relay_records
from .deletion_support import capture, unchanged
from .fixture import ACCOUNTS, check
from .retry_cases import record_acceptance
from .retry_support import check_page, receive_once
from .sync_support import TARGETS
from .terminal_support import (
    changed_packet, establish_terminal, exact_operations, input_summary, prepare_original,
    receive_empty, reject_mutation, signed_page_summary,
)


def restart(lab, label):
    before = capture(lab)
    previous = lab.process
    old_pid = previous.pid
    lab.restart()
    check(previous.poll() is not None and lab.process.poll() is None and lab.process.pid != old_pid,
          "终态恢复没有实际退出并启动独立 Relay 进程")
    unchanged(lab, before, label)
    lab.case_evidence.setdefault("relay_restarts", []).append({
        "label": label, "old_pid": old_pid, "old_exit_code": previous.returncode,
        "new_pid": lab.process.pid})


def targets(lab, packet, terminal, rows, payload, pages, *, repeated, label):
    results = {}
    for device in TARGETS:
        before = capture(lab)
        page = lab.pull(device)
        unchanged(lab, before, label + "_pull_" + device)
        if device in pages:
            check(page == pages[device] and page.signed_input() == pages[device].signed_input(),
                  "冲突或重启改变原目标签页字节、签名或槽位")
        else:
            pages[device] = page
        if terminal["outcome"] == "accepted":
            check_page(page, device, packet, terminal, rows)
            received = receive_once(lab, device, page, terminal, payload, already_processed=repeated)
            before = capture(lab)
            tail = lab.pull(device, "1", "1")
            check(tail["events"] == [] and tail["watermark"] == tail["next_after_seq"] == "1"
                  and not tail["has_more"], "冲突后目标存在额外尾部槽位")
            unchanged(lab, before, label + "_tail_" + device)
        else:
            received = receive_empty(lab, device, page, rows)
        results[device] = {"page": signed_page_summary(page), "received": received}
    check(relay_records(lab) == rows, "目标处理改变原终态、隐式上报回执或产生部分扇出")
    lab.case_evidence.setdefault("target_observations", []).append({"label": label, "targets": results})
    return results


def terminal_immutable(lab, *, terminal, mutation):
    logical = "m04_terminal"
    payload = "synthetic-M04-original-message"
    packet = prepare_original(lab, logical, payload, terminal)
    response, original_terminal, rows = establish_terminal(lab, packet, terminal)
    altered = changed_packet(packet, mutation)
    lab.case_evidence.update(terminal_kind=terminal, mutation_kind=mutation,
                             conflicting_input=input_summary(altered),
                             mutation_scope="synthetic HTTP byte mutation; no new MLS encryption")
    # 原 HTTP 结果只在真实接受时交给原客户端接受入口；拒绝标识不冒充签名证明。
    if terminal == "accepted":
        lab.case_evidence["sender_acceptance"] = record_acceptance(lab, response, False)
    pages = {}
    initial_targets = targets(lab, packet, original_terminal, rows, payload, pages,
                              repeated=False, label="before_conflicts")
    first_error = None
    for phase in range(3):
        label = "initial" if phase == 0 else "after_restart_" + str(phase)
        if phase:
            restart(lab, label)
        exact_operations(lab, packet, response, original_terminal, label + "_before_conflict")
        for repetition in range(2):
            attempt_label = label + "_conflict_" + str(repetition + 1)
            first_error = reject_mutation(lab, altered, original_terminal, attempt_label, first_error)
            exact_operations(lab, packet, response, original_terminal, attempt_label + "_restore_original")
        observed = targets(lab, packet, original_terminal, rows, payload, pages,
                           repeated=True, label=label + "_after_conflicts")
        check(observed == initial_targets, "原接受或拒绝目标的签页、槽、去重或双游标跨阶段变化")
        check(relay_records(lab) == rows, "同尝试异字节改写原终态或消息相关投影")
    clients = {device: lab.rust(device, "wire_inspect") for device in ACCOUNTS}
    sender = clients["a1"]
    check(sender["outbox_count"] == 1 and sender["inbox_count"] == 0
          and sender["accepted_outbox_count"] == (1 if terminal == "accepted" else 0),
          "原发送尝试被替换、错误接受或发生新消息")
    lab.case_evidence.update(final_terminal=original_terminal, final_relay=relay_records(lab),
                             final_clients=clients, relay_restart_count=2,
                             scope="message records and device stream projections; not full database bytes",
                             old_key_decryption="NOT_EXECUTED_ACCESS_RESTRICTED")


CASES = [(f"M04.terminal.{terminal}.{mutation}", partial(terminal_immutable, terminal=terminal, mutation=mutation))
         for terminal in ("accepted", "state_stale", "state_conflict", "recipient_set_mismatch")
         for mutation in ("semantic_header", "raw_header", "ciphertext")]
