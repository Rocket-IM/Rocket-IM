"""M02 丢接受响应两次，跨新 CLI 和 Relay 重启恢复同一密文与完整接受事实。"""

from functools import partial

from .deletion_observer import relay_records
from .deletion_support import capture, restart, unchanged
from .fixture import ACCOUNTS, check
from .retry_support import check_page, lose_response, observe_send, receive_once
from .sync_support import TARGETS


def record_acceptance(lab, accepted, duplicate):
    value = lab.rust("a1", "wire_accept", logical_message_id=accepted["logical_message_id"],
                     attempt_id=accepted["attempt_id"], acceptance_receipt=accepted["acceptance_receipt"])
    check(value == {"logical_message_id": accepted["logical_message_id"], "attempt_id": "P1",
          "acceptance_id": accepted["acceptance_id"], "status": "accepted", "duplicate": duplicate},
          "实际HTTP恢复的接受证明没有附到原尝试或重复附加不幂等")
    state = lab.rust("a1", "wire_inspect")
    check(state["outbox_count"] == state["accepted_outbox_count"] == 1 and state["inbox_count"] == 0,
          "发送端接受事实产生新消息或错误送达状态")
    return value


def exact_result(lab, packet, accepted, label):
    before = capture(lab)
    replies = {"submit_message": lab.submit(packet), "get_attempt": lab.attempt(accepted["logical_message_id"]),
               "close_attempt": lab.attempt(accepted["logical_message_id"], operation="close_attempt")}
    check(all(reply == accepted for reply in replies.values()), "重试/查询/封口的完整接受事实改变")
    unchanged(lab, before, label)
    lab.case_evidence.setdefault("acceptance_results", []).append({"label": label, "replies": replies})
    return replies["submit_message"]


def recover(lab, *, hook, order):
    logical = "m02_lost_acceptance"
    payload = "synthetic-M02-lost-acceptance"
    original = observe_send(lab, "initial_positive_control", logical, payload, reused=False)
    # 原接受响应真正丢失；基线只用于测试比较，不作为客户端接受输入。
    accepted, rows = lose_response(lab, original, hook, "initial_submit")
    restart(lab, "first_ack_loss_restart")
    check(relay_records(lab) == rows, "重启改变第一次已提交事实")
    pages = {device: lab.pull(device) for device in TARGETS}
    for device in TARGETS:
        check_page(pages[device], device, original, accepted, rows)
    early = order == "query_first"
    if early:
        receive_once(lab, "b1", pages["b1"], accepted, payload)
    recovered = observe_send(lab, "first_new_cli_recovery", logical, payload, reused=True, original=original)
    if early:
        before = capture(lab)
        check(lab.attempt(logical) == accepted, "先查询恢复改变完整接受事实")
        unchanged(lab, before, "query_before_second_submit")
    # 恢复后的提交再次丢ACK，随后再从第三个发送进程恢复，不使用测试变量直接代替重载。
    lose_response(lab, recovered, hook, "retry_loses_ack_again", expected_rows=rows)
    restart(lab, "second_ack_loss_restart")
    recovered = observe_send(lab, "second_new_cli_recovery", logical, payload, reused=True, original=original)
    actual_reply = exact_result(lab, recovered, accepted, "after_second_ack_loss")
    record_acceptance(lab, actual_reply, False)
    recovered = observe_send(lab, "after_saved_acceptance", logical, payload, reused=True, original=original)
    exact_result(lab, recovered, accepted, "after_saved_acceptance_exact_retry")
    record_acceptance(lab, actual_reply, True)
    before = capture(lab)
    error = lab.rust("a1", "wire_send", logical_message_id=logical, attempt_id="P1",
                     payload=payload + "-changed", expected_exit=1)
    observation = lab.encryption_observations[-1]
    check(error["code"] == "idempotency_conflict", "同尝试更改正文没有明确拒绝")
    if lab.probe_enabled:
        check(observation["calls"] == "0", "同尝试冲突进入消息创建")
    unchanged(lab, before, "changed_payload_rejected_without_persistence")
    lab.case_evidence["conflict_observation"] = observation
    final_targets = {}
    for device in TARGETS:
        current = lab.pull(device)
        check(current == pages[device] and current.signed_input() == pages[device].signed_input(),
              "恢复重试改变原页字节或签名")
        check_page(current, device, original, accepted, rows)
        final_targets[device] = receive_once(lab, device, current, accepted, payload,
                                             already_processed=early and device == "b1")
    check(relay_records(lab) == rows, "接收处理隐式上报回执或改变原接受/槽位")
    restart(lab, "after_all_recipients_processed")
    recovered = observe_send(lab, "after_receivers_and_final_restart", logical, payload,
                             reused=True, original=original)
    exact_result(lab, recovered, accepted, "final_exact_acceptance")
    record_acceptance(lab, actual_reply, True)
    for device in TARGETS:
        current = lab.pull(device)
        check(current == pages[device] and current.signed_input() == pages[device].signed_input(),
              "最终重启改变原目标页字节或签名")
        check(receive_once(lab, device, current, accepted, payload, already_processed=True)
              == final_targets[device], "重启丢失业务去重、槽身份或候选")
        tail = lab.pull(device, "1", "1")
        check(tail["events"] == [] and tail["watermark"] == tail["next_after_seq"] == "1"
              and not tail["has_more"], "接受重试追加了新的目标槽位")
    check(relay_records(lab) == rows, "最终接受事实或逐目标流不一致")
    calls = [v for v in lab.encryption_observations if v["operation"] == "wire_send"]
    check(len(calls) == 6, "实际发送/恢复观察数不符")
    if lab.probe_enabled:
        check([v["calls"] for v in calls] == ["1", "0", "0", "0", "0", "0"],
              "首发或五次恢复/冲突观察不符合直接计数")
    lab.case_evidence.update(hook=hook, recovery_order=order, receiver_processed_before_sender_recovery="b1" if early else None,
        accepted=accepted, final_relay=rows, targets=final_targets,
        final_clients={d: lab.rust(d, "wire_inspect") for d in ACCOUNTS},
        encryption_measurement="direct_feature_probe" if lab.probe_enabled else "NOT_INSTRUMENTED",
        process_scope="each rust call starts and waits for an independent CLI; Relay restart is separately verified")


CASES = [(f"M02.retry.{hook}.{order}", partial(recover, hook=hook, order=order))
         for hook in ("drop_after_commit", "after_commit_exit")
         for order in ("query_first", "retry_first")]
