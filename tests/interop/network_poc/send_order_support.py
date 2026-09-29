"""单未决发送门禁的真实 Rust 状态、原接受证明与目标消息观察。"""

import hashlib

from .fixture import check
from .reordering_recovery import recover
from .reordering_support import receive_targets, report_successes
from .slot_support import digest


def snapshot(lab, device="a1"):
    return hashlib.sha256((lab.directory / device / "state.enc").read_bytes()).hexdigest()


def inspect(lab):
    state = lab.rust("a1", "wire_inspect")
    check("send_order" in state, "Rust首发没有持久启用默认发送门")
    check(state["send_order"]["policy"] == "acceptance_serial_v1"
          and state["send_order"]["conversation_id"] == "G1", "持久门禁范围丢失")
    return state


def enable(lab):
    automatic = getattr(lab, "send_order_activation", "explicit") == "default"
    reply = None if automatic else lab.rust("a1", "wire_send_order_enable")
    state = lab.rust("a1", "wire_inspect")
    check(state["outbox_count"] == 0, "首次启用不是空发送范围")
    if automatic:
        check("send_order" not in state, "首发前已有显式门禁，不能证明默认策略")
    else:
        check(state["send_order"]["pending"] is None, "首次启用存在未决记录")
    lab.case_evidence.update(enable={"reply": reply, "state": state}, targets={},
                            activation="default_first_send" if automatic else "explicit",
                            submitted=[], created=[], blocked=[],
                            generation_basis="not exported; logical labels are not MLS generations; rejected new requests do not enter an outbound queue",
                            ratchet_configuration_changed=False)


def blocked(lab, label, logical="future_blocked", **fields):
    before, state = snapshot(lab), inspect(lab)
    check(state["send_order"]["pending"] is not None, "阻塞测试没有未决原尝试")
    error = lab.rust("a1", "wire_send", expected_exit=1, logical_message_id=logical,
                     attempt_id=fields.pop("attempt_id", "P1"),
                     payload=fields.pop("payload", "synthetic-order-" + logical), **fields)
    after = snapshot(lab)
    item = {"label": label, "logical_message_id": logical, "error": error,
            "snapshot_sha256_before": before, "snapshot_sha256_after": after,
            "state_before": state, "state_after": inspect(lab)}
    lab.case_evidence.setdefault("blocked", []).append(item)
    check(error["code"] == "send_order_pending" and "envelope" not in error
          and before == after and item["state_after"] == state,
          "未决尝试未阻止新密文或失败修改了持久快照")
    return error


def prepare(lab, index):
    logical = f"ordered_{index:02}"
    payload = "synthetic-order-" + logical
    packet = lab.prepare(logical, payload=payload)
    check(packet["reused"] is False, "首次允许的发送被误记为原包重试")
    state = inspect(lab)
    check(state["send_order"]["pending"] == {"logical_message_id": logical, "attempt_id": "P1"},
          "Rust没有持久保存唯一未决尝试")
    lab.case_evidence["created"].append({"logical_label": index, "logical_message_id": logical,
                                        "envelope_sha256": digest(packet["envelope"]), "state": state})
    return {"logical": logical, "payload": payload, "packet": packet,
            "payload_sha256": hashlib.sha256(payload.encode()).hexdigest()}


def accept(lab, record, accepted, *, duplicate=False):
    result = lab.rust("a1", "wire_accept", logical_message_id=record["logical"], attempt_id="P1",
                      acceptance_receipt=accepted["acceptance_receipt"])
    check(result == {"logical_message_id": record["logical"], "attempt_id": "P1",
                     "acceptance_id": accepted["acceptance_id"], "status": "accepted", "duplicate": duplicate},
          "实际接受证明未按原尝试持久保存")
    lab.case_evidence.setdefault("saved_acceptances", []).append(result)
    return result


def submit_and_accept(lab, record, *, label):
    accepted = lab.submit(record["packet"])
    check(accepted["outcome"] == "accepted" and lab.attempt(record["logical"]) == accepted,
          "真实HTTP提交/查询没有一致的完整接受事实")
    # HTTP成功和查询结果尚未写入Rust时，都不能释放门禁。
    blocked(lab, label + "_http_success_without_saved_proof")
    accept(lab, record, accepted)
    check(inspect(lab)["send_order"]["pending"] is None, "保存接受证明后门禁没有释放")
    record["accepted"] = accepted
    lab.case_evidence["submitted"].append({"logical_message_id": record["logical"], "accepted": accepted})
    return accepted


def finish(lab, packets, order, page_limit=100):
    state = inspect(lab)
    check(state["outbox_count"] == state["accepted_outbox_count"] == len(order)
          and state["send_order"]["pending"] is None, "发送队列未完整保存各原接受事实")
    # 复用的恢复报告将 key 称作 send_index；这里按实际首次创建顺序重键，不能拿逻辑标签充代次。
    ordered_packets = {index: packets[label] for index, label in enumerate(order)}
    send_indices = list(ordered_packets)
    targets = receive_targets(lab, ordered_packets, send_indices, page_limit, ())
    recover(lab, ordered_packets, send_indices, targets)
    report_successes(lab, ordered_packets, send_indices, targets, ())
    final_state = inspect(lab)
    check({k: v for k, v in final_state.items() if k != "sync"}
          == {k: v for k, v in state.items() if k != "sync"}, "目标恢复/回执处理改变发送门禁或接受事实")
    lab.case_evidence.update(accepted_messages=len(order), original_message_slots=3 * len(order),
                            target_valid_results=3 * len(order), target_quarantined_results=0,
                            final_sender=final_state, actual_created_logical_order=order,
                            encryption_measurement="NOT_INSTRUMENTED")
