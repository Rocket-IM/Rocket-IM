"""同一 Rust 会话的确认/重置丢响应与确定性拒绝不留锚。"""

import base64
import copy
from functools import partial

from .fixture import check, identity
from .first_trust_evidence import digest, state
from .first_trust_fixture import DEVICES, confirm, inspect, observe, roundtrip
from .first_trust_faults import preparation, unresolved
from .first_trust_session import TrustSession, public_identity, verify_public


def confirmation_transport(lab, *, phase, action):
    independent = preparation(lab, phase)
    with TrustSession(lab, "a1") as session:
        display = session.request("identity_trust_prepare", target=identity("b1"),
                                  purpose="verify" if phase == "confirm" else "reset")["display"]
        before = state(lab)
        lab.forwarding_helper("drop", action, device="a1")
        error = session.request("identity_trust_" + phase, display=display,
            independent_identity=independent, verification="synthetic_local", expected_error="anchor_response")
        lab.config_restore("a1")
    failed = state(lab)
    check((failed["snapshots"]["a1"] != before["snapshots"]["a1"]) == (action == "finish")
          and failed["relay"] == before["relay"], "确认传输故障保存边界不符")
    lab.case_evidence["confirmation_transport"] = {"phase": phase, "action": action, "error": error,
                                                  "before": before, "after_failure": failed}
    if action == "reserve":
        unresolved(lab, failed)
        return
    lab.resume("a1")
    ready = lab.rust("a1", "anchor_inspect")
    check(ready["status"] == "ready" and ready["active_txn"] is None, "原提交日志不能恢复")
    lab.resume("a1")
    check(state(lab) == failed and lab.rust("a1", "anchor_inspect")["revision"] == ready["revision"],
          "重复 Finish 重写核验记录")
    record = inspect(lab)
    check(record["status"] == ("verified" if phase == "confirm" else "unverified"), "恢复错用确认/reset 事实")
    if phase == "reset":
        confirm(lab, independent=independent)
    lab.case_evidence.update(recovery="EXACT_CONFIRMATION_JOURNAL_FINISHED", recovered_record=record,
                            anchor_after_resume=ready)


def deterministic_rejection(lab):
    observe(lab)
    original = lab.rust("a1", "anchor_inspect")
    before = state(lab)
    with TrustSession(lab, "a1") as session:
        session.request("identity_trust_prepare", target=identity("d1"), purpose="verify",
                        expected_error="identity_not_found")
        session.request("identity_trust_observe", identity=public_identity(lab, "b1") |
                        {"service_id": "foreign"}, expected_error="identity_context")
    error = lab.rust("a1", "identity_trust_prepare", target=identity("b1"), purpose="verify", expected_exit=1)
    check(error["code"] == "identity_session_required", "单次 CLI 接受了会话确认入口")
    current = lab.rust("a1", "anchor_inspect")
    check(state(lab) == before and current == original, "确定性拒绝留下预约或推进锚")
    confirm(lab)
    check(inspect(lab)["status"] == "verified", "拒绝后正常核验被卡住")
    lab.case_evidence.update(before_rejections=original, after_rejections=current)


def invalid_join_preserves_anchor_pause(lab):
    from .device_join_cases import join_device, prepare_device, setup
    from .join_cases import accept_add
    lab.group()
    setup(lab)
    verify_public(lab, "b1", "b2")
    candidate = prepare_device(lab, "invalid-join")
    record = accept_add(lab, candidate, "b1")
    forged = copy.deepcopy(record)
    signature = bytearray(base64.b64decode(forged["receipt"]["signature_bytes"]))
    signature[0] ^= 1
    forged["receipt"]["signature_bytes"] = base64.b64encode(signature).decode()
    before, anchor_before = state(lab), lab.rust("b2", "anchor_inspect")
    error = lab.rust("b2", "permission_join", record=forged, join=candidate["join"], expected_exit=1)
    check(error["code"] == "permission_signature", "坏回执未按原验签入口拒绝")
    after, anchor_after = state(lab), lab.rust("b2", "anchor_inspect")
    gate, journal = lab.directory / "b2/anchor-gate.enc", lab.directory / "b2/anchor-journal.enc"
    lab.case_evidence["invalid_join_anchor_effect"] = {"error": error, "before": before, "after": after,
        "anchor_before": anchor_before, "anchor_after": anchor_after, "gate_exists": gate.exists(),
        "gate_sha256": digest(gate.read_bytes()) if gate.exists() else None, "journal_exists": journal.exists(),
        "boundary": "snapshot and Relay unchanged; original public rejection after Reserve leaves unresolved anchor"}
    check(after == before and anchor_after["paused"] and anchor_after["active_txn"] is not None
          and int(anchor_after["revision"]) > int(anchor_before["revision"])
          and gate.is_file() and not journal.exists(), "拒绝锚副作用与原契约不符")
    blocked = join_device(lab, "invalid-join", expected_exit=1)
    check(blocked["code"] == "anchor_paused" and state(lab) == after
          and lab.rust("b2", "anchor_inspect") == anchor_after,
          "随后合法入群绕过或清除真正未决锚")
    lab.case_evidence.update(recovery="BLOCKED_UNRESOLVED_NO_RESUME_OR_CLEAR", legitimate_join_error=blocked)


def old_history_preserves_anchor_pause(lab):
    from .device_join_cases import join_device, prepare_device, setup
    from .join_cases import accept_add
    from .permission_recovery_cases import recover
    lab.group()
    old_packet, old_accepted = roundtrip(lab, "history-before-join", sender="b1")
    setup(lab)
    verify_public(lab, "b1", "b2")
    candidate = prepare_device(lab, "history-join")
    record = accept_add(lab, candidate, "b1")
    recover(lab, record, *DEVICES)
    join_device(lab, "history-join")
    check(lab.rust("b2", "wire_inspect")["history"]["past_epochs"] == [], "新设备意外持有旧历史")
    payload = "synthetic-legitimate-after-join"
    current = lab.rust("b1", "wire_send", logical_message_id="legitimate-after-join", attempt_id="P1", payload=payload)
    accepted = lab.submit(current, device="b1")
    lab.rust("b1", "wire_accept", logical_message_id="legitimate-after-join", attempt_id="P1",
             acceptance_receipt=accepted["acceptance_receipt"])
    valid = lab.receive("a1", current, acceptance_id=accepted["acceptance_id"],
                        acceptance_receipt=accepted["acceptance_receipt"])
    check(valid["payload_sha256"] == digest(payload.encode()), "对照新消息未实际解密")
    before, anchor_before = state(lab), lab.rust("b2", "anchor_inspect")
    error = lab.receive("b2", old_packet, acceptance_id=old_accepted["acceptance_id"],
                        acceptance_receipt=old_accepted["acceptance_receipt"], expected_exit=1)
    check(error["code"] == "history_unavailable", "旧消息未按真实缺历史入口拒绝")
    after, anchor_after = state(lab), lab.rust("b2", "anchor_inspect")
    gate, journal = lab.directory / "b2/anchor-gate.enc", lab.directory / "b2/anchor-journal.enc"
    lab.case_evidence["old_history_anchor_effect"] = {"error": error, "before": before, "after": after,
        "anchor_before": anchor_before, "anchor_after": anchor_after, "gate_exists": gate.exists(),
        "gate_sha256": digest(gate.read_bytes()) if gate.exists() else None, "journal_exists": journal.exists(),
        "boundary": "snapshot and Relay unchanged; old-epoch rejection after Reserve leaves unresolved anchor"}
    check(after == before and anchor_after["paused"] and anchor_after["active_txn"] is not None
          and int(anchor_after["revision"]) > int(anchor_before["revision"])
          and gate.is_file() and not journal.exists(), "旧历史拒绝锚副作用与原契约不符")
    blocked = lab.receive("b2", current, acceptance_id=accepted["acceptance_id"],
                          acceptance_receipt=accepted["acceptance_receipt"], expected_exit=1)
    check(blocked["code"] == "anchor_paused" and state(lab) == after
          and lab.rust("b2", "anchor_inspect") == anchor_after, "合法新接收清除真正未决锚")
    lab.case_evidence.update(recovery="BLOCKED_UNRESOLVED_NO_RESUME_OR_CLEAR", legitimate_receive_error=blocked,
                            accepted_current_message=accepted, control_receiver=valid)


CASES = [(f"Q01.F10.anchor.{phase}.drop.{action}", partial(confirmation_transport, phase=phase, action=action))
         for phase in ("confirm", "reset") for action in ("reserve", "finish")]
CASES += [("Q01.F10.anchor.deterministic_rejection", deterministic_rejection)]
CASES += [("Q01.F08.invalid_join_preserves_anchor_pause", invalid_join_preserves_anchor_pause)]
CASES += [("Q01.F08.old_history_preserves_anchor_pause", old_history_preserves_anchor_pause)]
