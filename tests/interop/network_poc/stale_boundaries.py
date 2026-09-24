"""拒绝证明的精确范围、旧程序、被移除发送者与迟到证明边界。"""

import base64
from copy import deepcopy
import json
import subprocess

from .closure_support import accept
from .closure_delivery import receive as receive_full
from .deletion_observer import relay_records
from .fixture import check, identity
from .send_order_support import snapshot
from .stale_delivery import receive
from .stale_support import advance, blocked, catch_up, persist, prepare, reject, statement, successor


def _setup(lab):
    packet = prepare(lab)
    advance(lab)
    return packet, reject(lab, packet)


def _signed(lab, proof, claims):
    value = deepcopy(proof)
    value["rejection_receipt"] = lab.relay_key("sign", expected_signature_key=lab.relay_receipt_key,
                                              statement=claims)["receipt"]
    return value


def _refuse(lab, proof, label, *, code="rejection_conflict", construction="valid_service_signature",
            expect_pending=True):
    before, state, rows = snapshot(lab), lab.rust("a1", "wire_inspect"), relay_records(lab)
    error = persist(lab, proof, expected_exit=1)
    after, current = snapshot(lab), lab.rust("a1", "wire_inspect")
    lab.case_evidence.setdefault("rejection_boundaries", []).append({"label": label,
        "construction": construction, "receipt": proof["rejection_receipt"], "error": error,
        "snapshot_sha256_before": before, "snapshot_sha256_after": after,
        "state_before": state, "state_after": current})
    check(error["code"] == code and before == after and state == current and relay_records(lab) == rows,
          "错误拒绝证明未明确失败或改变原状态")
    if expect_pending:
        blocked(lab)


def proof_boundaries(lab):
    packet, proof = _setup(lab)
    catch_up(lab, "a1", "a2", "b1")
    original = statement(proof)
    original_version = json.loads(base64.b64decode(packet["envelope"]["header_bytes"]))["authorization_version"]
    mutations = [
        ("wrong_service", {"service_id": "synthetic-other-service"}),
        ("wrong_conversation", {"conversation_id": "other-conversation"}),
        ("wrong_account", {"sender": {"account_id": "other-account", "device_id": "a1"}}),
        ("wrong_device", {"sender": {"account_id": "alice", "device_id": "other-device"}}),
        ("wrong_logical", {"logical_message_id": "other-logical"}),
        ("wrong_attempt", {"attempt_id": "other-attempt"}),
        ("wrong_digest", {"envelope_sha256": "0" * 64}),
        ("wrong_predecessor", {"replaces_attempt_id": "other-predecessor",
                               "predecessor_closure_id": "other-predecessor-closure"}),
        ("floor_not_strictly_newer", {"required_authorization_version": original_version}),
        ("known_floor_wrong_ref", {"required_crypto_state_ref": "0" * 64}),
    ]
    for label, fields in mutations:
        _refuse(lab, _signed(lab, proof, {**original, **fields}), label)
    # 正常签名器不签非法协议；这里单独证明 Rust 在验签前拒绝 schema，不冒称有效签名反例。
    malformed = [("unsupported_reason", {"code": "state_conflict"}),
                 ("unsupported_outcome", {"outcome": "cancelled_before_accept"}),
                 ("numeric_floor", {"required_authorization_version": 2}),
                 ("overflow_floor", {"required_authorization_version": "18446744073709551616"})]
    for label, fields in malformed:
        bad = deepcopy(proof)
        bad["rejection_receipt"]["statement_bytes"] = base64.b64encode(
            json.dumps({**original, **fields}, separators=(",", ":")).encode()).decode()
        _refuse(lab, bad, label, code="rejection_invalid", construction="statement_mutated_without_resigning")
    bad = deepcopy(proof)
    signature = bytearray(base64.b64decode(bad["rejection_receipt"]["signature_bytes"], validate=True))
    signature[0] ^= 1
    bad["rejection_receipt"]["signature_bytes"] = base64.b64encode(signature).decode()
    _refuse(lab, bad, "tampered_signature", code="rejection_signature", construction="signature_bit_flipped")
    check(persist(lab, proof)["duplicate"] is False, "负例污染了原合法拒绝保存")
    _refuse(lab, _signed(lab, proof, {**original, "closure_id": "synthetic-other-terminal"}),
            "different_terminal_after_saved_rejection")
    packet = successor(lab, proof)
    accepted = accept(lab, packet, "M1", "P2", replaces_attempt_id="P1", closure_id=proof["closure_id"])
    receive(lab, [("M1", "P2", "stale payload", packet, accepted)])
    return {"validly_signed_binding_rejections": len(mutations), "schema_rejections": len(malformed),
            "signature_rejections": 1, "terminal_conflicts": 1}


def removed_sender(lab):
    _, proof = _setup(lab)
    catch_up(lab, "a1", "a2", "b1")
    removal = advance(lab, ident="remove-sender", action={"kind": "revoke_device",
                                                         "account_id": "alice", "device_id": "a1"})
    # 本机随后已被撤销，不能再借其凭证拉页；使用上面真实 R0 返回的公开签名原记录。
    result = lab.rust("a1", "permission_recover", record=removal)
    before = snapshot(lab)
    saved = persist(lab, proof)
    state = lab.rust("a1", "permission_inspect")
    lab.case_evidence["removed_sender"] = {"permission_record": removal, "recovery": result,
        "saved_rejection": saved, "permission_state": state,
        "snapshot_sha256_before_terminal": before, "snapshot_sha256_after_terminal": snapshot(lab)}
    check(state["access_removed"] is True and state["recovery_status"] == "access_removed",
          "真实撤销没有持久阻断发送者")
    blocked(lab, code="access_removed", payload="stale payload")
    blocked(lab, logical="M1", attempt="P2", code="access_removed", payload="stale payload",
            replaces_attempt_id="P1", closure_id=proof["closure_id"])
    rows, original = relay_records(lab), snapshot(lab)
    denied = lab.attempt("M1", expected=403)
    lab.case_evidence["removed_sender"]["http_after_revocation"] = denied
    check(denied["code"] == "device_revoked" and relay_records(lab) == rows, "撤销设备仍可查询原拒绝")
    lab.restart()
    repeated = persist(lab, proof)
    check(repeated["duplicate"] is True and snapshot(lab) == original,
          "撤销后的迟到拒绝证明重写状态")
    blocked(lab, logical="M1", attempt="P2", code="access_removed", payload="stale payload",
            replaces_attempt_id="P1", closure_id=proof["closure_id"])
    check(rows["counts"]["accepted"] == rows["counts"]["events"] == 0 and relay_records(lab) == rows,
          "撤销后的拒绝恢复制造接受或投递")
    lab.case_evidence.update(final_relay=rows, accepted_messages=0, target_valid_results=0,
                            target_quarantined_results=0, progress="BLOCKED_ACCESS_REMOVED")
    return {"progress": "BLOCKED_ACCESS_REMOVED"}


def _old_program(lab, *, rejected):
    before, current = snapshot(lab), lab.rust("a1", "wire_inspect")
    request = {"directory": str(lab.directory / "a1"), "service": lab.service,
               "account": identity("a1")["account_id"], "device": "a1", "operation": "wire_inspect"}
    result = subprocess.run([str(lab.old_binary)], input=json.dumps(request), text=True,
                            capture_output=True, timeout=30)
    lab.process_count += 1
    reply = json.loads(result.stdout)
    lab.case_evidence.setdefault("old_program", []).append({"rejected": rejected, "reply": reply,
        "exit_code": result.returncode, "snapshot_sha256_before": before, "snapshot_sha256_after": snapshot(lab)})
    check(not result.stderr and result.returncode == int(rejected) and reply["ok"] is not rejected
          and snapshot(lab) == before, "旧程序兼容或拒绝格式未保持原快照")
    if rejected:
        check(reply["error"]["code"] == "state_decoding" and "wire_rejections" in reply["error"]["message"],
              "旧程序未因新拒绝字段明确拒绝")
    else:
        check(reply["result"] == current, "旧程序读取无拒绝标记快照结果不同")


def compatibility(lab):
    packet = prepare(lab)
    _old_program(lab, rejected=False)
    advance(lab)
    proof = reject(lab, packet)
    persist(lab, proof)
    _old_program(lab, rejected=True)
    catch_up(lab, "a1", "a2", "b1")
    packet = successor(lab, proof)
    _old_program(lab, rejected=True)
    accepted = accept(lab, packet, "M1", "P2", replaces_attempt_id="P1", closure_id=proof["closure_id"])
    receive(lab, [("M1", "P2", "stale payload", packet, accepted)])
    return {"compatible_reads": 1, "explicit_old_format_rejections": 2}


def _late(lab, proof, expected):
    before, state, rows = snapshot(lab), lab.rust("a1", "wire_inspect"), relay_records(lab)
    result = persist(lab, proof)
    current = lab.rust("a1", "wire_inspect")
    lab.case_evidence.setdefault("late_rejection", []).append({"result": result,
        "snapshot_sha256_before": before, "snapshot_sha256_after": snapshot(lab),
        "state_before": state, "state_after": current})
    check(result["duplicate"] is True and before == snapshot(lab) and state == current
          and current["send_order"]["pending"] == expected and relay_records(lab) == rows,
          "迟到旧拒绝证明释放或改变当前未决槽")
    blocked(lab)


def late_proof(lab):
    _, proof = _setup(lab)
    persist(lab, proof)
    catch_up(lab, "a1", "a2", "b1")
    packet = successor(lab, proof)
    _late(lab, proof, {"logical_message_id": "M1", "attempt_id": "P2"})
    blocked(lab, logical="M1", attempt="P3", payload="stale payload",
            replaces_attempt_id="P1", closure_id=proof["closure_id"])
    retry = successor(lab, proof)
    check(retry == {**packet, "reused": True}, "旧拒绝重放改变后继原包")
    accepted = accept(lab, retry, "M1", "P2", replaces_attempt_id="P1", closure_id=proof["closure_id"])
    next_packet = prepare(lab, "M2")
    _late(lab, proof, {"logical_message_id": "M2", "attempt_id": "P1"})
    next_accepted = accept(lab, next_packet, "M2", "P1")
    receive(lab, [("M1", "P2", "stale payload", packet, accepted),
                  ("M2", "P1", "stale payload", next_packet, next_accepted)])
    return {"late_replays": 2}


def signer_failure(lab):
    packet = prepare(lab)
    advance(lab)
    before, original = relay_records(lab), snapshot(lab)
    held = lab.receipt_key.with_suffix(".held")
    lab.receipt_key.rename(held)
    try:
        error = lab.submit(packet, expected=503)
    finally:
        held.rename(lab.receipt_key)
    after = relay_records(lab)
    lab.case_evidence["rejection_signer_failure"] = {"error": error, "relay_before": before, "relay_after": after,
        "snapshot_sha256_before": original, "snapshot_sha256_after": snapshot(lab)}
    check(error["code"] == "receipt_signer_unavailable" and error["outcome"] == "not_recorded"
          and before == after and snapshot(lab) == original, "签名失败留下部分拒绝或推进原尾链")
    missing = lab.attempt("M1")
    lab.case_evidence["rejection_signer_failure"]["get_after_failure"] = missing
    check(missing == {"outcome": "not_found", "logical_message_id": "M1", "attempt_id": "P1"},
          "签名失败仍留下原尝试终态")
    blocked(lab)
    proof = reject(lab, packet)
    persist(lab, proof)
    catch_up(lab, "a1", "a2", "b1")
    packet = successor(lab, proof)
    accepted = accept(lab, packet, "M1", "P2", replaces_attempt_id="P1", closure_id=proof["closure_id"])
    receive(lab, [("M1", "P2", "stale payload", packet, accepted)])
    return {"not_recorded": True}


def accepted_conflict(lab):
    packet = prepare(lab)
    accepted = accept(lab, packet, "M1", "P1")
    before, rows = snapshot(lab), relay_records(lab)
    closed = lab.attempt("M1", operation="close_attempt")
    lab.case_evidence["acceptance_wins"] = {"accepted": accepted, "close_response": closed,
        "relay_before": rows, "relay_after": relay_records(lab),
        "snapshot_sha256_before": before, "snapshot_sha256_after": snapshot(lab)}
    check(closed == accepted == lab.attempt("M1") and relay_records(lab) == rows and snapshot(lab) == before,
          "真实已接受消息被关闭为拒绝或改变原接受事实")
    header = json.loads(base64.b64decode(packet["envelope"]["header_bytes"], validate=True))
    acceptance_claims = json.loads(base64.b64decode(accepted["acceptance_receipt"]["statement_bytes"], validate=True))
    closure_id = "synthetic-contradictory-rejection"
    claims = {"protocol_version": "rim-message-rejection-1", "service_id": lab.service,
        "conversation_id": header["conversation_id"], "sender": identity("a1"),
        "logical_message_id": "M1", "attempt_id": "P1",
        "envelope_sha256": acceptance_claims["envelope_sha256"],
        "replaces_attempt_id": None, "predecessor_closure_id": None, "closure_id": closure_id,
        "outcome": "rejected_final", "code": "state_stale",
        "required_authorization_version": str(int(header["authorization_version"]) + 1),
        "required_crypto_state_ref": "0" * 64}
    # 仅让临时 fixture 服务签名器制造矛盾输入；Relay 未签发或持久保存这个终态。
    bad = _signed(lab, {"closure_id": closure_id}, claims)
    _refuse(lab, bad, "signed_rejection_after_real_accepted",
            construction="synthetic_contradiction_not_a_relay_terminal", expect_pending=False)
    next_packet = prepare(lab, "M2")
    next_accepted = accept(lab, next_packet, "M2", "P1")
    receive_full(lab, [("M1", "P1", "stale payload", packet, accepted),
                       ("M2", "P1", "stale payload", next_packet, next_accepted)])
    return {"synthetic_contradiction_refused": True, "relay_accepted_preserved": True}


CASES = [("STALE-BOUNDARY-proof", proof_boundaries), ("STALE-BOUNDARY-removed-sender", removed_sender),
         ("STALE-BOUNDARY-old-binary", compatibility), ("STALE-BOUNDARY-late-proof", late_proof),
         ("STALE-BOUNDARY-signer-failure", signer_failure), ("STALE-BOUNDARY-accepted-conflict", accepted_conflict)]
