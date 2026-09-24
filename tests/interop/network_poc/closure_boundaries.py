"""封口的精确作用域、互斥终态、旧无签名记录与迟到证明边界。"""

import base64
from copy import deepcopy

from .closure_delivery import receive
from .closure_support import (accept, blocked, close, close_request, persist, prepare,
                              snapshot, statement, successor)
from .deletion_observer import relay_records
from .fixture import check, identity


def _signed(lab, proof, claims):
    value = deepcopy(proof)
    value["closure_receipt"] = lab.relay_key("sign", expected_signature_key=lab.relay_receipt_key,
                                            statement=claims)["receipt"]
    return value


def _reject(lab, proof, label, *, code="closure_conflict"):
    before, state, rows = snapshot(lab), lab.rust("a1", "wire_inspect"), relay_records(lab)
    error = persist(lab, proof, expected_exit=1)
    after, current = snapshot(lab), lab.rust("a1", "wire_inspect")
    lab.case_evidence.setdefault("closure_rejections", []).append({"label": label, "error": error,
        "synthetic_receipt": proof["closure_receipt"], "snapshot_sha256_before": before,
        "snapshot_sha256_after": after, "state_before": state, "state_after": current})
    check(error["code"] == code and before == after and state == current and relay_records(lab) == rows,
          "无效封口没有被明确拒绝，或改写原状态")
    return error


def accepted_first(lab):
    packet = prepare(lab)
    request = close_request(lab)
    accepted = lab.submit(packet)
    before, rows = snapshot(lab), relay_records(lab)
    result = close(lab, request)
    lab.case_evidence["acceptance_wins"] = {"accepted": accepted, "close_response": result,
        "snapshot_sha256_before": before, "snapshot_sha256_after": snapshot(lab), "relay": rows}
    check(result == accepted and "closure_receipt" not in result and snapshot(lab) == before
          and relay_records(lab) == rows, "已经接受的尝试被重新封口")
    blocked(lab)
    check(accept(lab, packet, "M1", "P1") == accepted, "原接受重试改变证明")
    # 合成服务声明只用于证明 Rust 的双终态拒绝，不冒充 Relay 真实封口。
    claims = {"protocol_version": "rim-message-closure-1", "service_id": lab.service,
              "conversation_id": request["conversation_id"], "sender": identity("a1"),
              "logical_message_id": "M1", "attempt_id": "P1", "envelope_sha256": request["envelope_sha256"],
              "replaces_attempt_id": None, "predecessor_closure_id": None,
              "closure_id": "synthetic-contradictory-closure", "outcome": "cancelled_before_accept"}
    contradiction = _signed(lab, {}, claims)
    _reject(lab, contradiction, "signed_closure_after_local_acceptance")
    next_packet = prepare(lab, "M2")
    next_accepted = accept(lab, next_packet, "M2", "P1")
    receive(lab, [("M1", "P1", "closure payload", packet, accepted),
                  ("M2", "P1", "closure payload", next_packet, next_accepted)])
    return {"accepted": accepted, "closure_response": result}


def legacy_unsigned(lab):
    prepare(lab)
    request = close_request(lab)
    legacy_request = {key: request[key] for key in ("service_id", "conversation_id", "logical_message_id", "attempt_id")}
    before = snapshot(lab)
    legacy = close(lab, legacy_request)
    rows = relay_records(lab)
    repeated = close(lab, request)
    lab.case_evidence["legacy_unsigned"] = {"request": legacy_request, "legacy_response": legacy,
        "bound_request": request, "bound_retry_response": repeated, "relay": rows,
        "snapshot_sha256_before": before, "snapshot_sha256_after": snapshot(lab)}
    check(legacy["outcome"] == "cancelled_before_accept" and bool(legacy["closure_id"])
          and "closure_receipt" not in legacy and repeated == legacy == lab.attempt("M1")
          and rows == relay_records(lab) and snapshot(lab) == before,
          "旧无签名封口被补签升级或改变原记录")
    blocked(lab)
    blocked(lab, logical="M1", attempt="P2", replaces_attempt_id="P1", closure_id=legacy["closure_id"])
    state = lab.rust("a1", "wire_inspect")
    lab.restart()
    check(close(lab, request) == legacy and lab.attempt("M1") == legacy
          and relay_records(lab) == rows and lab.rust("a1", "wire_inspect") == state,
          "重启改变旧无签名封口边界")
    blocked(lab)
    for device in ("a2", "b1", "c1"):
        page = lab.pull(device)
        check(page["events"] == [] and page["watermark"] == "0", "无签名封口产生投递")
        lab.download(device, page)
        processed = lab.rust(device, "wire_process")
        check(processed["results"] == processed["deliveries"] == [], "空封口流产生成功消息")
    check(rows["counts"]["attempts"] == 1 and rows["counts"]["accepted"] == rows["counts"]["events"] == 0,
          "旧封口事实包含额外接受或投递")
    lab.case_evidence.update(final_relay=relay_records(lab), accepted_messages=0, target_valid_results=0,
                            target_quarantined_results=0, progress="BLOCKED_LEGACY_UNSIGNED_TERMINAL")
    return {"legacy": legacy, "progress": "BLOCKED_LEGACY_UNSIGNED_TERMINAL"}


def signed_boundaries(lab):
    prepare(lab)
    proof = close(lab, close_request(lab))
    original = statement(proof)
    mutations = [
        ("wrong_service", {"service_id": "synthetic-other-service"}),
        ("wrong_conversation", {"conversation_id": "other-conversation"}),
        ("wrong_account", {"sender": {"account_id": "other-account", "device_id": "a1"}}),
        ("wrong_device", {"sender": {"account_id": "alice", "device_id": "other-device"}}),
        ("wrong_logical_message", {"logical_message_id": "other-message"}),
        ("wrong_attempt", {"attempt_id": "other-attempt"}),
        ("wrong_envelope", {"envelope_sha256": "0" * 64}),
        ("wrong_predecessor", {"replaces_attempt_id": "other-predecessor",
                               "predecessor_closure_id": "other-predecessor-closure"}),
    ]
    for label, fields in mutations:
        bad = _signed(lab, proof, {**original, **fields})
        _reject(lab, bad, label)
        blocked(lab)
    tampered = deepcopy(proof)
    signature = bytearray(base64.b64decode(tampered["closure_receipt"]["signature_bytes"], validate=True))
    signature[0] ^= 1
    tampered["closure_receipt"]["signature_bytes"] = base64.b64encode(signature).decode()
    _reject(lab, tampered, "tampered_signature", code="closure_signature")
    blocked(lab)
    check(persist(lab, proof)["duplicate"] is False, "负例污染后合法封口无法首次保存")
    competing = _signed(lab, proof, {**original, "closure_id": "synthetic-conflicting-closure"})
    _reject(lab, competing, "different_signed_terminal_after_saved_closure")
    blocked(lab)
    packet = successor(lab, proof)
    accepted = accept(lab, packet, "M1", "P2", replaces_attempt_id="P1", closure_id=proof["closure_id"])
    receive(lab, [("M1", "P2", "closure payload", packet, accepted)])
    return {"rejected_signed_scope_cases": len(mutations), "rejected_signature_cases": 1,
            "rejected_terminal_conflicts": 1, "closure": proof, "accepted": accepted}


def late_proof(lab):
    prepare(lab)
    proof = close(lab, close_request(lab))
    persist(lab, proof)
    packet = successor(lab, proof)
    before, rows = lab.rust("a1", "wire_inspect"), relay_records(lab)
    original_snapshot = snapshot(lab)
    result = persist(lab, proof)
    after = lab.rust("a1", "wire_inspect")
    lab.case_evidence["late_proof"] = {"result": result, "state_before": before, "state_after": after,
        "snapshot_sha256_before": original_snapshot, "snapshot_sha256_after": snapshot(lab),
        "relay_before": rows, "relay_after": relay_records(lab)}
    check(result["duplicate"] is True and before == after and snapshot(lab) == original_snapshot
          and relay_records(lab) == rows
          and after["send_order"]["pending"] == {"logical_message_id": "M1", "attempt_id": "P2"},
          "迟到P1封口释放P2或将尾链退回P1")
    blocked(lab)
    blocked(lab, logical="M1", attempt="P3", replaces_attempt_id="P1", closure_id=proof["closure_id"])
    retry = successor(lab, proof)
    check(retry == {**packet, "reused": True}, "迟到旧证明改变P2原字节重试")
    accepted = accept(lab, retry, "M1", "P2", replaces_attempt_id="P1", closure_id=proof["closure_id"])
    next_packet = prepare(lab, "M2")
    current = lab.rust("a1", "wire_inspect")
    next_snapshot = snapshot(lab)
    late = persist(lab, proof)
    lab.case_evidence["late_proof"]["after_successor_accepted"] = {"result": late,
        "snapshot_sha256_before": next_snapshot, "snapshot_sha256_after": snapshot(lab),
        "state_before": current, "state_after": lab.rust("a1", "wire_inspect")}
    check(late["duplicate"] is True and lab.rust("a1", "wire_inspect") == current
          and snapshot(lab) == next_snapshot,
          "已经接受P2后的旧封口释放另一逻辑未决槽")
    blocked(lab)
    next_accepted = accept(lab, next_packet, "M2", "P1")
    receive(lab, [("M1", "P2", "closure payload", packet, accepted),
                  ("M2", "P1", "closure payload", next_packet, next_accepted)])
    return {"closure": proof, "accepted": accepted, "next_accepted": next_accepted}


CASES = [("closure_acceptance_wins", accepted_first), ("closure_legacy_unsigned", legacy_unsigned),
         ("closure_signed_boundaries", signed_boundaries), ("closure_late_proof", late_proof)]
