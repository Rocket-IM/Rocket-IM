"""精确签名封口与原尝试后继的联合观察；所有业务状态由原 Rust/Relay 保存。"""

import base64
import hashlib
import json

from .fixture import check
from .send_order_support import snapshot


def prepare(lab, logical="M1", attempt="P1", payload="closure payload", **fields):
    packet = lab.rust("a1", "wire_send", logical_message_id=logical, attempt_id=attempt,
                      payload=payload, **fields)
    lab.case_evidence.setdefault("created", []).append({"logical_message_id": logical,
        "attempt_id": attempt, "packet": packet, "payload_sha256": hashlib.sha256(payload.encode()).hexdigest()})
    return packet


def close_request(lab, logical="M1", attempt="P1"):
    before = snapshot(lab)
    request = lab.rust("a1", "wire_close_request", logical_message_id=logical, attempt_id=attempt)
    check(snapshot(lab) == before, "导出封口请求改变原持久快照")
    lab.case_evidence.setdefault("close_requests", []).append(request)
    return request


def close(lab, request, **httpopts):
    proof = lab.http("a1", "close_attempt", request, **httpopts)
    lab.case_evidence.setdefault("close_responses", []).append(proof)
    return proof


def persist(lab, proof, logical="M1", attempt="P1", **rustopts):
    result = lab.rust("a1", "wire_close", logical_message_id=logical, attempt_id=attempt,
                      closure_receipt=proof["closure_receipt"], **rustopts)
    lab.case_evidence.setdefault("saved_closures", []).append(result)
    return result


def blocked(lab, logical="other", attempt="P1", payload="closure payload",
            code="send_order_pending", **fields):
    before = snapshot(lab)
    state = lab.rust("a1", "wire_inspect")
    error = lab.rust("a1", "wire_send", expected_exit=1, logical_message_id=logical,
                     attempt_id=attempt, payload=payload, **fields)
    after = snapshot(lab)
    item = {"logical_message_id": logical, "attempt_id": attempt, "error": error,
            "snapshot_sha256_before": before, "snapshot_sha256_after": after,
            "state_before": state, "state_after": lab.rust("a1", "wire_inspect")}
    lab.case_evidence.setdefault("blocked", []).append(item)
    check(error["code"] == code and before == after and state == item["state_after"],
          "错误尝试未保持门禁或改变原快照")
    return error


def successor(lab, proof, logical="M1", attempt="P2", payload="closure payload"):
    return prepare(lab, logical, attempt, payload,
                   replaces_attempt_id=proof["attempt_id"], closure_id=proof["closure_id"])


def accept(lab, packet, logical, attempt, **submit_fields):
    state_before = lab.rust("a1", "wire_inspect")
    accepted = lab.submit(packet, **submit_fields)
    evidence = {"logical_message_id": logical, "attempt_id": attempt, "accepted": accepted,
                "state_before": state_before}
    lab.case_evidence.setdefault("acceptance_recovery", []).append(evidence)
    queried = lab.attempt(logical, attempt)
    evidence["queried"] = queried
    check(accepted["outcome"] == "accepted" and queried == accepted,
          "后继提交与查询没有保留原接受事实")
    result = lab.rust("a1", "wire_accept", logical_message_id=logical, attempt_id=attempt,
                      acceptance_receipt=accepted["acceptance_receipt"])
    evidence["saved_result"] = result
    check(result == {"logical_message_id": logical, "attempt_id": attempt,
                     "acceptance_id": accepted["acceptance_id"], "status": "accepted", "duplicate": False},
          "后继接受证明未精确绑定原尝试")
    current = lab.rust("a1", "wire_inspect")
    evidence["state_after"] = current
    check(current["send_order"]["pending"] is None
          and current["accepted_outbox_count"] == state_before["accepted_outbox_count"] + 1
          and current["outbox_count"] == state_before["outbox_count"], "后继接受未持久保存或未释放门禁")
    lab.case_evidence.setdefault("accepted", []).append(accepted)
    return accepted


def statement(proof):
    return json.loads(base64.b64decode(proof["closure_receipt"]["statement_bytes"], validate=True))
