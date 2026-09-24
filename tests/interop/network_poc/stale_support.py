"""过期拒绝取证与真实权限链补齐；终态、密码状态均由原实现持有。"""

import base64
import hashlib
import json

from .closure_support import accept, blocked, prepare as prepare_packet
from .deletion_observer import relay_records
from .fixture import CONVERSATION, SERVICE, check
from .permission_cases import REMOVE_CHARLIE, prepare as prepare_permission, submit
from .permission_recovery_cases import records
from .send_order_support import snapshot


def prepare(lab, logical="M1", attempt="P1", payload="stale payload", **fields):
    return prepare_packet(lab, logical, attempt, payload, **fields)


def advance(lab, ident="R0", action=None):
    change = prepare_permission(lab, ident, action or REMOVE_CHARLIE, device="a2")["change"]
    result = submit(lab, change, device="a2")
    record = {"change": change, "receipt": result["receipt"]}
    lab.case_evidence.setdefault("permission_r0", []).append(record)
    return record


def statement(proof):
    return json.loads(base64.b64decode(proof["rejection_receipt"]["statement_bytes"], validate=True))


def reject(lab, packet, logical="M1", attempt="P1", **submit_fields):
    before = snapshot(lab)
    response = lab.submit(packet, expected=409, **submit_fields)
    proof = lab.attempt(logical, attempt)
    check(set(proof) == {"outcome", "code", "logical_message_id", "attempt_id", "closure_id", "rejection_receipt"}
          and proof["code"] == "state_stale" and proof["outcome"] == "rejected_final"
          and proof["logical_message_id"] == logical and proof["attempt_id"] == attempt,
          "真实旧版本未持久保存完整签名拒绝")
    check({k: response[k] for k in proof} == proof and set(response) == set(proof) | {"message"},
          "第一次409丢失原拒绝证明")
    rows = relay_records(lab)
    repeated = lab.submit(packet, expected=409, **submit_fields)
    check({k: repeated[k] for k in proof} == proof
          and lab.attempt(logical, attempt, operation="close_attempt") == proof
          and relay_records(lab) == rows and snapshot(lab) == before,
          "重试/查询/封口改变原拒绝或客户端状态")
    fact = statement(proof)
    envelope = packet["envelope"]
    raw_header = base64.b64decode(envelope["header_bytes"], validate=True)
    raw_payload = base64.b64decode(envelope["payload_bytes"], validate=True)
    header = json.loads(raw_header)
    digest = hashlib.sha256(b"Rocket-IM/POC/message-envelope/v1\0" + len(raw_header).to_bytes(8, "big") + raw_header
                            + len(raw_payload).to_bytes(8, "big") + raw_payload).hexdigest()
    check(fact["protocol_version"] == "rim-message-rejection-1"
          and fact["code"] == proof["code"] and fact["outcome"] == proof["outcome"]
          and fact["closure_id"] == proof["closure_id"] and fact["envelope_sha256"] == digest
          and int(fact["required_authorization_version"]) > int(header["authorization_version"])
          and all(fact[k] == header[k] for k in ("service_id", "conversation_id", "sender", "logical_message_id", "attempt_id"))
          and fact["replaces_attempt_id"] == submit_fields.get("replaces_attempt_id")
          and fact["predecessor_closure_id"] == submit_fields.get("closure_id"), "拒绝签名字段未精确绑定原请求")
    lab.case_evidence.setdefault("rejections", []).append({"first": response, "repeat": repeated,
        "terminal": proof, "statement": fact, "relay": rows})
    return proof


def persist(lab, proof, logical="M1", attempt="P1", **rustopts):
    result = lab.rust("a1", "wire_reject", logical_message_id=logical, attempt_id=attempt,
                      rejection_receipt=proof["rejection_receipt"], **rustopts)
    lab.case_evidence.setdefault("saved_rejections", []).append(result)
    if result is not None and rustopts.get("expected_exit", 0) == 0:
        check(result["logical_message_id"] == logical and result["attempt_id"] == attempt
              and result["closure_id"] == proof["closure_id"] and result["outcome"] == "rejected_final"
              and result["code"] == "state_stale" and result["status"] == "rejected",
              "端侧保存未返回精确原拒绝终态")
    return result


def catch_up(lab, *devices):
    for device in devices:
        after = lab.rust(device, "wire_inspect")["configuration"]["authorization_version"]
        while True:
            page = records(lab, device=device, after=after, limit="1")
            entry = {"device": device, "after": after, "page": page, "results": []}
            lab.case_evidence.setdefault("permission_r1", []).append(entry)
            for record in page["records"]:
                entry["results"].append(lab.rust(device, "permission_recover", record=record))
            next_after = page["next_after_version"]
            check(not page["records"] or int(next_after) > int(after), "权限页未按已验证记录前进")
            after = next_after
            if not page["has_more"]:
                break
        check(lab.rust(device, "wire_inspect")["configuration"]["authorization_version"] == after,
              "R1未持久提交权限链与实际MLS状态")


def successor(lab, proof, logical="M1", attempt="P2", payload="stale payload"):
    return prepare(lab, logical, attempt, payload,
                   replaces_attempt_id=proof["attempt_id"], closure_id=proof["closure_id"])


def pending(lab, status):
    state = lab.rust("a1", "wire_inspect")
    check(state["send_order"]["pending"]["status"] == status, "发送门状态与实际权限补齐不符")
    lab.case_evidence.setdefault("pending_states", []).append(state)
    return state
