"""E02：成功持久化后继续收发、真实到期，再精确重试原加入/恢复。"""

import base64
import copy
import hashlib
import json
import time

from .fixture import ACCOUNTS, CONVERSATION, check
from .first_trust_evidence import state
from .key_package_fixture import decode


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def changed_byte(value):
    raw = bytearray(base64.b64decode(value))
    check(bool(raw), "异字节对照需要非空原件")
    raw[-1] ^= 1
    return base64.b64encode(raw).decode()


def facts(lab):
    devices = (*ACCOUNTS, lab.target)
    packages = lab.pool(lab.target)["packages"]
    return {
        "durable": state(lab),
        "wire": {d: lab.rust(d, "wire_inspect") for d in devices},
        "permission": {d: lab.rust(d, "permission_inspect") for d in devices},
        "recovery": {d: lab.recovery(d, "inspect") for d in devices},
        "materials": {key: {"consumed": value["consumed"], "material": value["material"]}
                      for key, value in packages.items()},
    }


def unchanged(lab, name, operation, expected=None, code=None):
    before = facts(lab)
    result = operation()
    after = facts(lab)
    lab.case_evidence.setdefault("retry_steps", []).append({
        "name": name, "result": result, "before": before, "after": after,
    })
    check(after == before, name + "改变了后续消息、密码状态、游标或账本")
    if expected is not None:
        check(result == expected, name + "没有返回原件")
    if code is not None:
        check(result["code"] == code, name + "错误原因不符")
    return result


def reused_original_candidate(lab, candidate):
    """普通prepare仍保存并随机重封快照；仅此旁证不要求actor文件摘要不变。"""
    before = facts(lab)
    result = lab.rust(lab.actor, "permission_prepare_claim", request_id="e02-original-claim")
    after = facts(lab)
    lab.case_evidence["original_candidate_retry"] = {
        "result": result, "before": before, "after": after,
        "scope": "reused candidate; ordinary prepare reseals actor snapshot with a fresh nonce",
    }
    check(result == {**candidate, "reused": True}, "迟到prepare没有精确复用原候选与Commit")
    comparable = copy.deepcopy(after)
    comparable["durable"]["snapshots"][lab.actor]["sha256"] = before["durable"]["snapshots"][lab.actor]["sha256"]
    check(comparable == before, "普通候选复用改变了快照长度、其他设备、公开状态或Relay账本")


def communicate(lab, prefix):
    """两方向都实际处理签页，保留恢复目标队首旧密文的隔离结果。"""
    for sender, receiver in ((lab.target, lab.actor), (lab.actor, lab.target)):
        logical = prefix + "-" + sender
        payload = "synthetic-e02-" + logical
        packet = lab.rust(sender, "wire_send", logical_message_id=logical,
                          attempt_id="P1", payload=payload)
        accepted = lab.submit(packet, device=sender)
        lab.rust(sender, "wire_accept", logical_message_id=logical, attempt_id="P1",
                 acceptance_receipt=accepted["acceptance_receipt"])
        before = lab.rust(receiver, "wire_inspect")
        page = lab.pull(receiver, before["sync"]["download_cursor"])
        lab.download(receiver, page)
        processed = lab.rust(receiver, "wire_process")
        matches = [item["result"] for item in processed["results"]
                   if item["result"].get("acceptance_id") == accepted["acceptance_id"]]
        check(len(matches) == 1 and matches[0]["status"] == "valid"
              and not matches[0]["message"]["duplicate"]
              and matches[0]["message"]["payload_sha256"] == hashlib.sha256(payload.encode()).hexdigest(),
              "后续双向消息未在签页中真实解密且仅处理一次")
        after = lab.rust(receiver, "wire_inspect")
        check(after["sync"]["download_cursor"] == after["sync"]["processed_cursor"] == page["next_after_seq"]
              and int(after["sync"]["processed_cursor"]) > int(before["sync"]["processed_cursor"])
              and after["inbox_count"] == before["inbox_count"] + 1, "后续消息没有实际推进游标和收件状态")
        lab.case_evidence.setdefault("communications", []).append({
            "logical": logical, "sender": sender, "receiver": receiver,
            "packet_sha256": digest(packet), "accepted": accepted, "page": page.wrapper,
            "processed": processed, "before": before, "after": after,
        })


def expire_after_progress(lab, package_hash):
    material = lab.pool(lab.target)["packages"][package_hash]["material"]
    deadline = int(material["not_after"])
    progressed = facts(lab)
    before_wait = int(time.time())
    check(before_wait < deadline, "时间链未在材料有效期内完成成功保存和后续收发")
    for device in (lab.actor, lab.target):
        wire = progressed["wire"][device]
        check(wire["outbox_count"] > 0 and wire["inbox_count"] > 0
              and int(wire["sync"]["processed_cursor"]) > 0, "迟到重试基准缺少实际双向消息进度")
    while int(time.time()) <= deadline:
        time.sleep(.1)
    lab.restart()
    check(facts(lab) == progressed, "自然到期或Relay重启回退了已加入状态")
    lab.case_evidence["expiry"] = {
        "clock": "actual UTC Unix seconds; no test clock override",
        "key_package_sha256": package_hash, "not_after": deadline,
        "progress_completed_at": before_wait, "retry_started_at": int(time.time()),
        "progressed_state": progressed,
    }


def assert_ledger(lab, recoveries):
    tables = state(lab)["relay"]["tables"]
    expected = {"recovery_attempts": recoveries, "recovery_edges": recoveries,
                "recovery_active": 0, "recovery_roots": recoveries,
                "permission_changes": 1 + recoveries, "permission_resolutions": 1 + recoveries,
                "kp_materials": 1 + recoveries}
    check(all(tables[name]["rows"] == count for name, count in expected.items()),
          "原加入/恢复之外产生了新分配、终态或Commit")
    lab.case_evidence["expected_ledger_counts"] = expected


def original_join(lab):
    lab.actor, lab.target = "a1", "d1"
    proof, _ = lab.publish("e02-original-material", lab.target, count=1, ttl=20)
    package = decode(proof)["action"]["packages"][0]
    lab.ready(lab.actor, lab.target)
    claim, allocation = lab.claim("e02-original-claim", lab.actor, lab.target, "e02-original-add")
    candidate = lab.prepare_join("e02-original-claim", lab.actor, lab.target)
    bundle = lab.accepted_bundle(candidate, lab.actor, lab.target)
    original_accepted = lab.submit_join(candidate, lab.actor)
    lab.case_evidence["original_accepted"] = original_accepted
    before_install = state(lab)
    lab.rust(lab.target, "permission_join", **bundle, failpoint="after_save", expected_exit=85)
    check(state(lab)["snapshots"][lab.target] != before_install["snapshots"][lab.target],
          "丢输出对照未实际持久安装加入")
    communicate(lab, "original-before-expiry")
    expire_after_progress(lab, hashlib.sha256(base64.b64decode(package)).hexdigest())
    assert_ledger(lab, 0)
    unchanged(lab, "original-allocation", lambda: lab.remote(lab.actor, claim), expected=allocation)
    reused_original_candidate(lab, candidate)
    accepted = unchanged(lab, "original-accepted", lambda: lab.submit_join(candidate, lab.actor), expected=original_accepted)
    check(accepted["receipt"] == bundle["record"]["receipt"], "原接受证明改变")
    unchanged(lab, "original-material-query", lambda: lab.http(lab.target, "get_join_material", {
        "service_id": lab.service, "conversation_id": CONVERSATION, "change_id": "e02-original-add"}), expected=bundle)
    for suffix in ("first", "after-negative"):
        result = unchanged(lab, "original-join-" + suffix, lambda: lab.rust(lab.target, "permission_join", **bundle))
        check(result["duplicate"], "原成功加入未被精确识别")
        if suffix == "first":
            for field in ("welcome", "commit_bytes"):
                bad = copy.deepcopy(bundle)
                container = bad["join"] if field == "welcome" else bad["record"]["change"]
                container[field] = changed_byte(container[field])
                unchanged(lab, "original-tampered-" + field,
                          lambda: lab.rust(lab.target, "permission_join", **bad, expected_exit=1), code="join_conflict")
    assert_ledger(lab, 0)
    communicate(lab, "original-after-retry")
    lab.case_evidence["original_bytes"] = {"candidate_sha256": digest(candidate), "bundle_sha256": digest(bundle)}


def recovered_join(lab):
    lab.setup_expired()
    intent, claim, allocated, bundle = lab.prepare_recovery("e02-recovery", package_ttl=20)
    accepted = lab.accept_recovery(bundle)
    lab.install_recovery(accepted["record"], tuple(ACCOUNTS))
    lab.recovery(lab.target, "observe", record=accepted["record"])
    before_install = state(lab)
    lab.recovery(lab.target, "apply", record=accepted["record"], failpoint="after_save", expected_exit=85)
    check(state(lab)["snapshots"][lab.target] != before_install["snapshots"][lab.target],
          "R1丢输出对照未实际持久安装恢复")
    lab.unchanged_original()
    communicate(lab, "recovered-before-expiry")
    expire_after_progress(lab, decode(intent)["key_package_sha256"])
    assert_ledger(lab, 1)
    result = unchanged(lab, "recovery-allocation", lambda: lab.remote_recovery(lab.actor, "claim", intent=intent, proof=claim))
    check(result == accepted and result["allocation"] == allocated["allocation"]
          and result["key_package"] == allocated["key_package"], "成功后领取未保持原分配及已接受终态")
    prepared = unchanged(lab, "recovery-candidate", lambda: lab.recovery(lab.actor, "prepare", intent=intent,
                         claim=claim, allocation=allocated["allocation"], key_package=allocated["key_package"]))
    check(prepared["duplicate"] and prepared["bundle"] == bundle, "迟到恢复prepare重新构造Commit")
    unchanged(lab, "recovery-accepted", lambda: lab.accept_recovery(bundle), expected=accepted)
    unchanged(lab, "recovery-query", lambda: lab.get_recovery(intent), expected=accepted)
    for device in (*ACCOUNTS, lab.target):
        result = unchanged(lab, "recovery-apply-" + device,
                           lambda: lab.recovery(device, "apply", record=accepted["record"]))
        check(result["duplicate"] and result["installed"]
              and result["checkpoint"] == lab.rust(device, "permission_inspect")["checkpoint"], "重复R1没有保持当前检查点")
    for field, code in (("welcome", "idempotency_conflict"), ("commit_bytes", "receipt_conflict")):
        bad = copy.deepcopy(accepted["record"])
        container = bad["bundle"] if field == "welcome" else bad["bundle"]["change"]
        container[field] = changed_byte(container[field])
        unchanged(lab, "recovery-tampered-" + field,
                  lambda: lab.recovery(lab.target, "apply", record=bad, expected_exit=1), code=code)
    result = unchanged(lab, "recovery-apply-after-negative",
                       lambda: lab.recovery(lab.target, "apply", record=accepted["record"]))
    check(result["duplicate"] and result["installed"], "异字节拒绝损坏了原成功结果")
    assert_ledger(lab, 1)
    communicate(lab, "recovered-after-retry")
    lab.case_evidence["original_bytes"] = {"allocation_sha256": digest(allocated["allocation"]),
        "bundle_sha256": digest(bundle), "commit_sha256": hashlib.sha256(base64.b64decode(bundle["change"]["commit_bytes"])).hexdigest(),
        "accepted_sha256": digest(accepted)}


CASES = {"E02_original_join_expired_retry": original_join,
         "E02_recovery_r1_expired_retry": recovered_join}
