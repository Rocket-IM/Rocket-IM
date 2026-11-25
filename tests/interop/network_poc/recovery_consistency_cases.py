"""恢复记录与 Q02：公开证据不能代替真实补链，也不能清除既有冲突。"""
from .fixture import ACCOUNTS, CONVERSATION, check
import base64
import copy
import hashlib

from .consistency_cases import assert_status, blocked, current_head, observe, sign_head, mutate_bytes
from .join_review_regressions import public_record, enable_anchor, reject_ready
from .join_recovery_fixture import signed_digest
from .key_package_fixture import decode
from .first_trust_session import public_identity


def resume(lab, device):
    return lab.rust(device, "consistency_resume", head=current_head(lab, device))


def signed(lab, statement):
    return lab.relay_key("sign", expected_signature_key=lab.relay_receipt_key,
                         statement=statement)["receipt"]


def accepted_witness(lab, bundle, predecessor):
    """合成 Service 双签见证；候选仍由真实设备生成，可独立执行实际 MLS。"""
    statement = decode(bundle["change"])
    checkpoint = copy.deepcopy(predecessor)
    checkpoint.update(authorization_version=statement["authorization_version"],
                      crypto_state_ref=statement["to_state_ref"])
    digest = hashlib.sha256(b"Rocket-IM/POC/recovery-candidate/v1\0")
    for field in ("statement_bytes", "signature_bytes", "commit_bytes"):
        raw = base64.b64decode(bundle["change"][field])
        digest.update(len(raw).to_bytes(8, "big")); digest.update(raw)
    receipt = decode(bundle["allocation"])
    receipt["result"] = {"kind": "accepted", "allocation_sha256": signed_digest(bundle["allocation"]),
                         "candidate_sha256": digest.hexdigest(), "checkpoint": checkpoint}
    return {"bundle": bundle, "receipt": signed(lab, receipt)}


def permission_change(lab, ident):
    change = lab.rust("a2", "permission_prepare", change_id=ident,
                      action={"kind": "remove_member", "account_id": "charlie"})["change"]
    accepted = lab.http("a2", "submit_permission_change", {
        "service_id": lab.service, "conversation_id": CONVERSATION, "change": change})
    return {"change": change, "receipt": accepted["receipt"]}


def paused_recovery(lab):
    lab.setup_expired()
    enable_anchor(lab, "b1")
    _, _, _, bundle = lab.prepare_recovery("paused-recovery")
    record = lab.accept_recovery(bundle)["record"]
    before = lab.rust("b1", "permission_inspect")["checkpoint"]
    observe(lab, current_head(lab))
    assert_status(lab, "needs_sync")
    blocked(lab)
    lab.recovery("b1", "observe", record=public_record(record))
    check(lab.rust("b1", "permission_inspect")["checkpoint"] == before,
          "公开恢复原件冒充了实际 MLS 检查点")
    lab.rust("b1", "consistency_resume", head=current_head(lab))
    blocked(lab)
    lab.recovery("b1", "apply", record=public_record(record))
    lab.restart()
    blocked(lab)
    lab.rust("b1", "consistency_resume", head=current_head(lab))
    assert_status(lab, "no_known_conflict")
    lab.install_recovery(record)
    lab.continued("recovery-after-sync", sender="b1", recipients=(*ACCOUNTS, lab.target))


def closed_floor(lab):
    lab.setup_expired()
    intent, _, _, _ = lab.prepare_recovery("closed-floor")
    record = permission_change(lab, "ahead-of-recovery-close")
    close = lab.control_proof(intent, "close", lab.target)
    closed = lab.remote_recovery(lab.target, "close", intent=intent, proof=close)
    for device in (lab.actor, lab.target):
        enable_anchor(lab, device)
        lab.recovery(device, "resolve", intent=intent, receipt=closed["receipt"])
        check(lab.recovery(device, "inspect")["pending"] is None, "有效关闭未清除原未决候选")
        assert_status(lab, "needs_sync", device)
        blocked(lab, device)
        resume(lab, device)
        blocked(lab, device)
    for device in ACCOUNTS:
        lab.rust(device, "permission_recover", record=record)
    lab.recovery(lab.target, "advance", record=record)
    lab.restart()
    blocked(lab, lab.actor)
    blocked(lab, lab.target)
    for device in (lab.actor, lab.target):
        resume(lab, device)
        assert_status(lab, "no_known_conflict", device)
    # 未入群目标只补公共链；恢复检查不能替代其 Welcome/R1。
    reject_ready(lab, lab.target, "wire_send", "join_required", logical_message_id="before-r1",
                 attempt_id="P1", payload="must-not-encrypt")
    _, _, _, bundle = lab.prepare_recovery("after-closed-floor")
    accepted = lab.accept_recovery(bundle)["record"]
    members = ("a1", "a2", "b1", lab.target)
    lab.install_recovery(accepted, members)
    for device in (lab.actor, lab.target):
        check(lab.recovery(device, "resolve", intent=intent, receipt=closed["receipt"])["duplicate"],
              "历史关闭原件重试未识别")
        assert_status(lab, "no_known_conflict", device)
    lab.continued("after-closed-floor", recipients=members)


def fork_fixture(lab):
    lab.setup_expired()
    predecessor = lab.rust("a1", "permission_inspect")["checkpoint"]
    intent, _, _, bundle = lab.prepare_recovery("fork-left")
    left = accepted_witness(lab, bundle, predecessor)
    close = lab.control_proof(intent, "close", lab.target)
    closed = lab.remote_recovery(lab.target, "close", intent=intent, proof=close)
    lab.recovery(lab.target, "resolve", intent=intent, receipt=closed["receipt"])
    lab.ready("a2", lab.target)
    lab.fetch_directory("a2", "a2", "fork-actor-directory")
    lab.actor = "a2"
    _, _, _, bundle = lab.prepare_recovery("fork-right")
    right = lab.accept_recovery(bundle)["record"]
    # 分别安装两支真实候选，避免只用任意伪造 state_ref 充当密码分叉。
    for device, record in (("a1", left), ("a2", right)):
        lab.recovery(device, "observe", record=record)
        lab.recovery(device, "apply", record=record)
    check(lab.rust("a1", "permission_inspect")["checkpoint"]["crypto_state_ref"]
          != lab.rust("a2", "permission_inspect")["checkpoint"]["crypto_state_ref"],
          "两支真实 MLS 后继没有分叉")
    return predecessor, left, right


def durable_fork(lab):
    predecessor, left, right = fork_fixture(lab)
    enable_anchor(lab, "b1")
    enable_anchor(lab, "c1")
    lab.recovery("b1", "observe", record=public_record(left))
    lab.recovery("b1", "apply", record=public_record(left))
    bad = copy.deepcopy(public_record(right))
    bad["receipt"]["signature_bytes"] = mutate_bytes(bad["receipt"]["signature_bytes"])
    reject_ready(lab, "b1", "join_recovery", command={"kind": "observe", "record": bad})
    # 第二份有效原件必须提交冲突证据，不能只报错后继续使用第一支。
    lab.recovery("b1", "observe", record=public_record(right),
                 env={"RIM_ANCHOR_FAILPOINT": "after_journal"}, expected_exit=87)
    lab.resume("b1")
    result = lab.recovery("b1", "observe", record=public_record(right))
    check(result["state"] == "consistency_paused", "分叉未返回持久暂停结果")
    lab.rust("c1", "consistency_challenge")
    fields = {"predecessor": predecessor,
              "left": {"recovery": public_record(left), "root": lab.original["record"]},
              "right": {"recovery": public_record(right), "root": lab.original["record"]}}
    invalid = copy.deepcopy(fields)
    invalid["right"]["root"]["receipt"]["signature_bytes"] = mutate_bytes(
        invalid["right"]["root"]["receipt"]["signature_bytes"])
    reject_ready(lab, "c1", "consistency_observe_fork", **invalid)
    lab.rust("c1", "consistency_observe_fork", **fields)
    for _ in range(2):
        lab.restart()
        for device in ("b1", "c1"):
            assert_status(lab, "fork_detected", device)
            reject_ready(lab, device, "identity_trust_observe", "consistency_paused",
                         identity=public_identity(lab, lab.target))
            blocked(lab, device)
            head = sign_head(lab, lab.rust(device, "permission_inspect")["checkpoint"], device)
            lab.rust(device, "consistency_resume", head=head)
            blocked(lab, device)
    lab.recovery("b1", "observe", record=public_record(left))
    lab.recovery("b1", "apply", record=public_record(left))
    blocked(lab)
    check(lab.rust("c1", "consistency_observe_fork", **fields)["duplicate"], "分叉原件未幂等")


def mixed_fork(lab):
    lab.setup_expired()
    predecessor = lab.rust("b1", "permission_inspect")["checkpoint"]
    _, _, _, bundle = lab.prepare_recovery("mixed-fork")
    recovery = accepted_witness(lab, bundle, predecessor)
    ordinary = permission_change(lab, "mixed-permission")
    lab.recovery("b1", "observe", record=public_record(recovery))
    lab.recovery("b1", "apply", record=public_record(recovery))
    lab.rust("b1", "consistency_challenge")
    lab.rust("b1", "consistency_observe_fork", predecessor=predecessor,
             left={"recovery": public_record(recovery), "root": lab.original["record"]}, right=ordinary)
    assert_status(lab, "fork_detected")
    resume(lab, "b1")
    blocked(lab)


def terminal_conflict(lab):
    lab.setup_expired()
    predecessor = lab.rust("a1", "permission_inspect")["checkpoint"]
    intent, _, _, bundle = lab.prepare_recovery("terminal-conflict")
    record = accepted_witness(lab, bundle, predecessor)
    close = lab.control_proof(intent, "close", lab.target)
    closed = lab.remote_recovery(lab.target, "close", intent=intent, proof=close)
    lab.recovery(lab.target, "resolve", intent=intent, receipt=closed["receipt"])
    lab.recovery(lab.target, "observe", record=record)
    lab.recovery(lab.actor, "observe", record=record)
    lab.recovery(lab.actor, "apply", record=record)
    lab.recovery(lab.actor, "resolve", intent=intent, receipt=closed["receipt"])
    for device in (lab.actor, lab.target):
        lab.restart()
        assert_status(lab, "fork_detected", device)
        resume(lab, device)
        blocked(lab, device)


def out_of_order(lab):
    lab.setup_expired()
    first = permission_change(lab, "missing-permission-link")
    for device in ("a1", "a2", "c1"):
        lab.rust(device, "permission_recover", record=first)
    lab.recovery(lab.target, "advance", record=first)
    _, _, _, bundle = lab.prepare_recovery("after-missing-link")
    second = lab.accept_recovery(bundle)["record"]
    enable_anchor(lab, "b1")
    lab.recovery("b1", "observe", record=public_record(second))
    assert_status(lab, "needs_sync")
    resume(lab, "b1")
    blocked(lab)
    lab.rust("b1", "permission_recover", record=first)
    lab.restart()
    blocked(lab)
    lab.recovery("b1", "observe", record=public_record(second))
    resume(lab, "b1")
    blocked(lab)
    lab.recovery("b1", "apply", record=public_record(second))
    lab.restart()
    blocked(lab)
    resume(lab, "b1")
    assert_status(lab, "no_known_conflict")
    members = ("a1", "a2", "b1", lab.target)
    lab.install_recovery(second, members)
    lab.continued("after-gap", sender="b1", recipients=members)


def full_checkpoint_conflict(lab):
    lab.setup_expired()
    intent, _, _, _ = lab.prepare_recovery("full-checkpoint-conflict")
    close = lab.control_proof(intent, "close", lab.target)
    closed = lab.remote_recovery(lab.target, "close", intent=intent, proof=close)
    witness = decode(closed["receipt"])
    checkpoint = witness["result"]["checkpoint"]
    # 版本和 crypto_state_ref 均相同，只有成员完整集合矛盾，也必须识别分叉。
    checkpoint["members"] = [m for m in checkpoint["members"] if m["account_id"] != "charlie"]
    enable_anchor(lab, lab.actor)
    lab.recovery(lab.actor, "resolve", intent=intent, receipt=signed(lab, witness))
    lab.restart()
    assert_status(lab, "fork_detected", lab.actor)
    resume(lab, lab.actor)
    blocked(lab, lab.actor)


def bad_commit_stays_paused(lab):
    from .join_recovery_cases import accepted_bad_commit
    accepted_bad_commit(lab)
    for device in (lab.actor, "b1"):
        resume(lab, device)
        assert_status(lab, "needs_sync", device)
        blocked(lab, device)


CASES = {"C01_recovery_while_consistency_paused": paused_recovery,
         "C02_closed_recovery_watermark": closed_floor,
         "C03_durable_recovery_fork": durable_fork,
         "C04_mixed_permission_recovery_fork": mixed_fork,
         "C05_recovery_terminal_conflict": terminal_conflict,
         "C06_out_of_order_recovery_chain": out_of_order,
         "C07_full_recovery_checkpoint_conflict": full_checkpoint_conflict,
         "C08_recovery_r1_failure_stays_paused": bad_commit_stays_paused}
