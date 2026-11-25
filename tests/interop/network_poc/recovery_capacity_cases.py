"""真实恢复原件 + 合成近满快照；容量夹具不代表自然累积或生产容量。"""
import copy
import json
import subprocess

from .fixture import ACCOUNTS, check, identity
from .consistency_cases import assert_status, blocked, mutate_bytes, sign_head
from .first_trust_evidence import state
from .first_trust_session import verify_public
from .join_review_regressions import enable_anchor, public_record, reject_ready
from .recovery_consistency_cases import fork_fixture


def fixture(lab, device, mode):
    helper = lab.probe_binary.with_name("openmls-recovery-capacity-fixture")
    result = subprocess.run([str(helper)], input=json.dumps({
        "directory": str(lab.directory / device),
        "context": {"service": lab.service, "account": identity(device)["account_id"], "device": device},
        "mode": mode}), text=True, capture_output=True, timeout=60)
    check(result.returncode == 0, "容量夹具失败: " + result.stdout[:300])
    return json.loads(result.stdout)


def seed(lab, device, mode):
    lab.case_evidence["synthetic_capacity"] = fixture(lab, device, mode)
    # 正常发布程序必须能验证并重新加载此快照。
    return lab.rust(device, "consistency_inspect")


def assert_capacity(lab, device, before, digest):
    result = assert_status(lab, "evidence_capacity_exhausted", device)
    check(result["paused"] and result["reason"] == "recovery_evidence_capacity", "未持久暂停")
    check(result["recovery_evidence_count"] == before["recovery_evidence_count"], "容量失败淘汰了既有证据")
    check(result["highest_observed_checkpoint"] == before["highest_observed_checkpoint"], "未保存原件却抬高水位")
    check(fixture(lab, device, "inspect") == digest, "容量失败改变了证据、候选、MLS 或消息账本")
    blocked(lab, device)
    lab.case_evidence["after_capacity"] = result


def prepare_full(lab, mode, anchored):
    _, left, right = fork_fixture(lab)
    lab.recovery("b1", "observe", record=public_record(left))
    lab.recovery("b1", "apply", record=public_record(left))
    before = seed(lab, "b1", mode)
    check(not before["paused"], "夹具在新证据到达前已暂停")
    if anchored:
        enable_anchor(lab, "b1")
    return left, right, before, fixture(lab, "b1", "inspect")


def conflict_capacity(lab, mode="count", anchored=False):
    left, right, before, digest = prepare_full(lab, mode, anchored)
    bad = copy.deepcopy(public_record(right))
    bad["receipt"]["signature_bytes"] = mutate_bytes(bad["receipt"]["signature_bytes"])
    reject_ready(lab, "b1", "join_recovery", command={"kind": "observe", "record": bad})
    check(lab.recovery("b1", "observe", record=public_record(left))["duplicate"], "满额原件不能精确重试")
    check(not lab.rust("b1", "consistency_inspect")["paused"], "坏签名或精确重试误触容量暂停")
    result = lab.recovery("b1", "observe", record=public_record(right))
    check(result["state"] == "consistency_paused", "没有交付已保存的暂停结果")
    lab.case_evidence["capacity_reply"] = result
    assert_capacity(lab, "b1", before, digest)
    for _ in range(2):
        lab.restart()
        # 当前分支的有效 head 也不能证明被拒收的另一份事实已解决。
        head = sign_head(lab, lab.rust("b1", "permission_inspect")["checkpoint"])
        lab.rust("b1", "consistency_resume", head=head)
        lab.recovery("b1", "observe", record=public_record(left))
        lab.recovery("b1", "apply", record=public_record(left))
        lab.recovery("b1", "observe", record=public_record(right))
        assert_capacity(lab, "b1", before, digest)
    if lab.old_binary and not anchored:
        previous = state(lab)
        current = lab.binary
        try:
            lab.binary = lab.old_binary
            error = lab.rust("b1", "inspect", expected_exit=1)
            check(error["code"] in ("state_decoding", "wrong_context"), "旧程序忽略新暂停状态")
        finally:
            lab.binary = current
        check(state(lab) == previous, "旧程序拒读改写了快照")
        lab.case_evidence["old_reader"] = "rejected_without_mutation"


def save_failure(lab):
    _, right, before, digest = prepare_full(lab, "count", False)
    original = state(lab)
    for point, code in (("before_save", 83), ("before_rename", 84)):
        lab.recovery("b1", "observe", record=public_record(right), failpoint=point, expected_exit=code)
        check(state(lab) == original, "保存前中断破坏原快照或 Relay")
        lab.restart()
        check(not lab.rust("b1", "consistency_inspect")["paused"], "保存失败虚报暂停已经持久化")
    lab.recovery("b1", "observe", record=public_record(right))
    assert_capacity(lab, "b1", before, digest)


def anchor_failure(lab, point, code):
    _, right, before, digest = prepare_full(lab, "count", True)
    lab.recovery("b1", "observe", record=public_record(right),
                 env={"RIM_ANCHOR_FAILPOINT": point}, expected_exit=code)
    lab.restart()
    if point == "after_reserve":
        for _ in range(2):
            error = lab.rust("b1", "wire_send", logical_message_id="uncertain-capacity",
                             attempt_id="P1", payload="must-not-encrypt", expected_exit=1)
            check(error["code"] == "anchor_paused", "无日志预约未阻断新密文")
            error = lab.resume("b1", expected_exit=1)
            check(error["code"] == "anchor_unresolved", "无日志预约被原地恢复")
            error = lab.recovery("b1", "observe", record=public_record(right), expected_exit=1)
            check(error["code"] == "anchor_paused", "无完整日志却重做原请求")
            check(fixture(lab, "b1", "inspect") == digest, "未决预约改变了原快照")
            lab.restart()
        lab.case_evidence["unresolved_anchor"] = lab.rust("b1", "anchor_inspect")
        return
    else:
        lab.resume("b1")
    assert_capacity(lab, "b1", before, digest)
    lab.recovery("b1", "observe", record=public_record(right))
    assert_capacity(lab, "b1", before, digest)


def closed_pending(lab):
    lab.setup_expired()
    intent, _, _, _ = lab.prepare_recovery("capacity-first-close")
    close = lab.control_proof(intent, "close", lab.target)
    closed = lab.remote_recovery(lab.target, "close", intent=intent, proof=close)
    for device in (lab.actor, lab.target):
        lab.recovery(device, "resolve", intent=intent, receipt=closed["receipt"])
    intent, _, _, _ = lab.prepare_recovery("capacity-pending-close")
    before = seed(lab, lab.actor, "count")
    check(lab.recovery(lab.actor, "inspect")["pending"] is not None, "夹具缺少原未决候选")
    digest = fixture(lab, lab.actor, "inspect")
    enable_anchor(lab, lab.actor)
    close = lab.control_proof(intent, "close", lab.target)
    closed = lab.remote_recovery(lab.target, "close", intent=intent, proof=close)
    for _ in range(2):
        lab.recovery(lab.actor, "resolve", intent=intent, receipt=closed["receipt"])
        lab.restart()
        assert_capacity(lab, lab.actor, before, digest)


def public_capacity(lab):
    for device in ACCOUNTS:
        verify_public(lab, "b2", device)
    lab.rust("b2", "permission_device_join_anchor", checkpoint=lab.checkpoint,
             relay_receipt_key=lab.relay_receipt_key)
    _, left, right = fork_fixture(lab)
    verify_public(lab, "b2", "d1")
    lab.rust("b2", "permission_pin_member", member=lab.member("d1"))
    lab.rust("b2", "permission_join_advance", record=lab.original["record"])
    lab.recovery("b2", "advance_public", record=public_record(left))
    before = seed(lab, "b2", "count")
    digest = fixture(lab, "b2", "inspect")
    enable_anchor(lab, "b2")
    lab.recovery("b2", "advance_public", record=public_record(right))
    lab.restart()
    assert_capacity(lab, "b2", before, digest)
    check(lab.rust("b2", "inspect")["group_id"] is None, "满额公共推进安装了 MLS")


def material_capacity(lab):
    lab.setup_expired()
    _, _, _, bundle = lab.prepare_recovery("capacity-material")
    record = lab.accept_recovery(bundle)["record"]
    lab.recovery(lab.target, "observe", record=public_record(record))
    before = seed(lab, lab.target, "bytes")
    digest = fixture(lab, lab.target, "inspect")
    enable_anchor(lab, lab.target)
    bad = copy.deepcopy(record)
    bad["bundle"]["welcome"] = mutate_bytes(bad["bundle"]["welcome"])
    reject_ready(lab, lab.target, "join_recovery", command={"kind": "observe", "record": bad})
    lab.recovery(lab.target, "observe", record=record)
    lab.restart()
    assert_capacity(lab, lab.target, before, digest)
    reject_ready(lab, lab.target, "join_recovery", "recovery_material_required",
                 command={"kind": "apply", "record": public_record(record)})


CASES = {
    "V01_count_conflict": conflict_capacity,
    "V02_bytes_conflict": lambda lab: conflict_capacity(lab, "bytes"),
    "V03_count_conflict_anchor": lambda lab: conflict_capacity(lab, "count", True),
    "V04_bytes_conflict_anchor": lambda lab: conflict_capacity(lab, "bytes", True),
    "V05_capacity_save_failure": save_failure,
    "V06_capacity_reserve_failure": lambda lab: anchor_failure(lab, "after_reserve", 86),
    "V07_capacity_journal_failure": lambda lab: anchor_failure(lab, "after_journal", 87),
    "V08_capacity_finish_failure": lambda lab: anchor_failure(lab, "after_finish", 88),
    "V09_capacity_closed_pending": closed_pending,
    "V10_capacity_public_chain": public_capacity,
    "V11_capacity_material_bytes": material_capacity,
}
