"""审查回归：候选私有材料、补链身份核验和 Apply 的预约前拒绝。"""
import base64
import copy
import time

from .fixture import ACCOUNTS, CONVERSATION, check, identity
from .first_trust_session import verify_public
from .join_review_regressions import enable_anchor, public_record, reject_ready
from .consistency_cases import assert_status, blocked, current_head


def pending_materials(lab):
    old = lab.generate("before-pending", "a1", count=1)["proof"]
    material = next(iter(lab.pool("a1")["packages"].values()))["material"]
    change = lab.rust("a1", "permission_prepare", change_id="pending-package-change",
                      action={"kind": "remove_member", "account_id": "charlie"})["change"]
    enable_anchor(lab, "a1")
    fields = {"count": 1, "not_before": material["not_before"], "not_after": material["not_after"],
              "source_key": lab.relay_receipt_key}
    reject_ready(lab, "a1", "key_package_generate", "permission_pending", request_id="during-pending", **fields)
    retry = lab.rust("a1", "key_package_generate", request_id="before-pending", **fields)
    check(retry["duplicate"] and retry["proof"] == old, "未决期间丢失原生成请求的精确重试")
    accepted = lab.http("a1", "submit_permission_change", {
        "service_id": lab.service, "conversation_id": CONVERSATION, "change": change})
    for device in ACCOUNTS:
        lab.rust(device, "permission_recover", record={"change": change, "receipt": accepted["receipt"]})
    lab.restart()
    lab.rust("a1", "inspect")  # 重载校验每份未消费材料的真实私有 bundle。
    lab.publish("after-pending", "a1", count=1)
    check(len(lab.pool("a1")["packages"]) == 2, "候选安装丢失旧材料或阻止后续生成")
    lab.continued("after-material-guard", recipients=("a1", "a2", "b1"))


def identity_gap(lab):
    lab.setup_expired()
    lab.publish("new-device-package", "b2", count=1)
    lab.ready("b1", "b2")
    lab.claim("new-device-claim", "b1", "b2", "new-device-add")
    candidate = lab.rust("b1", "permission_prepare_claim", request_id="new-device-claim")
    accepted = lab.submit_join(candidate, "b1")
    first = {"change": candidate["change"], "receipt": accepted["receipt"]}
    for device in ("a1", "b1", "c1"):
        lab.rust(device, "permission_recover", record=first)
    lab.recovery(lab.target, "advance", record=first)
    for device in ("a1", "c1", lab.target):
        verify_public(lab, device, "b2")
    _, _, _, bundle = lab.prepare_recovery("gap-with-new-device")
    second = lab.accept_recovery(bundle)["record"]
    enable_anchor(lab, "a2")
    lab.recovery("a2", "observe", record=public_record(second))
    assert_status(lab, "needs_sync", "a2")
    # 缺链期间先独立核验，既不补造检查点，也不解除暂停。
    verify_public(lab, "a2", "b2")
    assert_status(lab, "needs_sync", "a2")
    reject_ready(lab, "a2", "identity_trust_prepare", "consistency_paused",
                 target=identity("b2"), purpose="reset")
    blocked(lab, "a2")
    lab.rust("a2", "permission_recover", record=first)
    lab.recovery("a2", "observe", record=public_record(second))
    # 已保存 R0 但未 R1 的恢复门禁也不能阻断精确身份核验。
    verify_public(lab, "a2", "b2")
    assert_status(lab, "needs_sync", "a2")
    blocked(lab, "a2")
    lab.recovery("a2", "apply", record=public_record(second))
    lab.restart()
    blocked(lab, "a2")
    lab.rust("a2", "consistency_resume", head=current_head(lab, "a2"))
    assert_status(lab, "no_known_conflict", "a2")
    lab.install_recovery(second)
    lab.continued("after-identity-gap", sender="a2", recipients=(*ACCOUNTS, lab.target))


def apply_materials(lab):
    lab.setup_expired()
    _, _, _, bundle = lab.prepare_recovery("missing-material")
    record = lab.accept_recovery(bundle)["record"]
    enable_anchor(lab, lab.target)
    reject_ready(lab, lab.target, "join_recovery", "recovery_observe_required",
                 command={"kind": "apply", "record": record})
    lab.recovery(lab.target, "observe", record=public_record(record))
    reject_ready(lab, lab.target, "join_recovery", "recovery_material_required",
                 command={"kind": "apply", "record": public_record(record)})
    bad = copy.deepcopy(record)
    raw = bytearray(base64.b64decode(bad["bundle"]["welcome"])); raw[-1] ^= 1
    bad["bundle"]["welcome"] = base64.b64encode(raw).decode()
    reject_ready(lab, lab.target, "join_recovery", "recovery_invalid",
                 command={"kind": "apply", "record": bad})
    lab.restart()
    lab.install_recovery(record)
    check(lab.recovery(lab.target, "apply", record=public_record(record))["duplicate"],
          "已安装原件重试不应重新索取 Welcome")
    lab.continued("after-material-arrived", recipients=(*ACCOUNTS, lab.target))


def apply_unverified_identity(lab):
    # 保留合法实际群前驱，但没有为新设备核验身份；拒绝不得消耗独立锚。
    lab.setup_expired()
    lab.publish("new-device-package", "b2", count=1)
    lab.ready("b1", "b2")
    lab.claim("new-device-claim", "b1", "b2", "new-device-add")
    candidate = lab.rust("b1", "permission_prepare_claim", request_id="new-device-claim")
    accepted = lab.submit_join(candidate, "b1")
    first = {"change": candidate["change"], "receipt": accepted["receipt"]}
    for device in ACCOUNTS:
        lab.rust(device, "permission_recover", record=first)
    lab.recovery(lab.target, "advance", record=first)
    for device in ("a1", "c1", lab.target):
        verify_public(lab, device, "b2")
    _, _, _, bundle = lab.prepare_recovery("unverified-recovery")
    record = lab.accept_recovery(bundle)["record"]
    enable_anchor(lab, "a2")
    lab.recovery("a2", "observe", record=public_record(record))
    reject_ready(lab, "a2", "join_recovery", "identity_unverified",
                 command={"kind": "apply", "record": public_record(record)})
    verify_public(lab, "a2", "b2")
    lab.install_recovery(record)
    lab.continued("after-r1-identity", sender="a2", recipients=(*ACCOUNTS, lab.target))


def apply_expired_material(lab):
    lab.setup_expired()
    _, _, _, bundle = lab.prepare_recovery("short-recovery", package_ttl=5)
    record = lab.accept_recovery(bundle)["record"]
    lab.install_recovery(record, ACCOUNTS)
    lab.recovery(lab.target, "observe", record=record)
    enable_anchor(lab, lab.target)
    deadline = max(int(p["material"]["not_after"]) for p in lab.pool(lab.target)["packages"].values())
    while int(time.time()) <= deadline:
        time.sleep(.1)
    reject_ready(lab, lab.target, "join_recovery", "key_package_expired",
                 command={"kind": "apply", "record": record})
    lab.restart()
    _, _, _, next_bundle = lab.prepare_recovery("after-expired-apply")
    next_record = lab.accept_recovery(next_bundle)["record"]
    lab.install_recovery(next_record)
    # 旧 R0 已有更晚端点，确定性拒绝也不能消耗锚。
    reject_ready(lab, lab.target, "join_recovery", "recovery_superseded",
                 command={"kind": "apply", "record": record})
    lab.continued("after-expired-apply", recipients=(*ACCOUNTS, lab.target))


CASES = {"R06_pending_key_package_generation": pending_materials,
         "R07_recovery_identity_gap": identity_gap,
         "R08_recovery_apply_material_preflight": apply_materials,
         "R09_recovery_apply_identity_preflight": apply_unverified_identity,
         "R10_recovery_apply_expiry_preflight": apply_expired_material}
