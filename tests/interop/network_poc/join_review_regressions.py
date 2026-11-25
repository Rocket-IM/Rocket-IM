"""审查回归：真实独立锚拒绝，以及无群设备的公开 v2/v3 链与后续入群。"""
import base64
import copy
import time

from .fixture import ACCOUNTS, CONVERSATION, check, identity
from .first_trust_evidence import state
from .first_trust_session import verify_public


def enable_anchor(lab, device):
    lab.helper = lab.binary.with_name("openmls-rollback-anchor")
    check(lab.helper.is_file(), "缺少独立锚程序")
    lab.enable(device)


def reject_ready(lab, device, operation, code=None, **fields):
    before = state(lab)
    anchor = lab.rust(device, "anchor_inspect") if device in lab.configs else None
    error = lab.rust(device, operation, expected_exit=1, **fields)
    check(code is None or error["code"] == code, f"非预期拒绝: {error}")
    check(state(lab) == before, "拒绝改变原快照或 Relay")
    if anchor is not None:
        check(lab.rust(device, "anchor_inspect") == anchor, "拒绝消耗了独立锚")
    lab.case_evidence.setdefault("preflight_rejections", []).append(error)


def wait_package(lab, target="d1"):
    deadline = max(int(p["material"]["not_after"]) for p in lab.pool(target)["packages"].values())
    while int(time.time()) <= deadline:
        time.sleep(.1)


def claim_missing_pin(lab):
    lab.publish(count=1, ttl=12)
    lab.ready()
    lab.claim()
    enable_anchor(lab, "a1")
    reject_ready(lab, "a1", "permission_prepare_claim", "missing_pin", request_id="claim-1")
    lab.rust("a1", "permission_pin_member", member=lab.member("d1"))
    reject_ready(lab, "a1", "permission_prepare_claim", "invalid_permission", request_id="claim-1", validity_secs=0)
    candidate = lab.rust("a1", "permission_prepare_claim", request_id="claim-1")
    wait_package(lab)
    retry = lab.rust("a1", "permission_prepare_claim", request_id="claim-1")
    check(retry["reused"] and retry["change"] == candidate["change"] and retry["join"] == candidate["join"],
          "原候选过期后未精确返回持久原件")
    lab.case_evidence["expired_candidate_retry"] = "same_change_and_join"


def claim_expired(lab):
    lab.publish(count=1, ttl=5)
    lab.ready()
    lab.claim()
    lab.rust("a1", "permission_pin_member", member=lab.member("d1"))
    enable_anchor(lab, "a1")
    wait_package(lab)
    for _ in range(2):
        reject_ready(lab, "a1", "permission_prepare_claim", "invalid_join_material", request_id="claim-1")
        lab.restart()
    lab.continued("after-expired-rejection")


def public_record(record):
    return {"bundle": {key: record["bundle"][key] for key in ("intent", "claim", "allocation", "change")},
            "receipt": record["receipt"]}


def claim_predecessor(lab):
    lab.publish(count=1)
    lab.ready()
    lab.claim()
    lab.rust("a1", "permission_pin_member", member=lab.member("d1"))
    enable_anchor(lab, "a1")
    change = lab.rust("a2", "permission_prepare", change_id="advance-before-claim",
                      action={"kind": "remove_member", "account_id": "charlie"})["change"]
    accepted = lab.http("a2", "submit_permission_change", {
        "service_id": lab.service, "conversation_id": CONVERSATION, "change": change})
    for device in ACCOUNTS:
        lab.rust(device, "permission_recover", record={"change": change, "receipt": accepted["receipt"]})
    reject_ready(lab, "a1", "permission_prepare_claim", "key_package_predecessor", request_id="claim-1")
    lab.continued("after-stale-claim", recipients=("a1", "a2", "b1"))


def public_recovery_chain(lab, anchored=False):
    for device in ACCOUNTS:
        verify_public(lab, "b2", device)
    lab.rust("b2", "permission_device_join_anchor", checkpoint=lab.checkpoint, relay_receipt_key=lab.relay_receipt_key)
    lab.setup_expired()
    verify_public(lab, "b2", "d1")
    lab.rust("b2", "permission_pin_member", member=lab.member("d1"))
    if anchored:
        enable_anchor(lab, "b2")
    _, _, _, bundle = lab.prepare_recovery("public-first", package_ttl=10)
    accepted = lab.accept_recovery(bundle)
    public = public_record(accepted["record"])
    # 根 Add 还未验证：只有 v3 记录不能跳过公开链。
    reject_ready(lab, "b2", "join_recovery", command={"kind": "advance_public", "record": public})
    lab.rust("b2", "permission_join_advance", record=lab.original["record"])
    bad = copy.deepcopy(public)
    signature = bytearray(base64.b64decode(bad["receipt"]["signature_bytes"]))
    signature[0] ^= 1
    bad["receipt"]["signature_bytes"] = base64.b64encode(signature).decode()
    reject_ready(lab, "b2", "join_recovery", command={"kind": "advance_public", "record": bad})
    # 新入口只接受公开原件，不能借附带 Welcome 成为任意目标的恢复/安装通道。
    reject_ready(lab, "b2", "join_recovery", command={"kind": "advance_public", "record": accepted["record"]})
    # 第二后继先到时仍不能跳过第一后继。旧 Welcome 已过期，公共证明仍可验证。
    lab.install_recovery(accepted["record"], tuple(ACCOUNTS))
    lab.recovery("d1", "observe", record=accepted["record"])
    wait_package(lab)
    _, _, _, second_bundle = lab.prepare_recovery("public-second")
    second = lab.accept_recovery(second_bundle)
    second_public = public_record(second["record"])
    gap = lab.recovery("b2", "advance_public", record=second_public)
    check(gap["state"] == "consistency_paused", "缺链原件没有保留观察水位并暂停")
    lab.recovery("b2", "advance_public", record=public)
    lab.restart()
    check(lab.recovery("b2", "advance_public", record=public)["duplicate"], "公开恢复重试未识别原件")
    lab.recovery("b2", "advance_public", record=second_public)
    check(lab.rust("b2", "consistency_inspect")["paused"], "公共补链提前解除 Q02 发送暂停")
    check(lab.recovery("b2", "advance_public", record=public)["duplicate"], "历史原件重试回退了端点")
    reject_ready(lab, "b2", "join_recovery", command={"kind": "advance_public", "record": bad})
    check(lab.rust("b2", "inspect")["group_id"] is None, "公开推进提前安装了 MLS")
    check(lab.recovery("b2", "inspect")["installed_count"] == 0, "公开推进冒充 R1")
    lab.install_recovery(second["record"])
    if lab.old_binary and not anchored:
        before = state(lab)
        current = lab.binary
        try:
            lab.binary = lab.old_binary
            error = lab.rust("b2", "inspect", expected_exit=1)
            check(error["code"] in ("wrong_context", "state_decoding"), "旧程序忽略公开恢复记录")
        finally:
            lab.binary = current
        check(state(lab) == before, "旧程序拒读改写快照")
    # 只能沿正常 AddDevice + Welcome 加入；所有原成员（含恢复目标）参与真实通信。
    lab.publish("b2-package", "b2", count=1)
    lab.ready("b1", "b2")
    lab.claim("b2-claim", "b1", "b2", "b2-add")
    for device in (*ACCOUNTS, "d1"):
        verify_public(lab, device, "b2")
        verify_public(lab, "b2", device)
        if identity(device)["account_id"] != identity("b2")["account_id"]:
            lab.rust(device, "permission_pin_member", member=lab.member("b2"))
    candidate = lab.rust("b1", "permission_prepare_claim", request_id="b2-claim")
    joined = lab.accepted_bundle(candidate, "b1", "b2")
    lab.rust("d1", "permission_recover", record=joined["record"])
    lab.rust("b2", "permission_join", **joined)
    from .recovery_consistency_cases import resume
    resume(lab, "b2")
    check(not lab.rust("b2", "consistency_inspect")["paused"], "真实入群与 head 验证后未解除暂停")
    lab.restart()
    reject_ready(lab, "b2", "wire_receive", "history_unavailable", **lab.old_packet["envelope"],
                 acceptance_id=lab.old_acceptance["acceptance_id"],
                 acceptance_receipt=lab.old_acceptance["acceptance_receipt"])
    lab.continued("public-chain-joined", recipients=(*ACCOUNTS, "d1", "b2"))
    lab.continued("public-chain-reply", sender="b2", recipients=(*ACCOUNTS, "d1", "b2"))
    lab.case_evidence["public_chain"] = "v2_add -> two_v3_recoveries -> own_add_device -> welcome -> bidirectional_messaging"
