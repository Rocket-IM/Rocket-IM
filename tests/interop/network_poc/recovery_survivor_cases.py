"""E10.a：目标新材料有效时，另一幸存叶期限的真实 Welcome Apply 对照。"""

import re
import time

from .fixture import ACCOUNTS, check
from .first_trust_evidence import state
from .first_trust_session import verify_public
from .key_package_fixture import decode
from .recovery_competition_cases import recovery_ledger
from .recovery_offline_cases import pair, send, wait_until
from .recovery_watermark_cases import blocked, checkpoint, original_facts, resume, unchanged
from .recovery_welcome_cases import not_installed, target_view


SURVIVOR = "b2"


def healthy_views(lab):
    return {d: {"group": lab.rust(d, "inspect"),
                "permission": lab.rust(d, "permission_inspect"),
                "wire": lab.rust(d, "wire_inspect")}
            for d in (*ACCOUNTS, SURVIVOR)}


def material(lab, device, proof):
    package = decode(proof)["action"]["packages"][0]
    matches = [p for p in lab.pool(device)["packages"].values() if p["encoded"] == package]
    check(len(matches) == 1, "真实发布材料未准确保存在本机")
    return matches[0]["material"]


def setup(lab, *, original_ttl=10, survivor_ttl=45):
    lab.target, lab.actor = "d1", "a1"
    # 先真实加入短期幸存叶；不能等原目标到期后才建另一个 Welcome。
    proof, _ = lab.publish("e10-survivor-package", SURVIVOR, count=1, ttl=survivor_ttl)
    survivor_material = material(lab, SURVIVOR, proof)
    lab.ready("b1", SURVIVOR)
    lab.claim("e10-survivor-claim", "b1", SURVIVOR, "e10-survivor-add")
    candidate = lab.prepare_join("e10-survivor-claim", "b1", SURVIVOR)
    admission = lab.accepted_bundle(candidate, "b1", SURVIVOR)
    joined = lab.rust(SURVIVOR, "permission_join", **admission)
    lab.checkpoint = checkpoint(lab, lab.actor)
    check(checkpoint(lab, SURVIVOR) == lab.checkpoint, "幸存者未真实普通加入")
    lab.case_evidence["survivor_admission"] = {"device": SURVIVOR, "proof": proof,
        "material": survivor_material, "bundle": admission, "joined": joined,
        "view": lab.rust(SURVIVOR, "inspect")}

    proof, _ = lab.publish("original-package", lab.target, count=1, ttl=original_ttl)
    old_material = material(lab, lab.target, proof)
    lab.ready(); lab.claim("original-claim", change_id="original-add")
    candidate = lab.prepare_join("original-claim")
    for observer, peer in ((SURVIVOR, lab.target), (lab.target, SURVIVOR)):
        verify_public(lab, observer, peer)
        lab.rust(observer, "permission_pin_member", member=lab.member(peer))
    lab.original = lab.accepted_bundle(candidate)
    lab.rust(SURVIVOR, "permission_recover", record=lab.original["record"])
    for device in (*ACCOUNTS, SURVIVOR, lab.target):
        lab.root = lab.recovery(device, "root", **lab.original)["reference"]
    for device in (lab.actor, lab.target):
        for peer in (lab.actor, lab.target):
            lab.fetch_directory(device, peer, "e10-directory-" + peer)
    lab.scope = {"service_id": lab.service, "conversation_id": lab.checkpoint["conversation_id"],
                 "group_id": lab.rust(lab.actor, "inspect")["group_id"]}
    lab.old_packet, lab.old_acceptance = send(lab, "before-recovery",
        receivers=("a2", "b1", "c1", SURVIVOR))
    original = original_facts(lab)
    wait_until(int(old_material["not_after"]))
    intent, claim, allocation, bundle = lab.prepare_recovery("e10-recovery", package_ttl=180)
    accepted = lab.accept_recovery(bundle)
    check(accepted["state"] == "accepted", "缺少真实Service R0")
    lab.install_recovery(accepted["record"], (*ACCOUNTS, SURVIVOR))
    latest = checkpoint(lab, lab.actor)
    observed = lab.recovery(lab.target, "observe", record=accepted["record"])
    check(observed == {"duplicate": False, "installed": False}, "Observe冒充了目标R1")
    target = not_installed(lab, latest)
    new_material = target["packages"][decode(intent)["key_package_sha256"]]["material"]
    now = time.time()
    check(int(old_material["not_after"]) < now < int(survivor_material["not_after"])
          < int(new_material["not_after"]), "三种材料未建立真实独立期限")
    views = healthy_views(lab)
    check(all(v["permission"]["checkpoint"] == latest and v["group"]["active"]
              for v in views.values()), "未保留全体幸存者的真实有效群")
    check(lab.member(SURVIVOR) in latest["members"], "有限期幸存叶未留在最新树中")
    ledger = recovery_ledger(lab)
    check(len(ledger["recovery_attempts"]) == len(ledger["recovery_edges"])
          == len(ledger["recovery_roots"]) == 1 and not ledger["recovery_active"],
          "出现原目标以外的恢复")
    lab.case_evidence["prepared"] = {"intent": intent, "claim": claim, "allocation": allocation,
        "accepted": accepted, "original_material": old_material, "new_material": new_material,
        "survivor_material": survivor_material, "ready_at_unix_secs": now,
        "latest": latest, "target_r0": target, "healthy": views, "ledger": ledger,
        "original_facts": original}
    return intent, accepted, latest, ledger, original


def blocked_before_r1(lab, latest, phase):
    view = not_installed(lab, latest)
    blocked(lab, lab.target, phase + "-send", "join_required")
    # 公共链可核验完整；resume不能把它当成真实MLS安装或解除入群发送门禁。
    before = state(lab)
    healthy = healthy_views(lab)
    resume(lab, lab.target)
    after = state(lab)
    check(target_view(lab) == view and healthy_views(lab) == healthy
          and after["relay"] == before["relay"]
          and all(after["snapshots"][d] == s for d, s in before["snapshots"].items()
                  if d != lab.target), "提前resume改变MLS、R0、材料或健康群")
    lab.case_evidence.setdefault("early_resumes", []).append({"phase": phase,
        "before": before, "after": after, "target": view,
        "consistency": lab.rust(lab.target, "consistency_inspect"),
        "send_gate": "join_required"})
    blocked(lab, lab.target, phase + "-resume-send", "join_required")


def apply_expired(lab, record, phase):
    materials = lab.case_evidence["prepared"]
    deadline = int(materials["survivor_material"]["not_after"])
    target_deadline = int(materials["new_material"]["not_after"])
    started = time.time()
    check(deadline < started < target_deadline, "负例期限不属于另一幸存叶")
    error = unchanged(lab, phase, lambda: lab.recovery(lab.target, "apply",
        record=record, expected_exit=1), "welcome_validation")
    finished = time.time()
    entry = {"phase": phase, "started_at_unix_secs": started,
        "finished_at_unix_secs": finished, "survivor_not_after": deadline,
        "target_not_after": target_deadline, "error": error}
    lab.case_evidence.setdefault("lifetime_failures", []).append(entry)
    matched = re.search(r"Lifetime is in the past: not_after=(\d+), now=(\d+)", error["message"])
    check(matched is not None and int(matched[1]) == deadline
          and int(matched[2]) >= deadline and finished < target_deadline,
          "未到达真实幸存叶Lifetime，或目标材料也已过期")


def survivor_lifetime(lab, expired):
    intent, accepted, latest, ledger, original = setup(lab)
    record = accepted["record"]
    blocked_before_r1(lab, latest, "before-apply")
    if expired:
        unchanged(lab, "wait-survivor-expiry", lambda: wait_until(
            int(lab.case_evidence["prepared"]["survivor_material"]["not_after"])))
        for phase in ("expired-first-apply", "expired-after-restart"):
            apply_expired(lab, record, phase)
            check(unchanged(lab, phase + "-observe", lambda: lab.recovery(
                lab.target, "observe", record=record)) == {"duplicate": True, "installed": False},
                "失败丢失R0或误报R1")
            check(unchanged(lab, phase + "-query", lambda: lab.get_recovery(intent)) == accepted,
                  "失败撤回或改写已接受原件")
            blocked_before_r1(lab, latest, phase)
            unchanged(lab, phase + "-restart", lab.restart)
        pair(lab, SURVIVOR, "expired-survivor-still-communicates")
        blocked_before_r1(lab, latest, "after-healthy-communication")
        final_target = not_installed(lab, latest)
    else:
        started = time.time()
        before = state(lab)
        installed = lab.recovery(lab.target, "apply", record=record)
        finished = time.time()
        after = state(lab)
        final_target = target_view(lab)
        check(started < finished < int(lab.case_evidence["prepared"]["survivor_material"]["not_after"])
              and installed["installed"] and not installed["duplicate"]
              and installed["checkpoint"] == latest == final_target["permission"]["checkpoint"]
              and final_target["recovery"]["installed_count"] == 1
              and final_target["group"]["active"]
              and final_target["packages"][decode(intent)["key_package_sha256"]]["consumed"]
              and after["relay"] == before["relay"]
              and after["snapshots"][lab.target] != before["snapshots"][lab.target]
              and all(after["snapshots"][d] == s for d, s in before["snapshots"].items()
                      if d != lab.target), "合法对照未在期限前真实安装唯一R1")
        lab.case_evidence["successful_apply"] = {"started_at_unix_secs": started,
            "finished_at_unix_secs": finished, "result": installed,
            "before": before, "after": after, "target": final_target}
        resume(lab, lab.target)
        pair(lab, lab.target, "timely-target")
        unchanged(lab, "restart-after-timely-r1", lab.restart)
        duplicate = unchanged(lab, "timely-apply-exact-retry", lambda: lab.recovery(
            lab.target, "apply", record=record))
        check(duplicate["duplicate"] and duplicate["installed"], "R1精确重试未幂等")
        pair(lab, lab.target, "timely-target-restart")
    check(time.time() < int(lab.case_evidence["prepared"]["new_material"]["not_after"]),
          "目标新材料在本轮结束前到期")
    check(recovery_ledger(lab) == ledger and original_facts(lab) == original,
          "改写原事实或递归恢复幸存者")
    lab.case_evidence["completion"] = {"expected": "expired_blocked" if expired else "installed",
        "target": final_target, "healthy": healthy_views(lab), "ledger": recovery_ledger(lab),
        "original_unchanged": True, "no_recursive_recovery": True,
        "finished_at_unix_secs": time.time(), "target_material_still_valid": True}


CASES = {
    "E10_survivor_leaf_before_expiry": lambda lab: survivor_lifetime(lab, False),
    "E10_survivor_leaf_after_expiry": lambda lab: survivor_lifetime(lab, True),
}
