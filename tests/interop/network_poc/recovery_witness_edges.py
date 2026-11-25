"""W1 与原锚、真实旧副本、幸存叶 Lifetime 的交界。"""

import json
import re
import shutil
import time

from .fixture import ACCOUNTS, check
from .first_trust_evidence import state
from .join_review_regressions import enable_anchor, public_record
from .key_package_fixture import decode
from .recovery_witness_old_copy import create_joined_copy, old_call, old_view
from .recovery_survivor_cases import setup as survivor_setup
from .recovery_watermark_cases import resume
from .recovery_witness_deadlines import wait_expired
from .recovery_witness_lifecycle import prepared
from .recovery_witness_permissions import reject_mapped


def target_anchor_unresolved(lab):
    record, request = prepared(lab)
    delivery = lab.respond(record, request)["delivery"]
    if lab.target not in lab.configs:
        enable_anchor(lab, lab.target)
    lab.install(record, request, delivery, failpoint="before_save", expected_exit=83)
    anchor = lab.rust(lab.target, "anchor_inspect")
    check(anchor["status"] == "reserved", "失败没有留下真实未决锚预约")
    reject_mapped(lab, "unresolved-anchor-before-retry",
        lambda: lab.install(record, request, delivery, expected_exit=1),
        "w1_anchor_unresolved", ("anchor_paused",))
    reject_mapped(lab, "missing-journal-cannot-resume",
        lambda: lab.rust(lab.target, "anchor_resume", expected_exit=1),
        "w1_anchor_unresolved", ("anchor_unresolved",))
    lab.case_evidence["anchor_unresolved"] = anchor


def old_snapshot(lab):
    record, request = prepared(lab)
    delivery = lab.respond(record, request)["delivery"]
    if lab.target not in lab.configs:
        enable_anchor(lab, lab.target)
    original = lab.directory / "target-old-valid.enc"
    shutil.copy2(lab.snapshot(lab.target), original)
    lab.witness_request(record, ident="anchor-new-request")
    head = lab.rust(lab.target, "anchor_inspect")
    current = lab.directory / "target-current-before-replay.enc"
    shutil.copy2(lab.snapshot(lab.target), current)
    shutil.copy2(original, lab.snapshot(lab.target))
    reject_mapped(lab, "old-snapshot-cannot-restore-consumed-or-replaced-challenge",
        lambda: lab.install(record, request, delivery, expected_exit=1),
        "w1_anchor_unresolved", ("anchor_rollback", "anchor_paused", "anchor_conflict"))
    lab.case_evidence["replayed_snapshot"] = {
        "old": str(original), "current_preserved": str(current), "anchor_before": head,
        "scope": "replay exact old encrypted snapshot only; never rewrite independent anchor"}


def target_commit_failure(lab):
    check(getattr(lab, "fault_library", None), "缺少既有真实快照系统错误库")
    record, request = prepared(lab)
    delivery = lab.respond(record, request)["delivery"]
    trace = lab.directory / "w1-snapshot-syscalls.jsonl"
    env = {"DYLD_INSERT_LIBRARIES": str(lab.fault_library),
           "RIM_M06_TARGET": str(lab.snapshot(lab.target)),
           "RIM_M06_FAULT": "rename", "RIM_M06_TRACE": str(trace),
           "RIM_M06_SKIP_WRITES": "1" if lab.target in lab.configs else "0"}
    reject_mapped(lab, "real-atomic-rename-failure",
        lambda: lab.install(record, request, delivery, env=env, expected_exit=1),
        "w1_persistence_failed", ("snapshot_save",))
    check(trace.exists(), "故障装置没有命中真实系统调用")
    calls = [json.loads(line) for line in trace.read_text().splitlines()]
    check(sum(item.get("stage") == "rename" and item.get("ret") == -1 for item in calls) == 1,
          "没有准确的单次真实 rename 失败")
    lab.case_evidence["snapshot_system_failure"] = calls
    queried = lab.reload_diagnostic(lab.target, "fresh-reload-after-real-atomic-rename-failure")
    if queried["exit_code"] != 0 and lab.target in lab.configs:
        lab.reload_diagnostic(lab.target, "normal-anchor-resume-after-rename-failure",
                              operation="anchor_resume")
    check(queried["exit_code"] == 0 and queried["result"].get("ok"),
          "真实提交失败保留旧快照，但新进程查询失败: " + str(queried["result"]))
    recovered = lab.install(record, request, delivery)
    check(recovered["installed"] and not recovered["duplicate"], "提交失败已消耗材料或挑战")
    lab.observed("T", "normal-retry-after-system-failure", recovered)


def timeout_without_actor_r1(lab):
    lab.setup_w1()
    _, accepted = lab.accepted(install_actor=False)
    record = accepted["record"]
    request = lab.witness_request(record, ttl="3")["request"]
    wait_expired(lab, "witness-timeout-not-material-timeout",
                 int(decode(request)["expires_at_unix_secs"]))
    value = lab.build_intent("w1-timeout-must-not-new-recover")
    reject_mapped(lab, "witness-timeout-does-not-create-new-recovery",
        lambda: lab.recovery(lab.target, "sign", request=value, intent=None, expected_exit=1),
        "w1_new_attempt_not_eligible", ("recovery_not_expired",))
    check(lab.recovery(lab.actor, "inspect")["pending"] is not None,
          "等待超时偷偷合并批准者原 pending")
    lab.observed("A", "actor-still-has-real-pending-not-r1", lab.recovery(lab.actor, "inspect"))


def old_joined_copy(lab):
    lab.before_recovery_root = lambda: create_joined_copy(lab)
    lab.setup_w1()
    _, accepted = lab.accepted()
    record = accepted["record"]
    request = lab.witness_request(record)["request"]
    delivery = lab.respond(record, request)["delivery"]
    old_call(lab, "join_recovery", command={"kind": "witness_activate"})
    before = old_view(lab)
    public = public_record(record)
    advanced = old_call(lab, "join_recovery",
        command={"kind": "advance_public", "record": public}, expected_exit=1)
    after_advance_anchor = lab.old_copy_lab.anchor_views()
    after_observe = old_view(lab)
    semantic_before = {key: value for key, value in before.items() if key != "anchors"}
    semantic_after = {key: value for key, value in after_observe.items() if key != "anchors"}
    check(advanced["code"] == "already_grouped" and semantic_after == semantic_before
          and after_advance_anchor == before["anchors"],
          "公开恢复记录覆盖真实旧群、已入群拒绝仍有写入")
    main_before = state(lab)
    error = old_call(lab, "join_recovery", command={"kind": "witness_apply",
        "record": record, "request": request, "delivery": delivery}, expected_exit=1)
    after_apply_anchor = lab.old_copy_lab.anchor_views()
    after_apply = old_view(lab)
    check(error["code"] == "w1_already_grouped"
          and {key: value for key, value in after_apply.items() if key != "anchors"} == semantic_after
          and after_apply_anchor == after_observe["anchors"]
          and state(lab) == main_before, "W1 目标门覆盖旧群或拒绝仍有写入")
    lab.role_results["T"].append({"label": "real-old-joined-copy-denied",
        "public_advance": advanced, "result": error, "before": after_observe, "after": after_apply,
        "advance_anchor_after_before_diagnostics": after_advance_anchor,
        "apply_anchor_after_before_diagnostics": after_apply_anchor,
        "sampling": "dedicated read-only anchor sample immediately after tested action;"
                    " subsequent ordinary diagnostic reads may advance their own permits",
        "phase": "healthy-existing-group guard precedes challenge/material import",
        "new_private_bundle_imported_to_old_copy": False})
    installed = lab.install(record, request, delivery)
    check(installed["installed"], "旧副本拒绝破坏主目标合法恢复")
    lab.observed("T", "independent-main-target-legal-control", installed)


def other_leaf_expired(lab):
    original_prepare = lab.prepare_recovery
    def activated_prepare(*args, **kwargs):
        for observer in (lab.actor, lab.target, lab.witness):
            for member in (lab.actor, lab.target, lab.witness):
                lab.fetch_directory(observer, member, "w1-leaf-directory-" + member)
        lab.activate(policy=True, devices=(*ACCOUNTS, "b2", lab.target))
        return original_prepare(*args, **kwargs)
    lab.prepare_recovery = activated_prepare
    try:
        _, accepted, _, ledger, _ = survivor_setup(
            lab, original_ttl=30 if lab.helper else 10, survivor_ttl=90 if lab.helper else 45)
    finally:
        lab.prepare_recovery = original_prepare
    record = accepted["record"]
    deadline = int(lab.case_evidence["prepared"]["survivor_material"]["not_after"])
    if int(time.time()) < deadline - 30:
        wait_expired(lab, "request-issuance-within-last-30-live-seconds", deadline - 30)
    request = lab.witness_request(record)["request"]
    delivery = lab.respond(record, request)["delivery"]
    lab.case_evidence["other_leaf_deadline_order"] = {
        "survivor_not_after": deadline,
        "target_not_after": lab.case_evidence["prepared"]["new_material"]["not_after"],
        "request_issued": decode(request)["issued_at_unix_secs"],
        "request_expires": decode(request)["expires_at_unix_secs"]}
    wait_expired(lab, "other-survivor-leaf-only", deadline)
    check(int(decode(request)["expires_at_unix_secs"]) > deadline,
          "另一叶到期对照的见证请求也已过期")
    error = reject_mapped(lab, "actual-welcome-lifetime-validation",
        lambda: lab.install(record, request, delivery, expected_exit=1),
        "w1_mls_validation_failed", ("welcome_validation",))
    matched = re.search(r"Lifetime is in the past: not_after=(\d+), now=(\d+)", error["message"])
    check(matched is not None and int(matched[1]) == deadline and int(matched[2]) >= deadline,
          "拒绝未经过真实另一幸存叶 Lifetime 校验")
    check(lab.recovery(lab.target, "inspect")["installed_count"] == 0,
          "另一幸存叶到期后仍安装目标")
    lab.case_evidence["no_recursive_recovery"] = ledger


CASES = {
    "WC07-06-other-survivor-leaf-expiry": other_leaf_expired,
    "WC08-07-target-commit-failure": target_commit_failure,
    "WC08-10-anchor-unresolved": target_anchor_unresolved,
    "WC08-11-old-snapshot-replay": old_snapshot,
    "WC09-04-timeout-without-R1-not-successor": timeout_without_actor_r1,
    "WC10-05-real-old-joined-copy": old_joined_copy,
}
