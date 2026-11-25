"""真实 legacy R0/R1 的启用迁移；不在旧接受记录上补造策略或见证。"""

from .fixture import ACCOUNTS, check
from .first_trust_evidence import state
from .join_recovery_fixture import RecoveryLab
from .join_review_regressions import public_record
from .recovery_offline_cases import pair
from .recovery_watermark_cases import resume
from .recovery_witness_fixture import sha


def legacy_accepted(lab, *, target_installed=False):
    lab.setup_expired()
    lab.case_evidence["messages"] = [{"logical": "before-recovery", "sender": lab.actor,
        "direct_receivers": [device for device in ACCOUNTS if device != lab.actor],
        "payload_sha256": sha(b"synthetic-first-trust-before-recovery"),
        "packet": lab.old_packet, "accepted": lab.old_acceptance}]
    intent = RecoveryLab.intent(lab, "legacy-migration", package_ttl=300)
    claim = RecoveryLab.control_proof(lab, intent)
    allocated = lab.remote_recovery(lab.actor, "claim", intent=intent, proof=claim)
    bundle = lab.recovery(lab.actor, "prepare", intent=intent, claim=claim,
                          allocation=allocated["allocation"], key_package=allocated["key_package"])["bundle"]
    accepted = lab.accept_recovery(bundle)
    record = accepted["record"]
    for device in (*ACCOUNTS, lab.target):
        material = record if device in (lab.actor, lab.target) else public_record(record)
        lab.recovery(device, "observe", record=material)
    for device in ACCOUNTS:
        if device != lab.witness:
            lab.apply_survivor(device, record)
    if target_installed:
        installed = lab.recovery(lab.target, "apply", record=record)
        check(installed["installed"], "legacy 对照没有先真实安装")
        resume(lab, lab.target)
    lab.case_evidence["legacy_before_activation"] = {
        "intent": intent, "accepted": accepted, "target_installed": target_installed, "state": state(lab)}
    return record


def denied_legacy(lab, record, label):
    return lab.unchanged("T", label,
        lambda: lab.recovery(lab.target, "apply", record=record, expected_exit=1),
        "w1_policy_upgrade_required")


def legacy_installed(lab):
    record = legacy_accepted(lab, target_installed=True)
    lab.activate(policy=False)
    result = lab.unchanged("T", "legacy-installed-fact-exact-retry",
        lambda: lab.recovery(lab.target, "apply", record=record))
    check(result["installed"] and result["duplicate"], "迁移使已装 legacy 事实失效")
    inspected = lab.witness_command(lab.target, "inspect")
    for name in ("responses", "installation_facts", "installed", "challenges"):
        check(not inspected["witness_state"][name], "迁移补造 legacy W1 历史 " + name)
    lab.observed("T", "witness-ledger-has-no-fabricated-legacy-response", inspected)
    pair(lab, lab.target, "w1-legacy-installed")
    lab.restart()
    pair(lab, lab.target, "w1-legacy-installed-after-restart")


def legacy_target_survivor(lab):
    record = legacy_accepted(lab)
    lab.activate(policy=False)
    denied_legacy(lab, record, "legacy-first-target-install-denied")
    result = lab.apply_survivor(lab.witness, record)
    check(result["installed"] and not result["duplicate"], "目标迁移门错误阻挡合法幸存者补链")
    lab.observed("W", "legacy-commit-catchup-remains-valid", result)
    denied_legacy(lab, record, "survivor-success-is-not-target-success")


def migration_interrupted(lab):
    record = legacy_accepted(lab)
    lab.configure(lab.target, policy=None)
    before = state(lab)
    anchors_before = lab.anchor_views()
    check(lab.witness_command(lab.target, "activate", failpoint="before_save", expected_exit=83) is None,
          "迁移提交前提前输出成功")
    after = state(lab)
    anchors_after = lab.anchor_views()
    lab.role_results["T"].append({"label": "migration-before-save", "before": before,
        "after": after, "anchors_before": anchors_before, "anchors_after": anchors_after,
        "exit_code": 83, "classification": "w1_persistence_failed"})
    check(before == after, "中断迁移半写旧有效状态")
    queried = lab.reload_diagnostic(lab.target, "post-migration-interruption-old-state-query")
    if queried["exit_code"] != 0:
        check(queried["result"].get("error", {}).get("code") in ("anchor_paused", "anchor_unresolved"),
              "旧状态查询出现非锚故障: " + str(queried["result"]))
        resumed = lab.reload_diagnostic(lab.target, "post-migration-interruption-normal-resume",
                                        operation="anchor_resume")
        check(state(lab) == before, "中断迁移后诊断改变原业务快照")
        lab.case_evidence["migration_availability_limit"] = {
            "status": "OPEN_EXISTING_ANCHOR_UNRESOLVED",
            "query": queried["result"], "resume": resumed["result"],
            "scope": "U-PRE-MIGRATION preserves old complete bytes; it does not require anchor revision equality;"
                     " this scoped preservation result does not establish restart availability"}
        return
    result = lab.witness_command(lab.target, "activate")
    lab.observed("T", "fresh-process-completes-atomic-migration", result)
    denied_legacy(lab, record, "new-reader-enforces-migrated-gate")


def old_reader(lab):
    check(lab.old_binary is not None, "缺少真实迁移前程序，不能以模拟版本号代替")
    lab.setup_w1()
    _, accepted = lab.accepted()
    record = accepted["record"]
    request = lab.witness_request(record)["request"]
    lab.respond(record, request)
    current = lab.binary
    try:
        lab.binary = lab.old_binary
        error = lab.unchanged("T", "old-program-loads-new-snapshot",
            lambda: lab.rust(lab.target, "inspect", expected_exit=1))
        check(error["code"] in ("wrong_context", "state_decoding"),
              "旧程序未在版本/格式层明确拒读")
    finally:
        lab.binary = current
    lab.case_evidence["old_reader_mapping"] = {
        "observed_original_error": error, "semantic_class": "w1_unsupported_version",
        "boundary": "old binary retains original error vocabulary"}


def unauthorized_revision(lab):
    record = legacy_accepted(lab)
    lab.activate(policy=False)
    original = lab.witness_configs[lab.target]
    lab.configure(lab.target, policy=lab.policy(), version="2")
    lab.unchanged("T", "changed-config-without-new-trusted-hash",
        lambda: lab.witness_command(lab.target, "activate",
            env={"RIM_RECOVERY_WITNESS_CONFIG_SHA256": original[1]}, expected_exit=1),
        "w1_activation_unauthorized")
    lab.witness_configs[lab.target] = original
    denied_legacy(lab, record, "failed-revision-does-not-enable-old-welcome")


def monotonic_revision(lab):
    record = legacy_accepted(lab)
    lab.activate(policy=False)
    original = lab.witness_configs[lab.target]
    lab.configure(lab.target, policy=lab.policy(), version="2")
    revised = lab.witness_command(lab.target, "activate")
    lab.observed("T", "trusted-v2-policy-bound", revised)
    lab.witness_configs[lab.target] = original
    lab.unchanged("T", "original-v1-cannot-replace-v2",
        lambda: lab.witness_command(lab.target, "activate", expected_exit=1),
        "w1_activation_rollback")
    denied_legacy(lab, record, "adding-p-does-not-rebind-old-r0")


CASES = {
    "WC11-01-legacy-installed-idempotent": legacy_installed,
    "WC11-02-legacy-target-block-survivor-catchup": legacy_target_survivor,
    "WC11-03-migration-interruption": migration_interrupted,
    "WC11-04-old-reader-rejects-new-store": old_reader,
    "WC11-06-unauthorized-activation-revision": unauthorized_revision,
    "WC11-07-authorized-monotonic-revision-then-rollback": monotonic_revision,
}
