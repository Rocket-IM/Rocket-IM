"""W1 见证历史不能绕过当前权限、身份和所知水位门禁。"""

import copy
from .fixture import ACCOUNTS, CONVERSATION, check, identity
from .consistency_cases import current_head, observe
from .first_trust_session import public_identity
from .key_package_fixture import decode
from .recovery_watermark_cases import resume
from .recovery_witness_lifecycle import prepared


def reject_mapped(lab, label, action, semantic, original_codes):
    result = lab.unchanged("T", label, action)
    check(result["code"] in (semantic, *original_codes),
          label + " 没有命中指定原始门禁: " + str(result))
    lab.case_evidence.setdefault("original_gate_mappings", []).append({
        "label": label, "actual_error": result, "frozen_semantic_reason": semantic,
        "gate_priority": "existing global guard remains before W1 first-install checks"})
    return result


def remove(lab, account, ident, *, apply_target=False):
    change = lab.rust(lab.actor, "permission_prepare", change_id=ident,
                      action={"kind": "remove_member", "account_id": account})["change"]
    response = lab.http(lab.actor, "submit_permission_change", {
        "service_id": lab.service, "conversation_id": CONVERSATION, "change": change})
    record = {"change": change, "receipt": response["receipt"]}
    for device in ACCOUNTS:
        if identity(device)["account_id"] != account:
            lab.rust(device, "permission_recover", record=record)
    if apply_target:
        lab.rust(lab.target, "permission_recover", record=record)
    else:
        lab.recovery(lab.target, "advance", record=record)
    lab.case_evidence.setdefault("real_permission_changes", []).append(record)
    return record


def revoked_before_install(lab):
    record, request = prepared(lab)
    delivery = lab.respond(record, request)["delivery"]
    remove(lab, identity(lab.witness)["account_id"], "w1-revoke-w")
    lab.unchanged("T", "known-w-revocation-beats-historical-response",
        lambda: lab.install(record, request, delivery, expected_exit=1), "w1_witness_ineligible")
    check(lab.recovery(lab.target, "inspect")["installed_count"] == 0, "已知撤销后仍安装目标")
    lab.observed("W", "historical-real-installation-not-erased", lab.witness_command(lab.witness, "inspect"))


def changed_witness_key(lab):
    record, request = prepared(lab)
    delivery = lab.respond(record, request)["delivery"]
    changed = public_identity(lab, lab.witness) | {"signature_key": lab.public["b2"]["signature_key"]}
    result = lab.rust(lab.target, "identity_trust_observe", identity=changed)
    lab.observed("T", "known-key-change-preserved", result)
    reject_mapped(lab, "known-w-key-change-beats-response",
        lambda: lab.install(record, request, delivery, expected_exit=1),
        "w1_witness_ineligible", ("identity_changed",))
    check(lab.recovery(lab.target, "inspect")["installed_count"] == 0, "身份钥变化后仍安装")


def installed_revocation(lab):
    record, request = prepared(lab)
    delivery = lab.respond(record, request)["delivery"]
    lab.install(record, request, delivery)
    resume(lab, lab.target)
    remove(lab, identity(lab.witness)["account_id"], "w1-later-revoke-w", apply_target=True)
    resume(lab, lab.target)
    current = lab.rust(lab.target, "permission_inspect")["checkpoint"]
    result = lab.unchanged("T", "later-revocation-retains-exact-installed-fact",
        lambda: lab.install(record, request, delivery))
    check(result["duplicate"] and result["installed"]
          and lab.rust(lab.target, "permission_inspect")["checkpoint"] == current,
          "历史精确重试回退最新群或要求新W")
    lab.observed("W", "old-w-installation-remains-historical", lab.witness_command(lab.witness, "inspect"))


def target_loses_permission(lab):
    record, request = prepared(lab)
    delivery = lab.respond(record, request)["delivery"]
    lab.install(record, request, delivery)
    resume(lab, lab.target)
    remove(lab, identity(lab.target)["account_id"], "w1-remove-target", apply_target=True)
    reject_mapped(lab, "installed-retry-keeps-original-access-gate",
        lambda: lab.install(record, request, delivery, expected_exit=1),
        "w1_permission_denied", ("permission_pending",))
    inspected = lab.witness_command(lab.target, "inspect")
    check(bool(inspected["witness_state"]["installed"]), "失权后只读历史安装事实被抹除")
    lab.observed("T", "read-only-installation-fact-after-access-loss", inspected)


def higher_floor(lab):
    record, request = prepared(lab)
    delivery = lab.respond(record, request)["delivery"]
    lab.install(record, request, delivery)
    resume(lab, lab.target)
    change = lab.rust(lab.actor, "permission_prepare", change_id="w1-higher-floor",
                      action={"kind": "remove_member", "account_id": "charlie"})["change"]
    accepted = lab.http(lab.actor, "submit_permission_change",
        {"service_id": lab.service, "conversation_id": CONVERSATION, "change": change})
    later = {"change": change, "receipt": accepted["receipt"]}
    for device in (lab.actor, "a2", lab.witness):
        lab.rust(device, "permission_recover", record=later)
    observed = observe(lab, current_head(lab, lab.target), lab.target)
    lab.observed("T", "higher-public-floor-does-not-advance-local-r1", observed)
    reject_mapped(lab, "installed-old-witness-does-not-clear-send-gate",
        lambda: lab.rust(lab.target, "wire_send", logical_message_id="w1-ahead",
            attempt_id="P1", payload="synthetic-blocked", expected_exit=1),
        "w1_superseded", ("consistency_paused",))
    check(lab.witness_command(lab.target, "inspect")["witness_state"]["installed"],
          "较高水位抹掉已有安装历史")


def no_response_downgrade(lab):
    record, request = prepared(lab)
    delivery = lab.respond(record, request)["delivery"]
    new_ref = lab.configure(lab.target, policy=lab.policy(version="2"), version="2")
    lab.witness_command(lab.target, "activate")
    replacement = decode(delivery["response"])
    replacement["policy_ref"] = new_ref
    bad = copy.deepcopy(delivery)
    bad["response"] = lab.sign_witness_fixture(lab.witness, "response", replacement)
    lab.unchanged("T", "service-response-cannot-rebind-existing-policy",
        lambda: lab.install(record, request, bad, expected_exit=1), "w1_policy_mismatch")
    legal = lab.install(record, request, delivery)
    check(legal["installed"], "新启用修订使原固定 P 候选失效")
    lab.observed("T", "original-candidate-policy-stays-authoritative", legal)


CASES = {
    "WC07-04-known-w-revocation": revoked_before_install,
    "WC07-05-known-w-key-change": changed_witness_key,
    "WC10-02-installed-w-later-revoked": installed_revocation,
    "WC10-03-installed-target-loss-original-gate": target_loses_permission,
    "WC10-04-installed-higher-floor-send-gate": higher_floor,
    "WC11-05-trusted-activation-no-response-downgrade": no_response_downgrade,
}
