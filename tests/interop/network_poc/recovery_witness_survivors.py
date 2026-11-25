"""W1 有限可用性与幸存者补链；仅正常私有 Commit，保留每个角色结果。"""
import base64
import json
import re
import secrets
import time

from .fixture import ACCOUNTS, CONVERSATION, check, identity
from .first_trust_evidence import state
from .join_recovery_fixture import RecoveryLab, signed_digest
from .join_review_regressions import public_record, enable_anchor
from .key_package_fixture import decode
from .recovery_competition_cases import recovery_ledger
from .recovery_offline_cases import pair, send
from .recovery_watermark_cases import checkpoint, resume
from .recovery_witness_deadlines import wait_expired
from .recovery_witness_fixture import json_bytes, sha
from .recovery_witness_migration import legacy_accepted, denied_legacy


def directories(lab, observers=None, members=None):
    for observer in observers or (lab.actor, lab.target, lab.witness):
        for member in members or (lab.actor, lab.target, lab.witness):
            lab.fetch_directory(observer, member, "survivor-directory-" + member + "-" + secrets.token_hex(4))


def intent_value(lab, ident):
    """先完成允许的材料发布；拒绝比较从真实签名请求之前开始。"""
    proof, _ = lab.publish("publish-" + ident, lab.target, count=1, ttl=300)
    package = decode(proof)["action"]["packages"][0]
    view, pool = lab.recovery(lab.target, "inspect"), lab.pool(lab.target)
    floor = {key: view["public_head"][key] for key in ("authorization_version", "crypto_state_ref")}
    references = []
    for account in sorted({identity(d)["account_id"] for d in (lab.actor, lab.target, lab.witness)}):
        raw = base64.b64decode(pool["directories"][account]["snapshots"][-1])
        references.append({"account_id": account, "version": json.loads(raw)["version"], "sha256": sha(raw)})
    raw_policy = json_bytes(lab.policy())
    reference = lab.policy_ref or {"policy_id": "synthetic-policy", "policy_version": "1",
        "policy_sha256": sha(b"Rocket-IM/POC/recovery-witness-policy/v1\0"
                              + len(raw_policy).to_bytes(8, "big") + raw_policy)}
    now = int(time.time())
    return {"protocol_version": "rim-recovery-request-2", "witness_profile": "E10C-W1",
        "policy_ref": reference, "kind": "intent", "scope": lab.scope, "request_id": ident,
        "signer": lab.member(lab.target), "nonce": secrets.token_hex(32), "change_id": "change-" + ident,
        "root_admission": lab.root, "current_admission": view["roots"]["original-add"],
        "actor": lab.member(lab.actor), "predecessor": floor, "known_floor": floor,
        "directory_refs": references, "key_package_sha256": sha(base64.b64decode(package)),
        "history_policy": "from_recovery", "issued_at_unix_secs": str(now),
        "expires_at_unix_secs": str(now + 120)}


def blocked_target(lab, label):
    check(lab.recovery(lab.target, "inspect")["installed_count"] == 0, "目标被公共状态误装")
    lab.unchanged("T", label, lambda: lab.rust(lab.target, "wire_send",
        logical_message_id=label, attempt_id="P1", payload="synthetic-w1-blocked", expected_exit=1),
        "join_required")


def premature_resume(lab, label):
    before = state(lab)
    anchors_before = lab.anchor_views()
    original = lab.recovery(lab.target, "inspect")
    group = lab.rust(lab.target, "inspect")
    resume(lab, lab.target)
    after = state(lab)
    anchors_after = lab.anchor_views()
    check(lab.recovery(lab.target, "inspect") == original and lab.rust(lab.target, "inspect") == group
          and before["relay"] == after["relay"]
          and all(after["snapshots"][d] == value for d, value in before["snapshots"].items()
                  if d != lab.target)
          and all(anchors_after[d] == value for d, value in anchors_before.items()
                  if d != lab.target), "resume 快进了目标或改写其他角色")
    lab.role_results["T"].append({"label": label, "before": before, "after": after,
        "anchors_before": anchors_before, "anchors_after": anchors_after,
        "actual_r1_unchanged": True})
    blocked_target(lab, label + "-send")


def early_rejection(lab, value, code):
    before = recovery_ledger(lab)
    error = lab.unchanged("T", "target-intent-eligibility",
        lambda: lab.recovery(lab.target, "sign", request=value, intent=None, expected_exit=1), code)
    check(recovery_ledger(lab) == before, "分配前拒绝改变恢复账本")
    lab.case_evidence["preallocation"] = {"intent": value, "error": error, "ledger": before}
    lab.observed("A", "predecessor-retained", lab.rust(lab.actor, "inspect"))
    blocked_target(lab, "preallocation-target-send")


def public_request_fixture(lab, device, value):
    # 旧公开签名夹具可能重封装加密文件；业务拒绝的严格基线在夹具完成后建立。
    target_gate = None
    if device == lab.target:
        target_gate = next((event for event in reversed(lab.role_results["T"])
                            if event["label"] == "preallocation-target-send"), None)
        check(target_gate is not None and target_gate["result"]["code"] == "join_required"
              and target_gate["before"] == target_gate["after"]
              and target_gate["anchors_before"] == target_gate["anchors_after"],
              "未加入目标必须先真实验证发送拒绝及快照、账本、锚不变")
    def views():
        return {op: lab.rust(device, op) for op in (
            "inspect", "permission_inspect", "key_package_inspect")} | {
                "wire": ({"status": "NOT_INSPECTED_UNJOINED",
                          "verified_send_gate": target_gate["label"],
                          "observed_send_error": target_gate["result"]} if target_gate is not None else
                         lab.rust(device, "wire_inspect")),
                "recovery": lab.recovery(device, "inspect"),
                "witness": lab.witness_command(device, "inspect")}
    before, semantic = state(lab), views()
    proof = lab.sign_probe(device, value)
    after = state(lab)
    check(views() == semantic and before["relay"] == after["relay"]
          and all(after["snapshots"][d] == item for d, item in before["snapshots"].items() if d != device)
          and before["snapshots"][device]["bytes"] == after["snapshots"][device]["bytes"],
          "公开签名夹具改写了业务或密码语义")
    lab.case_evidence.setdefault("public_request_signatures", []).append({
        "device": device, "request": value, "proof": proof, "before": before, "after": after,
        "semantic_views_unchanged": True, "wire_inspect_performed": target_gate is None,
        "wire_gate_reference": target_gate["label"] if target_gate is not None else None,
        "scope": "public request signing only; no MLS candidate"})
    return proof


def same_control(lab):
    lab.setup_expired()
    directories(lab)
    domains = [{"member": lab.member(d), "control_domain_id": (
        "independent-w" if d in (lab.actor, lab.witness) else "target-domain")}
        for d in (lab.actor, lab.target, lab.witness)]
    lab.activate(domains=domains)
    value = intent_value(lab, "same-control")
    early_rejection(lab, value, "w1_witness_ineligible")
    # 公开签名夹具只绕过测试身份的请求生成门，不生成或修改任何 MLS 候选。
    proof = public_request_fixture(lab, lab.target, value)
    control = {"protocol_version": "rim-recovery-request-2", "witness_profile": "E10C-W1",
        "policy_ref": value["policy_ref"], "kind": "claim", "scope": lab.scope,
        "request_id": "claim-same-control", "signer": lab.member(lab.actor), "nonce": secrets.token_hex(32),
        "recovery_id": value["request_id"], "change_id": value["change_id"],
        "intent_sha256": signed_digest(proof), "reason": None}
    claim = public_request_fixture(lab, lab.actor, control)
    lab.unchanged("A", "service-rejects-before-allocation",
        lambda: lab.remote_recovery(lab.actor, "claim", intent=proof, proof=claim, expected=403),
        "w1_witness_ineligible")
    lab.observed("W", "same-domain-is-not-independent", lab.rust(lab.witness, "inspect"))
    lab.case_evidence.update(definition_status="UNREACHABLE_THROUGH_NORMAL_ENTRY",
        execution_scope="PASS_SCOPED_EARLY_REJECTION",
        remaining_exact_fixture="同控制域 P 无法经正常入口生成已持久 challenge；未执行原定义目标 Apply。")


def two_leaf_setup(lab):
    lab.setup_expired()
    directories(lab)
    online = list(ACCOUNTS)
    for index, removed in enumerate(("a2", "b1", "c1")):
        action = ({"kind": "revoke_device", **identity(removed)} if removed == "a2" else
                  {"kind": "remove_member", "account_id": identity(removed)["account_id"]})
        change = lab.rust(lab.actor, "permission_prepare", change_id="two-leaf-remove-" + str(index),
                          action=action)["change"]
        accepted = lab.http(lab.actor, "submit_permission_change", {
            "service_id": lab.service, "conversation_id": CONVERSATION, "change": change})
        record = {"change": change, "receipt": accepted["receipt"]}
        for device in online:
            lab.rust(device, "permission_recover", record=record)
        online.remove(removed)
        lab.recovery(lab.target, "advance", record=record)
    check(checkpoint(lab, lab.actor)["members"] == sorted(
        [lab.member(lab.actor), lab.member(lab.target)],
        key=lambda member: (member["account_id"], member["device_id"])), "没有建立真实两叶群")
    directories(lab, (lab.actor, lab.target), (lab.actor, lab.target))
    lab.case_evidence["two_leaf_checkpoint"] = checkpoint(lab, lab.actor)


def two_leaf_before(lab):
    two_leaf_setup(lab)
    # 指定的是原来真实存在、现已从准确前驱移除的 W，不凭空制造第三个身份。
    lab.activate(devices=(lab.actor, lab.target))
    early_rejection(lab, intent_value(lab, "two-leaf-before"), "w1_no_eligible_witness")
    lab.observed("W", "original-w-is-no-longer-a-survivor", lab.rust(lab.witness, "inspect"))


def two_leaf_existing(lab):
    two_leaf_setup(lab)
    intent = RecoveryLab.intent(lab, "two-leaf-legacy", package_ttl=300)
    claim = RecoveryLab.control_proof(lab, intent)
    allocated = lab.remote_recovery(lab.actor, "claim", intent=intent, proof=claim)
    bundle = lab.recovery(lab.actor, "prepare", intent=intent, claim=claim,
        allocation=allocated["allocation"], key_package=allocated["key_package"])["bundle"]
    record = lab.accept_recovery(bundle)["record"]
    for device in (lab.actor, lab.target):
        lab.recovery(device, "observe", record=record)
    lab.apply_survivor(lab.actor, record)
    lab.activate(policy=False, devices=(lab.actor, lab.target),
        domains=[{"member": lab.member(d), "control_domain_id": d + "-domain"}
                 for d in (lab.actor, lab.target)])
    ledger = recovery_ledger(lab)
    for phase in ("first", "fresh-restart"):
        if phase == "fresh-restart":
            lab.unchanged("T", phase, lab.restart)
        denied_legacy(lab, record, phase + "-legacy-r0")
        premature_resume(lab, phase + "-resume")
    check(recovery_ledger(lab) == ledger, "不支持两叶首次恢复却改变已接受占用")
    lab.case_evidence["error_mapping"] = {"semantic": "w1_no_eligible_witness",
        "actual_legacy_primary": "w1_policy_upgrade_required", "record": record}
    lab.observed("A", "current-r1-retained", lab.rust(lab.actor, "inspect"))
    lab.role_results["W"].append({"label": "no-current-witness", "current_member": False})


def no_policy(lab):
    record = legacy_accepted(lab)
    directories(lab, (lab.actor, lab.target))
    lab.activate(policy=False)
    denied_legacy(lab, record, "no-p-does-not-fall-back-to-legacy")
    early_rejection(lab, intent_value(lab, "no-policy"), "w1_policy_missing")
    lab.unchanged("T", "no-policy-restart", lab.restart)
    premature_resume(lab, "no-policy-resume")
    denied_legacy(lab, record, "restart-no-p-still-denies-legacy")
    lab.observed("W", "no-policy-does-not-fabricate-witness", lab.witness_command(lab.witness, "inspect"))


def accepted_without_w(lab, ident, *, package_ttl=300, observe_w=True):
    intent, claim, allocated, bundle = lab.prepare_recovery(ident, package_ttl=package_ttl)
    accepted = lab.accept_recovery(bundle)
    record = accepted["record"]
    for device in (*ACCOUNTS, lab.target):
        if device == lab.witness and not observe_w:
            continue
        material = record if device in (lab.actor, lab.target) else public_record(record)
        lab.recovery(device, "observe", record=material)
    for device in ACCOUNTS:
        if device != lab.witness:
            lab.apply_survivor(device, record)
    check(base64.b64decode(bundle["change"]["commit_bytes"])[:4] == b"\0\1\0\2",
          "本轮须使用正常私有 Commit")
    lab.case_evidence["prepared"] = {"intent": intent, "claim": claim, "allocation": allocated,
        "accepted": accepted}
    lab.observed("A", "actor-actual-r1", lab.rust(lab.actor, "inspect"))
    return intent, record


def offline(lab):
    lab.setup_w1()
    offline_state = state(lab)["snapshots"][lab.witness]
    offline_anchor = lab.anchor_views().get(lab.witness)
    _, record = accepted_without_w(lab, "offline-w", observe_w=False)
    request = lab.witness_request(record)["request"]
    ledger = recovery_ledger(lab)
    for phase in ("waiting", "restart"):
        if phase == "restart":
            lab.unchanged("T", "offline-relay-restart", lab.restart)
        lab.unchanged("T", phase + "-plain-apply-cannot-bypass",
            lambda: lab.recovery(lab.target, "apply", record=record, expected_exit=1),
            "w1_witness_not_installed")
        premature_resume(lab, phase + "-resume")
    pair(lab, "a2", "offline-w-other-healthy-members")
    check(state(lab)["snapshots"][lab.witness] == offline_state and recovery_ledger(lab) == ledger
          and lab.anchor_views().get(lab.witness) == offline_anchor,
          "离线 W 被悄悄应用或等待新增恢复")
    lab.role_results["W"].append({"label": "offline-no-witness-business-operation", "before": offline_state,
        "after": state(lab)["snapshots"][lab.witness], "response": None,
        "anchor_before": offline_anchor, "anchor_after": lab.anchor_views().get(lab.witness)})
    lab.case_evidence["availability"] = {"semantic": "w1_witness_unavailable",
        "actual_target_gate": "w1_witness_not_installed", "request": request,
        "transport_boundary": "fixture withholds W business operations; only read-only anchor diagnostics; no production presence transport"}


def catchup(lab):
    lab.setup_w1()
    _, record = accepted_without_w(lab, "timely-w")
    request = lab.witness_request(record)["request"]
    lab.unchanged("W", "before-actual-r1-no-response",
        lambda: lab.respond(record, request, expected_exit=1), "w1_witness_not_installed")
    installed = lab.apply_survivor(lab.witness, record)
    check(installed["installed"] and not installed["duplicate"], "W 补链未真实首次安装")
    response = lab.respond(record, request)
    lab.observed("W", "real-catchup-before-response", {"installed": installed, "response": response})
    target = lab.install(record, request, response["delivery"])
    check(target["installed"] and not target["duplicate"], "目标未独立首次安装")
    lab.observed("T", "real-welcome-after-w-catchup", target)
    resume(lab, lab.target)
    pair(lab, lab.witness, "caught-up-w")
    pair(lab, lab.target, "caught-up-target")


def original_add_setup(lab):
    lab.target, lab.actor = "d1", "a1"
    original_ttl = 30 if lab.helper is not None else 10
    lab.case_evidence["original_material_ttl_seconds"] = original_ttl
    lab.publish("original-package", lab.target, count=1, ttl=original_ttl)
    lab.ready(); lab.claim("original-claim", change_id="original-add")
    candidate = lab.prepare_join("original-claim")
    accepted = lab.submit_join(candidate)
    record = {"change": candidate["change"], "receipt": accepted["receipt"]}
    for device in ACCOUNTS:
        if device != lab.witness:
            lab.rust(device, "permission_recover", record=record)
    lab.original = lab.http(lab.target, "get_join_material", {
        "service_id": lab.service, "conversation_id": CONVERSATION, "change_id": "original-add"})
    for device in (*ACCOUNTS, lab.target):
        if device != lab.witness:
            lab.root = lab.recovery(device, "root", **lab.original)["reference"]
    lab.scope = {"service_id": lab.service, "conversation_id": CONVERSATION,
                 "group_id": lab.rust(lab.actor, "inspect")["group_id"]}
    directories(lab)
    lab.old_packet, lab.old_acceptance = send(lab, "before-recovery", receivers=("a2", "c1"))
    deadline = int(next(iter(lab.pool(lab.target)["packages"].values()))["material"]["not_after"])
    wait_expired(lab, "original-add", deadline)
    lab.activate()
    return deadline


def expired_target_view(lab, intent, request, label):
    """每次正常读取都记录 T 原件；读取的锚预约不冒充被测拒绝动作。"""
    view = {"recovery": lab.recovery(lab.target, "inspect"),
        "group": lab.rust(lab.target, "inspect"),
        "package": lab.pool(lab.target)["packages"][decode(intent)["key_package_sha256"]],
        "witness": lab.witness_command(lab.target, "inspect")}
    lab.observed("T", label, view)
    witness = view["witness"]["witness_state"]
    challenge = witness["challenges"][decode(request)["request_id"]]
    check(view["recovery"]["installed_count"] == 0 and not view["package"]["consumed"]
          and not witness["installed"] and challenge["status"] == "active"
          and challenge["request"] == request, "失效 W 后目标不再保持原 R0、未消费包及原挑战")
    return view


def observe_target_after_w_failure(lab, intent, request, baseline, failed_event, failure):
    """仅追加独立 T 结果；调用者必须重新抛出原 W 严格不变失败。"""
    evidence = {"w_assertion": str(failure), "w_event": failed_event["label"],
        "case_result": "FAIL", "w_retry": "NOT_ATTEMPTED_RESERVED_ANCHOR",
        "target_install": "NOT_ATTEMPTED_NO_AUTHENTIC_W_RESPONSE", "target_phases": []}
    lab.case_evidence["after_w_failure"] = evidence
    for phase in ("first", "restart"):
        item = {"phase": phase, "status": "NOT_REACHED"}
        evidence["target_phases"].append(item)
        try:
            if phase == "restart":
                lab.unchanged("T", "failed-w-relay-restart", lab.restart)
            view = expired_target_view(lab, intent, request, phase + "-failed-w-target-r0")
            check(view == baseline, "W 失败或 Relay 重启改变了目标 R0、私有包或挑战")
            blocked_target(lab, phase + "-failed-w-target-send")
            item.update(status="PASS_SCOPED_TARGET_GATE", send_error=lab.role_results["T"][-1]["result"])
            check(state(lab) == failed_event["after"], "追加 T 采证改变了快照或 Relay 账本")
            check(lab.anchor_views()[lab.witness] == failed_event["anchors_after"][lab.witness],
                  "追加 T 采证改变或恢复了 W 失败后的锚")
        except Exception as error:
            item.update(status="NOT_COMPLETED", error=str(error))
            if phase == "first":
                evidence["target_phases"].append({"phase": "restart", "status": "NOT_REACHED"})
            break


def expired(lab, original=False):
    old_deadline = original_add_setup(lab) if original else None
    if not original:
        lab.setup_w1()
    intent, record = accepted_without_w(lab, "late-w", package_ttl=300 if original else 15,
                                       observe_w=not original)
    request = lab.witness_request(record)["request"]
    deadline = old_deadline or int(lab.pool(lab.target)["packages"][
        decode(intent)["key_package_sha256"]]["material"]["not_after"])
    ledger = recovery_ledger(lab)
    target_before = expired_target_view(lab, intent, request, "before-expired-w-target-r0")
    if not original:
        wait_expired(lab, "recovery-add", deadline)
    for phase in ("first", "restart"):
        if phase == "restart":
            lab.unchanged("W", "expired-w-restart", lab.restart)
        action = (lambda: lab.rust(lab.witness, "permission_recover",
                    record=lab.original["record"], expected_exit=1)) if original else (
                  lambda: lab.recovery(lab.witness, "apply", record=public_record(record), expected_exit=1))
        label, code = phase + "-actual-expired-add", "permission_commit" if original else "recovery_commit"
        event_count = len(lab.role_results["W"])
        try:
            error = lab.unchanged("W", label, action, code)
        except AssertionError as failure:
            events = lab.role_results["W"][event_count:]
            if len(events) != 1 or str(failure) != label + " 改写了独立锚":
                raise
            event = events[0]
            error = event["result"]
            anchor = event["anchors_after"].get(lab.witness, {})
            match = re.search(r"Lifetime is in the past: not_after=(\d+), now=(\d+)", error.get("message", ""))
            if not (error.get("code") == code and match is not None and int(match[1]) == deadline
                    and int(match[2]) >= deadline and event["before"] == event["after"]
                    and anchor.get("paused") and anchor.get("active_txn")
                    and all(event["anchors_after"][d] == value for d, value in event["anchors_before"].items()
                            if d != lab.witness)):
                raise
            lab.case_evidence["actual_lifetime"] = {"deadline": deadline, "request": request,
                "semantic": "w1_mls_validation_failed", "original_add": original,
                "actual_error": error, "strict_w_anchor_unchanged": False,
                "relay_unchanged_no_recursive_recovery": recovery_ledger(lab) == ledger}
            observe_target_after_w_failure(lab, intent, request, target_before, event, failure)
            raise
        match = re.search(r"Lifetime is in the past: not_after=(\d+), now=(\d+)", error["message"])
        check(match is not None and int(match[1]) == deadline and int(match[2]) >= deadline,
              "没有到达真实待应用 Add 的 MLS Lifetime 校验")
        blocked_target(lab, phase + "-w-expired-target-send")
    check(recovery_ledger(lab) == ledger, "到期失败递归恢复了 W")
    check(not lab.witness_command(lab.witness, "inspect")["witness_state"]["responses"],
          "失败 W 产生了见证")
    lab.case_evidence["actual_lifetime"] = {"deadline": deadline, "request": request,
        "semantic": "w1_mls_validation_failed", "original_add": original,
        "relay_unchanged_no_recursive_recovery": True}


def unhealthy(lab):
    lab.setup_w1()
    _, record = accepted_without_w(lab, "unhealthy-w")
    request = lab.witness_request(record)["request"]
    if lab.witness not in lab.configs:
        enable_anchor(lab, lab.witness)
    path = lab.directory / lab.witness / "state.enc"
    old = path.read_bytes()
    lab.rust(lab.witness, "consistency_challenge")
    newer = path.read_bytes()
    check(old != newer, "未产生真实锚推进")
    path.write_bytes(old)
    detected = lab.rust(lab.witness, "inspect", expected_exit=1)
    check(detected["code"] == "anchor_conflict", "未建立已知不健康的独立锚状态")
    anchor = lab.rust(lab.witness, "anchor_inspect")
    check(anchor["paused"], "独立锚冲突未保持暂停")
    error = lab.unchanged("W", "inconsistent-anchor-before-real-w-apply",
        lambda: lab.recovery(lab.witness, "apply", record=public_record(record), expected_exit=1),
        "anchor_paused")
    check(lab.rust(lab.witness, "anchor_inspect") == anchor, "已不健康 W 响应又改写独立锚")
    lab.unchanged("W", "unhealthy-previous-state-cannot-issue-response",
        lambda: lab.respond(record, request, expected_exit=1), "w1_witness_not_installed")
    blocked_target(lab, "unhealthy-w-target-send")
    lab.case_evidence["fault"] = {"kind": "restore_actual_previous_w_snapshot_only",
        "previous_sha256": sha(old), "current_sha256": sha(newer),
        "initial_conflict": detected, "actual_error": error, "semantic": "w1_local_unhealthy",
        "anchor_and_all_other_roles_retained": True}


CASES = {
    "WC02-04-same-control": same_control,
    "WC03-01-two-leaf-before-allocation": two_leaf_before,
    "WC03-02-two-leaf-existing-r0": two_leaf_existing,
    "WC03-03-fixed-w-offline-wait": offline,
    "WC03-04-enabled-without-policy-legacy-denied": no_policy,
    "WC04-01-w-catchup-before-deadline": catchup,
    "WC04-02-unapplied-original-add-expired": lambda lab: expired(lab, True),
    "WC04-03-recovery-add-expired": expired,
    "WC04-04-w-unhealthy": unhealthy,
}
