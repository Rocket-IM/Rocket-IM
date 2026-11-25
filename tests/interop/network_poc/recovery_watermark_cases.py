"""E03：真实更高水位、旧意图保持和补链前后的发送门禁。"""

import copy
import hashlib
import json

from .fixture import ACCOUNTS, check
from .consistency_cases import current_head, observe
from .first_trust_evidence import state
from .key_package_fixture import decode, transaction
from .recovery_consistency_cases import permission_change
from .recovery_retry_cases import communicate


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
        default=lambda raw: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}).encode()).hexdigest()


def facts(lab):
    devices = (*ACCOUNTS, lab.target)
    # 尚未安装R1的目标不能wire_inspect；完整加密快照仍覆盖其全部私有状态。
    return {"durable": state(lab),
            "permission": {d: lab.rust(d, "permission_inspect") for d in devices},
            "consistency": {d: lab.rust(d, "consistency_inspect") for d in devices},
            "recovery": {d: lab.recovery(d, "inspect") for d in devices}}


def unchanged(lab, name, action, code=None):
    before = facts(lab)
    result = action()
    after = facts(lab)
    lab.case_evidence.setdefault("unchanged_steps", []).append({
        "name": name, "result": result, "before": before, "after": after})
    check(after == before, name + "产生了半写、候选、消息或水位变化")
    if code is not None:
        check(result["code"] == code, name + "未到达指定门禁")
    return result


def blocked(lab, device, name, code="consistency_paused"):
    return unchanged(lab, name, lambda: lab.rust(device, "wire_send",
        logical_message_id=name, attempt_id="P1", payload="synthetic-e03-must-not-encrypt",
        expected_exit=1), code)


def checkpoint(lab, device):
    return lab.rust(device, "permission_inspect")["checkpoint"]


def paused(lab, device, floor, name):
    current = lab.rust(device, "consistency_inspect")
    check(current["status"] == "needs_sync" and current["paused"]
          and current["freshness"] == "unknown"
          and current["highest_observed_checkpoint"] == floor,
          name + "丢失完整高水位或提前解除暂停")
    lab.case_evidence.setdefault("watermarks", []).append({
        "name": name, "device": device, "consistency": current,
        "permission": lab.rust(device, "permission_inspect"),
        "recovery": lab.recovery(device, "inspect")})
    blocked(lab, device, name + "-send")


def resume(lab, device):
    # 每次取新challenge绑定的真实head；重放已观察head会提前返回duplicate。
    head = current_head(lab, device)
    result = lab.rust(device, "consistency_resume", head=head)
    lab.case_evidence.setdefault("resume_attempts", []).append({
        "device": device, "head": head, "result": result})


def original_facts(lab):
    queries = {"permission_changes": ("change_id", "original-add"),
               "permission_resolutions": ("change_id", "original-add"),
               "join_materials": ("change_id", "original-add"),
               "kp_materials": ("accepted_change", "original-add"),
               "attempts": ("acceptance_id", lab.old_acceptance["acceptance_id"]),
               "events": ("acceptance_id", lab.old_acceptance["acceptance_id"])}
    with transaction(lab) as db:
        result = {}
        for table, (column, value) in queries.items():
            rows = [dict(r) for r in db.execute(
                "SELECT * FROM " + table + " WHERE " + column + "=? ORDER BY rowid", (value,))]
            check(bool(rows), "原接受或消息事实缺失: " + table)
            if table == "events":
                availability = [{"event_id": r["event_id"], "device": r["device"],
                                 "availability": r.pop("availability")} for r in rows]
            result[table] = {"rows": len(rows), "sha256": digest(rows)}
            if table == "events":
                result[table]["availability"] = availability
        return result


def original_preserved(lab, original):
    expected = copy.deepcopy(original)
    removed = [r for r in expected["events"]["availability"] if r["device"] == "c1"]
    check(len(removed) == 1 and removed[0]["availability"] == "available", "缺少真实移除前的旧槽")
    # Remove必须投影访问撤销；旧槽其余字段（含原密文/接受证明）保持。
    removed[0]["availability"] = "access_removed"
    after = original_facts(lab)
    lab.case_evidence["original_facts_check"] = {"before": original, "expected": expected, "after": after}
    check(after == expected, "原接受/旧槽被改写，或真实撤权投影不符")


def attempt(lab, intent):
    with transaction(lab) as db:
        row = db.execute("SELECT intent,predecessor,claim,allocation,state FROM recovery_attempts WHERE recovery_id=?",
                         (decode(intent)["request_id"],)).fetchone()
        check(row is not None, "原恢复尝试丢失")
        return dict(row)


def assert_counts(lab, attempts):
    tables = state(lab)["relay"]["tables"]
    expected = {"recovery_attempts": attempts, "recovery_edges": 1, "recovery_active": 0,
                "recovery_roots": 1, "permission_changes": 3, "permission_resolutions": 3}
    check(all(tables[k]["rows"] == v for k, v in expected.items()), "账本产生额外候选或接受")
    lab.case_evidence["expected_ledger_counts"] = expected


def actor_behind(lab):
    lab.setup_expired()
    original = original_facts(lab)
    lab.case_evidence["original_facts_before"] = original
    intent = lab.intent("e03-old-intent")
    claim = lab.control_proof(intent)
    allocated = lab.remote_recovery(lab.actor, "claim", intent=intent, proof=claim)
    old_attempt = attempt(lab, intent)
    check(allocated["state"] == "allocated" and allocated["record"] is None
          and lab.recovery(lab.actor, "inspect")["pending"] is None,
          "起点必须已领取且尚未生成候选")
    prepare = lambda: lab.recovery(lab.actor, "prepare", intent=intent, claim=claim,
        allocation=allocated["allocation"], key_package=allocated["key_package"], expected_exit=1)
    before = checkpoint(lab, lab.actor)
    successor = permission_change(lab, "e03-a-real-successor")
    head = current_head(lab, lab.actor)
    floor = decode(head)["checkpoint"]
    check(int(floor["authorization_version"]) > int(before["authorization_version"]), "Service未真实前进")
    observe(lab, head, lab.actor)
    check(checkpoint(lab, lab.actor) == before, "公开head冒充批准者R1")
    lab.case_evidence["original_attempt"] = {"intent": intent, "claim": claim,
        "allocated": allocated, "row": old_attempt, "successor": successor, "head": head}
    unchanged(lab, "actor-prepare-before-catchup", prepare, "consistency_paused")
    paused(lab, lab.actor, floor, "actor-behind")
    resume(lab, lab.actor)
    paused(lab, lab.actor, floor, "actor-premature-resume")
    check(attempt(lab, intent) == old_attempt, "拒绝或提前resume改写旧分配/意图")

    for device in ACCOUNTS:
        lab.rust(device, "permission_recover", record=successor)
    lab.recovery(lab.target, "advance", record=successor)
    lab.restart()
    check(checkpoint(lab, lab.actor) == floor, "批准者没有实际补齐完整前驱")
    paused(lab, lab.actor, floor, "actor-caught-up-before-resume")
    for device in (lab.actor, lab.target):
        resume(lab, device)
        current = lab.rust(device, "consistency_inspect")
        check(current["status"] == "no_known_conflict" and not current["paused"]
              and current["highest_observed_checkpoint"] == floor and current["freshness"] == "unknown",
              "合法补链后未恢复检查或丢失原高水位")
    blocked(lab, lab.target, "target-public-chain-only", "join_required")
    unchanged(lab, "old-intent-after-catchup", prepare, "recovery_predecessor_changed")
    retried = unchanged(lab, "original-intent-exact-sign", lambda: lab.recovery(lab.target, "sign",
        request=decode(intent), intent=None))
    check(retried["duplicate"] and retried["proof"] == intent, "旧意图精确重试没有返回原件")
    rewritten = copy.deepcopy(decode(intent))
    rewritten["predecessor"] = rewritten["known_floor"] = {
        k: floor[k] for k in ("authorization_version", "crypto_state_ref")}
    unchanged(lab, "old-intent-rewrite-rejected", lambda: lab.recovery(lab.target, "sign",
        request=rewritten, intent=None, expected_exit=1), "idempotency_conflict")
    check(attempt(lab, intent) == old_attempt, "补链使旧意图或分配发生隐式改绑")

    close = lab.control_proof(intent, "close", lab.target)
    closed = lab.remote_recovery(lab.target, "close", intent=intent, proof=close)
    for device in (lab.actor, lab.target):
        lab.recovery(device, "resolve", intent=intent, receipt=closed["receipt"])
    check(closed["state"] == "closed" and attempt(lab, intent) == {**old_attempt, "state": "closed"},
          "正规关闭改变旧意图/分配原件")
    unchanged(lab, "old-intent-after-close", prepare, "recovery_closed")
    fresh, _, _, bundle = lab.prepare_recovery("e03-new-intent")
    check(decode(fresh)["predecessor"] == rewritten["predecessor"]
          and decode(fresh)["request_id"] != decode(intent)["request_id"]
          and decode(fresh)["key_package_sha256"] != decode(intent)["key_package_sha256"],
          "新尝试没有使用新意图、正确前驱和新材料")
    accepted = lab.accept_recovery(bundle)
    lab.install_recovery(accepted["record"], ("a1", "a2", "b1", lab.target))
    assert_counts(lab, 2)
    communicate(lab, "e03-actor-recovered")
    original_preserved(lab, original)
    check(attempt(lab, intent) == {**old_attempt, "state": "closed"}, "新恢复覆盖旧尝试")
    lab.case_evidence["completion"] = {"old_closed": closed, "new_intent": fresh,
        "new_accepted": accepted, "original_facts": original, "final_state": facts(lab)}


def late_accepted(lab):
    lab.setup_expired()
    original = original_facts(lab)
    lab.case_evidence["original_facts_before"] = original
    intent, _, _, bundle = lab.prepare_recovery("e03-late-accepted")
    accepted = lab.accept_recovery(bundle)
    record = accepted["record"]
    accepted_checkpoint = decode(record["receipt"])["result"]["checkpoint"]
    lab.install_recovery(record, tuple(ACCOUNTS))
    successor = permission_change(lab, "e03-b-real-successor")
    for device in ACCOUNTS:
        lab.rust(device, "permission_recover", record=successor)
    relay = state(lab)["relay"]
    head = current_head(lab, lab.target)
    floor = decode(head)["checkpoint"]
    check(int(floor["authorization_version"]) > int(accepted_checkpoint["authorization_version"]),
          "签名水位未高于迟到接受")
    observe(lab, head, lab.target)
    check(checkpoint(lab, lab.target) is None, "公开head提前安装了目标R1")
    paused(lab, lab.target, floor, "target-higher-head")
    observed = lab.recovery(lab.target, "observe", record=record)
    check(not observed["duplicate"] and not observed["installed"] and checkpoint(lab, lab.target) is None,
          "迟到公开接受被当作R1")
    paused(lab, lab.target, floor, "target-late-r0")
    resume(lab, lab.target)
    paused(lab, lab.target, floor, "target-premature-resume")
    lab.restart()
    paused(lab, lab.target, floor, "target-restarted-before-r1")
    lab.recovery(lab.target, "apply", record=record)
    check(checkpoint(lab, lab.target) == accepted_checkpoint
          and lab.recovery(lab.target, "inspect")["installed_count"] == 1,
          "中间R1未真实安装或冒充更高检查点")
    paused(lab, lab.target, floor, "target-intermediate-r1")
    resume(lab, lab.target)
    paused(lab, lab.target, floor, "target-intermediate-resume")
    duplicate = unchanged(lab, "target-duplicate-intermediate-r1",
        lambda: lab.recovery(lab.target, "apply", record=record))
    check(duplicate["duplicate"] and duplicate["installed"], "中间R1重复未保留成功结果")
    lab.restart()
    paused(lab, lab.target, floor, "target-restarted-after-r1")
    lab.rust(lab.target, "permission_recover", record=successor)
    check(checkpoint(lab, lab.target) == floor, "没有实际处理更高后继")
    paused(lab, lab.target, floor, "target-caught-up-before-resume")
    resume(lab, lab.target)
    final = lab.rust(lab.target, "consistency_inspect")
    check(final["status"] == "no_known_conflict" and not final["paused"]
          and final["highest_observed_checkpoint"] == floor and final["freshness"] == "unknown",
          "完整补链后未正常解除暂停，或误称全局最新")
    check(state(lab)["relay"] == relay, "本地观察/补链/拒绝修改Service账本")
    queried = lab.get_recovery(intent)
    check(queried["record"] == record and queried["allocation"] == accepted["allocation"],
          "后继或本地拒绝改写原恢复接受")
    assert_counts(lab, 1)
    communicate(lab, "e03-target-recovered")
    original_preserved(lab, original)
    lab.case_evidence["completion"] = {"accepted": accepted, "successor": successor,
        "higher_head": head, "original_facts": original, "final_state": facts(lab)}


CASES = {"E03_actor_behind_r0": actor_behind,
         "E03_target_late_accepted_below_floor": late_accepted}
