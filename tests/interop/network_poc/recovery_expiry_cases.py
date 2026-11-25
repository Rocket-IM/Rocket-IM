"""E07.a：材料先到期，首次接受回滚，显式关闭后以新材料恢复。"""

import json
import time

from .fixture import ACCOUNTS, check
from .first_trust_evidence import state
from .key_package_fixture import decode
from .recovery_close_cases import attempt_facts, close_committed
from .recovery_retry_cases import communicate
from .recovery_watermark_cases import checkpoint, facts, original_facts, unchanged


def material_expires_before_intent(lab):
    lab.setup_expired()
    original = original_facts(lab)
    intent, claim, allocated, bundle = lab.prepare_recovery(
        "e07-short-material", ttl=120, package_ttl=12)
    arguments = dict(intent=intent, claim=claim, allocation=allocated["allocation"],
                     key_package=allocated["key_package"])
    initial = attempt_facts(lab, intent)
    material = json.loads(initial["material"]["metadata"])
    deadline = int(material["not_after"])
    intent_deadline = int(decode(intent)["expires_at_unix_secs"])
    candidate_deadline = int(decode(bundle["change"])["expires_at_unix_secs"])
    old_checkpoint = checkpoint(lab, lab.actor)
    check(int(time.time()) < deadline < min(intent_deadline, candidate_deadline),
          "没有形成材料有效且独立早于意图/候选到期的边界")
    check(initial["attempt"]["state"] == initial["material"]["state"] == "allocated"
          and len(initial["active"]) == 1 and not initial["edges"], "缺少真实未决分配")
    lab.case_evidence["original_request"] = {"intent": intent, "claim": claim,
        "allocated": allocated, "bundle": bundle, "attempt": initial}
    clock = {"material_not_before": material["not_before"], "material_not_after": deadline,
             "intent_expires": intent_deadline, "candidate_expires": candidate_deadline}
    lab.case_evidence["clock_boundary"] = clock

    def cross_deadline():
        # 使用原Relay有界延迟；业务校验及暂存写入先完成，最后取样须回滚事务。
        while True:
            remaining = deadline - 3 - time.time()
            if remaining <= 0:
                break
            time.sleep(min(.1, remaining))
        start = time.time()
        delay = int((deadline - start + .2) * 1000)
        check(start < deadline and 1 <= delay <= 5000, "未在材料有效期内进入提交窗口")
        lab.control("hook", hook="delay_before_commit", delay_ms=str(delay))
        clock.update(accept_started_at=time.time(), delay_ms=delay)
        try:
            return lab.remote_recovery(lab.actor, "accept", bundle=bundle, expected=409)
        finally:
            clock["accept_returned_at"] = time.time()

    unchanged(lab, "material-expired-at-final-check", cross_deadline, "recovery_expired")
    check(clock["accept_started_at"] < deadline <= clock["accept_returned_at"]
          < min(intent_deadline, candidate_deadline), "拒绝时并非只有材料期限越界")
    check(attempt_facts(lab, intent) == initial, "期限失败改变原分配/根/后继或请求")
    # 本次请求从到期后开始，真实库在材料校验处拒绝，与上一条最后取样分开记账。
    unchanged(lab, "expired-material-new-accept", lambda: lab.remote_recovery(
        lab.actor, "accept", bundle=bundle, expected=400), "invalid_join_material")

    for phase in ("after-expiry", "after-restart"):
        if phase == "after-restart":
            unchanged(lab, "restart-with-expired-allocation", lab.restart)
        for name, action in (
            ("query", lambda: lab.get_recovery(intent)),
            ("claim-exact", lambda: lab.remote_recovery(lab.actor, "claim", intent=intent, proof=claim)),
        ):
            check(unchanged(lab, phase + "-" + name, action) == allocated,
                  "材料到期或重启自动释放/替换分配")
        check(unchanged(lab, phase + "-prepare-exact", lambda: lab.recovery(
            lab.actor, "prepare", **arguments)) == {"bundle": bundle, "duplicate": True},
            "材料到期后精确prepare重新生成候选或Commit")
        check(lab.recovery(lab.actor, "inspect")["pending"] == bundle
              and attempt_facts(lab, intent) == initial, "未决候选或分配被自动清除")
        for device, code in ((lab.actor, "recovery_pending"), (lab.target, "join_required")):
            unchanged(lab, phase + "-send-" + device, lambda d=device: lab.rust(d, "wire_send",
                logical_message_id=phase + "-" + d, attempt_id="P1",
                payload="synthetic-e07-blocked", expected_exit=1), code)

    close = lab.control_proof(intent, "close", lab.target)
    before_close = state(lab)
    closed = lab.remote_recovery(lab.target, "close", intent=intent, proof=close)
    closed_attempt, after_close = attempt_facts(lab, intent), state(lab)
    terminal = close_committed(lab, initial, closed_attempt, original, close, before_close, after_close)
    check(closed["state"] == "closed" and closed["receipt"] == terminal
          and lab.recovery(lab.actor, "inspect")["pending"] == bundle,
          "正规关闭未返回原终态，或HTTP响应隐式清理本地候选")
    lab.case_evidence["explicit_close"] = {"proof": close, "result": closed,
        "before": before_close, "after": after_close, "attempt": closed_attempt}
    for device in (lab.actor, lab.target):
        before = state(lab)
        result = lab.recovery(device, "resolve", intent=intent, receipt=terminal)
        after = state(lab)
        lab.case_evidence.setdefault("resolves", []).append({"device": device,
            "result": result, "before": before, "after": after})
        check(result == {"duplicate": False, "state": "closed"}
              and after["relay"] == before["relay"]
              and after["snapshots"][device] != before["snapshots"][device]
              and all(after["snapshots"][d] == s for d, s in before["snapshots"].items() if d != device)
              and lab.recovery(device, "inspect")["pending"] is None,
              "真实resolve没有原子保存本机终态，或改写其他归属")
    check(checkpoint(lab, lab.actor) == old_checkpoint, "拒绝/关闭/resolve提前推进群版本")
    unchanged(lab, "old-prepare-after-resolve", lambda: lab.recovery(lab.actor, "prepare",
        **arguments, expected_exit=1), "recovery_closed")

    fresh, _, _, fresh_bundle = lab.prepare_recovery("e07-fresh-material")
    old, new = decode(intent), decode(fresh)
    check(all(new[k] != old[k] for k in ("request_id", "change_id", "key_package_sha256"))
          and new["predecessor"] == old["predecessor"]
          and new["current_admission"] == old["current_admission"],
          "正规关闭后没有换新意图/材料，或错误推进原前驱")
    accepted = lab.accept_recovery(fresh_bundle)
    check(accepted["state"] == "accepted", "新材料没有完成R0")
    lab.install_recovery(accepted["record"])
    current_checkpoint = checkpoint(lab, lab.target)
    check(int(current_checkpoint["authorization_version"]) == int(old_checkpoint["authorization_version"]) + 1
          and all(checkpoint(lab, d) == current_checkpoint for d in (*ACCOUNTS, lab.target)),
          "新材料没有真实完成唯一R1")
    communicate(lab, "e07-after-fresh-r1")
    for name, action in (
        ("historical-accept", lambda: lab.accept_recovery(bundle)),
        ("historical-close", lambda: lab.remote_recovery(lab.target, "close", intent=intent, proof=close)),
    ):
        check(unchanged(lab, name, action) == {**closed, "head": current_checkpoint},
              "新恢复后旧请求改变原closed事实")
    for device in (lab.actor, lab.target):
        check(unchanged(lab, "historical-resolve-" + device, lambda d=device: lab.recovery(
            d, "resolve", intent=intent, receipt=terminal)) == {"duplicate": True}, "旧resolve回退新状态")
    communicate(lab, "e07-after-historical-retries")
    final = attempt_facts(lab, intent)
    check(all(final[k] == closed_attempt[k] for k in ("attempt", "material", "requests"))
          and original_facts(lab) == original, "新恢复或通信改写原关闭/材料/旧接受/旧消息")
    counts = {"recovery_attempts": 2, "recovery_requests": 5, "recovery_edges": 1,
              "recovery_roots": 1, "recovery_active": 0, "permission_changes": 2,
              "permission_resolutions": 2, "kp_materials": 3}
    tables = state(lab)["relay"]["tables"]
    check(all(tables[t]["rows"] == n for t, n in counts.items()), "拒绝或重试新增分配/请求/Commit")
    edge = final["edges"][0]
    check(edge["recovery_id"] == new["request_id"] and json.loads(edge["current_ref"]) == old["current_admission"]
          and final["roots"][0]["current_ref"] == edge["successor_ref"], "过期尝试获得接受后继")
    lab.case_evidence["completion"] = {"fresh_intent": fresh, "accepted": accepted,
        "original_before": original, "original_after": original_facts(lab),
        "old_attempt": final, "expected_counts": counts, "final_state": facts(lab)}


CASES = {"E07_material_expires_before_intent": material_expires_before_intent}
