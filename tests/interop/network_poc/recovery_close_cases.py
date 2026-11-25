"""E06.c：关闭已提交但响应丢失，未知候选保持到真实终态解析。"""

import copy
import hashlib
import http.client
import json
import secrets

from .fixture import ACCOUNTS, check
from .first_trust_evidence import state
from .join_recovery_fixture import signed_digest
from .key_package_fixture import decode, transaction
from .recovery_retry_cases import communicate
from .recovery_watermark_cases import checkpoint, facts, original_facts, unchanged


def attempt_facts(lab, intent):
    value = decode(intent)
    with transaction(lab) as db:
        return {
            "attempt": dict(db.execute("SELECT * FROM recovery_attempts WHERE recovery_id=?",
                                       (value["request_id"],)).fetchone()),
            "material": dict(db.execute("SELECT * FROM kp_materials WHERE hash=?",
                                        (value["key_package_sha256"],)).fetchone()),
            "requests": [dict(r) for r in db.execute(
                "SELECT * FROM recovery_requests WHERE recovery_id=? ORDER BY rowid", (value["request_id"],))],
            "roots": [dict(r) for r in db.execute("SELECT * FROM recovery_roots ORDER BY rowid")],
            "active": [dict(r) for r in db.execute("SELECT * FROM recovery_active ORDER BY rowid")],
            "edges": [dict(r) for r in db.execute("SELECT * FROM recovery_edges ORDER BY rowid")],
        }


def unknown(lab, name, intent, arguments, bundle):
    check(lab.recovery(lab.actor, "inspect")["pending"] == bundle, "未知结果擅自清除或改变原候选")
    reused = unchanged(lab, name + "-prepare-exact", lambda: lab.recovery(lab.actor, "prepare", **arguments))
    check(reused == {"bundle": bundle, "duplicate": True}, "未知结果重试重新生成候选或Commit")
    for device, code in ((lab.actor, "recovery_pending"), (lab.target, "join_required")):
        unchanged(lab, name + "-send-" + device, lambda d=device: lab.rust(d, "wire_send",
            logical_message_id=name + "-" + d, attempt_id="P1", payload="synthetic-e06-blocked",
            expected_exit=1), code)
    # 复用原已发布材料，仅换请求标识，核查本地未知请求不能被替换。
    replacement = copy.deepcopy(decode(intent))
    replacement.update(request_id=name + "-new-intent", change_id=name + "-new-change",
                       nonce=secrets.token_hex(32))
    unchanged(lab, name + "-new-intent", lambda: lab.recovery(lab.target, "sign",
              request=replacement, intent=None, expected_exit=1), "recovery_pending")


def close_committed(lab, before, after, original, close, before_state, after_state):
    """首个close允许准确的终态写入；不允许接受候选或改写旧事实。"""
    terminal = json.loads(after["attempt"]["terminal"])
    result = decode(terminal)["result"]
    check(after["attempt"] == {**before["attempt"], "state": "closed",
                                "terminal": after["attempt"]["terminal"]}
          and result["kind"] == "closed" and result["close_sha256"] == signed_digest(close)
          and result["allocation_sha256"] == signed_digest(json.loads(before["attempt"]["allocation"]))
          and result["checkpoint"] == json.loads(before["attempt"]["predecessor"])
          and after["material"] == {**before["material"], "state": "retired"}
          and not after["active"] and after["edges"] == before["edges"] == []
          and after["roots"] == before["roots"], "关闭未原子退役，或错误接受/改变原入口")
    check(after["requests"][:-1] == before["requests"] and len(after["requests"]) == 3
          and json.loads(after["requests"][-1]["proof"]) == close, "关闭请求未准确保留一次")
    check(after_state["snapshots"] == before_state["snapshots"]
          and original_facts(lab) == original, "丢响应改写客户端或原加入/旧消息事实")
    allowed = {"recovery_attempts", "recovery_requests", "recovery_active", "kp_materials", "kp_inventory"}
    old_tables, new_tables = before_state["relay"]["tables"], after_state["relay"]["tables"]
    check(set(old_tables) == set(new_tables) and before_state["relay"]["public_keys"] == after_state["relay"]["public_keys"]
          and all(old_tables[t] == new_tables[t] for t in old_tables if t not in allowed),
          "关闭改变权限Commit、消息、身份或无关账本")
    return terminal


def close_response_lost(lab):
    lab.setup_expired()
    original = original_facts(lab)
    intent, claim, allocated, bundle = lab.prepare_recovery("e06-lost-close")
    arguments = dict(intent=intent, claim=claim, allocation=allocated["allocation"],
                     key_package=allocated["key_package"])
    close = lab.control_proof(intent, "close", lab.target)
    body = json.dumps({"kind": "close", "intent": intent, "proof": close}).encode()
    body_hash = hashlib.sha256(body).hexdigest()
    lab.case_evidence["original_request"] = {"intent": intent, "claim": claim, "allocated": allocated,
        "bundle": bundle, "close": close, "body_utf8": body.decode(), "body_sha256": body_hash}
    before = state(lab)
    before_attempt = attempt_facts(lab, intent)
    old_checkpoint = checkpoint(lab, lab.actor)
    lab.control("hook", hook="drop_after_commit")
    try:
        lab.http(lab.target, "join_recovery", {}, raw=body)
    except (http.client.RemoteDisconnected, ConnectionResetError) as error:
        lab.case_evidence["lost_response"] = {"type": type(error).__name__, "hook": "drop_after_commit"}
    else:
        raise AssertionError("关闭丢响应注入未生效")
    after = state(lab)
    closed_attempt = attempt_facts(lab, intent)
    # 装置只读观察Service落盘；此处不把终态交给客户端resolve。
    terminal = close_committed(lab, before_attempt, closed_attempt, original, close, before, after)
    lab.case_evidence["close_commit"] = {"before": before, "after": after,
        "before_attempt": before_attempt, "closed_attempt": closed_attempt}
    unknown(lab, "after-lost-response", intent, arguments, bundle)
    unchanged(lab, "restart-while-unknown", lab.restart)
    unknown(lab, "after-restart", intent, arguments, bundle)

    closed = unchanged(lab, "query-closed", lambda: lab.get_recovery(intent))
    check(closed["state"] == "closed" and closed["receipt"] == terminal
          and closed["allocation"] == allocated["allocation"] and closed["record"] is None,
          "查询没有返回唯一原关闭，或错误认为已接受")
    check(hashlib.sha256(body).hexdigest() == body_hash, "关闭重试改变原HTTP正文")
    for name, action in (
        ("close-exact", lambda: lab.http(lab.target, "join_recovery", {}, raw=body)),
        ("claim-after-close", lambda: lab.remote_recovery(lab.actor, "claim", intent=intent, proof=claim)),
        ("late-accept-after-close", lambda: lab.accept_recovery(bundle)),
    ):
        check(unchanged(lab, name, action) == closed, "重试或迟到接受改变原closed终态")
    unknown(lab, "after-query-before-resolve", intent, arguments, bundle)

    for device in (lab.actor, lab.target):
        before_resolve = state(lab)
        result = lab.recovery(device, "resolve", intent=intent, receipt=closed["receipt"])
        after_resolve = state(lab)
        lab.case_evidence.setdefault("resolves", []).append({"device": device, "result": result,
            "before": before_resolve, "after": after_resolve})
        check(result == {"duplicate": False, "state": "closed"}
              and after_resolve["relay"] == before_resolve["relay"]
              and after_resolve["snapshots"][device] != before_resolve["snapshots"][device]
              and all(after_resolve["snapshots"][d] == s for d, s in before_resolve["snapshots"].items() if d != device),
              "真实resolve未持久保存或改写了其他归属")
        check(lab.recovery(device, "inspect")["pending"] is None, "验证关闭后未清pending")
    check(checkpoint(lab, lab.actor) == old_checkpoint, "关闭/resolve改变实际群版本")
    unchanged(lab, "restart-after-resolve", lab.restart)
    for device in (lab.actor, lab.target):
        check(unchanged(lab, "resolve-exact-" + device, lambda d=device: lab.recovery(d, "resolve",
              intent=intent, receipt=closed["receipt"])) == {"duplicate": True}, "关闭原件没有持久幂等")
    unchanged(lab, "old-prepare-after-resolve", lambda: lab.recovery(lab.actor, "prepare",
              **arguments, expected_exit=1), "recovery_closed")

    fresh, _, _, fresh_bundle = lab.prepare_recovery("e06-after-resolve")
    old, new = decode(intent), decode(fresh)
    check(new["request_id"] != old["request_id"] and new["change_id"] != old["change_id"]
          and new["key_package_sha256"] != old["key_package_sha256"]
          and new["predecessor"] == old["predecessor"] and new["current_admission"] == old["current_admission"],
          "关闭后没有新意图/材料，或错误推进未接受的前驱/端点")
    accepted = lab.accept_recovery(fresh_bundle)
    lab.install_recovery(accepted["record"])
    fresh_checkpoint = checkpoint(lab, lab.target)
    check(int(fresh_checkpoint["authorization_version"]) == int(old_checkpoint["authorization_version"]) + 1
          and all(checkpoint(lab, d) == fresh_checkpoint for d in (*ACCOUNTS, lab.target)), "新恢复未真实完成R1")
    communicate(lab, "e06-after-new-r1")
    expected_closed = {**closed, "head": fresh_checkpoint}
    check(unchanged(lab, "old-close-after-new-r1", lambda: lab.http(lab.target, "join_recovery", {}, raw=body))
          == expected_closed, "新恢复覆盖历史关闭原件")
    for device in (lab.actor, lab.target):
        check(unchanged(lab, "historical-resolve-" + device, lambda d=device: lab.recovery(d, "resolve",
              intent=intent, receipt=closed["receipt"])) == {"duplicate": True}, "旧resolve回退新状态")
    communicate(lab, "e06-after-historical-retry")
    current = attempt_facts(lab, intent)
    check(all(current[k] == closed_attempt[k] for k in ("attempt", "material", "requests"))
          and original_facts(lab) == original, "新恢复/通信改写旧终态、材料或原加入/消息事实")
    tables = state(lab)["relay"]["tables"]
    counts = {"recovery_attempts": 2, "recovery_requests": 5, "recovery_edges": 1,
              "recovery_roots": 1, "recovery_active": 0, "permission_changes": 2,
              "permission_resolutions": 2, "kp_materials": 3}
    check(all(tables[t]["rows"] == n for t, n in counts.items()), "精确重试新增分配、请求或接受Commit")
    edge = current["edges"][0]
    check(edge["recovery_id"] == new["request_id"] and json.loads(edge["current_ref"]) == old["current_admission"]
          and current["roots"][0]["current_ref"] == edge["successor_ref"], "历史关闭意外获得接受后继")
    lab.case_evidence["completion"] = {"closed": closed, "fresh_intent": fresh, "accepted": accepted,
        "old_attempt": current, "original_before": original, "original_after": original_facts(lab),
        "expected_counts": counts, "final_state": facts(lab)}


CASES = {"E06_close_response_lost": close_response_lost}
