"""E05.c：真实竞争败者在R1及版本推进后原字节重放，拒绝不留半提交。"""

import copy
import hashlib
import json
import secrets

from .fixture import ACCOUNTS, check
from .first_trust_evidence import state
from .key_package_fixture import decode, transaction
from .recovery_consistency_cases import permission_change
from .recovery_retry_cases import communicate
from .recovery_watermark_cases import (
    assert_counts, checkpoint, original_facts, original_preserved, unchanged,
)


def recovery_ledger(lab):
    # 一次显式事务读取全部恢复账本及其已接受的权限/材料原件。
    with transaction(lab) as db:
        result = {table: [dict(row) for row in db.execute(
            "SELECT * FROM " + table + " ORDER BY rowid")]
            for table in ("recovery_attempts", "recovery_requests", "recovery_active",
                          "recovery_edges", "recovery_roots")}
        ids = [row["change_id"] for row in result["recovery_attempts"]]
        for table, column in (("permission_changes", "change_id"),
                              ("permission_resolutions", "change_id"),
                              ("kp_materials", "accepted_change")):
            result[table] = [dict(row) for ident in ids for row in db.execute(
                "SELECT * FROM " + table + " WHERE " + column + "=? ORDER BY rowid", (ident,))]
        return result


def unique_successor(lab, winner, loser):
    ledger = recovery_ledger(lab)
    attempts, edges = ledger["recovery_attempts"], ledger["recovery_edges"]
    check(len(attempts) == len(edges) == len(ledger["recovery_roots"]) == 1
          and attempts[0]["state"] == "accepted"
          and attempts[0]["recovery_id"] == winner["request_id"]
          and not ledger["recovery_active"], "竞争生成额外尝试、活动槽或接受后继")
    edge, root = edges[0], ledger["recovery_roots"][0]
    check(edge["root_id"] == root["root_id"] == attempts[0]["root_id"]
          and json.loads(edge["current_ref"]) == winner["current_admission"] == loser["current_admission"]
          and edge["recovery_id"] == winner["request_id"]
          and root["current_ref"] == edge["successor_ref"], "原接受没有唯一、准确的后继边")
    check(len(ledger["recovery_requests"]) == 2
          and all(row["recovery_id"] == winner["request_id"] for row in ledger["recovery_requests"]),
          "败者留下请求预留或重复分配")
    check(all(len(ledger[table]) == 1 for table in
              ("permission_changes", "permission_resolutions", "kp_materials")),
          "接受的Commit、权限结果或材料不唯一")
    return ledger


def drain_actor(lab, actor, phase):
    """群消息也投递其他成员；先逐条核验积压，再使用单条收发辅助函数。"""
    before = lab.rust(actor, "wire_inspect")
    page = lab.pull(actor, before["sync"]["download_cursor"])
    lab.download(actor, page)
    processed = lab.rust(actor, "wire_process")
    after = lab.rust(actor, "wire_inspect")
    lab.case_evidence.setdefault("backlog_drains", []).append({
        "actor": actor, "phase": phase, "before": before, "page": page.wrapper,
        "processed": processed, "after": after})
    known = {lab.old_acceptance["acceptance_id"]: {
        "logical_message_id": "before-recovery",
        "payload_sha256": hashlib.sha256(b"synthetic-first-trust-before-recovery").hexdigest(),
        "duplicate": True}}
    for item in lab.case_evidence.get("communications", []):
        known[item["accepted"]["acceptance_id"]] = {
            "logical_message_id": item["logical"],
            "payload_sha256": hashlib.sha256(("synthetic-e02-" + item["logical"]).encode()).hexdigest(),
            "duplicate": False}
    added = 0
    for item in processed["results"]:
        result = item["result"]
        expected = known.get(result.get("acceptance_id"))
        check(result["status"] == "valid" and expected is not None
              and all(result["message"][key] == value for key, value in expected.items()),
              "积压消息未按原接受/正文正确解密，或错误重复处理")
        added += int(not result["message"]["duplicate"])
    check(not page["has_more"] and not after["sync"]["halted"]
          and after["sync"]["pending_count"] == 0
          and after["sync"]["download_cursor"] == after["sync"]["processed_cursor"] == page["next_after_seq"]
          and int(after["sync"]["processed_cursor"]) >= int(before["sync"]["processed_cursor"])
          and after["inbox_count"] == before["inbox_count"] + added,
          "积压处理跳过消息、回退游标或错误增加收件箱")


def loser_replay(lab):
    lab.setup_expired()
    original = original_facts(lab)
    # a2必须真实核验目标并持有准确目录，不能因装置缺信任而无法准备赢家。
    lab.ready("a2", lab.target, "e05-a2-target")
    lab.fetch_directory("a2", "a2", "e05-a2-owner")
    first = lab.intent("e05-first")
    first_claim = lab.control_proof(first)
    rival = decode(first)
    rival.update(request_id="e05-rival", change_id="change-e05-rival",
                 nonce=secrets.token_hex(32), actor=lab.member("a2"))
    # 第二个并存目标意图使用既有显式probe签名；不修改目标的请求账本。
    # 两批准者的claim均走正常签名/持久化入口，后续准备、R0/R1与通信也用正常程序。
    second = lab.sign_probe(lab.target, rival)
    second_claim = lab.control_proof(second, device="a2")
    contenders = [("a1", first, first_claim), ("a2", second, second_claim)]
    bodies = [json.dumps({"kind": "claim", "intent": intent, "proof": claim}).encode()
              for _, intent, claim in contenders]
    body_hashes = [hashlib.sha256(body).hexdigest() for body in bodies]
    lab.case_evidence["original_requests"] = [
        {"actor": actor, "intent": intent, "claim": claim,
         "body_utf8": body.decode(), "body_sha256": digest}
        for (actor, intent, claim), body, digest in zip(contenders, bodies, body_hashes)]
    before_race = state(lab)
    results = lab.simultaneous([
        lambda index=index: lab.http(contenders[index][0], "join_recovery", {},
                                    raw=bodies[index], expected=(200, 409))
        for index in range(2)])
    lab.case_evidence["competition"] = {"results": results, "before": before_race, "after": state(lab)}
    check(sum(r.get("state") == "allocated" for r in results) == 1
          and sum(r.get("code") == "recovery_busy" for r in results) == 1,
          "真实并发未产生一个赢家与一个recovery_busy败者")
    check(state(lab)["snapshots"] == before_race["snapshots"], "远程竞争改变本机私有状态")
    win = 0 if results[0].get("state") == "allocated" else 1
    lose = 1 - win
    lab.actor, intent, claim = contenders[win]
    loser_actor, loser_intent, _ = contenders[lose]
    winner, loser = decode(intent), decode(loser_intent)
    allocated = results[win]
    ledger = recovery_ledger(lab)
    check(len(ledger["recovery_attempts"]) == len(ledger["recovery_active"]) == 1
          and not ledger["recovery_edges"] and len(ledger["recovery_requests"]) == 2
          and all(row["recovery_id"] == winner["request_id"]
                  for table in ("recovery_attempts", "recovery_requests", "recovery_active")
                  for row in ledger[table]), "首轮败者已留下半记录")
    lab.case_evidence["race_outcome"] = {"winner": lab.actor, "loser": loser_actor, "ledger": ledger}
    bundle = lab.recovery(lab.actor, "prepare", intent=intent, claim=claim,
                          allocation=allocated["allocation"], key_package=allocated["key_package"])["bundle"]
    accepted = lab.accept_recovery(bundle)
    check(accepted["state"] == "accepted", "赢家没有真实R0")
    lab.install_recovery(accepted["record"])
    accepted_ledger = unique_successor(lab, winner, loser)
    lab.case_evidence["winner_accepted"] = accepted
    installed = checkpoint(lab, lab.target)
    check(all(checkpoint(lab, d) == installed for d in (*ACCOUNTS, lab.target)), "赢家R1未实际安装")

    successor = permission_change(lab, "e05-normal-version-successor")
    for device in (*ACCOUNTS, lab.target):
        lab.rust(device, "permission_recover", record=successor)
    advanced = checkpoint(lab, lab.target)
    check(int(advanced["authorization_version"]) == int(installed["authorization_version"]) + 1
          and advanced["crypto_state_ref"] != installed["crypto_state_ref"]
          and all(checkpoint(lab, d) == advanced for d in ("a1", "a2", "b1", lab.target))
          and all(lab.member(d) in advanced["members"] for d in ("a1", "a2", lab.target)),
          "未实际推进版本或错误撤销了竞争者/目标资格")
    lab.case_evidence["version_progress"] = {"r1": installed, "successor": successor, "advanced": advanced}

    for phase in ("after-version-progress", "after-relay-restart"):
        if phase == "after-relay-restart":
            unchanged(lab, "relay-restart", lab.restart)
        check(hashlib.sha256(bodies[lose]).hexdigest() == body_hashes[lose], "重放改变了原HTTP正文")
        unchanged(lab, "loser-" + phase, lambda: lab.http(loser_actor, "join_recovery", {},
                  raw=bodies[lose], expected=409), "recovery_superseded")
        current = unchanged(lab, "winner-query-" + phase, lambda: lab.get_recovery(intent))
        expected = copy.deepcopy(accepted)
        expected["head"] = advanced  # 正常权限后继会更新响应head，不能误作旧原件被覆盖。
        check(current == expected, "赢家的原接受、分配、材料或Commit被重写")
        check(unique_successor(lab, winner, loser) == accepted_ledger, "拒绝或版本推进改写恢复账本")
        # 两位批准者均须继续双向通信，也覆盖重启后已推进的消息状态。
        for actor in (contenders[win][0], loser_actor):
            lab.actor = actor
            drain_actor(lab, actor, phase)
            communicate(lab, "e05-" + phase + "-" + actor)
        lab.actor = contenders[win][0]
    check(unique_successor(lab, winner, loser) == accepted_ledger, "后续通信改写唯一恢复后继")
    assert_counts(lab, 1)
    original_preserved(lab, original)
    lab.case_evidence["final_ledger"] = accepted_ledger


CASES = {"E05_loser_replay_after_version_advance": loser_replay}
