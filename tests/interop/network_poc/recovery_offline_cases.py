"""E09.b：离线位置与新材料期限四例，按实际待应用 Add 验证补链。"""

import hashlib
import re
import time

from .fixture import ACCOUNTS, CONVERSATION, check
from .consistency_cases import current_head, observe
from .first_trust_evidence import state
from .join_review_regressions import public_record
from .key_package_fixture import decode
from .recovery_competition_cases import recovery_ledger
from .recovery_consistency_cases import permission_change
from .recovery_watermark_cases import (
    blocked, checkpoint, facts, original_facts, original_preserved, resume, unchanged,
)


OFFLINE = "b1"


def mls_view(lab):
    return {"group": lab.rust(OFFLINE, "inspect"),
            "permission": lab.rust(OFFLINE, "permission_inspect"),
            "wire": lab.rust(OFFLINE, "wire_inspect")}


def wait_until(deadline):
    while time.time() <= deadline:
        time.sleep(.1)


def send(lab, logical, sender="a1", receivers=()):
    payload = "synthetic-e09-" + logical
    packet = lab.rust(sender, "wire_send", logical_message_id=logical, attempt_id="P1", payload=payload)
    accepted = lab.submit(packet, device=sender)
    lab.rust(sender, "wire_accept", logical_message_id=logical, attempt_id="P1",
             acceptance_receipt=accepted["acceptance_receipt"])
    expected = hashlib.sha256(payload.encode()).hexdigest()
    for device in receivers:
        received = lab.receive(device, packet, acceptance_id=accepted["acceptance_id"],
                               acceptance_receipt=accepted["acceptance_receipt"])
        check(received["payload_sha256"] == expected and not received["duplicate"], "在线消息未实际解密")
    item = {"logical": logical, "sender": sender, "direct_receivers": list(receivers),
            "payload_sha256": expected, "packet": packet, "accepted": accepted}
    lab.case_evidence.setdefault("messages", []).append(item)
    return packet, accepted


def drain(lab, receiver, required):
    before = lab.rust(receiver, "wire_inspect")
    page = lab.pull(receiver, before["sync"]["download_cursor"])
    lab.download(receiver, page)
    processed = lab.rust(receiver, "wire_process")
    after = lab.rust(receiver, "wire_inspect")
    evidence = {"receiver": receiver, "required_acceptance": required, "before": before,
                "page": page.wrapper, "processed": processed, "after": after}
    lab.case_evidence.setdefault("signed_drains", []).append(evidence)
    known = {x["accepted"]["acceptance_id"]: x for x in lab.case_evidence["messages"]}
    slots = {x["event_id"]: x for x in page["events"]}
    isolated = {key for key, message in known.items() if receiver == lab.target
                and message["logical"] in ("before-recovery", "during-offline-change")}
    found, quarantined, added = [], [], 0
    for item in processed["results"]:
        result = item["result"]
        slot = slots[item["event_id"]]
        acceptance = slot["event"]["acceptance_id"]
        original = known.get(acceptance)
        check(original is not None and item["event_seq"] == slot["event_seq"]
              and slot["event"]["envelope"] == original["packet"]["envelope"], "签页消息来源不明")
        if acceptance in isolated:
            check(result == {"status": "quarantined", "code": "history_unavailable"}
                  and all(x["event_id"] != item["event_id"] for x in processed["deliveries"]),
                  "新目标的明确旧历史未隔离或误报成功投递")
            quarantined.append(acceptance)
            continue
        check(result["status"] == "valid" and result["acceptance_id"] == acceptance,
              "补链后签页含未解密消息")
        duplicate = receiver in original["direct_receivers"]
        check(result["message"]["payload_sha256"] == original["payload_sha256"]
              and result["message"]["logical_message_id"] == original["logical"]
              and result["message"]["duplicate"] == duplicate, "积压消息原件或去重不符")
        found.append(result["acceptance_id"])
        added += int(not duplicate)
    check(required in found and not page["has_more"] and not after["sync"]["halted"]
          and after["sync"]["pending_count"] == 0
          and after["sync"]["download_cursor"] == after["sync"]["processed_cursor"] == page["next_after_seq"]
          and int(after["sync"]["processed_cursor"]) > int(before["sync"]["processed_cursor"])
          and after["inbox_count"] == before["inbox_count"] + added
          and after["sync"]["quarantined_count"] == before["sync"]["quarantined_count"] + len(quarantined)
          and set(quarantined) == isolated.intersection(x["event"]["acceptance_id"] for x in slots.values()),
          "签页未完整推进、旧历史隔离或收件计数不符")
    evidence.update(new_messages=added, quarantined_acceptances=quarantined)


def pair(lab, peer, phase):
    for sender, receiver in ((peer, lab.actor), (lab.actor, peer)):
        _, accepted = send(lab, phase + "-" + sender, sender)
        drain(lab, receiver, accepted["acceptance_id"])


def setup(lab, applied, expired):
    lab.target, lab.actor = "d1", "a1"
    lab.publish("original-package", lab.target, count=1, ttl=10)
    lab.ready(); lab.claim("original-claim", change_id="original-add")
    candidate = lab.prepare_join("original-claim")
    accepted = lab.submit_join(candidate)
    record = {"change": candidate["change"], "receipt": accepted["receipt"]}
    online = tuple(d for d in ACCOUNTS if applied or d != OFFLINE)
    for device in online:
        lab.rust(device, "permission_recover", record=record)
    lab.original = lab.http(lab.target, "get_join_material", {"service_id": lab.service,
        "conversation_id": CONVERSATION, "change_id": "original-add"})
    check(lab.original == {"record": record, "join": candidate["join"]}, "原Add材料不符")
    for device in (*online, lab.target):
        lab.root = lab.recovery(device, "root", **lab.original)["reference"]
    offline_snapshot = state(lab)["snapshots"][OFFLINE]
    lab.case_evidence["offline_start"] = {"applied_original_add": applied,
        "snapshot": offline_snapshot, "mls": mls_view(lab), "recovery": lab.recovery(OFFLINE, "inspect")}
    check(checkpoint(lab, OFFLINE)["authorization_version"] == ("2" if applied else "1"),
          "离线位置不真实")
    for device in (lab.actor, lab.target):
        for member in (lab.actor, lab.target):
            lab.fetch_directory(device, member, "e09-directory-" + member)
    lab.scope = {"service_id": lab.service, "conversation_id": CONVERSATION,
                 "group_id": lab.rust(lab.actor, "inspect")["group_id"]}
    lab.old_packet, lab.old_acceptance = send(lab, "before-recovery", receivers=("a2", "c1"))
    original = original_facts(lab)
    old_deadline = int(next(iter(lab.pool(lab.target)["packages"].values()))["material"]["not_after"])
    wait_until(old_deadline)
    unrelated = permission_change(lab, "e09-unrelated-remove")
    for device in ("a1", "a2", "c1"):
        lab.rust(device, "permission_recover", record=unrelated)
    lab.recovery(lab.target, "advance", record=unrelated)
    original_preserved(lab, original)
    send(lab, "during-offline-change", receivers=("a2",))
    intent, _, _, bundle = lab.prepare_recovery("e09-recovery", package_ttl=15 if expired else 60)
    accepted = lab.accept_recovery(bundle)
    lab.install_recovery(accepted["record"], ("a1", "a2", lab.target))
    latest = checkpoint(lab, lab.actor)
    send(lab, "during-offline-recovery", receivers=(lab.target,))
    package = lab.pool(lab.target)["packages"][decode(intent)["key_package_sha256"]]
    new_deadline = int(package["material"]["not_after"])
    if expired:
        wait_until(new_deadline)
    returned = time.time()
    check((returned > new_deadline) == expired and returned > old_deadline,
          "四例未进入指定真实期限")
    check(state(lab)["snapshots"][OFFLINE] == offline_snapshot, "离线期间改写了离线成员状态")
    lab.case_evidence["online_chain"] = {"original": lab.original, "unrelated": unrelated,
        "recovery": accepted, "latest": latest, "old_not_after": old_deadline,
        "new_not_after": new_deadline, "returned_at_unix_secs": returned,
        "new_material_expired": expired, "offline_snapshot_unchanged": True}
    return unrelated, accepted["record"], latest, original_facts(lab), recovery_ledger(lab)


def paused(lab, latest, name):
    view = lab.rust(OFFLINE, "consistency_inspect")
    check(view["status"] == "needs_sync" and view["paused"]
          and view["highest_observed_checkpoint"] == latest, "未持续保存真实更高水位与暂停")
    blocked(lab, OFFLINE, name + "-send")


def early_resume(lab, latest, name):
    before = facts(lab)
    mls = mls_view(lab)
    resume(lab, OFFLINE)
    after = facts(lab)
    check(mls_view(lab) == mls and before["durable"]["relay"] == after["durable"]["relay"]
          and all(after["durable"]["snapshots"][d] == v for d, v in before["durable"]["snapshots"].items()
                  if d != OFFLINE), "提前resume推进实际群或改写其他状态")
    lab.case_evidence.setdefault("early_resumes", []).append({"name": name, "before": before,
        "after": after, "mls_unchanged": mls})
    paused(lab, latest, name)


def lifetime_failure(lab, action, code, name, deadline):
    started = time.time()
    check(started > deadline, "未跨过实际待应用Add期限")
    error = unchanged(lab, name, action, code)
    lab.case_evidence.setdefault("lifetime_failures", []).append({"name": name,
        "not_after": deadline, "started_at_unix_secs": started,
        "finished_at_unix_secs": time.time(), "error": error,
        "new_material_valid_at_start": started < lab.case_evidence["online_chain"]["new_not_after"]})
    actual = re.search(r"Lifetime is in the past: not_after=(\d+), now=(\d+)", error["message"])
    check(actual is not None and int(actual[1]) == deadline and int(actual[2]) >= deadline,
          "负例未到达真实MLS期限校验，不能以缺链或WrongEpoch代替")


def offline_case(lab, applied, expired):
    unrelated, record, latest, original, ledger = setup(lab, applied, expired)
    public = public_record(record)
    before = mls_view(lab)
    head = current_head(lab, OFFLINE)
    observe(lab, head, OFFLINE)
    check(mls_view(lab) == before, "公开head冒充实际补链")
    lab.case_evidence["return_head"] = head
    early_resume(lab, latest, "before-chain")
    unchanged(lab, "restart-before-chain", lab.restart)
    early_resume(lab, latest, "restart-before-chain")
    if applied:
        missing = lab.recovery(OFFLINE, "observe", record=public)
        check(missing["state"] == "consistency_paused" and mls_view(lab) == before,
              "缺无关前驱时恢复记录快进实际群")
        lab.case_evidence["missing_predecessor"] = missing
        unchanged(lab, "apply-before-predecessor", lambda: lab.recovery(OFFLINE, "apply",
            record=public, expected_exit=1), "recovery_observe_required")
        lab.rust(OFFLINE, "permission_recover", record=unrelated)
        check(checkpoint(lab, OFFLINE)["authorization_version"] == "3", "无关Remove补链不准确")
        observed = lab.recovery(OFFLINE, "observe", record=public)
        check(observed == {"duplicate": False, "installed": False}, "实际R1前未保存准确R0")
        early_resume(lab, latest, "public-r0-before-r1")
        deadline = lab.case_evidence["online_chain"]["new_not_after"]
        action = lambda: lab.recovery(OFFLINE, "apply", record=public, expected_exit=1)
        code = "recovery_commit"
    else:
        unchanged(lab, "missing-root-observe", lambda: lab.recovery(OFFLINE, "observe",
            record=public, expected_exit=1), "recovery_chain_missing")
        unchanged(lab, "missing-root-create", lambda: lab.recovery(OFFLINE, "root",
            **lab.original, expected_exit=1), "recovery_chain_missing")
        deadline = lab.case_evidence["online_chain"]["old_not_after"]
        action = lambda: lab.rust(OFFLINE, "permission_recover", record=lab.original["record"], expected_exit=1)
        code = "permission_commit"
    if applied and not expired:
        started = time.time()
        check(started < deadline, "及时正例在实际Apply前意外过期")
        result = lab.recovery(OFFLINE, "apply", record=public)
        lab.case_evidence["successful_apply"] = {"started_at_unix_secs": started,
            "finished_at_unix_secs": time.time(), "not_after": deadline, "result": result}
        check(result["installed"] and not result["duplicate"] and result["checkpoint"] == latest
              and checkpoint(lab, OFFLINE) == latest, "真实补链未达到同一完整后继")
        paused(lab, latest, "r1-still-paused")
        unchanged(lab, "restart-before-final-resume", lab.restart)
        paused(lab, latest, "restart-r1-still-paused")
        resume(lab, OFFLINE)
        check(lab.rust(OFFLINE, "consistency_inspect")["status"] == "no_known_conflict", "完整补链后不能显式恢复")
        pair(lab, OFFLINE, "caught-up-before-restart")
        unchanged(lab, "restart-after-catchup", lab.restart)
        pair(lab, OFFLINE, "caught-up-after-restart")
    else:
        for phase in ("first", "after-restart"):
            if phase == "after-restart":
                unchanged(lab, "restart-after-expiry", lab.restart)
            lifetime_failure(lab, action, code, phase + "-expired-add", deadline)
            early_resume(lab, latest, phase + "-after-expiry")
    # 即使离线幸存者无法补链，其他已安装最新R1的成员仍可通信。
    pair(lab, lab.target, "online-members")
    check(original_facts(lab) == original and recovery_ledger(lab) == ledger,
          "补链、过期或消息改写原accepted/材料/后继，或递归创建新恢复")
    if not (applied and not expired):
        paused(lab, latest, "final-expired")
    lab.case_evidence["completion"] = {"expected": "caught_up" if applied and not expired else "expired_paused",
        "offline": mls_view(lab), "consistency": lab.rust(OFFLINE, "consistency_inspect"),
        "recovery": lab.recovery(OFFLINE, "inspect"), "main": facts(lab),
        "original_unchanged": True, "recovery_ledger": ledger, "no_recursive_recovery": True}


CASES = {
    "E09_applied_add_before_new_expiry": lambda lab: offline_case(lab, True, False),
    "E09_applied_add_after_new_expiry": lambda lab: offline_case(lab, True, True),
    "E09_unapplied_add_before_new_expiry": lambda lab: offline_case(lab, False, False),
    "E09_unapplied_add_after_new_expiry": lambda lab: offline_case(lab, False, True),
}
