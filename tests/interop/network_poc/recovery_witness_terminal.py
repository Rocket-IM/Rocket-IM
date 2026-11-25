"""W1 保持原分配、关闭与唯一接受后继生命周期。"""

import time

from .fixture import check
from .first_trust_evidence import state
from .key_package_fixture import decode
from .recovery_close_cases import attempt_facts, close_committed
from .recovery_watermark_cases import original_facts, resume
from .recovery_witness_deadlines import wait_expired


def allocated_close(lab):
    lab.setup_w1()
    intent, _, _, bundle = lab.prepare_recovery()
    close = lab.control_proof(intent, "close", lab.target)
    original = original_facts(lab)
    before, before_attempt = state(lab), attempt_facts(lab, intent)
    closed = lab.remote_recovery(lab.target, "close", intent=intent, proof=close)
    after, after_attempt = state(lab), attempt_facts(lab, intent)
    check(closed["state"] == "closed" and closed["record"] is None, "分配没有正常关闭")
    close_committed(lab, before_attempt, after_attempt, original, close, before, after)
    for device, role in ((lab.actor, "A"), (lab.target, "T")):
        result = lab.recovery(device, "resolve", intent=intent, receipt=closed["receipt"])
        check(result["state"] == "closed" and not result["duplicate"], "关闭终态未持久解析")
        lab.observed(role, "normal-signed-close-resolve", result)
    exact = lab.unchanged("T", "closed-request-exact-retry",
        lambda: lab.remote_recovery(lab.target, "close", intent=intent, proof=close))
    check(exact == closed, "精确关闭重试改变终态")
    lab.case_evidence["closed_allocation"] = {"bundle": bundle, "before": before_attempt,
        "after": after_attempt, "closed": closed}


def accepted_close(lab):
    lab.setup_w1()
    intent, accepted = lab.accepted()
    close = lab.control_proof(intent, "close", lab.target)
    result = lab.unchanged("T", "accepted-close-returns-original",
        lambda: lab.remote_recovery(lab.target, "close", intent=intent, proof=close))
    check(result == accepted and result["state"] == "accepted", "关闭改写已接受原件")
    repeated = lab.unchanged("T", "accepted-close-exact-retry",
        lambda: lab.remote_recovery(lab.target, "close", intent=intent, proof=close))
    check(repeated == accepted, "已接受关闭精确重试改变原件")
    record = accepted["record"]
    request = lab.witness_request(record)["request"]
    delivery = lab.respond(record, request)["delivery"]
    installed = lab.install(record, request, delivery)
    check(installed["installed"], "对 accepted 请求关闭损坏合法安装")
    lab.observed("T", "accepted-still-installable", installed)


def accepted_successor(lab, reject_previous=False):
    lab.setup_w1()
    first_intent, first = lab.accepted(package_ttl=15)
    first_record = first["record"]
    deadline = int(lab.pool(lab.target)["packages"][decode(first_intent)["key_package_sha256"]]["material"]["not_after"])
    first_request = lab.witness_request(first_record, ttl=str(deadline - int(time.time())))["request"]
    first_delivery = lab.respond(first_record, first_request)["delivery"]
    original = attempt_facts(lab, first_intent)
    wait_expired(lab, "current-accepted-material-before-new-successor", deadline)
    next_intent, second = lab.accepted("w1-successor")
    second_record = second["record"]
    parsed = decode(next_intent)
    check(parsed["current_admission"] != parsed["root_admission"],
          "新意图回退原根而非接续当前已接受端点")
    current = attempt_facts(lab, first_intent)
    check(all(current[key] == original[key] for key in ("attempt", "material", "requests"))
          and current["edges"][:1] == original["edges"] and len(current["edges"]) == 2,
          "新后继改写旧接受或产生重复边")
    lab.observed("W", "actual-second-r1-and-unique-successor", lab.recovery(lab.witness, "inspect"))
    if reject_previous:
        lab.unchanged("T", "previous-r0-cannot-first-install-after-successor",
            lambda: lab.install(first_record, first_request, first_delivery, expected_exit=1),
            "w1_superseded")
    request = lab.witness_request(second_record, ident="w1-successor-request")["request"]
    delivery = lab.respond(second_record, request)["delivery"]
    installed = lab.install(second_record, request, delivery)
    check(installed["installed"] and not installed["duplicate"], "合法后继未首次安装")
    resume(lab, lab.target)
    lab.observed("T", "latest-accepted-r1", installed)
    lab.case_evidence["unique_successor"] = {"first": first, "second": second,
        "before": original, "after": current}


CASES = {
    "WC09-01-allocated-normal-close": allocated_close,
    "WC09-02-accepted-close-original": accepted_close,
    "WC09-03-expired-current-eligible-successor": accepted_successor,
    "WC09-05-superseded-r0": lambda lab: accepted_successor(lab, True),
}
