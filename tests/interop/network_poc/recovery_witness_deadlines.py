"""真实系统时间到期；不改系统时钟，不绕过 OpenMLS Lifetime。"""

import copy
import time

from .fixture import check
from .key_package_fixture import decode
from .recovery_competition_cases import recovery_ledger
from .recovery_watermark_cases import resume


def wait_expired(lab, label, deadline):
    started = time.time()
    while int(time.time()) < deadline:
        time.sleep(min(.1, max(.01, deadline - time.time())))
    lab.case_evidence.setdefault("real_deadlines", []).append({
        "label": label, "not_after_unix_secs": deadline, "started_at": started,
        "finished_at": time.time(), "clock_source": "actual OS UTC seconds; no substituted MLS time"})


def request_deadline(lab):
    lab.setup_w1()
    _, accepted = lab.accepted()
    record = accepted["record"]
    request = lab.witness_request(record, ttl="3")["request"]
    delivery = lab.respond(record, request)["delivery"]
    deadline = int(decode(request)["expires_at_unix_secs"])
    wait_expired(lab, "request-and-response", deadline)
    lab.unchanged("T", "first-install-after-request-expiry",
        lambda: lab.install(record, request, delivery, expected_exit=1), "w1_deadline_expired")
    lab.observed("W", "actual-r1-survives-response-expiry", lab.witness_command(lab.witness, "inspect"))


def response_deadline(lab):
    lab.setup_w1()
    _, accepted = lab.accepted()
    record = accepted["record"]
    request = lab.witness_request(record)["request"]
    delivery = lab.respond(record, request)["delivery"]
    response = decode(delivery["response"])
    deadline = int(time.time()) + 2
    response["expires_at_unix_secs"] = str(deadline)
    changed = copy.deepcopy(delivery)
    changed["response"] = lab.sign_witness_fixture(lab.witness, "response", response)
    wait_expired(lab, "shorter-response-only", deadline)
    check(int(time.time()) < int(decode(request)["expires_at_unix_secs"]),
          "响应单变量用例连请求也已到期")
    lab.unchanged("T", "first-install-after-response-expiry",
        lambda: lab.install(record, request, changed, expected_exit=1), "w1_deadline_expired")
    legal = lab.install(record, request, delivery)
    check(legal["installed"], "原合法仍有效响应不能安装")
    lab.observed("T", "original-still-live-response-control", legal)


def package_deadline(lab):
    lab.setup_w1()
    intent, accepted = lab.accepted(package_ttl=15)
    record = accepted["record"]
    material = lab.pool(lab.target)["packages"][decode(intent)["key_package_sha256"]]["material"]
    deadline = int(material["not_after"])
    remaining = deadline - int(time.time())
    check(remaining > 1, "请求构造前材料已到期，装置没有进入目标窗口")
    request = lab.witness_request(record, ttl=str(remaining))["request"]
    delivery = lab.respond(record, request)["delivery"]
    check(int(decode(request)["expires_at_unix_secs"]) == deadline,
          "未对齐真实新材料与挑战期限")
    wait_expired(lab, "material-request-response-simultaneous", deadline)
    lab.unchanged("T", "material-expiry-has-frozen-precedence",
        lambda: lab.install(record, request, delivery, expected_exit=1), "w1_material_expired")
    lab.case_evidence["failure_attribution"] = {
        "primary": "w1_material_expired", "other_expired_guards": ["request", "response"],
        "single_variable": False}


def installed_retry_expired(lab):
    lab.setup_w1()
    intent, accepted = lab.accepted(package_ttl=15)
    record = accepted["record"]
    material = lab.pool(lab.target)["packages"][decode(intent)["key_package_sha256"]]["material"]
    deadline = int(material["not_after"])
    request = lab.witness_request(record, ttl=str(deadline - int(time.time())))["request"]
    delivery = lab.respond(record, request)["delivery"]
    installed = lab.install(record, request, delivery)
    check(installed["installed"], "期限内没有真实安装")
    resume(lab, lab.target)
    ledger = recovery_ledger(lab)
    wait_expired(lab, "installed-material-and-witness", deadline)
    for phase in ("expired", "fresh-restart"):
        if phase == "fresh-restart":
            lab.restart()
        result = lab.unchanged("T", phase + "-exact-original",
            lambda: lab.install(record, request, delivery))
        check(result["installed"] and result["duplicate"], "已安装精确重试重新要求新见证")
    check(recovery_ledger(lab) == ledger, "到期精确重试新增分配或 Commit")


CASES = {
    "WC07-01-request-deadline": request_deadline,
    "WC07-02-response-deadline": response_deadline,
    "WC07-03-package-deadline": package_deadline,
    "WC10-01-installed-exact-retry-expired": installed_retry_expired,
}
