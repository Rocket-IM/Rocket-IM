"""W1 请求生命周期与真实快照提交退出窗口。"""

from .fixture import check
from .first_trust_evidence import state
from .join_review_regressions import public_record
from .recovery_competition_cases import recovery_ledger
from .recovery_watermark_cases import resume


def prepared(lab, *, install_witness=True):
    lab.setup_w1()
    _, accepted = lab.accepted(install_witness=install_witness)
    record = accepted["record"]
    request = lab.witness_request(record)["request"]
    return record, request


def exact_retry(lab):
    record, request = prepared(lab)
    delivery = lab.respond(record, request)["delivery"]
    before_ledger = recovery_ledger(lab)
    retried_request = lab.unchanged("T", "request-output-lost-exact-retry",
        lambda: lab.witness_request(record))
    retried_response = lab.unchanged("W", "response-output-lost-exact-retry",
        lambda: lab.respond(record, request))
    check(retried_request["request"] == request and retried_request["duplicate"],
          "相同请求重签、延长期限或增加挑战")
    check(retried_response["delivery"] == delivery and retried_response["duplicate"],
          "响应精确重试改变保存原件")
    check(recovery_ledger(lab) == before_ledger, "纯见证重试写 Relay 或新增恢复")


def cancelled(lab):
    record, request = prepared(lab)
    delivery = lab.respond(record, request)["delivery"]
    result = lab.witness_command(lab.target, "cancel", request_id="w1-request")
    lab.observed("T", "cancel-is-persisted-first", result)
    lab.unchanged("T", "cancelled-request-cannot-install",
        lambda: lab.install(record, request, delivery, expected_exit=1), "w1_challenge_inactive")
    check(lab.recovery(lab.target, "inspect")["installed_count"] == 0, "取消后仍安装 R1")


def replaced(lab):
    record, request = prepared(lab)
    delivery = lab.respond(record, request)["delivery"]
    replacement = lab.witness_request(record, ident="w1-request-next")["request"]
    check(replacement != request, "替代挑战没有新原件")
    lab.observed("T", "replacement-is-persisted-first", replacement)
    lab.unchanged("T", "replaced-request-cannot-install",
        lambda: lab.install(record, request, delivery, expected_exit=1), "w1_challenge_inactive")


def refresh(lab):
    lab.setup_w1()
    _, accepted = lab.accepted()
    record = accepted["record"]
    original = lab.witness_request(record, ttl="3")["request"]
    previous = lab.respond(record, original)["delivery"]
    ledger = recovery_ledger(lab)
    from .key_package_fixture import decode
    from .recovery_witness_deadlines import wait_expired
    wait_expired(lab, "old-challenge-before-refresh", int(decode(original)["expires_at_unix_secs"]))
    request = lab.witness_request(record, ident="w1-refresh")["request"]
    response = lab.respond(record, request)
    check(response["delivery"] != previous and recovery_ledger(lab) == ledger,
          "新挑战没有绑定新请求或改变恢复分配")
    lab.observed("W", "respond-from-existing-installation-fact", response)
    result = lab.install(record, request, response["delivery"])
    check(result["installed"] and not result["duplicate"], "新挑战没有允许同一 R0 的正常安装")
    lab.observed("T", "same-r0-new-challenge-install", result)


def challenge_limit(lab):
    record, _ = prepared(lab)
    ledger = recovery_ledger(lab)
    for index in range(2, 17):
        lab.witness_request(record, ident="w1-request-" + str(index))
    lab.unchanged("T", "seventeenth-challenge-does-not-reserve",
        lambda: lab.witness_request(record, ident="w1-request-17", expected_exit=1),
        "w1_resource_exhausted")
    check(recovery_ledger(lab) == ledger, "挑战上限拒绝分配了新恢复")


def cancelled_after_install(lab):
    record, request = prepared(lab)
    delivery = lab.respond(record, request)["delivery"]
    result = lab.install(record, request, delivery)
    check(result["installed"], "先 Apply 未安装")
    lab.observed("T", "install-wins-serialized-order", result)
    lab.unchanged("T", "cancel-after-install-cannot-roll-back",
        lambda: lab.witness_command(lab.target, "cancel", request_id="w1-request"))
    duplicate = lab.unchanged("T", "installed-fact-survives-cancel",
        lambda: lab.install(record, request, delivery))
    check(duplicate["installed"] and duplicate["duplicate"], "取消撤销了已安装历史事实")


def snapshot_exit(lab, phase, after):
    record, request = prepared(lab, install_witness=phase != "w-install")
    point, exit_code = ("after_save", 85) if after else ("before_save", 83)
    delivery = lab.respond(record, request)["delivery"] if phase == "target" else None
    before = state(lab)
    anchors_before = lab.anchor_views()
    if phase == "w-install":
        device, role = lab.witness, "W"
        action = lambda **options: lab.recovery(device, "apply", record=public_record(record), **options)
    elif phase == "response":
        device, role = lab.witness, "W"
        action = lambda **options: lab.respond(record, request, **options)
    else:
        device, role = lab.target, "T"
        action = lambda **options: lab.install(record, request, delivery, **options)
    options = {"failpoint": point}
    if after and device in lab.configs:
        point, exit_code = "anchor_after_finish", 88
        options = {"env": {"RIM_ANCHOR_FAILPOINT": "after_finish"}}
    check(action(**options, expected_exit=exit_code) is None, "退出窗口提前输出成功")
    after_exit = state(lab)
    anchors_after = lab.anchor_views()
    lab.role_results[role].append({"label": phase + "-" + point, "exit_code": exit_code,
        "before": before, "after": after_exit, "success_output": False,
        "anchors_before": anchors_before, "anchors_after": anchors_after,
        "classification": "committed-output-lost" if after else "w1_persistence_failed"})
    check(before["relay"] == after_exit["relay"] and
          all(before["snapshots"][d] == value for d, value in after_exit["snapshots"].items()
              if d != device), "单设备提交退出改变其他状态")
    check((before["snapshots"][device] != after_exit["snapshots"][device]) == after,
          "退出不在指定持久化边界")
    check(all(anchors_after[key] == value for key, value in anchors_before.items()
              if key != device), "单设备退出改变其他设备锚")
    if after and device in lab.configs:
        recovered = lab.rust(device, "anchor_resume")
        lab.observed(role, "normal-anchor-resume-after-finished-commit", recovered)
    if not after:
        queried = lab.reload_diagnostic(device, "fresh-reload-and-query-exact-records")
        if queried["exit_code"] != 0 and device in lab.configs:
            lab.reload_diagnostic(device, "normal-anchor-resume-after-failed-precommit",
                                  operation="anchor_resume")
        check(queried["exit_code"] == 0 and queried["result"].get("ok"),
              "完整旧快照保留，但冻结要求的新进程查询失败: " + str(queried["result"]))
    if not after and phase == "w-install":
        lab.unchanged("W", "failed-install-left-no-signable-fact",
            lambda: lab.respond(record, request, expected_exit=1), "w1_witness_not_installed")
    restarted = lab.unchanged(role, "committed-output-loss-exact-retry", action) if after else action()
    check(restarted.get("duplicate", False) == after, "新进程没有辨别真实已提交事实")
    lab.observed(role, "fresh-process-retry", restarted)
    if phase == "w-install":
        resume(lab, device)
        delivery = lab.respond(record, request)["delivery"]
    elif phase == "response":
        delivery = restarted["delivery"]
    if phase != "target":
        installed = lab.install(record, request, delivery)
        check(installed["installed"], "故障恢复后目标仍不能合法安装")
        lab.observed("T", "normal-install-after-durable-recovery", installed)
    resume(lab, lab.target)


CASES = {
    "WC06-01-request-response-exact-loss-retry": exact_retry,
    "WC06-03-cancelled": cancelled,
    "WC06-04-replaced": replaced,
    "WC06-06-refresh-same-accepted": refresh,
    "WC06-07-seventeenth-challenge": challenge_limit,
    "WC08-01-w-install-before-save": lambda lab: snapshot_exit(lab, "w-install", False),
    "WC08-02-w-install-after-save-lost-output": lambda lab: snapshot_exit(lab, "w-install", True),
    "WC08-03-response-before-save": lambda lab: snapshot_exit(lab, "response", False),
    "WC08-04-response-after-save-lost-output": lambda lab: snapshot_exit(lab, "response", True),
    "WC08-05-target-before-save": lambda lab: snapshot_exit(lab, "target", False),
    "WC08-06-target-after-save-lost-output": lambda lab: snapshot_exit(lab, "target", True),
    "WC08-08-replace-before-apply": replaced,
    "WC08-09-apply-before-cancel": cancelled_after_install,
}
