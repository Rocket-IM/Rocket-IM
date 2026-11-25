"""E10C-W1 第一条纵向链：正常私有 Commit、见证持久化及目标独立安装。"""

from .fixture import check
from .first_trust_evidence import state
from .recovery_competition_cases import recovery_ledger
from .recovery_offline_cases import pair
from .recovery_watermark_cases import resume


def honest_witness(lab):
    lab.setup_w1()
    _, accepted = lab.accepted()
    record = accepted["record"]
    ledger = recovery_ledger(lab)
    request = lab.witness_request(record)["request"]
    response = lab.respond(record, request)
    delivery = response["delivery"]
    lab.observed("W", "durable-r1-then-response", response)
    before = state(lab)
    result = lab.install(record, request, delivery)
    after = state(lab)
    check(result["installed"] and not result["duplicate"], "目标没有首次安装真实 R1")
    check(before["relay"] == after["relay"]
          and all(before["snapshots"][d] == value for d, value in after["snapshots"].items()
                  if d != lab.target), "目标安装越界写入")
    lab.observed("T", "independent-welcome-and-atomic-install", result)
    resume(lab, lab.target)
    for phase in ("installed", "fresh-process-reload"):
        if phase == "fresh-process-reload":
            lab.restart()
        exact = lab.unchanged("T", phase + "-exact-install",
            lambda: lab.install(record, request, delivery))
        check(exact["installed"] and exact["duplicate"], "精确安装重试不幂等")
        pair(lab, lab.witness, "w1-w-" + phase)
        pair(lab, lab.target, "w1-t-" + phase)
    check(recovery_ledger(lab) == ledger, "见证或目标通信增加分配、Commit 或接受后继")
    lab.case_evidence["accepted_ledger_unchanged"] = ledger


def witness_not_installed(lab):
    lab.setup_w1()
    _, accepted = lab.accepted(install_witness=False)
    record = accepted["record"]
    request = lab.witness_request(record)["request"]
    lab.unchanged("W", "cannot-sign-before-real-r1",
        lambda: lab.respond(record, request, expected_exit=1), "w1_witness_not_installed")
    lab.unchanged("T", "plain-apply-cannot-bypass-witness",
        lambda: lab.recovery(lab.target, "apply", record=record, expected_exit=1),
        "w1_witness_not_installed")
    check(lab.recovery(lab.target, "inspect")["installed_count"] == 0,
          "幸存者拒绝后目标却安装了 R1")
    lab.unchanged("T", "target-send-stays-blocked",
        lambda: lab.rust(lab.target, "wire_send", logical_message_id="w1-no-w",
            attempt_id="P1", payload="synthetic-uninstalled", expected_exit=1), "join_required")


CASES = {
    "WC01-01-honest-w-durable-then-target": honest_witness,
    "WC01-02-w-r1-not-durable-no-statement": witness_not_installed,
}

from .recovery_witness_lifecycle import CASES as LIFECYCLE_CASES
CASES.update(LIFECYCLE_CASES)
from .recovery_witness_bindings import CASES as BINDING_CASES
CASES.update(BINDING_CASES)
from .recovery_witness_deadlines import CASES as DEADLINE_CASES
CASES.update(DEADLINE_CASES)
from .recovery_witness_migration import CASES as MIGRATION_CASES
CASES.update(MIGRATION_CASES)
from .recovery_witness_terminal import CASES as TERMINAL_CASES
CASES.update(TERMINAL_CASES)
from .recovery_witness_permissions import CASES as PERMISSION_CASES
CASES.update(PERMISSION_CASES)
from .recovery_witness_survivors import CASES as SURVIVOR_CASES
CASES.update(SURVIVOR_CASES)
from .recovery_witness_edges import CASES as EDGE_CASES
CASES.update(EDGE_CASES)
from .recovery_witness_limits import CASES as LIMIT_CASES
CASES.update(LIMIT_CASES)
