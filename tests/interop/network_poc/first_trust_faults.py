"""F10：注册事务、核验快照和真实独立锚的可恢复/持续阻断窗口。"""

from functools import partial
import http.client

from .fixture import check, identity
from .first_trust_evidence import database, state
from .first_trust_fixture import confirm, inspect, observe
from .first_trust_session import TrustSession, public_identity

POINTS = {"before_save": 83, "before_rename": 84, "after_save": 85,
          "after_reserve": 86, "after_journal": 87, "after_finish": 88}
HOOKS = ("before_commit_exit", "after_commit_exit", "drop_after_commit")


def relay_registration(lab, *, phase, hook):
    if phase == "begin":
        operation = "begin_device_registration"
        request = {"service_id": lab.service, "registration_id": "registration-fault",
                   "signature_key": lab.public["a1"]["signature_key"]}
    else:
        operation = "complete_device_registration"
        challenge = lab.begin_registration("a1", "registration-fault")
        request = {"service_id": lab.service, "proof": lab.prove_registration("a1", challenge)}
    before, process = state(lab), lab.process
    lab.control("hook", hook=hook)
    try:
        lab.http("a1", operation, request)
        raise AssertionError("Relay 故障没有切断 HTTP 输出")
    except (http.client.RemoteDisconnected, ConnectionResetError) as error:
        disconnected = type(error).__name__
    expected_exit = {"before_commit_exit": 86, "after_commit_exit": 87}.get(hook)
    actual_exit = process.poll() if expected_exit is None else process.wait(timeout=10)
    failed = state(lab)
    check(actual_exit == expected_exit and failed["snapshots"] == before["snapshots"], "HTTP 故障改变设备快照")
    if hook == "before_commit_exit":
        check(failed == before, "事务前退出写入部分注册")
    else:
        check(failed["relay"] != before["relay"], "提交后故障丢失注册记录")
    lab.restart()
    result = lab.http("a1", operation, request)
    committed = database(lab)
    check(lab.http("a1", operation, request) == result and database(lab) == committed,
          "注册精确重试改写原挑战/证明/公钥")
    if phase == "begin":
        proof = lab.prove_registration("a1", result)
        registered = lab.complete_registration("a1", proof)
    else:
        proof, registered = request["proof"], result
    check(registered["signature_key"] == lab.public["a1"]["signature_key"], "恢复错误绑定")
    lab.case_evidence.update(relay_fault={"phase": phase, "hook": hook, "pid": process.pid,
        "exit_code": actual_exit, "exception": disconnected, "before": before, "after_failure": failed},
        recovered=result, public_registration_proof={"proof": proof}, final_database=database(lab))


def preparation(lab, phase):
    independent = public_identity(lab, "b1")
    if phase != "observe":
        observe(lab)
    if phase == "reset":
        confirm(lab)
        independent = independent | {"signature_key": lab.public["d1"]["signature_key"]}
        lab.rust("a1", "identity_trust_observe", identity=independent)
    return independent


def check_committed(lab, phase, saved, independent):
    records = lab.rust("a1", "identity_trust_inspect")["records"]
    if phase == "observe":
        check(bool(records) == saved, "observe 保存边界不符")
        if not saved:
            lab.rust("a1", "identity_trust_observe", identity=independent)
    elif phase == "confirm":
        check(records[0]["status"] == ("verified" if saved else "unverified"), "确认保存边界不符")
    else:
        check(records[0]["status"] == ("unverified" if saved else "changed"), "reset 保存边界不符")
        if not saved:
            confirm(lab, purpose="reset", independent=independent)
    if inspect(lab)["status"] != "verified":
        confirm(lab, independent=independent)
    check(inspect(lab)["status"] == "verified", "正常新会话不能恢复准确事实")


def mutation_fault(lab, *, phase, point):
    independent = preparation(lab, phase)
    before = state(lab)
    if phase == "observe":
        lab.rust("a1", "identity_trust_observe", identity=independent,
                 failpoint=point, expected_exit=POINTS[point])
    else:
        with TrustSession(lab, "a1") as session:
            display = session.request("identity_trust_prepare", target=identity("b1"),
                                      purpose="reset" if phase == "reset" else "verify")["display"]
            session.request("identity_trust_" + phase, display=display, independent_identity=independent,
                verification="synthetic_local", failpoint=point, expected_exit=POINTS[point])
    failed = state(lab)
    saved = point == "after_save"
    check((failed["snapshots"]["a1"] != before["snapshots"]["a1"]) == saved
          and failed["relay"] == before["relay"], "本机核验保存窗口错误")
    lab.case_evidence["mutation_fault"] = {"phase": phase, "point": point,
        "before": before, "after_failure": failed, "snapshot_saved": saved}
    lab.restart()
    if lab.helper:
        unresolved(lab, failed)
    else:
        check_committed(lab, phase, saved, independent)
        lab.case_evidence["recovery"] = "COMMITTED_FACT_QUERIED_OR_FRESH_DISPLAY_CONFIRMED"


def unresolved(lab, failed):
    anchor = lab.rust("a1", "anchor_inspect")
    check(anchor["paused"] and anchor["active_txn"] is not None, "缺日志预约未保持暂停")
    errors = []
    for _ in range(2):
        error = lab.blocked("a1", "anchor_resume")
        check(error["code"] == "anchor_unresolved", "缺精确日志却完成 Finish")
        errors.append(error)
        error = lab.blocked("a1", "identity_trust_inspect")
        check(error["code"] == "anchor_paused", "核验查询清除真正未决预约")
        errors.append(error)
        error = lab.blocked("a1", "send", id="blocked", payload="synthetic-blocked")
        check(error["code"] == "anchor_paused", "未决预约放行密码操作")
        lab.restart()
        current = lab.rust("a1", "anchor_inspect")
        check(state(lab) == failed and all(anchor[k] == current[k] for k in
              ("active_txn", "revision", "anchor_head", "local_head")), "拒绝/重启改变未决状态")
    lab.case_evidence.update(recovery="BLOCKED_UNRESOLVED", unresolved_anchor=anchor, errors=errors)


def anchor_window(lab, *, phase="observe", point=None, dropped=None):
    independent = preparation(lab, phase)
    before = state(lab)
    if phase == "prepare":
        operation, fields = "identity_trust_prepare", {"target": identity("b1"), "purpose": "verify"}
    else:
        operation, fields = "identity_trust_observe", {"identity": independent}
    if dropped:
        lab.forwarding_helper("drop", dropped, device="a1")
        options = {}
    else:
        options = ({"failpoint": point} if POINTS[point] < 86
                   else {"env": {"RIM_ANCHOR_FAILPOINT": point}})
    if phase == "prepare":
        with TrustSession(lab, "a1", env=options.get("env")) as session:
            if dropped:
                error = session.request(operation, **fields, expected_error="anchor_response")
            else:
                session.request(operation, **fields, expected_exit=POINTS[point])
    elif dropped:
        error = lab.rust("a1", operation, **fields, expected_exit=1)
        check(error["code"] == "anchor_response", "传输丢响应原因不符")
    else:
        lab.rust("a1", operation, **fields, **options, expected_exit=POINTS[point])
    if dropped:
        lab.config_restore("a1")
        lab.case_evidence["transport_error"] = error
    saved = phase == "observe" and (dropped == "finish" or point in ("after_save", "after_journal", "after_finish"))
    resumable = dropped == "finish" or point in ("after_journal", "after_finish")
    failed = state(lab)
    check((failed["snapshots"]["a1"] != before["snapshots"]["a1"]) == saved
          and failed["relay"] == before["relay"], "锚窗口改变错误状态范围")
    lab.case_evidence["anchor_fault"] = {"phase": phase, "point": point, "drop": dropped,
        "before": before, "after_failure": failed, "saved": saved,
        "journal_present": (lab.directory / "a1/anchor-journal.enc").exists()}
    if not resumable:
        unresolved(lab, failed)
        return
    lab.resume("a1")
    ready = lab.rust("a1", "anchor_inspect")
    check(ready["status"] == "ready" and ready["active_txn"] is None, "精确日志没有完成 Finish")
    lab.resume("a1")
    check(state(lab) == failed and lab.rust("a1", "anchor_inspect")["revision"] == ready["revision"],
          "重复 Finish 重写快照或推进锚")
    check(inspect(lab)["status"] == "unverified", "observe/prepare 被当成确认")
    confirm(lab)
    check(inspect(lab)["status"] == "verified", "原未核验事实不能经新展示完成")
    lab.case_evidence.update(recovery="EXACT_JOURNAL_FINISHED_THEN_NEW_DISPLAY", anchor_after_resume=ready)


CASES = [(f"Q01.F10.relay.{phase}.{hook}", partial(relay_registration, phase=phase, hook=hook))
         for phase in ("begin", "complete") for hook in HOOKS]
CASES += [(f"Q01.F10.local.{phase}.{point}", partial(mutation_fault, phase=phase, point=point))
          for phase in ("observe", "confirm", "reset") for point in tuple(POINTS)[:3]]
ANCHOR_CASES = [(f"Q01.F10.anchor.observe.{point}", partial(anchor_window, point=point)) for point in POINTS]
ANCHOR_CASES += [(f"Q01.F10.anchor.{phase}.drop.{action}", partial(anchor_window, phase=phase, dropped=action))
                for phase in ("observe", "prepare") for action in ("reserve", "finish")]
ANCHOR_CASES += [(f"Q01.F10.anchor.prepare.{point}", partial(anchor_window, phase="prepare", point=point))
                for point in ("after_reserve", "after_journal", "after_finish")]
ANCHOR_CASES += [(f"Q01.F10.anchor.{phase}.{point}", partial(mutation_fault, phase=phase, point=point))
                for phase in ("confirm", "reset") for point in tuple(POINTS)[:3]]
