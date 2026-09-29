"""回收的真实 CLI/Relay 提交中断与独立锚丢响应；不清除未决锚。"""

from functools import partial
import http.client

from .fixture import check
from .reclamation_cases import compacted, roundtrip
from .reclamation_fixture import (DEVICES, apply, approve, database, finish, prepare_requests,
                                  snapshot, terminal_candidate)

POINTS = {"before_save": 83, "before_rename": 84, "after_save": 85,
          "after_reserve": 86, "after_journal": 87, "after_finish": 88}
HOOKS = ("before_commit_exit", "after_commit_exit", "drop_after_commit")


def prepared(lab):
    record = terminal_candidate(lab)
    requests = prepare_requests(lab, [record])
    return record, requests, approve(lab, requests)


def local_commit(lab, *, point):
    record, _, receipts = prepared(lab)
    before, rows = snapshot(lab, "b1"), database(lab)
    lab.rust("b1", "wire_reclaim", receipt=receipts["b1"], failpoint=point, expected_exit=POINTS[point])
    saved = point == "after_save"
    check((snapshot(lab, "b1") != before) == saved and database(lab) == rows,
          "回收故障保存边界错误或本地退出提前改变Relay")
    lab.restart()
    recovered = lab.rust("b1", "wire_reclaim", receipt=receipts["b1"])
    check(recovered["duplicate"] == saved, "回收重试没有按实际提交边界恢复")
    results = {"b1": recovered}
    for device in ("a1", "a2", "c1"):
        results[device] = lab.rust(device, "wire_reclaim", receipt=receipts[device])
    finish(lab, results)
    compacted(lab, [record])
    lab.case_evidence.update(progress="LOCAL_COMMIT_RECOVERED_EXACTLY_ONCE",
        fault={"point": point, "before": before, "snapshot_saved": saved}, recovered=recovered)


def relay_commit(lab, *, phase, hook):
    record = terminal_candidate(lab)
    requests = prepare_requests(lab, [record])
    if phase == "confirm":
        operation, target = "confirm_reclaim", requests["c1"]
        for device in DEVICES[:-1]:
            check(lab.http(device, operation, requests[device])["status"] == "pending",
                  "参与者不足却发放回收许可")
    else:
        receipts = approve(lab, requests)
        results = apply(lab, receipts)
        operation, target = "finish_reclaim", results["c1"]["finish_request"]
        for device in DEVICES[:-1]:
            check(lab.http(device, operation, results[device]["finish_request"])["status"] == "pending",
                  "部分本机提交就清理Relay载荷")
    before, snapshots, process = database(lab), {d: snapshot(lab, d) for d in DEVICES}, lab.process
    lab.control("hook", hook=hook)
    try:
        lab.http("c1", operation, target)
        raise AssertionError("指定Relay提交窗口没有断开HTTP响应")
    except (http.client.RemoteDisconnected, ConnectionResetError) as error:
        disconnected = type(error).__name__
    expected_exit = {"before_commit_exit": 86, "after_commit_exit": 87}.get(hook)
    actual_exit = process.poll() if expected_exit is None else process.wait(timeout=10)
    after = database(lab)
    check(actual_exit == expected_exit and snapshots == {d: snapshot(lab, d) for d in DEVICES},
          "Relay故障退出码错误或裸HTTP改变本机状态")
    if hook == "before_commit_exit":
        check(after == before, "Relay提交前退出留下部分计划或删除")
    lab.restart()
    recovered = lab.http("c1", operation, target)
    check(recovered["status"] == ("ready" if phase == "confirm" else "complete"),
          "重启后未按同一原请求恢复")
    committed = database(lab)
    check(lab.http("c1", operation, target) == recovered and database(lab) == committed,
          "重复原回收请求再次发放容量或改变结果")
    if phase == "confirm":
        receipts = {device: lab.http(device, "confirm_reclaim", requests[device])["receipt"]
                    for device in DEVICES}
        results = apply(lab, receipts)
        finish(lab, results)
    compacted(lab, [record])
    lab.case_evidence.update(progress="RELAY_TRANSACTION_RECOVERED_EXACTLY_ONCE",
        relay_fault={"phase": phase, "hook": hook, "exception": disconnected,
                     "exit_code": actual_exit, "before": before, "after_failure": after},
        recovered=recovered, final_relay=database(lab))


def anchored(lab, *, point=None, dropped=None):
    record, _, receipts = prepared(lab)
    before, rows = snapshot(lab, "b1"), database(lab)
    if dropped:
        lab.forwarding_helper("drop", dropped, device="b1")
        error = lab.rust("b1", "wire_reclaim", receipt=receipts["b1"], expected_exit=1)
        lab.config_restore("b1")
        saved, resumable = dropped == "finish", dropped == "finish"
        lab.case_evidence["anchor_transport_error"] = error
    else:
        options = ({"failpoint": point} if POINTS[point] < 86
                   else {"env": {"RIM_ANCHOR_FAILPOINT": point}})
        lab.rust("b1", "wire_reclaim", receipt=receipts["b1"], expected_exit=POINTS[point], **options)
        saved = point in ("after_save", "after_journal", "after_finish")
        resumable = point in ("after_journal", "after_finish")
    current = snapshot(lab, "b1")
    check((current != before) == saved and database(lab) == rows,
          "锚故障保存边界错误或Relay提前删除")
    anchored_state = lab.rust("b1", "anchor_inspect")
    lab.case_evidence["anchor_fault"] = {"point": point, "dropped": dropped,
        "before": before, "after": current, "snapshot_saved": saved, "anchor": anchored_state}
    if not resumable:
        check(anchored_state["active_txn"] is not None and anchored_state["paused"],
              "真正未决预约没有保持暂停")
        for _ in range(2):
            error = lab.blocked("b1", "anchor_resume")
            check(error["code"] == "anchor_unresolved", "缺精确日志却完成锚恢复")
            error = lab.blocked("b1", "wire_reclaim", receipt=receipts["b1"])
            check(error["code"] == "anchor_paused", "未决锚允许继续回收")
            error = lab.blocked("b1", "wire_send", logical_message_id="blocked-new", attempt_id="P1", payload="blocked")
            check(error["code"] == "anchor_paused", "未决锚允许新的密码动作")
            lab.restart()
            check(database(lab) == rows and snapshot(lab, "b1") == current,
                  "重启或错误重试清除了未决状态")
        lab.case_evidence["progress"] = "BLOCKED_UNRESOLVED_ANCHOR_NO_RELAY_RECLAMATION"
        return
    lab.resume("b1")
    ready = lab.rust("b1", "anchor_inspect")
    check(ready["status"] == "ready" and ready["active_txn"] is None
          and ready["anchor_head"] == current["sha256"], "没有恢复精确已保存回收结果")
    lab.resume("b1")
    check(snapshot(lab, "b1") == current and lab.rust("b1", "anchor_inspect")["revision"] == ready["revision"],
          "重复锚恢复再次提交或重写快照")
    results = apply(lab, receipts)
    check(results["b1"]["duplicate"], "精确锚恢复后又执行第二次回收")
    finish(lab, results)
    compacted(lab, [record])
    lab.case_evidence.update(progress="EXACT_ANCHORED_RECLAMATION_RECOVERED", anchor_after=ready)


CASES = [(f"M12.reclaim.local.{point}", partial(local_commit, point=point))
         for point in ("before_save", "before_rename", "after_save")]
CASES += [(f"M12.reclaim.relay.{phase}.{hook}", partial(relay_commit, phase=phase, hook=hook))
          for phase in ("confirm", "finish") for hook in HOOKS]
ANCHOR_CASES = [("M12.reclaim.anchor.roundtrip", roundtrip)]
ANCHOR_CASES += [(f"M12.reclaim.anchor.{point}", partial(anchored, point=point)) for point in POINTS]
ANCHOR_CASES += [(f"M12.reclaim.anchor.drop.{action}", partial(anchored, dropped=action))
                for action in ("reserve", "finish")]
