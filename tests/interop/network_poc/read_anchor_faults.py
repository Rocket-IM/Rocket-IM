"""显式阅读三段操作的锚/快照真实中断；未决状态只观察摘要和拒绝。"""

from functools import partial

from .deletion_observer import relay_records
from .fixture import check
from .read_anchor_fixture import anchor_state, assert_blocked, state
from .read_support import (finish, inspect, load_messages, mark, pending, publish,
                           report, snapshot, synchronize)

POINTS = {"before_save": 83, "before_rename": 84, "after_save": 85,
          "after_reserve": 86, "after_journal": 87, "after_finish": 88}


def setup(lab, phase):
    records = publish(lab)
    ids = load_messages(lab, records)
    fields, page = {"event_ids": ids}, None
    operation = "wire_read"
    if phase != "mark":
        mark(lab, ids)
        report(lab)
        page = lab.pull("b1", after="1")
        check([s["event"]["type"] for s in page["events"]] == ["delivery", "read"],
              "输入不是 HTTP 原件中的本人送达和 Read 签页")
        if phase == "download":
            operation, fields = "wire_download_signed", page.signed_input()
        else:
            lab.download("b1", page)
            operation, fields = "wire_process", {}
    before = state(lab)
    lab.case_evidence["fault_input"] = {"phase": phase, "operation": operation,
        "before": before, "anchor_before": anchor_state(lab),
        "signed_page": page.wrapper if page else None}
    return records, ids, operation, fields, before, page


def unresolved(lab, operation, fields, rows, *, reason="anchor_unresolved"):
    head, anchored = snapshot(lab), anchor_state(lab)
    check(anchored["active_txn"] is not None and anchored["paused"], "没有真正未决预约")
    rejections = []
    for _ in range(2):
        rejections.append(assert_blocked(lab, "anchor_resume", {}, code=reason))
        for op, data in ((operation, fields), ("wire_read_pending", {}), ("wire_read_inspect", {}),
                         ("wire_send", {"logical_message_id": "blocked-new", "attempt_id": "P1",
                                        "payload": "synthetic-must-stay-blocked"})):
            rejections.append(assert_blocked(lab, op, data))
        lab.restart()
        current = anchor_state(lab)
        check(snapshot(lab) == head and relay_records(lab) == rows, "拒绝或重启改变快照/Relay事实")
        check(all(current[k] == anchored[k] for k in ("active_txn", "revision", "anchor_head", "local_head")),
              "重复恢复或业务重试释放了未决预约")
    lab.case_evidence.update(recovery="BLOCKED_UNRESOLVED", unresolved_anchor=current,
                            blocked_errors=rejections, final_relay=rows,
                            final_snapshot_sha256=head, pending_state_observation="BLOCKED_BY_ANCHOR")


def recover(lab, phase, records, ids, before, page, *, saved, rows):
    target, prior_anchor = snapshot(lab), anchor_state(lab)
    assert_blocked(lab, "wire_read_pending", {})
    resumed = lab.resume("b1")
    current = anchor_state(lab)
    check(current["status"] == "ready" and current["active_txn"] is None
          and current["anchor_head"] == target, "恢复没有精确完成原目标")
    # 第二次恢复只验证已完成承诺，不能重复 Finish 或改变版本。
    lab.resume("b1")
    repeated = anchor_state(lab)
    check(repeated["revision"] == current["revision"] and snapshot(lab) == target,
          "重复恢复重新提交结果或推进预约版本")
    after = state(lab)
    check(relay_records(lab) == rows and after["message_slot"] == before["message_slot"],
          "锚恢复改写原消息槽或服务回执")
    check({k: v for k, v in after["wire"].items() if k != "sync"}
          == {k: v for k, v in before["wire"].items() if k != "sync"}, "恢复改变密码或消息事实")
    if not saved:
        check(after == before, "未提交的锚预约改变阅读/游标")
    elif phase == "mark":
        check(after["reads"]["pending_count"] == 1 and after["reads"]["confirmed_count"] == 0
              and after["wire"] == before["wire"], "意图保存后恢复提前确认或改变同步状态")
    elif phase == "download":
        check(after["reads"] == before["reads"] and after["pending"] == before["pending"]
              and after["wire"]["sync"]["download_cursor"] == "3"
              and after["wire"]["sync"]["processed_cursor"] == "1", "只下载就确认或丢失已存页")
    else:
        read = page["events"][-1]
        check(after["reads"]["pending_count"] == 0 and after["reads"]["confirmed_count"] == 1
              and after["reads"]["records"][0]["confirmation"] ==
              {"event_id": read["event_id"], "event_seq": read["event_seq"]}
              and after["wire"]["sync"]["processed_cursor"] == "3", "处理恢复缺少精确本人确认")
    lab.restart()
    check(state(lab) == after and relay_records(lab) == rows, "重启改变恢复结果")
    if phase == "mark":
        repeated_mark = mark(lab, ids)
        check(repeated_mark["marked_count"] == int(not saved)
              and repeated_mark["duplicate_count"] == int(saved), "恢复重复阅读生成第二意图")
        report(lab)
    results = synchronize(lab)
    expected = int(not (phase == "process" and saved))
    check(sum(r["read_confirmed_count"] for r in results) == expected,
          "恢复后重复确认或没有确认本人精确 Read")
    lab.case_evidence.update(recovery="EXACT_SAVED_TARGET" if saved else "NO_RESERVATION_COMMITTED",
        anchor_before_resume=prior_anchor, resumed=resumed, anchor_after_resume=current,
        state_after_resume=after, snapshot_sha256_after_resume=target,
        newly_confirmed_after_resume=expected)
    finish(lab, records)


def fault(lab, *, phase, kind, point):
    records, ids, operation, fields, before, page = setup(lab, phase)
    rows = relay_records(lab)
    if kind == "client":
        code = POINTS[point]
        options = ({"failpoint": point} if code < 86 else {"env": {"RIM_ANCHOR_FAILPOINT": point}})
        lab.rust("b1", operation, **fields, **options, expected_exit=code)
        saved = point in ("after_save", "after_journal", "after_finish")
        resumable = point in ("after_journal", "after_finish")
    else:
        action = kind.split("_")[-1]
        mode = "drop" if kind.startswith("drop") else "crash_" + point
        lab.forwarding_helper(mode, action, device="b1")
        error = lab.rust("b1", operation, **fields, expected_exit=1)
        lab.case_evidence["anchor_transport_error"] = error
        lab.config_restore("b1")
        saved = action == "finish"
        resumable = saved or (kind.startswith("authority") and point != "after_save")
    head = snapshot(lab)
    check((head != before["snapshot_sha256"]) == saved, "实际快照保存边界与故障窗口不符")
    check(relay_records(lab) == rows, "本机中断改变服务端回执")
    lab.case_evidence["fault"] = {"kind": kind, "point": point, "phase": phase,
        "snapshot_saved": saved, "snapshot_sha256_after_fault": head,
        "journal_present": (lab.directory / "b1/anchor-journal.enc").exists()}
    if resumable:
        recover(lab, phase, records, ids, before, page, saved=saved, rows=rows)
    else:
        unresolved(lab, operation, fields, rows)


CASES = []
for phase in ("mark", "download", "process"):
    for point in POINTS:
        CASES.append((f"M13.anchor.{phase}.client.{point}",
                      partial(fault, phase=phase, kind="client", point=point)))
    for action in ("reserve", "finish"):
        CASES.append((f"M13.anchor.{phase}.drop.{action}",
                      partial(fault, phase=phase, kind="drop_" + action, point="response")))
        for point in ("before_save", "before_rename", "after_save"):
            CASES.append((f"M13.anchor.{phase}.authority.{action}.{point}",
                          partial(fault, phase=phase, kind="authority_" + action, point=point)))
