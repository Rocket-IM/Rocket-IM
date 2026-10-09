"""准备及查询自身的锚窗口；缺精确日志的预约持续阻断，绝不清锚。"""

from functools import partial

from .fixture import check
from .reclamation_faults import POINTS
from .reclamation_fixture import snapshot, terminal_candidate
from .reclamation_preparation_cases import COMMON_CASES
from .reclamation_preparation_support import host, local_plan, state


def unresolved(lab, failed, *, has_plan):
    original = lab.rust("c1", "anchor_inspect")
    check(original["paused"] and original["active_txn"] is not None, "预期真正未决锚")
    errors = []
    for _ in range(2):
        error = lab.blocked("c1", "anchor_resume")
        check(error["code"] == "anchor_unresolved", "没有精确日志却解除未决预约")
        errors.append(error)
        for operation, fields in (
            ("wire_reclaim_list", {"limit": "100"}),
            ("wire_reclaim_recover", {"plan_id": "anchor-plan"}),
            ("wire_send", {"logical_message_id": "blocked", "attempt_id": "P1", "payload": "blocked"})):
            error = lab.blocked("c1", operation, **fields)
            expected = "reclaim_not_found" if operation == "wire_reclaim_recover" and not has_plan else "anchor_paused"
            check(error["code"] == expected, "恢复入口未保持元数据拒绝优先级或绕过真正未决锚")
            errors.append(error)
        lab.restart()
        current = lab.rust("c1", "anchor_inspect")
        check(state(lab) == failed and all(current[key] == original[key]
              for key in ("active_txn", "revision", "anchor_head", "local_head")),
              "拒绝或重启改变业务状态/解除预约")
    return {"status": "BLOCKED_UNRESOLVED", "has_persisted_plan": has_plan,
            "anchor": current, "errors": errors}


def anchored(lab, *, phase, point=None, dropped=None):
    record = terminal_candidate(lab)
    fields = {"plan_id": "anchor-plan", "acceptance_ids": [record["accepted"]["acceptance_id"]]}
    operation = "wire_reclaim_request"
    if phase != "prepare":
        lab.rust("c1", operation, **fields)
        local_plan(lab, "c1", "anchor-plan")
        operation = "wire_reclaim_" + phase
        fields = {"limit": "100"} if phase == "list" else {"plan_id": "anchor-plan"}
    before, anchor_before = state(lab), lab.rust("c1", "anchor_inspect")
    if dropped:
        lab.forwarding_helper("drop", dropped, device="c1")
        error = lab.rust("c1", operation, **fields, expected_exit=1)
        lab.config_restore("c1")
        lab.case_evidence["anchor_transport_error"] = error
        resumable = dropped == "finish"
        saved = resumable and phase == "prepare"
    else:
        code = POINTS[point]
        options = {"failpoint": point} if code < 86 else {"env": {"RIM_ANCHOR_FAILPOINT": point}}
        lab.rust("c1", operation, **fields, **options, expected_exit=code)
        resumable = point in ("after_journal", "after_finish")
        saved = phase == "prepare" and point in ("after_save", "after_journal", "after_finish")
    failed = state(lab)
    check((failed["snapshots"]["c1"] != before["snapshots"]["c1"]) == saved
          and failed["relay"] == before["relay"], "锚故障快照边界错误或提前确认 Relay")
    lab.case_evidence["preparation_anchor_fault"] = {"phase": phase, "point": point,
        "drop": dropped, "before": before, "after": failed, "anchor_before": anchor_before,
        "snapshot_saved": saved, "journal_present": (lab.directory / "c1/anchor-journal.enc").exists()}
    if not resumable:
        lab.case_evidence.update(progress="PREPARATION_OR_QUERY_REMAINS_BLOCKED",
                                recovery=unresolved(lab, failed, has_plan=phase != "prepare" or saved))
        return
    resumed = lab.resume("c1")
    ready = lab.rust("c1", "anchor_inspect")
    check(ready["status"] == "ready" and ready["active_txn"] is None
          and ready["anchor_head"] == failed["snapshots"]["c1"]["sha256"], "未恢复精确已保存目标")
    lab.resume("c1")
    check(lab.rust("c1", "anchor_inspect")["revision"] == ready["revision"]
          and state(lab) == failed, "重复恢复推进锚或重写快照")
    recovered = host(lab, "confirm")
    check(recovered["confirmed"]["status"] == "pending", "恢复后不能取得固定本机请求")
    after_queries = lab.rust("c1", "anchor_inspect")
    lab.case_evidence.update(anchor_after_resume=ready, anchor_after_host_queries=after_queries,
        query_anchor_transactions=2, expected_revision_steps=4,
        observed_revision_steps=int(after_queries["revision"]) - int(ready["revision"]))
    check(int(after_queries["revision"]) == int(ready["revision"]) + 4
          and snapshot(lab, "c1") == failed["snapshots"]["c1"],
          "独立宿主 list/recover 各完成 Reserve/Finish 共4次修订且不重写快照")
    lab.case_evidence.update(progress="EXACT_PREPARATION_OR_QUERY_ANCHOR_RECOVERED",
                            resumed=resumed)


ANCHOR_CASES = list(COMMON_CASES)
for phase in ("prepare", "list", "recover"):
    points = POINTS if phase == "prepare" else ("after_reserve", "after_journal", "after_finish")
    ANCHOR_CASES += [(f"M12.prepare.anchor.{phase}.{point}", partial(anchored, phase=phase, point=point))
                     for point in points]
    ANCHOR_CASES += [(f"M12.prepare.anchor.{phase}.drop.{action}",
                     partial(anchored, phase=phase, dropped=action)) for action in ("reserve", "finish")]
