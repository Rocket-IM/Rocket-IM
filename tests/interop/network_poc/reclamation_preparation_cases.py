"""真实 MLS、独立宿主丢材料及 HTTP 中断后的固定请求恢复。"""

from functools import partial

from .fixture import check
from .reclamation_cases import compacted
from .reclamation_faults import HOOKS, POINTS
from .reclamation_fixture import (DEVICES, apply, approve, database, digest, prepare_requests,
                                  publish, snapshot, synchronize, terminal_candidate)
from .reclamation_preparation_support import host, local_plan, state, unchanged_rejection


def confirm_loss(lab, *, hook):
    record = terminal_candidate(lab)
    requests = prepare_requests(lab, [record])
    for device in DEVICES[:-1]:
        check(lab.http(device, "confirm_reclaim", requests[device])["status"] == "pending",
              "参与者不足却发放许可")
    before, process = state(lab), lab.process
    lab.control("hook", hook=hook)
    lost = host(lab, "confirm_lost", expected_exit=91)
    expected_exit = {"before_commit_exit": 86, "after_commit_exit": 87}.get(hook)
    exit_code = process.poll() if expected_exit is None else process.wait(timeout=10)
    failed = state(lab)
    check(exit_code == expected_exit and failed["snapshots"] == before["snapshots"],
          "确认故障退出码错误或改变本机快照")
    if hook == "before_commit_exit":
        check(failed == before, "Relay 提交前退出留下部分确认")
    check(all(not row["payload_is_null"] for row in failed["relay"]["attempts"]),
          "尚未应用就清除 Relay 原件")
    lab.restart()
    following = publish(lab, "after-lost-confirm", payload="synthetic-progress-after-preparation")
    synchronize(lab, "c1", report_delivery=True)
    current_p = lab.rust("c1", "wire_inspect")["sync"]["processed_cursor"]
    check(int(current_p) > int(requests["c1"]["processed_seq"]), "第二条真实消息未推进 P")
    recovered = host(lab, "confirm")
    check(recovered["confirmed"]["status"] == "ready"
          and recovered["original_p"] == requests["c1"]["processed_seq"]
          and recovered["recovered"]["request_json"] == requests["c1"].request_json
          and recovered["request_json_sha256"] == lost["request_json_sha256"],
          "新宿主没有恢复原 P、原编码确认与许可")
    before_apply = state(lab)
    applied = host(lab, "apply_lost", expected_exit=92)
    check(not applied["duplicate"] and applied["reclaimed_count"] == 1
          and database(lab) == before_apply["relay"], "本机保存后丢返回材料导致重复或 Relay 提前回收")
    finished = host(lab, "finish")
    check(finished["finished"]["status"] == "pending" and finished["duplicate"],
          "本机 applied 未能恢复精确完成请求")
    for device in DEVICES[:-1]:
        receipt = lab.http(device, "confirm_reclaim", requests[device])["receipt"]
        result = lab.rust(device, "wire_reclaim", receipt=receipt)
        last = lab.http(device, "finish_reclaim", result["finish_request"])
    check(last["status"] == "complete", "所有参与者恢复后没有完成回收")
    compacted(lab, [record])
    rows = state(lab)
    repeated = host(lab, "finish")
    check(repeated["finished"]["status"] == "complete" and state(lab) == rows,
          "完成后重试重复清理或改变快照/Relay")
    active = next(row for row in rows["relay"]["attempts"]
                  if row["acceptance_id"] == following["accepted"]["acceptance_id"])
    check(not active["payload_is_null"] and active["availability"] == "available", "无关新原件丢失")
    lab.case_evidence.update(progress="DURABLE_PREPARATION_RECOVERED_AFTER_HOST_LOSS_AND_P_ADVANCE",
        confirm_fault={"hook": hook, "exit_code": exit_code, "before": before, "after": failed},
        original_p=requests["c1"]["processed_seq"], current_p=current_p,
        request_json_sha256=digest(requests["c1"].request_json.encode()), final=rows,
        host_isolation="fresh process and allowlisted input; not an OS filesystem security boundary")


def finish_loss(lab, *, hook):
    record = terminal_candidate(lab)
    results = apply(lab, approve(lab, prepare_requests(lab, [record])))
    for device in DEVICES[:-1]:
        check(lab.http(device, "finish_reclaim", results[device]["finish_request"])["status"] == "pending",
              "最后参与者完成前清除载荷")
    before, process = state(lab), lab.process
    lab.control("hook", hook=hook)
    host(lab, "finish_lost", expected_exit=93)
    expected_exit = {"before_commit_exit": 86, "after_commit_exit": 87}.get(hook)
    actual_exit = process.poll() if expected_exit is None else process.wait(timeout=10)
    failed = state(lab)
    check(actual_exit == expected_exit and failed["snapshots"] == before["snapshots"], "完成故障改写快照")
    if hook == "before_commit_exit":
        check(failed == before, "完成提交前退出留下部分删除")
    lab.restart()
    recovered = host(lab, "finish")
    check(recovered["finished"]["status"] == "complete", "宿主未能只凭本机 applied 恢复完成")
    compacted(lab, [record])
    complete = state(lab)
    host(lab, "finish")
    check(state(lab) == complete, "完成重试重复计费、回收或改写快照")
    lab.case_evidence.update(progress="APPLIED_MATERIAL_RECOVERS_FINISH_WITHOUT_HOST_COPY",
        finish_fault={"hook": hook, "exit_code": actual_exit, "before": before, "after": failed}, final=complete)


def prepare_save(lab, *, point):
    record = terminal_candidate(lab)
    fields = {"plan_id": "saved-prepare", "acceptance_ids": [record["accepted"]["acceptance_id"]]}
    before = state(lab)
    lab.rust("c1", "wire_reclaim_request", **fields, failpoint=point, expected_exit=POINTS[point])
    failed = state(lab)
    saved = point == "after_save"
    check((failed["snapshots"]["c1"] != before["snapshots"]["c1"]) == saved
          and failed["relay"] == before["relay"], "准备保存边界错误或提前发送确认")
    listing = lab.rust("c1", "wire_reclaim_list", limit="100")
    check(len(listing["plans"]) == int(saved), "保存前后计划可见性错误")
    repeated = lab.rust("c1", "wire_reclaim_request", **fields)
    check(repeated["duplicate"] == saved, "准备重试没有按实际保存边界去重")
    recovered = host(lab, "confirm")
    check(recovered["confirmed"]["status"] == "pending"
          and recovered["recovered"]["request_json"] == repeated["request_json"], "准备故障后不能恢复原编码")
    lab.case_evidence.update(progress="PREPARE_SAVE_BOUNDARY_RECOVERED", point=point,
                            snapshot_saved=saved, before=before, after_failure=failed)


def pagination(lab):
    synchronize(lab, "c1")
    for operation, fields, code in (
        ("wire_reclaim_recover", {"plan_id": "unknown"}, "reclaim_not_found"),
        ("wire_reclaim_list", {"limit": "0"}, "reclaim_invalid"),
        ("wire_reclaim_list", {"limit": "101"}, "reclaim_invalid"),
        ("wire_reclaim_list", {"limit": "1", "after_plan_id": "bad/id"}, "reclaim_invalid")):
        unchanged_rejection(lab, operation, code, **fields)
    empty = lab.rust("c1", "wire_reclaim_list", limit="1")
    check(empty == {"plans": [], "has_more": False, "next_after_plan_id": None}, "空计划分页错误")
    first = terminal_candidate(lab, logical="pagination-one")
    second = terminal_candidate(lab, logical="pagination-two")
    for plan, record in (("z-plan", first), ("a-plan", second)):
        lab.rust("c1", "wire_reclaim_request", plan_id=plan,
                 acceptance_ids=[record["accepted"]["acceptance_id"]])
        local_plan(lab, "c1", plan)
    before = state(lab)
    other = lab.rust("b1", "wire_reclaim_list", limit="100")
    absent = lab.rust("b1", "wire_reclaim_recover", plan_id="a-plan", expected_exit=1)
    check(other["plans"] == [] and absent["code"] == "reclaim_not_found" and state(lab) == before,
          "本机发现/恢复泄露另一账号计划或改写状态")
    page1 = lab.rust("c1", "wire_reclaim_list", limit="1")
    page2 = lab.rust("c1", "wire_reclaim_list", limit="1", after_plan_id=page1["next_after_plan_id"])
    check(page1 == {"plans": [{"plan_id": "a-plan", "status": "prepared"}],
                    "has_more": True, "next_after_plan_id": "a-plan"}
          and page2 == {"plans": [{"plan_id": "z-plan", "status": "prepared"}],
                        "has_more": False, "next_after_plan_id": None}
          and state(lab) == before, "分页不是稳定 ID 排序或查询重写状态")
    unchanged_rejection(lab, "wire_reclaim_request", "reclaim_conflict", plan_id="a-plan",
                        acceptance_ids=[first["accepted"]["acceptance_id"]])
    unchanged_rejection(lab, "wire_reclaim_request", "reclaim_conflict", plan_id="overlapping",
                        acceptance_ids=[second["accepted"]["acceptance_id"]])
    lab.case_evidence.update(progress="LOCAL_PAGINATION_AND_METADATA_REJECTIONS", pages=[page1, page2])


COMMON_CASES = [(f"M12.prepare.confirm.{hook}", partial(confirm_loss, hook=hook)) for hook in HOOKS]
COMMON_CASES += [(f"M12.prepare.finish.{hook}", partial(finish_loss, hook=hook)) for hook in HOOKS]
COMMON_CASES += [("M12.prepare.pagination", pagination)]
CASES = COMMON_CASES + [(f"M12.prepare.local.{point}", partial(prepare_save, point=point))
                        for point in ("before_save", "before_rename", "after_save")]
