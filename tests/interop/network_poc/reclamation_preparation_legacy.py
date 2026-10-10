"""真实 build5 的 v1 已应用兼容和从未持久原请求的历史限制。"""

from contextlib import contextmanager

from .fixture import check
from .reclamation_cases import compacted
from .reclamation_fixture import (DEVICES, apply, approve, database, finish, publish,
                                  snapshot, synchronize, terminal_candidate)
from .reclamation_preparation_support import local_plan, state


@contextmanager
def legacy(lab):
    check(getattr(lab, "legacy_binary", None) is not None, "该场景必须显式提供真实 build5 --legacy-binary")
    current = lab.binary
    references = lab.include_terminal_references
    lab.binary = lab.legacy_binary
    lab.include_terminal_references = False
    try:
        yield
    finally:
        lab.binary = current
        lab.include_terminal_references = references


def old_requests(lab, record, plan):
    selected = [record["accepted"]["acceptance_id"]]
    requests = {}
    for device in DEVICES:
        before = snapshot(lab, device)
        reply = lab.rust(device, "wire_reclaim_request", plan_id=plan, acceptance_ids=selected)
        check(snapshot(lab, device) == before and "request_json" not in reply, "旧程序意外执行新版持久准备")
        requests[device] = reply["request"]
    return requests


def applied_v1(lab):
    with legacy(lab):
        record = terminal_candidate(lab)
        requests = old_requests(lab, record, "v1-applied")
        receipts = approve(lab, requests)
        results = apply(lab, receipts)
    before = state(lab)
    recovered = {device: local_plan(lab, device, "v1-applied", "applied") for device in DEVICES}
    for device in DEVICES:
        check(recovered[device]["result"] == results[device]
              and recovered[device]["finish_request"] == results[device]["finish_request"],
              "新版未原样恢复真实旧 v1 应用结果")
    check(state(lab) == before, "读取旧 v1 材料迁移或改写快照")
    finish(lab, results)
    complete = compacted(lab, [record])
    for device in DEVICES:
        check(lab.http(device, "finish_reclaim", recovered[device]["finish_request"])["status"] == "complete",
              "旧 v1 恢复的完成材料不能精确重试")
    check(database(lab) == complete and state(lab)["snapshots"] == before["snapshots"], "旧完成重试改变状态")
    lab.case_evidence.update(progress="REAL_BUILD5_V1_APPLIED_FINISH_RECOVERED", recovered=recovered,
        before=before, final=state(lab), original_confirm_encoding="NOT_PERSISTED_BY_BUILD5_NOT_CLAIMED")


def lost_unprepared(lab):
    with legacy(lab):
        record = terminal_candidate(lab)
        requests = old_requests(lab, record, "old-never-saved")
        # 观察者仅保留摘要/P用于断言；切换新版后不把旧 request/receipt 输入任何恢复调用。
        approve(lab, requests)
    before = state(lab)
    listing = lab.rust("c1", "wire_reclaim_list", limit="100")
    error = lab.rust("c1", "wire_reclaim_recover", plan_id="old-never-saved", expected_exit=1)
    check(listing["plans"] == [] and error["code"] == "reclaim_not_found" and state(lab) == before,
          "从未保存的历史材料被猜造或错误列举")
    publish(lab, "legacy-p-progress")
    synchronize(lab, "c1", report_delivery=True)
    request = lab.rust("c1", "wire_reclaim_request", plan_id="old-never-saved",
                       acceptance_ids=[record["accepted"]["acceptance_id"]])
    check(int(request["request"]["processed_seq"]) > int(requests["c1"]["processed_seq"]), "旧限制样本未推进 P")
    prepared = state(lab)
    error = lab.http("c1", "confirm_reclaim", {}, raw=request["request_json"].encode(), expected=409)
    check(error["code"] == "reclamation_conflict" and state(lab) == prepared
          and all(not row["payload_is_null"] for row in prepared["relay"]["attempts"]),
          "旧材料丢失未继续阻断或清掉原件")
    recovered = local_plan(lab, "c1", "old-never-saved")
    check(recovered["request_json"] == request["request_json"], "新版固定了被拒请求之后又猜测旧材料")
    lab.case_evidence.update(progress="OBSERVED_LIMITATION_LEGACY_NEVER_PERSISTED_MATERIAL",
        limitation="build5 从未保存且宿主已丢原件；新版不能反推 Relay 原请求，无旧计划查询接口",
        original_p=requests["c1"]["processed_seq"], regenerated_p=request["request"]["processed_seq"],
        error=error, final=state(lab), outcome="OBSERVED_LIMITATION", verification="PASS")


def prepared_v2_rejects_build5(lab):
    record = terminal_candidate(lab)
    prepared = lab.rust("c1", "wire_reclaim_request", plan_id="v2-prepared",
                        acceptance_ids=[record["accepted"]["acceptance_id"]])
    check(prepared["status"] == "prepared" and not prepared["duplicate"], "未生成真正 v2 prepared")
    before = state(lab)
    with legacy(lab):
        error = lab.rust("c1", "wire_inspect", expected_exit=1)
    check(error["code"] == "state_decoding" and state(lab) == before,
          "真实 build5 没有明确拒绝 v2 prepared 或改写了原件")
    recovered = local_plan(lab, "c1", "v2-prepared")
    check(recovered["request_json"] == prepared["request_json"] and state(lab) == before,
          "旧版拒载后新版未能恢复原准备材料")
    lab.case_evidence.update(progress="REAL_BUILD5_REFUSES_PREPARED_V2_WITHOUT_MUTATION",
                            error=error, before=before, recovered=recovered, final=state(lab))


CASES = [("M12.prepare.legacy.v1_applied", applied_v1),
         ("M12.prepare.legacy.never_persisted", lost_unprepared),
         ("M12.prepare.legacy.v2_rejected_by_build5", prepared_v2_rejects_build5)]
