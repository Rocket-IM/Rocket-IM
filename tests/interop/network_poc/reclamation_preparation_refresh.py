"""低处理游标的同计划恢复；真实 HTTP 与保存窗口，保留已接受请求原件。"""

from concurrent.futures import ThreadPoolExecutor
from functools import partial
import http.client

from .fixture import check
from .reclamation_cases import compacted
from .reclamation_faults import POINTS
from .reclamation_fixture import (DEVICES, PreparedRequest, apply, approve, database, finish,
                                  publish, snapshot, synchronize, terminal_candidate)
from .reclamation_preparation_support import local_plan, state
from .stream_fixture import StreamPage

PLAN = "refresh-plan"


def prepare(lab, record, *, device="a1", **options):
    return lab.rust(device, "wire_reclaim_request", plan_id=PLAN,
                    acceptance_ids=[record["accepted"]["acceptance_id"]], **options)


def rejection(lab, request, codes=("reclamation_pending",)):
    before = database(lab)
    result = lab.http("a1", "confirm_reclaim", request, expected=409)
    check(result["code"] in codes and database(lab) == before,
          "低 P 原请求未明确拒绝或拒绝留下 Relay 部分状态")
    lab.case_evidence.setdefault("old_request_rejections", []).append(result)
    return result


def lagging(lab):
    synchronize(lab, "a1")
    record = publish(lab, "lagging-before-terminal")
    for device in DEVICES[1:]:
        synchronize(lab, device, report_delivery=True)
    for device in DEVICES[1:]:
        synchronize(lab, device)
    lab.control("set_availability", acceptance_id=record["accepted"]["acceptance_id"],
                availability="deleted")
    for device in DEVICES[1:]:
        synchronize(lab, device)
    old = PreparedRequest(prepare(lab, record))
    check(old["processed_seq"] == "0", "复现没有保留发送方未同步的原 P=0")
    rejection(lab, old)
    return record, old


def refresh(lab, record, old):
    before, rows = snapshot(lab, "a1"), database(lab)
    result = prepare(lab, record)
    new = PreparedRequest(result)
    check(not result["duplicate"] and int(new["processed_seq"]) > int(old["processed_seq"])
          and new.request_json != old.request_json and snapshot(lab, "a1") != before
          and database(lab) == rows, "有可信相关槽后未先保存同计划新 P 或提前发送 HTTP")
    repeated = prepare(lab, record)
    recovered = local_plan(lab, "a1", PLAN)
    check(repeated["duplicate"] and repeated["request_json"] == new.request_json
          and recovered["request_json"] == new.request_json, "刷新后进程重开没有固定准确原件")
    lab.case_evidence["refresh"] = {"old_request_json": old.request_json,
        "new_request_json": new.request_json, "before": before, "after": snapshot(lab, "a1")}
    return new


def complete(lab, record, request):
    requests = {"a1": request}
    for device in DEVICES[1:]:
        requests[device] = PreparedRequest(prepare(lab, record, device=device))
    finish(lab, apply(lab, approve(lab, requests)))
    compacted(lab, [record])


def lagging_sender(lab):
    record, old = lagging(lab)
    synchronize(lab, "a1")
    check(lab.rust("a1", "wire_inspect")["sync"]["processed_cursor"] == "3",
          "原复现未通过真实签页处理三个已终态送达槽")
    new = refresh(lab, record, old)
    # 两个真实 HTTP 请求竞争；不以客户端取消旧请求作为正确性前提。
    with ThreadPoolExecutor(max_workers=2) as pool:
        delayed = pool.submit(lab.http, "a1", "confirm_reclaim", old, expected=409)
        current = pool.submit(lab.http, "a1", "confirm_reclaim", new)
        stale, accepted = delayed.result(), current.result()
    check(stale["code"] in ("reclamation_pending", "reclamation_conflict")
          and accepted["status"] == "pending", "迟到低 P 请求抢占或覆盖刷新后的确认")
    rejection(lab, old, ("reclamation_conflict",))
    complete(lab, record, new)
    lab.case_evidence.update(progress="LAGGING_SENDER_REFRESHED_AND_COMPLETED",
                            concurrent_old=stale, concurrent_new=accepted)


def late_read(lab):
    record = terminal_candidate(lab)
    old = PreparedRequest(prepare(lab, record))
    response = lab.http("b1", "report_read", {"service_id": lab.service,
                        "acceptance_ids": [record["accepted"]["acceptance_id"]]})
    check(response["receipts"][0]["read"], "准备后迟到已读没有真实提交")
    rejection(lab, old)
    for device in DEVICES:
        synchronize(lab, device)
    new = refresh(lab, record, old)
    rejection(lab, old)
    complete(lab, record, new)
    lab.case_evidence["progress"] = "LATE_RELATED_READ_REFRESHED_AND_COMPLETED"


def unrelated_after_lost_confirm(lab):
    record = terminal_candidate(lab)
    original = PreparedRequest(prepare(lab, record))
    lab.control("hook", hook="drop_after_commit")
    try:
        lab.http("a1", "confirm_reclaim", original)
        raise AssertionError("确认提交后未实际丢失 HTTP 响应")
    except (http.client.RemoteDisconnected, ConnectionResetError) as error:
        lab.case_evidence["lost_response"] = type(error).__name__
    lab.restart()
    following = publish(lab, "unrelated-after-confirm", sender="b1")
    synchronize(lab, "a1", report_delivery=True)
    before = snapshot(lab, "a1")
    current_p = lab.rust("a1", "wire_inspect")["sync"]["processed_cursor"]
    repeated = prepare(lab, record)
    check(int(current_p) > int(original["processed_seq"]) and repeated["duplicate"]
          and repeated["request_json"] == original.request_json
          and snapshot(lab, "a1") == before, "无关流前进改变已接受但丢响应的原请求")
    check(local_plan(lab, "a1", PLAN)["request_json"] == original.request_json,
          "重开恢复没有保持原确认编码")
    complete(lab, record, original)
    retained = next(row for row in database(lab)["attempts"]
                    if row["acceptance_id"] == following["accepted"]["acceptance_id"])
    check(not retained["payload_is_null"], "原计划回收删除了无关新消息")
    lab.case_evidence.update(progress="LOST_COMMITTED_CONFIRM_KEEPS_ORIGINAL_REQUEST",
                            original_p=original["processed_seq"], current_p=current_p)


def legacy_tombstone(lab):
    record, old = lagging(lab)
    # 显式请求旧投影；旧匿名槽和后续引用均取自真实签页 HTTP，不重签或猜造关联。
    previous = StreamPage(lab.http("a1", "pull_events_signed", {"service_id": lab.service,
        "after_seq": "0", "limit": "100", "include_terminal_references": False}))
    check(all("terminal_reference" not in slot and "event" not in slot
              for slot in previous["events"]), "旧投影意外带关联引用或终态载荷")
    lab.download("a1", previous)
    processed = lab.rust("a1", "wire_process")
    check(all(item["result"]["status"] == "unavailable" for item in processed["results"]),
          "旧占位未保留 unavailable 处理结果")
    saved = snapshot(lab, "a1")
    unchanged = prepare(lab, record)
    check(unchanged["duplicate"] and unchanged["request_json"] == old.request_json
          and snapshot(lab, "a1") == saved, "匿名占位被当作选中消息证明")
    current = lab.pull("a1", after="0")
    check(all(slot.get("terminal_reference", {}).get("acceptance_id")
              == record["accepted"]["acceptance_id"] and "event" not in slot
              for slot in current["events"]), "真实签页未提供终态回执引用或恢复了载荷")
    error = lab.rust("a1", "wire_download", **current, expected_exit=1)
    check(error["code"] == "stream_source_required" and snapshot(lab, "a1") == saved,
          "终态引用绕过签页来源门禁")
    lab.download("a1", current)
    again = lab.rust("a1", "wire_process")
    check(again["results"] == [], "重叠补引用重复执行已经成功的占位槽")
    new = refresh(lab, record, old)
    complete(lab, record, new)
    lab.case_evidence.update(progress="LEGACY_ANONYMOUS_SLOT_REFRESHED_AFTER_SIGNED_OVERLAP",
        old_page_source="real signed HTTP page with include_terminal_references=false; no old binary claim",
        overlap_source="real pull_events_signed HTTP response", unsigned_error=error)


def save_boundary(lab, *, point):
    record, old = lagging(lab)
    synchronize(lab, "a1")
    before = state(lab)
    options = ({"failpoint": point} if POINTS[point] < 86
               else {"env": {"RIM_ANCHOR_FAILPOINT": point}})
    prepare(lab, record, expected_exit=POINTS[point], **options)
    failed = state(lab)
    saved = point in ("after_save", "after_journal")
    check((failed["snapshots"]["a1"] != before["snapshots"]["a1"]) == saved
          and failed["relay"] == before["relay"], "刷新保存窗口错误或本机故障改变 Relay")
    lab.restart()
    if hasattr(lab, "configs") and point == "after_save":
        check(not (lab.directory / "a1/anchor-journal.enc").exists(), "预期无精确锚日志窗口")
        anchor = lab.rust("a1", "anchor_inspect")
        check(anchor["active_txn"] is not None and anchor["paused"], "缺日志窗口未保留真正预约")
        for _ in range(2):
            check(lab.blocked("a1", "anchor_resume")["code"] == "anchor_unresolved",
                  "刷新保存后无日志却解除了预约")
            check(lab.blocked("a1", "wire_reclaim_recover", plan_id=PLAN)["code"] == "anchor_paused",
                  "恢复入口绕过无日志未决锚")
            lab.restart()
        check(state(lab) == failed, "阻断或重启改变刷新快照或 Relay")
        lab.case_evidence.update(progress="REFRESH_SAVED_WITHOUT_JOURNAL_REMAINS_BLOCKED",
                                point=point, before=before, after=failed, anchor=anchor)
        return
    if hasattr(lab, "configs"):
        lab.resume("a1")
    recovered = local_plan(lab, "a1", PLAN)
    check((recovered["request_json"] != old.request_json) == saved,
          "重开恢复没有按真实保存边界选择旧或新请求")
    if saved:
        repeated = prepare(lab, record)
        check(repeated["duplicate"] and repeated["request_json"] == recovered["request_json"],
              "保存后重试再次生成刷新请求")
        request = PreparedRequest(recovered)
    else:
        request = refresh(lab, record, old)
    complete(lab, record, request)
    lab.case_evidence.update(progress="REFRESH_SAVE_BOUNDARY_RECOVERED", point=point,
                            before=before, after_failure=failed, saved=saved)


COMMON_CASES = [("M12.prepare.refresh.lagging_sender", lagging_sender),
                ("M12.prepare.refresh.late_read", late_read),
                ("M12.prepare.refresh.unrelated_after_lost_confirm", unrelated_after_lost_confirm),
                ("M12.prepare.refresh.legacy_tombstone", legacy_tombstone)]
CASES = COMMON_CASES + [(f"M12.prepare.refresh.local.{point}", partial(save_boundary, point=point))
                        for point in ("before_save", "before_rename", "after_save")]
ANCHOR_CASES = COMMON_CASES + [(f"M12.prepare.refresh.anchor.{point}", partial(save_boundary, point=point))
                               for point in ("after_save", "after_journal")]
