"""显式阅读命令与当前设备已读事实；真实用户交互仍需独立验收。"""

from copy import deepcopy

from .deletion_observer import relay_records
from .fixture import check, identity
from .read_support import (finish, inspect, load_messages, mark, pending, publish,
                           refuse, report, snapshot, synchronize)


def lifecycle(lab):
    records = publish(lab, 2)
    ids = load_messages(lab, records)
    load_messages(lab, records, "a2")
    for device in ("a2", "b1"):
        processed = lab.rust(device, "wire_process")
        for candidate in processed["deliveries"]:
            lab.http(device, "report_delivery", {"service_id": lab.service, **candidate})
        check(inspect(lab, device)["records"] == [], "送达自动创建阅读意图")
    rows = relay_records(lab)
    check(all(r["is_read"] == 0 for r in rows["receipts"])
          and not any(r["type"] == "read" for r in rows["events"]), "后台接收/送达自动产生已读")
    result = mark(lab, ids)
    check(result == {"marked_count": 2, "duplicate_count": 0, "pending_count": 2, "confirmed_count": 0},
          "显式批次没有共同保存两个意图")
    before, state, original = snapshot(lab), inspect(lab), pending(lab)
    check(mark(lab, list(reversed(ids))) == {"marked_count": 0, "duplicate_count": 2,
          "pending_count": 2, "confirmed_count": 0} and snapshot(lab) == before
          and inspect(lab) == state and pending(lab) == original, "重复阅读改写原待办或请求")
    report(lab)
    synchronize(lab)
    before, state = snapshot(lab), inspect(lab)
    check(mark(lab, ids)["confirmed_count"] == 2 and snapshot(lab) == before and inspect(lab) == state,
          "迟到阅读把已确认变回待报")
    synchronize(lab, "a2")
    check(inspect(lab, "a2")["records"] == [], "同账号/其他设备收到read事件自动标记本地阅读")
    finish(lab, records)


def read_event_before_intent(lab):
    records = publish(lab)
    ids = load_messages(lab, records)
    request = {"service_id": lab.service, "acceptance_ids": [records[0]["accepted"]["acceptance_id"]]}
    # 旧脚本/外部宿主已报告，不冒称本机存在显式意图；正常HTTP只持有设备凭证。
    response = lab.http("b1", "report_read", request)
    synchronize(lab)
    check(inspect(lab)["records"] == [], "早到Service已读记录自动生成阅读意图")
    result = mark(lab, ids)
    check(result["pending_count"] == 1 and result["confirmed_count"] == 0, "标记操作跳过显式待报持久状态")
    state = inspect(lab)
    resolved = lab.rust("b1", "wire_process")
    check(resolved["results"] == [] and resolved["read_confirmed_count"] == 1,
          "已存在原Read事件未用于恢复，或重新处理了原消息")
    lab.case_evidence["prior_read_event"] = {"legacy_report": response, "state_after_mark": state,
        "reconcile": resolved, "state_after_process": inspect(lab)}
    finish(lab, records)


def per_device(lab):
    records = publish(lab)
    b_ids = load_messages(lab, records)
    a_ids = load_messages(lab, records, "a2")
    mark(lab, b_ids)
    mark(lab, a_ids, "a2")
    report(lab, "a2")
    results = synchronize(lab)
    check(inspect(lab)["pending_count"] == 1 and inspect(lab)["confirmed_count"] == 0
          and sum(r["read_confirmed_count"] for r in results) == 0, "A2的真实read错误结束B1待办")
    synchronize(lab, "a2")
    report(lab)
    synchronize(lab)
    synchronize(lab, "a1")
    check(inspect(lab, "a1")["records"] == [], "A2阅读被扩大为同账号A1已读")
    finish(lab, records, readers=("a2", "b1"))


def wrong_attempt_confirmation(lab):
    records = publish(lab)
    ids = load_messages(lab, records)
    mark(lab, ids)
    report(lab)
    page = lab.pull("b1", after="1")
    modified = deepcopy(page)
    reads = [s["event"] for s in modified["events"] if s["event"]["type"] == "read"]
    check(len(reads) == 1 and reads[0]["device"] == identity("b1"), "缺少真实本人read槽")
    reads[0]["attempt_id"] = "synthetic-wrong-attempt"
    signed = lab.sign_test_page(modified)
    lab.download("b1", signed)
    result = lab.rust("b1", "wire_process")
    state = inspect(lab)
    check(state["pending_count"] == 1 and state["confirmed_count"] == 0
          and result["read_confirmed_count"] == 0, "错attempt的有效Service签页误清阅读待办")
    lab.case_evidence.update(synthetic_confirmation={"construction": "fixture_service_resigned_wrong_attempt",
        "original_page": page.wrapper, "altered_page": signed.wrapper, "process": result, "read_state": state},
        final_relay=relay_records(lab), progress="PENDING_WRONG_ATTEMPT_CONFIRMATION", confirmed_read_intents=0)


def batch_pagination(lab):
    records = publish(lab, 101)
    ids = load_messages(lab, records)
    mark(lab, ids[:100])
    mark(lab, ids[100:])
    first = pending(lab)
    check(first["pending_count"] == 101 and first["has_more"] and len(first["request"]["acceptance_ids"]) == 100,
          "待报分页没有遵守HTTP100上限")
    report(lab)
    synchronize(lab)
    second = pending(lab)
    check(second["pending_count"] == 1 and not second["has_more"]
          and set(first["request"]["acceptance_ids"]).isdisjoint(second["request"]["acceptance_ids"]),
          "确认第一批后跳过、重复或提前完成第二批")
    report(lab)
    synchronize(lab)
    lab.case_evidence["batches"] = [first, second, pending(lab)]
    finish(lab, records)


def invalid_batch(lab):
    records = publish(lab, 2)
    ids = load_messages(lab, records)
    for invalid in ([], [ids[0], ids[0]], [ids[0]] * 101):
        refuse(lab, invalid, code="read_invalid")
    refuse(lab, [ids[0], "unknown-event"], code="read_target_not_found")
    check(mark(lab, [ids[0]])["marked_count"] == 1, "错误批次污染合法意图")
    state = inspect(lab)
    refuse(lab, [ids[1], "unknown-event"], code="read_target_not_found")
    check(inspect(lab) == state, "部分有效批次写入了第二意图")
    mark(lab, [ids[1]])
    report(lab)
    synchronize(lab)
    finish(lab, records)


CASES = [("M13.read.lifecycle", lifecycle), ("M13.read.prior_event", read_event_before_intent),
         ("M13.read.per_device", per_device), ("M13.read.wrong_attempt", wrong_attempt_confirmation),
         ("M13.read.batch_pagination", batch_pagination), ("M13.read.invalid_batch", invalid_batch)]
