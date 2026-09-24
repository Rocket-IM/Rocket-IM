"""M13 显式阅读、HTTP 报告及签页下载/处理的真实退出恢复。"""

from functools import partial
import hashlib
import http.client
import json
import subprocess

from .deletion_observer import relay_records
from .fixture import check, identity
from .read_support import (DEVICES, finish, inspect, load_messages, mark, pending,
                           publish, report, snapshot, synchronize)

EXIT_CODES = {"before_save": 83, "before_rename": 84, "after_save": 85}


def _record(lab, kind, **fields):
    item = {"kind": kind, **fields}
    lab.case_evidence.setdefault("read_faults", []).append(item)
    return item


def _observed_rust(lab, operation, *, expected_exit=0, **fields):
    """只观察原 CLI 的真实 PID/退出；不复制阅读状态机或保存实现。"""
    request = {"directory": str(lab.directory / "b1"), "service": lab.service,
               "account": identity("b1")["account_id"], "device": "b1",
               "operation": operation, **fields}
    process = subprocess.Popen([str(lab.binary)], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    lab.process_count += 1
    evidence = _record(lab, "rust_process", operation=operation, pid=process.pid,
                       failpoint=fields.get("failpoint"), expected_exit_code=expected_exit)
    try:
        stdout, stderr = process.communicate(json.dumps(request), timeout=30)
    except BaseException:
        process.kill()
        stdout, stderr = process.communicate(timeout=5)
        evidence.update(exit_code=process.returncode, interrupted=True)
        raise
    evidence.update(exit_code=process.returncode, stdout_bytes=len(stdout.encode()),
                    stdout_sha256=hashlib.sha256(stdout.encode()).hexdigest(),
                    stderr_bytes=len(stderr.encode()),
                    stderr_sha256=hashlib.sha256(stderr.encode()).hexdigest())
    check(process.returncode == expected_exit, "阅读故障实际 Rust 退出码不符")
    if expected_exit:
        check(not stdout.strip(), "退出窗口不应交付成功响应")
        evidence["success_response_emitted"] = False
        return None, process.pid
    reply = json.loads(stdout)
    check(reply["ok"] is True, "新的 Rust 进程无法读取已提交状态")
    return reply["result"], process.pid


def _state(lab, *, previous_pid=None):
    before = snapshot(lab)
    reads, pid = _observed_rust(lab, "wire_read_inspect")
    check(previous_pid is None or pid != previous_pid, "恢复观察未启动独立 Rust 进程")
    value = {"snapshot_sha256": before, "reads": reads,
             "pending": pending(lab), "wire": lab.rust("b1", "wire_inspect"),
             "message_slot": lab.rust("b1", "wire_slot_inspect", event_seq="1")}
    check(snapshot(lab) == before and inspect(lab) == reads, "只读观察改写阅读快照")
    _record(lab, "state", pid=pid, previous_pid=previous_pid, state=value)
    return value


def _setup(lab):
    records = publish(lab)
    ids = load_messages(lab, records)
    return records, ids


def _pending_one(state, records, ids):
    reads = state["reads"]
    check(reads["pending_count"] == 1 and reads["confirmed_count"] == 0
          and len(reads["records"]) == 1, "原阅读意图没有完整保持待报")
    item = reads["records"][0]
    check(item["message_event_id"] == ids[0] and item["device_id"] == "b1"
          and item["account_id"] == identity("b1")["account_id"]
          and item["acceptance_id"] == records[0]["accepted"]["acceptance_id"]
          and item["status"] == "pending" and item["confirmation"] is None,
          "待报记录错绑消息、本人设备或提前确认")


def _restart(lab, rows):
    old_pid = lab.process.pid
    lab.restart()
    current = relay_records(lab)
    _record(lab, "relay_restart", old_pid=old_pid, new_pid=lab.process.pid, relay=current)
    check(lab.process.pid != old_pid and lab.process.poll() is None and current == rows,
          "Relay 重启改变既有记录或未启动新进程")


def _reported_rows(before, after, records):
    accepted = records[0]["accepted"]["acceptance_id"]
    check(after["attempts"] == before["attempts"]
          and after["logical_messages"] == before["logical_messages"]
          and [e for e in after["events"] if e["type"] == "message"] == before["events"],
          "已读报告改写原接受、字节摘要或消息槽")
    check(after["counts"] == {"attempts": 1, "logical_messages": 1, "accepted": 1,
                              "events": 11, "message_events": 3, "receipts": 1}
          and after["receipts"] == [{"acceptance_id": accepted, "account": identity("b1")["account_id"],
                                      "device": "b1", "delivered": 1, "is_read": 1}],
          "阅读事务没有同时保存唯一本人回执及完整通知")
    expected = {(identity(d)["account_id"], d) for d in DEVICES}
    for kind in ("delivery", "read"):
        events = [e for e in after["events"] if e["type"] == kind]
        check(len(events) == 4 and {(e["account"], e["device"]) for e in events} == expected
              and all(e["acceptance_id"] == accepted and e["availability"] == "available" for e in events),
              "已读或隐含送达通知重复、遗漏或错绑接受")
    check(len({e["event_id"] for e in after["events"]}) == 11, "事件身份重复")
    check(after["streams"] == [{**s, "watermark": str(int(s["watermark"]) + 2)} for s in before["streams"]],
          "已读扇出没有保持原流身份及连续水位")


def _page(lab, records):
    cursor = lab.rust("b1", "wire_inspect")["sync"]["download_cursor"]
    page = lab.pull("b1", after=cursor)
    check(not page["has_more"] and [v["event"]["type"] for v in page["events"]] == ["delivery", "read"]
          and all(v["event"]["device"] == identity("b1")
                  and v["event"]["acceptance_id"] == records[0]["accepted"]["acceptance_id"]
                  for v in page["events"]), "故障输入不是本人已读的真实 HTTP 签页")
    _record(lab, "signed_read_page", after_seq=cursor, signed_page=page.wrapper)
    return page


def _finish(lab, records, *, expected_confirmed=1):
    results = synchronize(lab)
    check(sum(r["read_confirmed_count"] for r in results) == expected_confirmed,
          "恢复没有且仅按实际未提交数量确认阅读")
    finish(lab, records)


def mark_save(lab, *, point):
    records, ids = _setup(lab)
    before, rows = _state(lab), relay_records(lab)
    _record(lab, "mark_before", point=point, state=before, relay=rows, event_ids=ids)
    _, pid = _observed_rust(lab, "wire_read", event_ids=ids, failpoint=point, expected_exit=EXIT_CODES[point])
    after, committed = _state(lab, previous_pid=pid), point == "after_save"
    check((after["snapshot_sha256"] != before["snapshot_sha256"]) == committed
          and after["wire"] == before["wire"] and after["message_slot"] == before["message_slot"]
          and relay_records(lab) == rows,
          "阅读意图保存边界错误或改变原消息/Relay")
    if committed:
        _pending_one(after, records, ids)
    else:
        check(after == before, "阅读提交前退出留下部分意图")
    _restart(lab, rows)
    recovered = mark(lab, ids)
    check(recovered == {"marked_count": int(not committed), "duplicate_count": int(committed),
                        "pending_count": 1, "confirmed_count": 0}, "同一阅读恢复没有按持久边界去重")
    _pending_one(_state(lab), records, ids)
    report(lab)
    _finish(lab, records)


def relay_loss(lab, *, hook):
    records, ids = _setup(lab)
    mark(lab, ids)
    before, rows, process = _state(lab), relay_records(lab), lab.process
    request = before["pending"]["request"]
    _record(lab, "report_before", hook=hook, request=request, state=before, relay=rows)
    lab.control("hook", hook=hook)
    try:
        response = lab.http("b1", "report_read", request)
        _record(lab, "unexpected_http_response", response=response)
        raise AssertionError("已读指定事务窗口未断开 HTTP")
    except (http.client.RemoteDisconnected, ConnectionResetError) as error:
        lost = _record(lab, "report_disconnected", hook=hook, exception=type(error).__name__,
                       response_received=False, relay_pid=process.pid)
    expected_exit = {"before_commit_exit": 86, "after_commit_exit": 87}.get(hook)
    actual_exit = process.poll() if expected_exit is None else process.wait(timeout=10)
    current = relay_records(lab)
    lost.update(relay_exit_code=actual_exit, relay=current)
    check(actual_exit == expected_exit and _state(lab) == before,
          "报告退出/存活边界不符或裸 HTTP 改变本地阅读")
    committed = hook != "before_commit_exit"
    if committed:
        _reported_rows(rows, current, records)
    else:
        check(current == rows, "报告提交前退出留下部分回执或通知")
    _restart(lab, current)
    check(pending(lab)["request"] == request, "重启后没有导出同一原阅读请求")
    report(lab)
    recovered = relay_records(lab)
    _reported_rows(rows, recovered, records)
    check((not committed or recovered == current) and _state(lab) == before,
          "原报告重试新增通知或 HTTP 成功清除了待报")
    _finish(lab, records)


def notification_save(lab, *, point, operation):
    records, ids = _setup(lab)
    mark(lab, ids)
    report(lab)
    page = _page(lab, records)
    if operation == "wire_process":
        lab.download("b1", page)
    before, rows = _state(lab), relay_records(lab)
    _pending_one(before, records, ids)
    _record(lab, "notification_before", operation=operation, point=point, state=before, relay=rows)
    fields = page.signed_input() if operation == "wire_download_signed" else {}
    _, pid = _observed_rust(lab, operation, **fields, failpoint=point, expected_exit=EXIT_CODES[point])
    after, committed = _state(lab, previous_pid=pid), point == "after_save"
    check((after["snapshot_sha256"] != before["snapshot_sha256"]) == committed
          and after["message_slot"] == before["message_slot"]
          and relay_records(lab) == rows, "通知保存边界错误或本地操作改变 Relay/原消息槽")
    check({k: v for k, v in after["wire"].items() if k != "sync"}
          == {k: v for k, v in before["wire"].items() if k != "sync"},
          "处理已读通知改变了密码/消息/历史状态")
    if not committed:
        check(after == before, "通知提交前退出留下部分游标、槽或确认")
    else:
        expected_sync = dict(before["wire"]["sync"])
        if operation == "wire_download_signed":
            expected_sync.update(download_cursor=page["next_after_seq"], slot_count=3, pending_count=2)
        else:
            expected_sync.update(processed_cursor=page["next_after_seq"], pending_count=0)
        check(after["wire"]["sync"] == expected_sync, "通知槽、下载/处理游标未按提交边界整体保存")
    if operation == "wire_download_signed":
        _pending_one(after, records, ids)
        check(after["reads"] == before["reads"] and after["pending"] == before["pending"],
              "仅下载已读签页就清除了待报")
    elif committed:
        read = next(e for e in page["events"] if e["event"]["type"] == "read")
        check(after["reads"]["pending_count"] == 0 and after["reads"]["confirmed_count"] == 1
              and after["reads"]["records"][0]["confirmation"] ==
              {"event_id": read["event_id"], "event_seq": read["event_seq"]},
              "已提交处理没有绑定精确本人 Read 槽")
    _restart(lab, rows)
    if operation == "wire_download_signed":
        downloaded = lab.download("b1", page)
        _record(lab, "download_recovered", result=downloaded, state=_state(lab))
        _pending_one(_state(lab), records, ids)
    _finish(lab, records, expected_confirmed=int(operation != "wire_process" or not committed))


CASES = [("M13-FAULT-mark-" + p, partial(mark_save, point=p)) for p in EXIT_CODES]
CASES += [("M13-FAULT-report-" + h, partial(relay_loss, hook=h))
          for h in ("drop_after_commit", "before_commit_exit", "after_commit_exit")]
for name, operation in (("download", "wire_download_signed"), ("process", "wire_process")):
    CASES += [("M13-FAULT-" + name + "-" + p, partial(notification_save, point=p, operation=operation))
              for p in EXIT_CODES]
