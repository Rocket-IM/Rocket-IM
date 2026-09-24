"""封口响应丢失与 Rust 快照退出；恢复输入只来自真实 HTTP 查询。"""

from functools import partial
import http.client

from .closure_delivery import receive
from .closure_support import (accept, blocked, close, close_request, persist, prepare,
                              snapshot, successor)
from .deletion_observer import relay_records
from .fixture import check
from .slot_support import digest


def _record(lab, kind, stage, **fields):
    item = {"kind": kind, "stage": stage, **fields}
    lab.case_evidence.setdefault("closure_faults", []).append(item)
    return item


def _pending(lab, *, closed=None):
    state = lab.rust("a1", "wire_inspect")
    expected = {"logical_message_id": "M1", "attempt_id": "P1"}
    if closed is not None:
        expected.update(status="closed_awaiting_successor", closure_id=closed["closure_id"])
    check(state["send_order"]["pending"] == expected, "封口恢复没有保持精确原槽或后继保留状态")
    return state


def _closed_rows(rows):
    check(rows["counts"] == {"attempts": 1, "logical_messages": 1, "accepted": 0,
                             "events": 0, "message_events": 0, "receipts": 0},
          "未提交封口产生部分记录、接受或投递")
    row = rows["attempts"][0]
    proof = row["result"]
    check(row["outcome"] == proof["outcome"] == "cancelled_before_accept"
          and proof["logical_message_id"] == "M1" and proof["attempt_id"] == "P1"
          and row["closure_id"] == proof["closure_id"] and bool(proof["closure_receipt"])
          and row["header_sha256"] is None and row["payload_sha256"] is None
          and row["successor"] is None and row["acceptance_id"] is None
          and rows["logical_messages"][0]["tail"] == "P1"
          and rows["logical_messages"][0]["accepted_attempt"] is None,
          "原封口证明、NULL密文或尾链不完整")
    return proof


def _finish(lab, proof):
    blocked(lab)
    packet = successor(lab, proof)
    check(packet["reused"] is False, "恢复后的首个后继未创建独立尝试")
    accepted = accept(lab, packet, "M1", "P2", replaces_attempt_id="P1",
                      closure_id=proof["closure_id"])
    check(lab.rust("a1", "wire_inspect")["send_order"]["pending"] is None,
          "后继接受没有释放门禁")
    receive(lab, [("M1", "P2", "closure payload", packet, accepted)])
    return {"closure": proof, "accepted": accepted}


def relay_loss(lab, *, hook):
    """关闭事务的三个真实退出窗口，区别回滚、已提交和响应断连。"""
    packet = prepare(lab)
    request = close_request(lab)
    before, original = relay_records(lab), snapshot(lab)
    check(before["counts"]["attempts"] == before["counts"]["events"] == 0,
          "封口故障必须从尚未提交的原尝试开始")
    process = lab.process
    _record(lab, "relay_loss", "before_close", hook=hook, request=request,
            relay=before, sender=_pending(lab), snapshot_sha256=original,
            original_envelope_json_sha256=digest(packet["envelope"]))
    lab.control("hook", hook=hook)
    try:
        close(lab, request)
        raise AssertionError("指定封口窗口未丢失 HTTP 响应")
    except (http.client.RemoteDisconnected, ConnectionResetError) as error:
        item = _record(lab, "relay_loss", "disconnected", hook=hook,
                       response_received=False, exception=type(error).__name__, relay_pid=process.pid)
    expected_exit = {"before_commit_exit": 86, "after_commit_exit": 87}.get(hook)
    actual_exit = process.poll() if expected_exit is None else process.wait(timeout=10)
    rows = relay_records(lab)
    item.update(relay_exit_code=actual_exit, relay_after=rows, snapshot_sha256_after=snapshot(lab))
    check(actual_exit == expected_exit and snapshot(lab) == original,
          "Relay封口实际退出或本地快照边界不符")
    committed = hook != "before_commit_exit"
    observed = _closed_rows(rows) if committed else None
    if not committed:
        check(rows == before, "提交前退出留下部分封口事实")
    blocked(lab)
    _pending(lab)
    lab.restart()
    _record(lab, "relay_loss", "restarted", hook=hook, old_pid=process.pid,
            new_pid=lab.process.pid, relay=relay_records(lab), sender=_pending(lab))
    check(lab.process.poll() is None and lab.process.pid != process.pid and relay_records(lab) == rows,
          "Relay重启改变封口提交事实")
    queried = lab.attempt("M1")
    _record(lab, "relay_loss", "first_http_query", hook=hook, result=queried)
    expected = observed if committed else {"outcome": "not_found", "logical_message_id": "M1",
                                          "attempt_id": "P1"}
    check(queried == expected and relay_records(lab) == rows, "HTTP查询未恢复原封口或回滚状态")
    blocked(lab)
    proof = close(lab, request)
    recovered = relay_records(lab)
    _record(lab, "relay_loss", "http_recovered", hook=hook, result=proof, relay=recovered)
    check(proof == lab.attempt("M1") == _closed_rows(recovered), "封口重试与查询不是同一原证明")
    if committed:
        check(proof == observed and recovered == rows, "已提交封口重试制造新终态")
    check(close(lab, request) == proof and relay_records(lab) == recovered, "重复封口改变原记录")
    blocked(lab)
    saved = persist(lab, proof)
    _record(lab, "relay_loss", "local_saved", hook=hook, result=saved,
            sender=_pending(lab, closed=proof), snapshot_sha256=snapshot(lab))
    check(saved["duplicate"] is False and relay_records(lab) == recovered,
          "首次端侧封口保存被误记为重复或改写Relay")
    return _finish(lab, proof)


def save_crash(lab, *, point):
    """三个快照退出点必须整体保存封口证明与仅允许原逻辑后继的门禁。"""
    prepare(lab)
    proof = close(lab, close_request(lab))
    before, rows = snapshot(lab), relay_records(lab)
    code = {"before_save": 83, "before_rename": 84, "after_save": 85}[point]
    _record(lab, "save_crash", "before_exit", point=point, proof=proof,
            snapshot_sha256_before=before, sender=_pending(lab), relay=rows)
    persist(lab, proof, failpoint=point, expected_exit=code)
    after = snapshot(lab)
    committed = point == "after_save"
    item = _record(lab, "save_crash", "after_exit", point=point, verified_exit_code=code,
                   success_response_emitted=False, snapshot_sha256_before=before, snapshot_sha256_after=after)
    check((after != before) if committed else (after == before), "封口证明与门禁没有同一快照提交")
    item["sender"] = _pending(lab, closed=proof if committed else None)
    blocked(lab)
    if not committed:
        blocked(lab, logical="M1", attempt="P2", replaces_attempt_id="P1", closure_id=proof["closure_id"])
    process = lab.process
    lab.restart()
    queried = lab.attempt("M1")
    _record(lab, "save_crash", "http_recovered", point=point, old_pid=process.pid,
            new_pid=lab.process.pid, proof=queried, relay=relay_records(lab))
    check(lab.process.poll() is None and lab.process.pid != process.pid
          and queried == proof and relay_records(lab) == rows, "封口退出恢复没有保持原服务终态")
    blocked(lab)
    saved = persist(lab, queried)
    _record(lab, "save_crash", "local_recovered", point=point, result=saved,
            sender=_pending(lab, closed=proof), snapshot_sha256=snapshot(lab))
    check(saved["duplicate"] is committed and relay_records(lab) == rows,
          "重复保存没有反映真实快照提交边界")
    return _finish(lab, proof)


CASES = [("closure_relay_" + hook, partial(relay_loss, hook=hook))
         for hook in ("drop_after_commit", "before_commit_exit", "after_commit_exit")]
CASES += [("closure_save_" + point, partial(save_crash, point=point))
          for point in ("before_save", "before_rename", "after_save")]
