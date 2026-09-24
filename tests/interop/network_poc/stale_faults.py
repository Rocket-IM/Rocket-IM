"""state_stale 真实 HTTP 故障和拒绝、R1、后继三个快照边界。"""

import base64
from functools import partial
import hashlib
import http.client

from .closure_support import accept
from .deletion_observer import relay_records
from .fixture import CONVERSATION, check
from .send_order_support import snapshot
from .stale_delivery import receive
from .stale_support import advance, blocked, catch_up, persist, prepare, reject, statement, successor


EXIT_CODES = {"before_save": 83, "before_rename": 84, "after_save": 85}


def _record(lab, kind, stage, **fields):
    item = {"kind": kind, "stage": stage, **fields}
    lab.case_evidence.setdefault("stale_faults", []).append(item)
    return item


def _pending(lab, proof=None, *, ready=False, attempt="P1"):
    state = lab.rust("a1", "wire_inspect")
    expected = {"logical_message_id": "M1", "attempt_id": attempt}
    if proof is not None:
        claims = statement(proof)
        expected.update(status="rejected_awaiting_successor" if ready else "rejected_awaiting_checkpoint",
                        closure_id=proof["closure_id"],
                        required_authorization_version=claims["required_authorization_version"],
                        required_crypto_state_ref=claims["required_crypto_state_ref"])
    check(state["send_order"]["pending"] == expected, "拒绝恢复未保持精确原尝试及权限门槛")
    return state


def _rejected_rows(rows, packet):
    check(rows["counts"] == {"attempts": 1, "logical_messages": 1, "accepted": 0,
                             "events": 0, "message_events": 0, "receipts": 0},
          "拒绝事务产生部分记录、接受或投递")
    row = rows["attempts"][0]
    proof = row["result"]
    check(row["outcome"] == proof["outcome"] == "rejected_final" and proof["code"] == "state_stale"
          and proof["logical_message_id"] == "M1" and proof["attempt_id"] == "P1"
          and row["closure_id"] == proof["closure_id"] and bool(proof["rejection_receipt"])
          and row["successor"] is None and row["acceptance_id"] is None
          and rows["logical_messages"][0]["tail"] == "P1"
          and rows["logical_messages"][0]["accepted_attempt"] is None,
          "拒绝结果、尾链或签名证明未同事务完整保存")
    for part in ("header", "payload"):
        expected = hashlib.sha256(base64.b64decode(packet["envelope"][part + "_bytes"], validate=True)).hexdigest()
        check(row[part + "_sha256"] == expected, "拒绝记录没有保持原 MLS 包完整字节")
    return proof


def _setup(lab):
    packet = prepare(lab)
    permission = advance(lab)
    proof = reject(lab, packet)
    return packet, permission, proof


def _finish(lab, proof, packet=None):
    catch_up(lab, "a1", "a2", "b1")
    blocked(lab)
    if packet is None:
        _pending(lab, proof, ready=True)
        packet = successor(lab, proof)
        check(packet["reused"] is False, "首次合法后继没有创建独立尝试")
    accepted = accept(lab, packet, "M1", "P2", replaces_attempt_id="P1", closure_id=proof["closure_id"])
    receive(lab, [("M1", "P2", "stale payload", packet, accepted)])
    return {"rejection": proof, "accepted": accepted}


def relay_loss(lab, *, hook):
    packet = prepare(lab)
    advance(lab)
    before, original, process = relay_records(lab), snapshot(lab), lab.process
    check(before["counts"]["attempts"] == before["counts"]["events"] == 0, "拒绝故障前已有消息记录")
    _record(lab, "relay_loss", "before_submit", hook=hook, relay=before,
            snapshot_sha256=original, sender=_pending(lab))
    lab.control("hook", hook=hook)
    try:
        lab.submit(packet, expected=409)
        raise AssertionError("拒绝事务指定窗口没有断开 HTTP 响应")
    except (http.client.RemoteDisconnected, ConnectionResetError) as error:
        item = _record(lab, "relay_loss", "disconnected", hook=hook,
                       exception=type(error).__name__, response_received=False, relay_pid=process.pid)
    expected_exit = {"before_commit_exit": 86, "after_commit_exit": 87}.get(hook)
    actual = process.poll() if expected_exit is None else process.wait(timeout=10)
    rows = relay_records(lab)
    item.update(relay_exit_code=actual, relay_after=rows, snapshot_sha256_after=snapshot(lab))
    check(actual == expected_exit and snapshot(lab) == original, "拒绝事务实际退出或客户端边界不符")
    committed = hook != "before_commit_exit"
    observed = _rejected_rows(rows, packet) if committed else None
    if not committed:
        check(rows == before, "拒绝提交前退出留下部分原尝试")
    blocked(lab)
    lab.restart()
    queried = lab.attempt("M1")
    _record(lab, "relay_loss", "first_http_query", hook=hook, result=queried,
            old_pid=process.pid, new_pid=lab.process.pid, relay_after=relay_records(lab))
    expected = observed if committed else {"outcome": "not_found", "logical_message_id": "M1", "attempt_id": "P1"}
    check(lab.process.poll() is None and lab.process.pid != process.pid and queried == expected
          and relay_records(lab) == rows, "重启首次查询未保持原拒绝或回滚事实")
    blocked(lab)
    proof = reject(lab, packet)
    recovered = relay_records(lab)
    check(proof == _rejected_rows(recovered, packet), "真实 HTTP 恢复不等于完整原拒绝")
    if committed:
        check(proof == observed and recovered == rows, "拒绝重试制造另一签名终态")
    saved = persist(lab, proof)
    _record(lab, "relay_loss", "local_saved", hook=hook, proof=proof, result=saved,
            sender=_pending(lab, proof), snapshot_sha256=snapshot(lab))
    check(saved["duplicate"] is False and relay_records(lab) == recovered, "首次拒绝保存错误或改写Relay")
    blocked(lab, logical="M1", attempt="P2", code="rejection_checkpoint_required",
            payload="stale payload", replaces_attempt_id="P1", closure_id=proof["closure_id"])
    return _finish(lab, proof)


def rejection_save(lab, *, point):
    _, _, proof = _setup(lab)
    before, rows = snapshot(lab), relay_records(lab)
    _record(lab, "rejection_save", "before_exit", point=point, proof=proof,
            snapshot_sha256=before, sender=_pending(lab), relay=rows)
    persist(lab, proof, failpoint=point, expected_exit=EXIT_CODES[point])
    committed, after = point == "after_save", snapshot(lab)
    _record(lab, "rejection_save", "after_exit", point=point, verified_exit_code=EXIT_CODES[point],
            success_response_emitted=False, snapshot_sha256_before=before, snapshot_sha256_after=after,
            sender=_pending(lab, proof if committed else None))
    check((after != before) if committed else (after == before), "拒绝证明未符合原子保存边界")
    blocked(lab)
    blocked(lab, logical="M1", attempt="P2", code="rejection_checkpoint_required" if committed else "send_order_pending",
            payload="stale payload", replaces_attempt_id="P1", closure_id=proof["closure_id"])
    lab.restart()
    queried = lab.attempt("M1")
    check(queried == proof and relay_records(lab) == rows, "重启丢失原签名拒绝事实")
    saved = persist(lab, queried)
    _record(lab, "rejection_save", "recovered", point=point, queried=queried, result=saved,
            sender=_pending(lab, proof))
    check(saved["duplicate"] is committed, "恢复duplicate与真实拒绝保存边界不符")
    return _finish(lab, proof)


def permission_save(lab, *, point):
    _, permission, proof = _setup(lab)
    persist(lab, proof)
    cp_before = lab.rust("a1", "permission_inspect")
    page = lab.http("a1", "get_permission_records", {"service_id": lab.service,
        "conversation_id": CONVERSATION, "after_version": cp_before["checkpoint"]["authorization_version"], "limit": "32"})
    check(page["records"] == [permission] and page["has_more"] is False, "R1故障输入不是HTTP原权限记录")
    before, rows = snapshot(lab), relay_records(lab)
    _record(lab, "permission_save", "before_exit", point=point, permission_page=page,
            snapshot_sha256=before, permission=cp_before, sender=_pending(lab, proof))
    lab.rust("a1", "permission_recover", record=page["records"][0],
             failpoint=point, expected_exit=EXIT_CODES[point])
    committed, after = point == "after_save", snapshot(lab)
    cp_after = lab.rust("a1", "permission_inspect")
    _record(lab, "permission_save", "after_exit", point=point, verified_exit_code=EXIT_CODES[point],
            success_response_emitted=False, snapshot_sha256_before=before, snapshot_sha256_after=after,
            permission=cp_after, sender=_pending(lab, proof, ready=committed))
    check((after != before) if committed else (after == before), "R1未符合实际快照提交边界")
    claims = statement(proof)
    check(cp_after["checkpoint"] == cp_before["checkpoint"] if not committed else
          (cp_after["checkpoint"]["authorization_version"] == claims["required_authorization_version"]
           and cp_after["checkpoint"]["crypto_state_ref"] == claims["required_crypto_state_ref"]),
          "R1检查点与已提交边界不符")
    blocked(lab)
    if not committed:
        blocked(lab, logical="M1", attempt="P2", code="rejection_checkpoint_required",
                payload="stale payload", replaces_attempt_id="P1", closure_id=proof["closure_id"])
    lab.restart()
    check(lab.attempt("M1") == proof and relay_records(lab) == rows, "R1保存退出改变Relay原拒绝")
    return _finish(lab, proof)


def successor_save(lab, *, point):
    _, _, proof = _setup(lab)
    persist(lab, proof)
    catch_up(lab, "a1", "a2", "b1")
    before, rows = snapshot(lab), relay_records(lab)
    _record(lab, "successor_save", "before_exit", point=point, sender=_pending(lab, proof, ready=True),
            snapshot_sha256=before)
    lab.rust("a1", "wire_send", logical_message_id="M1", attempt_id="P2", payload="stale payload",
             replaces_attempt_id="P1", closure_id=proof["closure_id"],
             failpoint=point, expected_exit=EXIT_CODES[point])
    committed, after = point == "after_save", snapshot(lab)
    _record(lab, "successor_save", "after_exit", point=point, verified_exit_code=EXIT_CODES[point],
            success_response_emitted=False, snapshot_sha256_before=before, snapshot_sha256_after=after,
            sender=_pending(lab, None if committed else proof, ready=True, attempt="P2" if committed else "P1"))
    check((after != before) if committed else (after == before), "后继原包与尾链未同快照提交")
    blocked(lab)
    lab.restart()
    check(lab.attempt("M1") == proof and relay_records(lab) == rows, "未提交后继改变原Relay拒绝")
    packet = successor(lab, proof)
    _record(lab, "successor_save", "recovered", point=point, reused=packet["reused"], packet=packet)
    check(packet["reused"] is committed, "后继恢复未按实际保存原包重试")
    return _finish(lab, proof, packet)


CASES = [("STALE-FAULT-relay-" + hook, partial(relay_loss, hook=hook))
         for hook in ("drop_after_commit", "before_commit_exit", "after_commit_exit")]
for name, function in (("rejection", rejection_save), ("R1", permission_save), ("successor", successor_save)):
    CASES += [("STALE-FAULT-" + name + "-" + point, partial(function, point=point)) for point in EXIT_CODES]
