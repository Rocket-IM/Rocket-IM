"""M03 单未决发送槽的真实断连、持久提交退出及旧程序降级取证。"""

import base64
import hashlib
import http.client
import json
import subprocess

from .deletion_observer import relay_records
from .fixture import check, identity
from .send_order_support import blocked
from .slot_support import digest


def _snapshot(lab):
    return (lab.directory / "a1" / "state.enc").read_bytes()


def _hash(value):
    return hashlib.sha256(value).hexdigest()


def _record(lab, kind, stage, **fields):
    value = {"kind": kind, "stage": stage, **fields}
    lab.case_evidence.setdefault("faults", []).append(value)
    return value


def _pending(lab, record, *, cleared=False):
    state = lab.rust("a1", "wire_inspect")
    expected = None if cleared else {"logical_message_id": record["logical"],
                                    "attempt_id": record["packet"]["attempt_id"]}
    check(state["send_order"]["pending"] == expected, "单未决槽未保持原尝试或未按提交边界清除")
    return state


def _blocked(lab, record, kind, stage):
    blocked(lab, kind + "_" + stage)
    state = _pending(lab, record)
    _record(lab, kind, stage, sender=state, snapshot_sha256=_hash(_snapshot(lab)))


def _accepted_rows(rows, record):
    check(rows["counts"] == {"attempts": 1, "logical_messages": 1, "accepted": 1,
                             "events": 3, "message_events": 3, "receipts": 0},
          "丢ACK恢复必须只有一份完整接受及三个原投递槽")
    attempt = rows["attempts"][0]
    accepted = attempt["result"]
    envelope = record["packet"]["envelope"]
    check(accepted["outcome"] == attempt["outcome"] == "accepted"
          and accepted["logical_message_id"] == record["logical"]
          and accepted["attempt_id"] == record["packet"]["attempt_id"]
          and accepted["acceptance_id"] == attempt["acceptance_id"]
          and accepted["availability"] == attempt["availability"] == "available"
          and accepted["recipients"] == [identity(d) for d in ("a2", "b1", "c1")]
          and bool(accepted["acceptance_receipt"]), "离线接受事实及完整目标不符")
    check(attempt["header_sha256"] == _hash(base64.b64decode(envelope["header_bytes"], validate=True))
          and attempt["payload_sha256"] == _hash(base64.b64decode(envelope["payload_bytes"], validate=True)),
          "Relay提交字节不是原持久发送尝试")
    check([(e["account"], e["device"]) for e in rows["events"]]
          == [(identity(d)["account_id"], d) for d in ("a2", "b1", "c1")]
          and len({e["event_id"] for e in rows["events"]}) == 3
          and all(e["seq"] == "1" and e["type"] == "message" and e["availability"] == "available"
                  and e["acceptance_id"] == accepted["acceptance_id"] for e in rows["events"]),
          "原接受存在重复、遗漏或错误设备投递")
    return accepted


def lose_ack(lab, record, hook):
    """丢失真实HTTP响应后保留门禁；返回HTTP恢复结果，不把离线观察当作接受输入。"""
    check(hook in ("drop_after_commit", "before_commit_exit", "after_commit_exit"), "不支持的提交故障")
    before = relay_records(lab)
    check(before["counts"] == {"attempts": 0, "logical_messages": 0, "accepted": 0,
                               "events": 0, "message_events": 0, "receipts": 0}, "故障必须作用于尚未接受的首条")
    snapshot = _snapshot(lab)
    process = lab.process
    _record(lab, "lose_ack", "before_submit", hook=hook, relay_before=before,
            sender=_pending(lab, record), snapshot_sha256=_hash(snapshot),
            original_envelope_sha256=digest(record["packet"]["envelope"]),
            payload_sha256=record["payload_sha256"])
    lab.control("hook", hook=hook)
    try:
        lab.submit(record["packet"])
        raise AssertionError("指定提交窗口未丢失HTTP接受响应")
    except (http.client.RemoteDisconnected, ConnectionResetError) as error:
        disconnected = _record(lab, "lose_ack", "disconnected", hook=hook,
                               exception=type(error).__name__, response_received=False, relay_pid=process.pid)
    expected_exit = {"before_commit_exit": 86, "after_commit_exit": 87}.get(hook)
    actual_exit = process.poll() if expected_exit is None else process.wait(timeout=10)
    disconnected["relay_exit_code"] = actual_exit
    check(actual_exit == expected_exit, "Relay实际退出码或丢ACK存活状态不符")
    offline = relay_records(lab)
    disconnected.update(relay_after=offline, snapshot_sha256_after=_hash(_snapshot(lab)))
    check(_snapshot(lab) == snapshot, "HTTP提交/断连改变端侧加密快照")
    committed = hook != "before_commit_exit"
    observed = _accepted_rows(offline, record) if committed else None
    if not committed:
        check(offline == before, "提交前退出留下了部分接受或投递")
    _blocked(lab, record, "lose_ack", "after_loss_" + hook)
    lab.restart()
    restarted = relay_records(lab)
    _record(lab, "lose_ack", "relay_restarted", hook=hook, relay_pid=lab.process.pid,
            relay_after=restarted, normal_restart_count=1)
    check(lab.process.poll() is None and lab.process.pid != process.pid and restarted == offline,
          "Relay重启改变提交事实或没有启动新进程")
    _blocked(lab, record, "lose_ack", "after_restart_" + hook)
    queried = lab.attempt(record["logical"], attempt=record["packet"]["attempt_id"])
    _record(lab, "lose_ack", "first_http_query", hook=hook, result=queried)
    expected = observed if committed else {"outcome": "not_found", "logical_message_id": record["logical"],
                                          "attempt_id": record["packet"]["attempt_id"]}
    check(queried == expected and relay_records(lab) == offline, "首次HTTP查询改写或未恢复完整原事实")
    # 查询到接受事实也不替代本地 wire_accept 的持久提交。
    _blocked(lab, record, "lose_ack", "after_query_" + hook)
    restored = lab.prepare(record["logical"], record["packet"]["attempt_id"], payload=record["payload"])
    _record(lab, "lose_ack", "original_reloaded", hook=hook, reused=restored["reused"],
            original_envelope_sha256=digest(record["packet"]["envelope"]),
            restored_envelope_sha256=digest(restored["envelope"]))
    check(restored == {**record["packet"], "reused": True}, "恢复未复用完整原尝试及原字节")
    accepted = lab.submit(restored)
    found = lab.attempt(record["logical"], attempt=record["packet"]["attempt_id"])
    after = relay_records(lab)
    _record(lab, "lose_ack", "http_recovered", hook=hook, submit=accepted, get_attempt=found,
            relay_after=after, sender=_pending(lab, record))
    check(accepted == found == _accepted_rows(after, record), "恢复提交/查询与完整接受事实不一致")
    if committed:
        check(accepted == observed and after == offline, "已提交重试制造新的接受或重复投递")
    repeated = lab.submit(restored)
    repeated_query = lab.attempt(record["logical"], attempt=record["packet"]["attempt_id"])
    repeated_rows = relay_records(lab)
    _record(lab, "lose_ack", "repeated_http_recovery", hook=hook, submit=repeated,
            get_attempt=repeated_query, relay_after=repeated_rows)
    check(repeated == repeated_query == accepted and repeated_rows == after, "重复恢复制造第二次接受或投递")
    _blocked(lab, record, "lose_ack", "before_local_accept_" + hook)
    return accepted


def accept_crash(lab, record, accepted, point):
    """实际退出验证接受证明与门禁同一快照提交；恢复使用再次HTTP查询的原证明。"""
    codes = {"before_save": 83, "before_rename": 84, "after_save": 85}
    check(point in codes and accepted["outcome"] == "accepted"
          and accepted["logical_message_id"] == record["logical"], "接受提交故障输入不符")
    fields = {"logical_message_id": accepted["logical_message_id"], "attempt_id": accepted["attempt_id"],
              "acceptance_receipt": accepted["acceptance_receipt"]}
    before = _snapshot(lab)
    relay = relay_records(lab)
    _record(lab, "accept_crash", "before_exit", point=point, snapshot_sha256_before=_hash(before),
            sender=_pending(lab, record), accepted=accepted, relay_before=relay)
    lab.rust("a1", "wire_accept", **fields, failpoint=point, expected_exit=codes[point])
    after = _snapshot(lab)
    _record(lab, "accept_crash", "after_exit", point=point, verified_exit_code=codes[point],
            success_response_emitted=False, snapshot_sha256_before=_hash(before), snapshot_sha256_after=_hash(after))
    committed = point == "after_save"
    check((after != before) if committed else (after == before), "接受证明实际快照提交边界不符")
    sender = _pending(lab, record, cleared=committed)
    _record(lab, "accept_crash", "fresh_cli_after_exit", point=point, sender=sender)
    if not committed:
        _blocked(lab, record, "accept_crash", "after_exit_" + point)
    process = lab.process
    lab.restart()
    _record(lab, "accept_crash", "relay_restarted", point=point, relay_pid=lab.process.pid,
            relay_after=relay_records(lab), normal_restart_count=1,
            sender=_pending(lab, record, cleared=committed))
    check(lab.process.poll() is None and lab.process.pid != process.pid and relay_records(lab) == relay,
          "接受提交恢复重启改变Relay完整原事实")
    recovered = lab.attempt(record["logical"], attempt=accepted["attempt_id"])
    _record(lab, "accept_crash", "http_proof_recovered", point=point, result=recovered)
    check(recovered == accepted, "接受退出后HTTP查询未返回完整原接受事实")
    if not committed:
        _blocked(lab, record, "accept_crash", "after_restart_query_" + point)
    result = lab.rust("a1", "wire_accept", logical_message_id=recovered["logical_message_id"],
                      attempt_id=recovered["attempt_id"], acceptance_receipt=recovered["acceptance_receipt"])
    final = _pending(lab, record, cleared=True)
    _record(lab, "accept_crash", "local_accept_recovered", point=point, result=result, sender=final,
            snapshot_sha256=_hash(_snapshot(lab)), relay_sha256=digest(relay_records(lab)))
    check(result == {"logical_message_id": accepted["logical_message_id"], "attempt_id": accepted["attempt_id"],
                     "acceptance_id": accepted["acceptance_id"], "status": "accepted", "duplicate": committed},
          "重复接受只应出现在after_save真实提交后")
    check(relay_records(lab) == relay, "本地接受恢复改写Relay记录")
    return result


def old_program(lab, *, enabled=True):
    """未启用快照保持兼容，启用后的新快照须明确拒绝降级。"""
    before = _snapshot(lab)
    request = {"directory": str(lab.directory / "a1"), "service": lab.service,
               "account": identity("a1")["account_id"], "device": "a1", "operation": "wire_inspect"}
    evidence = _record(lab, "old_program", "before_read", snapshot_sha256_before=_hash(before))
    try:
        output = subprocess.run([str(lab.old_binary)], input=json.dumps(request), text=True,
                                capture_output=True, timeout=30)
    finally:
        lab.process_count += 1
    after = _snapshot(lab)
    evidence.update(exit_code=output.returncode, snapshot_sha256_after=_hash(after),
                    stderr_sha256=_hash(output.stderr.encode()), stderr_bytes=len(output.stderr.encode()))
    reply = json.loads(output.stdout)
    evidence["mode_enabled"] = enabled
    if not enabled:
        expected = lab.rust("a1", "wire_inspect")
        evidence["result"] = reply.get("result")
        check(output.returncode == 0 and reply.get("ok") is True and reply["result"] == expected
              and "send_order" not in expected and before == after,
              "未启用新快照没有保持旧程序读取兼容")
        evidence["snapshot_unchanged"] = True
        return reply["result"]
    check(output.returncode == 1, "旧程序没有明确拒绝新门禁快照")
    evidence["error"] = reply.get("error")
    check(reply.get("ok") is False and reply["error"]["code"] == "state_decoding"
          and "wire_send_order" in reply["error"]["message"], "旧程序拒绝原因不是新门禁字段")
    check(before == after, "旧程序读取改变新快照原字节")
    evidence["snapshot_unchanged"] = True
    return reply["error"]
