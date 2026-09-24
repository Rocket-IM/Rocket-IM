"""M08 提交前后真实退出取证；只保存公开结果、文件和原字节摘要。"""

import http.client

from .deletion_observer import relay_records
from .deletion_support import capture, unchanged
from .fixture import check
from .message_cases import header
from .retry_support import committed_fact
from .terminal_support import changed_packet, input_summary, reject_mutation


def request(lab, packet, operation, proof, *, expected=(200, 409)):
    if operation == "submit_message":
        return lab.submit(packet, expected=expected, **proof)
    source = header(packet)
    fields = {name: source[name] for name in ("service_id", "conversation_id", "logical_message_id", "attempt_id")}
    if operation == "close_attempt":
        fields.update(proof)
    return lab.http("a1", operation, fields, expected=expected)


def check_terminal(lab, packet, outcome, *, reason=None, parent=None):
    rows = relay_records(lab)
    source = input_summary(packet)
    attempt_id = source["header"]["attempt_id"]
    record = next(row for row in rows["attempts"] if row["attempt_id"] == attempt_id)
    value = record["result"]
    check(value["outcome"] == record["outcome"] == outcome
          and value["logical_message_id"] == source["header"]["logical_message_id"]
          and value["attempt_id"] == attempt_id and record["successor"] is None,
          "恢复后的原尝试身份、终态或后继不正确")
    if outcome == "accepted":
        accepted, observed = committed_fact(lab)
        check(accepted == value and observed == rows, "接受事实没有完整提交")
    else:
        count = 2 if parent is not None else 1
        check(rows["counts"] == {"attempts": count, "logical_messages": 1, "accepted": 0,
              "events": 0, "message_events": 0, "receipts": 0}
              and all(row["watermark"] == "0" for row in rows["streams"]),
              "拒绝或封口产生接受、部分扇出或额外流水位")
        fields = {"outcome", "logical_message_id", "attempt_id", "closure_id"}
        if outcome == "rejected_final":
            fields.add("code")
            check(value["code"] == reason, "重启后拒绝原因改变")
            if reason == "state_stale":
                # 本装置启用真实签名，旧版本拒绝必须保留证明；不能降为可选字段。
                fields.add("rejection_receipt")
                check(set(value["rejection_receipt"]) == {"statement_bytes", "signature_bytes"},
                      "旧版本拒绝缺少完整原签名证明")
        check(set(value) == fields and bool(value["closure_id"]), "拒绝或封口缺少精确结果/唯一封口标识")
    if outcome == "cancelled_before_accept":
        check(record["header_sha256"] is None and record["payload_sha256"] is None,
              "未见原包的封口不应伪称保存过原头或密文")
    else:
        check(record["header_sha256"] == source["header_sha256"]
              and record["payload_sha256"] == source["payload_sha256"], "已提交原尝试字节摘要改变")
    chain = rows["logical_messages"][0]
    check(chain["tail"] == attempt_id
          and chain["accepted_attempt"] == (attempt_id if outcome == "accepted" else None)
          and record["closure_id"] == value.get("closure_id")
          and record["acceptance_id"] == value.get("acceptance_id"), "逻辑链尾、接受或封口字段不同步")
    if parent is not None:
        predecessor = next(row for row in rows["attempts"] if row["attempt_id"] == "P1")
        check(predecessor == {**parent, "successor": "P2"}
              and record["logical_key"] == parent["logical_key"]
              and value["closure_id"] != parent["closure_id"], "封口 P2 没有原子推进父后继与逻辑链尾")
    return value, rows


def check_submit_reply(reply, terminal):
    if terminal["outcome"] == "accepted":
        check(reply == terminal, "重试没有返回完整原接受结果")
    else:
        expected = terminal
        if terminal["outcome"] == "cancelled_before_accept":
            expected = {**terminal, "code": "attempt_closed"}
        check(set(reply) == set(expected) | {"message"}
              and {key: reply[key] for key in expected} == expected
              and isinstance(reply["message"], str) and bool(reply["message"]),
              "原包重试未保持拒绝/封口原因与原 closure")


def crash(lab, packet, operation, proof, hook, before):
    process = lab.process
    lab.control("hook", hook=hook)
    try:
        request(lab, packet, operation, proof)
        raise AssertionError("指定事务窗口没有造成 HTTP 断连")
    except (http.client.RemoteDisconnected, ConnectionResetError) as error:
        exception = type(error).__name__
    expected_exit = 86 if hook == "before_commit_exit" else 87
    check(process.wait(timeout=10) == expected_exit, "Relay 未在指定窗口实际退出 86/87")
    # Relay 尚未重新启动；只读显式事务观察 WAL 中已提交结果，不以 HTTP 恢复替代离线证据。
    offline = capture(lab)
    check(offline["clients"] == before["clients"], "HTTP 退出改写客户端快照")
    lab.case_evidence["crash"] = {"hook": hook, "operation": operation, "relay_pid": process.pid,
        "relay_exit_code": process.returncode, "http_exception": exception,
        "response_received": False, "before": before, "offline_after_exit": offline}
    return offline


def restart_after_exit(lab, offline):
    process = lab.process
    old_pid = process.pid
    old_exit = process.returncode
    lab.restart()
    check(lab.process.poll() is None and lab.process.pid != old_pid and process.returncode == old_exit,
          "没有实际建立新的 Relay 进程")
    unchanged(lab, offline, "first_restart_matches_offline_committed_projection")
    lab.case_evidence["crash"]["restarted_pid"] = lab.process.pid


def exact_operations(lab, packet, terminal, proof, label, *, parent=None):
    replies = {}
    for operation in ("submit_message", "get_attempt", "close_attempt"):
        before = capture(lab)
        reply = request(lab, packet, operation, proof)
        if operation == "submit_message":
            check_submit_reply(reply, terminal)
        else:
            check(reply == terminal, "查询/重复封口改变完整原终态")
        unchanged(lab, before, label + "_" + operation)
        replies[operation] = reply
    if parent is not None:
        before = capture(lab)
        parent_result = lab.attempt(terminal["logical_message_id"], attempt="P1")
        check(parent_result == parent["result"], "后继封口改变父尝试的原 closure 结果")
        unchanged(lab, before, label + "_parent_query")
        replies["get_parent"] = parent_result
    lab.case_evidence.setdefault("terminal_responses", []).append({"label": label, "responses": replies})
    return replies


def mutations(lab, packet, terminal, proof, label):
    responses = {}
    for mutation in ("semantic_header", "raw_header", "ciphertext"):
        altered = changed_packet(packet, mutation)
        if terminal["outcome"] == "cancelled_before_accept":
            before = capture(lab)
            reply = request(lab, altered, "submit_message", proof, expected=409)
            check_submit_reply(reply, terminal)
            unchanged(lab, before, label + "_" + mutation)
        else:
            reply = reject_mutation(lab, altered, terminal, label + "_" + mutation)
        responses[mutation] = {"input": input_summary(altered), "response": reply}
    lab.case_evidence.setdefault("altered_requests", []).append({"label": label, "responses": responses})
    return responses


def reload_original(lab, packet, payload, label):
    before = lab.rust("a1", "wire_inspect")
    source = header(packet)
    recovered = lab.prepare(source["logical_message_id"], source["attempt_id"], payload=payload)
    check(recovered == {**packet, "reused": True} and lab.rust("a1", "wire_inspect") == before,
          "新 Rust CLI 未从已保存尝试恢复完整原信封")
    evidence = {"label": label, "reused": True, "input": input_summary(recovered),
                "encryption_measurement": "NOT_INSTRUMENTED"}
    lab.case_evidence.setdefault("sender_recoveries", []).append(evidence)
    return recovered
