"""M12实际累计消息的快照预算及已配置待处理队列恢复，不修改阈值或端侧文件。"""

import hashlib
import json
import subprocess

from .deletion_observer import relay_records
from .fixture import check, identity

PAYLOAD = "q" * (64 * 1024)
PAYLOAD_HASH = hashlib.sha256(PAYLOAD.encode()).hexdigest()
SNAPSHOT_LIMIT = 16 * 1024 * 1024
SNAPSHOT_OVERHEAD = 37


def snapshot(lab, device):
    path = lab.directory / device / "state.enc"
    return {"bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def command(lab, device, operation, **fields):
    """记录独立CLI真实退出；探索的预算阈值不预设消息条数。"""
    request = {"directory": str(lab.directory / device), "service": lab.service,
               "account": identity(device)["account_id"], "device": device,
               "operation": operation, **fields}
    before = snapshot(lab, device)
    process = subprocess.Popen([str(lab.binary)], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    lab.process_count += 1
    trace = {"device": device, "operation": operation, "pid": process.pid, "before": before}
    lab.case_evidence.setdefault("commands", []).append(trace)
    try:
        stdout, stderr = process.communicate(json.dumps(request), timeout=30)
    except BaseException:
        process.kill()
        stdout, stderr = process.communicate(timeout=5)
        trace.update(interrupted=True, exit_code=process.returncode,
                     after=snapshot(lab, device),
                     stdout_sha256=hashlib.sha256(stdout.encode()).hexdigest(),
                     stderr_sha256=hashlib.sha256(stderr.encode()).hexdigest())
        raise
    after = snapshot(lab, device)
    trace.update(exit_code=process.returncode, after=after,
                 stdout_sha256=hashlib.sha256(stdout.encode()).hexdigest(),
                 stderr_sha256=hashlib.sha256(stderr.encode()).hexdigest())
    check(process.returncode in (0, 1), "配额操作发生非业务退出")
    reply = json.loads(stdout)
    trace["ok"] = reply["ok"]
    check(reply["ok"] == (process.returncode == 0), "CLI状态与退出码不符")
    if not reply["ok"]:
        trace["error"] = reply["error"]
        check("result" not in reply and before == after, "预算失败交付成功结果或改写快照")
    return reply


def budget_error(reply):
    check(reply["ok"] is False and reply["error"]["code"] == "snapshot_save",
          "预期真实总快照预算失败，却遇到其他拒绝")
    check("oversize" in reply["error"]["message"].lower(), "保存失败不是快照大小限制")


def restart_same(lab, device, expected):
    before = snapshot(lab, device)
    old_pid = lab.process.pid
    rows = relay_records(lab)
    lab.restart()
    check(lab.process.pid != old_pid and lab.rust(device, "wire_inspect") == expected
          and snapshot(lab, device) == before and relay_records(lab) == rows,
          "重启或新CLI错误释放容量、改变密码/消息状态")
    lab.case_evidence["restart"] = {"old_pid": old_pid, "new_pid": lab.process.pid,
                                  "snapshot": before, "state": expected}


def sender_snapshot_budget(lab):
    previous = None
    for number in range(1, 257):
        logical = f"large-{number}"
        reply = command(lab, "a1", "wire_send", logical_message_id=logical,
                        attempt_id="P1", payload=PAYLOAD)
        if not reply["ok"]:
            failed = logical
            budget_error(reply)
            break
        previous = (logical, reply["result"])
        check(not reply["result"]["reused"], "实际累计发送复用了旧逻辑消息")
    else:
        raise AssertionError("256次64KiB实际发送仍未触及原快照预算")
    check(previous is not None, "初始快照已满")
    state = lab.rust("a1", "wire_inspect")
    check(state["outbox_count"] == number - 1 < 4096, "不是字节预算先于条数限制")
    check(state["inbox_count"] == 0 and snapshot(lab, "a1")["bytes"] <= SNAPSHOT_LIMIT + SNAPSHOT_OVERHEAD,
          "累计发送突破快照预算或污染收件")
    restart_same(lab, "a1", state)
    budget_error(command(lab, "a1", "wire_send", logical_message_id=failed, attempt_id="P1", payload=PAYLOAD))
    retry = command(lab, "a1", "wire_send", logical_message_id=previous[0], attempt_id="P1", payload=PAYLOAD)
    check(retry["ok"] and retry["result"]["reused"]
          and retry["result"]["envelope"] == previous[1]["envelope"]
          and lab.rust("a1", "wire_inspect") == state, "满预算后不能复用原包或改变原状态")
    received = lab.receive("b1", previous[1])
    check(not received["duplicate"] and received["payload_sha256"] == PAYLOAD_HASH,
          "最后成功保存的真实MLS消息无法解密")
    rows = relay_records(lab)
    check(rows["counts"]["attempts"] == 0 and rows["counts"]["events"] == 0,
          "未显式提交的实验消息被自动外发")
    lab.case_evidence.update(scope="actual_64KiB_sends_without_relay_submission",
        successful_messages=number - 1, failed_logical_message_id=failed,
        final_state=state, final_snapshot=snapshot(lab, "a1"), final_relay=rows,
        progress="BYTE_BUDGET_REMAINS_BLOCKED_ORIGINAL_RETRY_AVAILABLE")


def receiver_snapshot_budget(lab):
    previous = None
    senders = ("a1", "a2", "c1")
    for number in range(1, 257):
        sender = senders[(number - 1) % len(senders)]
        logical = f"receive-large-{number}"
        packet = lab.rust(sender, "wire_send", logical_message_id=logical, attempt_id="P1", payload=PAYLOAD)
        accepted = lab.submit(packet, device=sender)
        fields = {**packet["envelope"], "acceptance_id": accepted["acceptance_id"],
                  "acceptance_receipt": accepted["acceptance_receipt"]}
        reply = command(lab, "b1", "wire_receive", **fields)
        if not reply["ok"]:
            budget_error(reply)
            break
        check(reply["result"]["payload_sha256"] == PAYLOAD_HASH and not reply["result"]["duplicate"],
              "实际累计接收不是新消息或解密不符")
        previous = fields
    else:
        raise AssertionError("256次64KiB实际接收仍未触及原快照预算")
    check(previous is not None, "初始收件快照已满")
    state = lab.rust("b1", "wire_inspect")
    check(state["inbox_count"] == number - 1 < 4096 and state["outbox_count"] == 0,
          "收件失败不是字节预算先于条数限制")
    rows = relay_records(lab)
    check(rows["counts"]["accepted"] == number and rows["counts"]["message_events"] == number * 3
          and rows["receipts"] == [], "接受/收件/送达混淆，失败消息被确认或丢失")
    restart_same(lab, "b1", state)
    budget_error(command(lab, "b1", "wire_receive", **fields))
    retry = command(lab, "b1", "wire_receive", **previous)
    check(retry["ok"] and retry["result"]["duplicate"]
          and retry["result"]["payload_sha256"] == PAYLOAD_HASH
          and lab.rust("b1", "wire_inspect") == state, "满预算后旧收件去重丢失")
    check(relay_records(lab) == rows, "失败/重试的本地收件改变了Relay已提交状态")
    lab.case_evidence.update(scope="actual_64KiB_messages_from_three_real_MLS_senders_and_HTTP_acceptance",
        successful_messages=number - 1, failed_logical_message_id=logical,
        failed_acceptance_id=accepted["acceptance_id"], final_state=state,
        final_snapshot=snapshot(lab, "b1"), final_relay=rows,
        progress="BYTE_BUDGET_REMAINS_BLOCKED_ACCEPTED_MESSAGE_NOT_LOCALLY_DELIVERED")


def pending_queue_release(lab):
    messages = []
    for number in range(1, 4):
        packet = lab.prepare(f"pending-{number}")
        messages.append((packet, lab.submit(packet)))
    first = lab.pull("b1", limit="2")
    lab.download("b1", first)
    state = lab.rust("b1", "wire_inspect")
    check(state["sync"]["pending_limit"] == 2 and state["sync"]["pending_count"] == 2
          and state["sync"]["slot_count"] == 2 and state["inbox_count"] == 0, "未实际填满配置队列")
    rest = lab.pull("b1", after="2")
    before = snapshot(lab, "b1")
    error = lab.download("b1", rest, expected_exit=1)
    check(error["code"] == "resource_exhausted" and snapshot(lab, "b1") == before,
          "满pending下载未整体拒绝")
    lab.download("b1", first)
    check(lab.rust("b1", "wire_inspect") == state, "满额重叠旧页占用新容量")
    restart_same(lab, "b1", state)
    processed = lab.rust("b1", "wire_process")
    check(len(processed["results"]) == 2 and all(r["result"]["status"] == "valid" for r in processed["results"])
          and processed["sync"]["pending_count"] == 0 and processed["sync"]["slot_count"] == 2,
          "处理没有仅释放pending，或删除了累计槽位")
    lab.download("b1", rest)
    final = lab.rust("b1", "wire_process")
    check(len(final["results"]) == 1 and final["results"][0]["result"]["status"] == "valid"
          and final["sync"]["pending_count"] == 0 and final["sync"]["slot_count"] == 3
          and final["sync"]["processed_cursor"] == "3", "释放pending后未恢复原第三条消息")
    for candidate in final["deliveries"]:
        result = lab.http("b1", "report_delivery", {"service_id": lab.service, **candidate})
        check(result["delivered"] and not result["read"], "队列恢复混淆已读状态")
    rows = relay_records(lab)
    check(len(rows["receipts"]) == 3 and rows["counts"]["message_events"] == 9, "恢复后回执或原消息重复")
    lab.case_evidence.update(scope="real_HTTP_signed_pages_with_explicit_pending_limit_2_not_default_1000",
        first_signed_page=first.wrapper, rejected_signed_page=rest.wrapper,
        full_state=state, rejected_error=error, first_process=processed, resumed_process=final,
        final_state=lab.rust("b1", "wire_inspect"), final_relay=rows,
        progress="PENDING_CAPACITY_RELEASED_BY_PROCESSING_CUMULATIVE_SLOTS_RETAINED")


CASES = [("M12.quota.pending_release", pending_queue_release),
         ("M12.quota.sender_snapshot_budget", sender_snapshot_budget),
         ("M12.quota.receiver_snapshot_budget", receiver_snapshot_budget)]
