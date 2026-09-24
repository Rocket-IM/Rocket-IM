"""M12.e：原8槽背压、正常/截断/重置/真实读超时及完整恢复。"""

import hashlib

from .backpressure_support import occupy, readmission, record, reject_ninth, wait_events
from .deletion_observer import relay_records
from .fixture import check


def finish_held(lab, held, mode):
    ports = [h.port for h in held]
    since = held[0].started_ns
    replies = []
    if mode == "complete":
        for request in held:
            request.complete()
        replies = [request.response() for request in held]
        check(all(status == 200 and body["result"]["outcome"] == "accepted" for status, body in replies),
              "8条完整正文未全部正常接受")
    elif mode == "truncate":
        for request in held:
            request.truncate()
        replies = [request.response() for request in held]
        check(all(status == 400 and body["error"]["code"] == "invalid_envelope"
                  and body["error"]["outcome"] == "not_recorded" for status, body in replies),
              "截断正文未明确拒绝")
    elif mode == "reset":
        for request in held:
            request.reset()
    else:
        check(mode == "timeout", "未知背压场景")
        timed_out = wait_events(lab, ports, "body_read_timeout", timeout=12, since_ns=since)
        check(len(timed_out) == 8 and all(e["socket_timeout_seconds"] == 8 and
                                         7_500_000_000 <= e["elapsed_ns"] <= 12_000_000_000 for e in timed_out),
              "没有观察到8条原8秒socket读超时")
        # 收到独立进程的原TimeoutError之后才读取EOF并关闭客户端。
        check(all(not h.closed for h in held), "超时前客户端已主动关闭")
        wait_events(lab, ports, "worker_finished", since_ns=since)
        for request in held:
            request.assert_eof()
        record(lab, "original_socket_timeouts", events=timed_out, clients_kept_open=True)
    finished = wait_events(lab, ports, "worker_finished", since_ns=since)
    check(len(finished) == 8, "原线程没有精确释放8次")
    record(lab, "initial_workers_finished", mode=mode, events=finished, replies=replies)
    return replies


def consume(lab, packets):
    expected = {packet["logical"]: packet for packet in packets}
    total = len(packets)
    final = {}
    for device in ("a2", "b1", "c1"):
        page = lab.pull(device)
        check(len(page["events"]) == total and page["watermark"] == str(total), "恢复后目标流丢失或多出消息")
        lab.download(device, page)
        result = lab.rust(device, "wire_process")
        record(lab, "rust_consume", device=device, page=page.wrapper, result=result)
        check(len(result["results"]) == len(result["deliveries"]) == total, "恢复后的真实Rust处理/候选数量不符")
        found = set()
        for item in result["results"]:
            value = item["result"]
            check(value["status"] == "valid" and value["message"]["duplicate"] is False,
                  "合法原消息恢复后未成功解密")
            message = value["message"]
            logical = message["logical_message_id"]
            check(logical in expected and logical not in found and
                  message["payload_sha256"] == expected[logical]["plaintext_sha256"], "解密摘要或消息去重不符")
            found.add(logical)
        check(found == set(expected), "恢复后未精确收到所有原消息")
        state = lab.rust(device, "wire_inspect")
        check(state["inbox_count"] == state["sync"]["slot_count"] == total
              and state["sync"]["download_cursor"] == state["sync"]["processed_cursor"] == str(total)
              and state["sync"]["source_verified"] and not state["sync"]["halted"]
              and state["sync"]["pending_count"] == state["sync"]["quarantined_count"] == 0,
              "真实Rust的最终游标/槽/来源状态不符")
        lab.download(device, page)
        repeated = lab.rust(device, "wire_process")
        check(repeated["results"] == [] and repeated["deliveries"] == result["deliveries"]
              and lab.rust(device, "wire_inspect") == state, "重复补拉改变原处理或候选")
        final[device] = {"state": state, "results": result, "repeat": repeated}
    return final


def roundtrip(lab, mode):
    packets = []
    for index in range(2):
        logical = "backpressure_" + str(index)
        plaintext = "synthetic-backpressure-message-" + str(index)
        packets.append({"logical": logical, "packet": lab.prepare(logical, payload=plaintext),
                        "plaintext_sha256": hashlib.sha256(plaintext.encode()).hexdigest()})
    before = relay_records(lab)
    # 八条真实连接重试同一原包；不同密文的大乱序窗口另记失败，不混入连接额度验收。
    held = occupy(lab, "submit_message", [{"envelope": packets[0]["packet"]["envelope"]}] * 8)
    retry = packets[-1]["packet"]
    try:
        reject_ninth(lab, retry, held, before)
        replies = finish_held(lab, held, mode)
    finally:
        for request in held:
            request.close()
    if mode == "complete":
        original_acceptances = [body["result"] for _, body in replies]
        after = relay_records(lab)
        check(after["counts"]["accepted"] == 1 and after["counts"]["message_events"] == 3,
              "8条同原包重试没有保持一次接受与3目标完整投递")
        check(all(value == original_acceptances[0] for value in original_acceptances)
              and lab.attempt(packets[0]["logical"]) == original_acceptances[0], "并发原包重试的完整接受结果不一致")
    else:
        check(relay_records(lab) == before, "截断/重置/超时产生了部分消息写入")
        check(lab.attempt(packets[0]["logical"])["outcome"] == "not_found", "失败请求留下可查询尝试")
    check(lab.attempt(packets[-1]["logical"])["outcome"] == "not_found", "第9拒绝请求留下记录")
    record(lab, "first_recovery_records", records=relay_records(lab), rejected_attempt="not_found")
    # 不重启Relay、不直接读写信号量；HTTP重新占满8槽证明原进程容量恢复。
    readmission(lab, retry)
    accepted = lab.submit(retry)
    check(accepted["outcome"] == "accepted" and lab.attempt(packets[-1]["logical"]) == accepted,
          "解除背压后原包未正常接受")
    saved = relay_records(lab)
    check(lab.submit(retry) == accepted and relay_records(lab) == saved, "原包重试产生新接受或重复槽")
    delivered = packets if mode == "complete" else packets[-1:]
    final = consume(lab, delivered)
    check(relay_records(lab) == saved, "客户端只读恢复改变Relay消息记录")
    lab.case_evidence.update(mode=mode, final_clients=final, final_relay=saved,
                             retried_acceptance=accepted, accepted_messages=len(delivered),
                             relay_restart_count=0, slots=8, socket_timeout_seconds=8,
                             held_requests="eight_exact_retries_of_one_original_envelope",
                             receipt_reports="NOT_EXECUTED", all_quotas="NOT_COMPLETE")


CASES = [("M12_slots_complete", lambda lab: roundtrip(lab, "complete")),
         ("M12_slots_truncate", lambda lab: roundtrip(lab, "truncate")),
         ("M12_slots_reset", lambda lab: roundtrip(lab, "reset")),
         ("M12_slots_timeout", lambda lab: roundtrip(lab, "timeout"))]
