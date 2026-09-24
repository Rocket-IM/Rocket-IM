"""M09尝试链时序：旧包/封口互斥、同一封口后的双后继裁决。"""

from functools import partial
import hashlib
from itertools import permutations

from .attempt_support import held_race, key, message_rows, ordered_requests, packet, retry_packet
from .fixture import check, identity

TARGETS = ("a2", "b1", "c1")


def verify_delivery(lab, logical, saved, accepted):
    """逐目标读真实HTTP页并交给Rust；重放与重启不能再次交付。"""
    check(accepted["recipients"] == [identity(device) for device in TARGETS], "原接受目标集合错误")
    pages = {}
    for device in TARGETS:
        page = lab.pull(device)
        check(page["watermark"] == page["next_after_seq"] == "1" and not page["has_more"],
              "目标流未恰好提交一个槽位")
        check(len(page["events"]) == 1, "目标流扇出重复或遗漏")
        slot = page["events"][0]
        check(slot["event_seq"] == "1" and slot["stream_id"] == lab.streams[device]
              and slot["availability"] == "available", "投递槽位归属错误")
        check(slot["event"]["type"] == "message" and slot["event"]["envelope"] == saved["envelope"]
              and slot["event"]["acceptance_id"] == accepted["acceptance_id"], "胜者投递内容改变")
        lab.download(device, page)
        lab.download(device, page)
        received = lab.rust(device, "wire_process")
        check(len(received["results"]) == 1, "真实接收未只交付一次")
        value = received["results"][0]["result"]["message"]
        check(value["logical_message_id"] == logical and value["attempt_id"] == accepted["attempt_id"]
              and value["duplicate"] is False
              and value["payload_sha256"] == hashlib.sha256(("synthetic-M09-" + logical).encode()).hexdigest(),
              "真实MLS解密结果不对应胜者")
        check(received["deliveries"] == [{"acceptance_id": accepted["acceptance_id"],
                                          "attempt_id": accepted["attempt_id"], "event_id": slot["event_id"]}],
              "送达候选归属错误")
        check(lab.rust(device, "wire_process")["results"] == [], "重复处理再次交付")
        pages[device] = page
    check(lab.pull("a1")["events"] == [], "向发送设备额外扇出")
    before = message_rows(lab)
    lab.restart()
    check(message_rows(lab) == before, "重启改变接受、封口、链尾或投递")
    for device, original in pages.items():
        page = lab.pull(device)
        check(page == original, "重启改变完整目标页")
        lab.download(device, page)
        check(lab.rust(device, "wire_process")["results"] == [], "重启后重复交付")
        state = lab.rust(device, "wire_inspect")
        check(state["inbox_count"] == 1 and state["sync"]["download_cursor"] == "1"
              and state["sync"]["processed_cursor"] == "1", "重启去重/双游标不完整")
    lab.case_evidence.update(target_pages=pages, committed_rows=before)


def verify_terminal(lab, logical, old, winner, accepted, *, closed=None, proof=None):
    proof = proof or {}
    check(lab.attempt(logical, accepted["attempt_id"]) == accepted, "接受终态未保持完整")
    check(lab.attempt(logical, operation="close_attempt") == accepted, "封口未返回已接受结果")
    check(lab.submit(winner, **proof) == accepted, "重试改变接受或时限/目标")
    if closed:
        check(lab.attempt(logical) == closed, "旧封口终态改变")
        refused = lab.submit(old, expected=409)
        check(refused["code"] == "attempt_closed" and refused["closure_id"] == closed["closure_id"],
              "旧包在重启后复活")
    stats = lab.control("stats")
    check(stats["accepted"] == "1" and stats["attempts"] == ("2" if closed else "1")
          and stats["events"] == stats["message_events"] == "3", "终态接受/尝试/扇出计数错误")
    rows = message_rows(lab)
    check(len(rows["logical"]) == 1 and rows["logical"][0][1:] == (accepted["attempt_id"], accepted["attempt_id"]),
          "链尾与唯一接受尝试不一致")
    check(sum(row["outcome"] == "accepted" for row in rows["attempts"]) == 1, "产生多重接受")
    if closed:
        predecessor = next(row for row in rows["attempts"] if row["attempt_id"] == "P1")
        check(predecessor["successor"] == accepted["attempt_id"], "前驱未指向唯一胜出后继")
    lab.case_evidence.update(final_stats=stats, final_rows=rows, acceptance=accepted)


def old_close_race(lab, *, first):
    logical = "m09_old_close_" + first
    old = packet(lab, logical)
    requests = {
        "old": ("old", "a1", "submit_message", {"envelope": old["envelope"]}, 200 if first == "old" else 409),
        "close": ("close", "a1", "close_attempt", key(logical), 200),
    }
    results = held_race(lab, [requests[first], requests["close" if first == "old" else "old"]])
    old = retry_packet(lab, old, logical)
    if first == "old":
        accepted = results["old"]
        check(results["close"] == accepted, "后到封口撤回已接受尝试")
        verify_delivery(lab, logical, old, accepted)
        verify_terminal(lab, logical, old, old, accepted)
    else:
        closed = results["close"]
        check(closed["outcome"] == "cancelled_before_accept" and results["old"]["code"] == "attempt_closed"
              and results["old"]["closure_id"] == closed["closure_id"], "封口后旧包获得接受")
        check(lab.control("stats")["message_events"] == "0", "已封口旧包残留投递")
        proof = {"replaces_attempt_id": "P1", "closure_id": closed["closure_id"]}
        successor = packet(lab, logical, "P2", **proof)
        accepted = lab.submit(successor, **proof)
        retry_packet(lab, successor, logical, "P2", **proof)
        verify_delivery(lab, logical, successor, accepted)
        verify_terminal(lab, logical, old, successor, accepted, closed=closed, proof=proof)


def successor_race(lab, *, order):
    logical = "m09_successors_" + "_".join(order)
    old = packet(lab, logical)
    closed = lab.attempt(logical, operation="close_attempt")
    check(closed["outcome"] == "cancelled_before_accept", "未得到真实前驱封口")
    proof = {"replaces_attempt_id": "P1", "closure_id": closed["closure_id"]}
    second = packet(lab, logical, "P2", **proof)
    # 单一Rust发送状态顺序前进，不复制或回滚密码状态。P3的本地前驱是P2，
    # 合成封口仅用于制造对抗HTTP请求；不是正式客户端封口验证或双分支流程。
    local_third_proof = {"replaces_attempt_id": "P2", "closure_id": "synthetic-M09-scheduler-only"}
    third = packet(lab, logical, "P3", **local_third_proof)
    check(second["envelope"]["payload_bytes"] != third["envelope"]["payload_bytes"], "后继重复使用密码输出")
    candidates = {"p2": second, "p3": third}
    winner_label = next(label for label in order if label in candidates)
    loser_label = "p3" if winner_label == "p2" else "p2"
    requests = {"old": ("old", "a1", "submit_message", {"envelope": old["envelope"]}, 409),
                "close": ("close", "a1", "close_attempt", key(logical), 200)}
    for label, saved in candidates.items():
        requests[label] = (label, "a1", "submit_message", {"envelope": saved["envelope"], **proof},
                           200 if label == winner_label else 409)
    responses = ordered_requests(lab, [requests[label] for label in order])
    accepted = responses[winner_label]
    check(accepted["outcome"] == "accepted" and accepted["attempt_id"] == winner_label.upper(), "接受了错误后继")
    refused = responses[loser_label]
    check(refused["code"] == "logical_message_already_accepted" and refused["acceptance"] == accepted,
          "后到后继未返回原始完整接受结果")
    check(responses["old"]["code"] == "attempt_closed" and responses["old"]["closure_id"] == closed["closure_id"],
          "已封口前驱复活")
    check(responses["close"] == (closed if order.index("close") < order.index(winner_label) else accepted),
          "封口响应不对应实际事务顺序")
    retry_packet(lab, old, logical)
    retry_packet(lab, second, logical, "P2", **proof)
    retry_packet(lab, third, logical, "P3", **local_third_proof)
    winner = candidates[winner_label]
    verify_delivery(lab, logical, winner, accepted)
    check(lab.attempt(logical, loser_label.upper())["outcome"] == "not_found", "输掉竞争的后继残留尝试")
    refused = lab.submit(candidates[loser_label], expected=409, **proof)
    check(refused["code"] == "logical_message_already_accepted" and refused["acceptance"] == accepted,
          "重启后败者复活或接受结果改变")
    verify_terminal(lab, logical, old, winner, accepted, closed=closed, proof=proof)
    lab.case_evidence.update(order=order, winner=winner_label, loser=loser_label,
                             successor_scope="sequential real MLS ciphertexts; adversarial HTTP siblings, not SDK concurrent replacement",
                             p3_local_predecessor="P2", p3_http_predecessor="P1",
                             p3_local_closure="synthetic-M09-scheduler-only")


CASES = [("M09.old_close." + first, partial(old_close_race, first=first)) for first in ("old", "close")]
CASES += [("M09.successors." + "_".join(order), partial(successor_race, order=order))
          for order in permutations(("old", "close", "p2", "p3"))]
