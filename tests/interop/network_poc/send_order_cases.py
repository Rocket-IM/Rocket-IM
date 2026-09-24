"""显式单槽门禁：故意越序请求、丢接受响应、证明保存退出和原包恢复。"""

from functools import partial
import hashlib
import json
import subprocess

from .deletion_observer import relay_records
from .fixture import check, identity
from .send_order_faults import accept_crash, lose_ack, old_program
from .send_order_support import accept, blocked, enable, finish, inspect, prepare, submit_and_accept
from .slot_support import digest


ORDER = [0, 1, 4, 6, 3, 7, 5, 2, 8]


def original_load(lab, page_limit):
    old_program(lab, enabled=False)
    enable(lab)
    old_program(lab)
    lab.case_evidence["previous_failed_logical_schedule"] = ORDER
    packets = {}
    for position, index in enumerate(ORDER):
        record = prepare(lab, index)
        packets[index] = record
        # 先尝试生成所有未来消息；拒绝来自Rust，不由Python预先隐藏请求。
        for later in ORDER[position + 1:]:
            blocked(lab, "future_request_before_current_acceptance", f"ordered_{later:02}")
        state = inspect(lab)
        lab.rust("a1", "wire_send_order_enable")
        check(inspect(lab) == state, "重复启用清除了现有未决尝试")
        restored = lab.prepare(record["logical"], payload=record["payload"])
        check(restored == {**record["packet"], "reused": True}, "阻塞后不能重试原包")
        submit_and_accept(lab, record, label="normal")
    finish(lab, packets, ORDER, page_limit)


def response_loss(lab, hook):
    enable(lab)
    first = prepare(lab, 0)
    accepted = lose_ack(lab, first, hook)
    accept(lab, first, accepted)
    first["accepted"] = accepted
    second = prepare(lab, 1)
    # 迟到重复旧证明不得释放当前另一条未决消息。
    accept(lab, first, accepted, duplicate=True)
    blocked(lab, "late_old_acceptance_does_not_release_new_head")
    submit_and_accept(lab, second, label="after_ack_recovery")
    finish(lab, {0: first, 1: second}, [0, 1], 1)


def acceptance_save(lab, point):
    enable(lab)
    first = prepare(lab, 0)
    accepted = lab.submit(first["packet"])
    blocked(lab, "before_acceptance_save")
    accept_crash(lab, first, accepted, point)
    first["accepted"] = accepted
    second = prepare(lab, 1)
    submit_and_accept(lab, second, label="after_snapshot_recovery")
    finish(lab, {0: first, 1: second}, [0, 1])


def closed_head(lab):
    enable(lab)
    first = prepare(lab, 0)
    closure = lab.attempt(first["logical"], operation="close_attempt")
    lab.case_evidence["closed_response"] = closure
    check(closure["outcome"] == "cancelled_before_accept" and closure["closure_id"], "未提交原尝试没有真实封口")
    blocked(lab, "closed_head_does_not_release_other_message")
    blocked(lab, "unsigned_closure_does_not_admit_successor", first["logical"], attempt_id="P2",
            payload=first["payload"], replaces_attempt_id="P1", closure_id=closure["closure_id"])
    state, rows = inspect(lab), relay_records(lab)
    check(rows["counts"]["accepted"] == rows["counts"]["message_events"] == 0,
          "只封口流程产生接受或投递")
    lab.restart()
    lab.rust("a1", "wire_send_order_enable")
    check(inspect(lab) == state and relay_records(lab) == rows, "重启或重入解除封口未决门禁")
    blocked(lab, "closed_head_still_blocks_after_restart")
    for device in ("a2", "b1", "c1"):
        page = lab.pull(device)
        check(page["events"] == [] and page["watermark"] == "0", "封口产生目标消息")
        lab.download(device, page)
        value = lab.rust(device, "wire_process")
        check(value["results"] == value["deliveries"] == [], "空流产生成功消息或候选")
    lab.case_evidence.update(closure=closure, final_sender=state, final_relay=rows,
                            accepted_messages=0, original_message_slots=0, target_valid_results=0,
                            target_quarantined_results=0, terminal_progress="BLOCKED_NO_TRUSTED_TERMINAL_PROOF")


def concurrent_requests(lab):
    enable(lab)
    children = []
    for index in (0, 1):
        logical = f"ordered_{index:02}"
        request = {"directory": str(lab.directory / "a1"), "service": lab.service,
                   "account": identity("a1")["account_id"], "device": "a1", "operation": "wire_send",
                   "logical_message_id": logical, "attempt_id": "P1", "payload": "synthetic-order-" + logical}
        child = subprocess.Popen([str(lab.binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        lab.process_count += 1
        child.stdin.write(json.dumps(request))
        child.stdin.close()
        child.stdin = None
        children.append((index, child))
    replies = []
    try:
        for index, child in children:
            stdout, stderr = child.communicate(timeout=30)
            reply = json.loads(stdout)
            check(not stderr and child.returncode == (0 if reply["ok"] else 1), "并发CLI输出异常")
            replies.append({"logical_label": index, "pid": child.pid, "exit_code": child.returncode, "reply": reply})
    finally:
        for _, child in children:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
    lab.case_evidence["concurrent_cli"] = {"replies": replies, "scheduler": "two real processes launched before waiting; no forced lock-contention barrier"}
    successes = [r for r in replies if r["reply"]["ok"]]
    failures = [r for r in replies if not r["reply"]["ok"]]
    check(len(successes) == len(failures) == 1
          and failures[0]["reply"]["error"]["code"] in ("busy", "send_order_pending"),
          "两个竞争的新消息没有保持唯一未决尝试")
    winner, loser = successes[0]["logical_label"], failures[0]["logical_label"]
    logical = f"ordered_{winner:02}"
    record = {"logical": logical, "payload": "synthetic-order-" + logical,
              "packet": successes[0]["reply"]["result"],
              "payload_sha256": hashlib.sha256(("synthetic-order-" + logical).encode()).hexdigest()}
    check(inspect(lab)["outbox_count"] == 1, "并发调用产生两条持久新消息")
    check(record["packet"]["reused"] is False, "并发胜者不是首次创建")
    lab.case_evidence["created"].append({"logical_label": winner, "logical_message_id": logical,
                                        "envelope_sha256": digest(record["packet"]["envelope"]),
                                        "state": inspect(lab)})
    blocked(lab, "concurrent_loser_stays_blocked", f"ordered_{loser:02}")
    submit_and_accept(lab, record, label="concurrent_winner")
    next_record = prepare(lab, loser)
    submit_and_accept(lab, next_record, label="concurrent_loser_retry")
    finish(lab, {winner: record, loser: next_record}, [winner, loser])


CASES = [("M03_order_original_schedule_full", partial(original_load, page_limit=100)),
         ("M03_order_original_schedule_pages", partial(original_load, page_limit=1))]
CASES += [("M03_order_" + hook, partial(response_loss, hook=hook))
          for hook in ("drop_after_commit", "before_commit_exit", "after_commit_exit")]
CASES += [("M03_order_accept_" + point, partial(acceptance_save, point=point))
          for point in ("before_save", "before_rename", "after_save")]
CASES += [("M03_order_closed_head", closed_head), ("M03_order_concurrent_cli", concurrent_requests)]
