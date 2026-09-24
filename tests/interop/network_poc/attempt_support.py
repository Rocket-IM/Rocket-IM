"""M09时序协调与非秘密证据；复用M07屏障和既有Rust/HTTP入口。"""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import json
import sqlite3

from .fixture import CONVERSATION, SERVICE, check


def key(logical, attempt="P1"):
    return {"service_id": SERVICE, "conversation_id": CONVERSATION,
            "logical_message_id": logical, "attempt_id": attempt}


def packet(lab, logical, attempt="P1", device="a1", **proof):
    return lab.rust(device, "wire_send", logical_message_id=logical, attempt_id=attempt,
                    payload="synthetic-M09-" + logical, **proof)


def retry_packet(lab, saved, logical, attempt="P1", device="a1", **proof):
    before = lab.rust(device, "wire_inspect")
    again = packet(lab, logical, attempt, device, **proof)
    after = lab.rust(device, "wire_inspect")
    check(again["reused"] and again["envelope"] == saved["envelope"], "重试没有复用原始密文")
    check(before["outbox_count"] == after["outbox_count"], "重试新增了发送记录")
    return again


def held_race(lab, requests):
    """首请求写完但未提交时，其他HTTP确实到达SQLite BEGIN；不推断等待者FIFO。"""
    first = requests[0][0]
    lab.probe("arm", labels=[{"label": label, "hold_before_commit": label == first}
                              for label, *_ in requests])
    released = False
    with ThreadPoolExecutor(max_workers=len(requests)) as pool:
        futures = {}
        try:
            for index, (label, device, operation, fields, expected) in enumerate(requests):
                futures[label] = pool.submit(lab.http, device, operation, fields, expected=expected, label=label)
                lab.wait_for(label, "before_commit_waiting" if index == 0 else "begin_requested")
            held = lab.probe("status")
            check(not any(future.done() for future in futures.values()), "持锁窗口已有HTTP结果")
            check([e["label"] for e in held["events"] if e["stage"] == "acquired"] == [first],
                  "等待者越过了未提交事务")
            lab.case_evidence["held_timeline"] = held
            lab.probe("release", label=first, point="before_commit", decision="commit")
            released = True
            results = {label: future.result(timeout=10) for label, future in futures.items()}
        finally:
            if not released:
                lab.probe("release", label=first, point="before_commit", decision="rollback")
    for label, *_ in requests:
        lab.wait_for(label, "responded")
    lab.case_evidence["timeline"] = lab.probe("status")
    lab.case_evidence["responses"] = results
    return results


def ordered_requests(lab, requests):
    """所有HTTP先同时在途，再按给定排列释放BEGIN；明确测试调度而非SQLite公平性。"""
    lab.probe("arm", labels=[{"label": label, "hold_before_begin": True} for label, *_ in requests])
    with ThreadPoolExecutor(max_workers=len(requests)) as pool:
        futures = {label: pool.submit(lab.http, device, operation, fields, expected=expected, label=label)
                   for label, device, operation, fields, expected in requests}
        for label, *_ in requests:
            lab.wait_for(label, "before_begin_waiting")
        held = lab.probe("status")
        check(not any(future.done() for future in futures.values()), "四方请求尚未全在途就结束")
        check(not any(e["stage"] == "acquired" for e in held["events"]), "请求越过了指定BEGIN顺序")
        lab.case_evidence["all_requests_pending"] = held
        results = {}
        for label, *_ in requests:
            lab.probe("release", label=label, point="before_begin", decision="continue")
            results[label] = futures[label].result(timeout=10)
            lab.wait_for(label, "responded")
    timeline = lab.probe("status")
    check([e["label"] for e in timeline["events"] if e["stage"] == "acquired"] == [r[0] for r in requests],
          "实际事务顺序不符指定排列")
    lab.case_evidence.update(timeline=timeline, responses=results)
    return results


def message_rows(lab):
    """仅测试读取Relay已提交视图；显式读事务，无凭证/用户秘密。"""
    uri = (lab.directory / "relay.sqlite").resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, isolation_level=None)) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        try:
            attempts = db.execute("SELECT logical_key,attempt_id,outcome,closure_id,successor,result,header,payload FROM attempts ORDER BY logical_key,attempt_id").fetchall()
            events = db.execute("SELECT account,device,seq,event_id,content,availability FROM events ORDER BY account,device,seq").fetchall()
            logical = db.execute("SELECT key,tail,accepted_attempt FROM logical_messages ORDER BY key").fetchall()
            db.commit()
        except BaseException:
            db.rollback()
            raise
    return {"attempts": [{"logical_key": row[0], "attempt_id": row[1], "outcome": row[2], "closure_id": row[3],
                           "successor": row[4], "result": json.loads(row[5]),
                           "header_sha256": hashlib.sha256(row[6]).hexdigest() if row[6] else None,
                           "payload_sha256": hashlib.sha256(row[7]).hexdigest() if row[7] else None} for row in attempts],
            "events": [{"account": r[0], "device": r[1], "seq": str(r[2]), "event_id": r[3],
                        "event": json.loads(r[4]), "availability": r[5]} for r in events], "logical": logical}
