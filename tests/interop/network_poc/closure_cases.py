"""签名封口的有界后继、旧程序拒绝及真实接受恢复。"""

from functools import partial
import json
import subprocess

from .closure_delivery import receive
from .closure_support import (accept, blocked, close, close_request, persist, prepare,
                              snapshot, successor)
from .deletion_observer import relay_records
from .fixture import check, identity


def lifecycle(lab):
    first = prepare(lab)
    request = close_request(lab)
    before = snapshot(lab)
    proof = close(lab, request)
    check(proof["outcome"] == "cancelled_before_accept" and snapshot(lab) == before,
          "HTTP封口错误释放本地状态")
    blocked(lab)
    blocked(lab, logical="M1", attempt="P2", replaces_attempt_id="P1", closure_id=proof["closure_id"])
    rows = relay_records(lab)
    check(close(lab, request) == proof and lab.attempt("M1") == proof and relay_records(lab) == rows,
          "封口重试或查询改变精确终态")
    check(rows["counts"]["accepted"] == rows["counts"]["events"] == 0
          and rows["attempts"][0]["header_sha256"] is None
          and rows["attempts"][0]["payload_sha256"] is None, "未提交封口错误存储密文或投递")
    result = persist(lab, proof)
    check(result["duplicate"] is False, "首个封口保存被误记为重复")
    blocked(lab)
    check(persist(lab, proof)["duplicate"] is True, "重复封口没有幂等")
    second = successor(lab, proof)
    check(second["reused"] is False and second["envelope"] != first["envelope"], "后继没有独立新尝试")
    retry = successor(lab, proof)
    check(retry["reused"] is True and retry["envelope"] == second["envelope"], "后继重启重试未复用原密文")
    late = lab.submit(first, expected=409)
    check(late["code"] == "attempt_closed" and relay_records(lab) == rows, "迟到旧密文越过封口")
    accepted = accept(lab, second, "M1", "P2", replaces_attempt_id="P1", closure_id=proof["closure_id"])
    state = lab.rust("a1", "wire_inspect")
    check(state["send_order"]["pending"] is None, "已接受后继未释放门禁")
    check(close(lab, request) == accepted, "已接受逻辑消息被重新封口")
    check(persist(lab, proof)["duplicate"] is True
          and lab.rust("a1", "wire_inspect") == state, "旧封口重放使已接受逻辑倒退")
    third = prepare(lab, "M2")
    accepted_next = accept(lab, third, "M2", "P1")
    receive(lab, [("M1", "P2", "closure payload", second, accepted),
                  ("M2", "P1", "closure payload", third, accepted_next)])


def chain(lab, *, exhaust):
    packet = prepare(lab)
    for index in range(1, 5):
        proof = close(lab, close_request(lab, attempt=f"P{index}"))
        persist(lab, proof, attempt=f"P{index}")
        packet = successor(lab, proof, attempt=f"P{index + 1}")
        check(packet["reused"] is False, "有限链未建立新后继")
    if exhaust:
        proof = close(lab, close_request(lab, attempt="P5"))
        persist(lab, proof, attempt="P5")
        blocked(lab, logical="M1", attempt="P6", code="send_order_successor_limit",
                replaces_attempt_id="P5", closure_id=proof["closure_id"])
        blocked(lab)
        rows = relay_records(lab)
        check(rows["counts"]["attempts"] == 5 and rows["counts"]["accepted"] == 0,
              "已耗尽后继链产生接受")
        lab.case_evidence.update(final_relay=rows, successor_limit=4, progress="BLOCKED_LIMIT_EXPLICIT")
    else:
        accepted = accept(lab, packet, "M1", "P5", replaces_attempt_id="P4", closure_id=proof["closure_id"])
        receive(lab, [("M1", "P5", "closure payload", packet, accepted)])


def old_program(lab, *, rejected):
    before = snapshot(lab)
    request = {"directory": str(lab.directory / "a1"), "service": lab.service,
               "account": identity("a1")["account_id"], "device": "a1", "operation": "wire_inspect"}
    result = subprocess.run([str(lab.old_binary)], input=json.dumps(request), text=True,
                            capture_output=True, timeout=30)
    lab.process_count += 1
    reply = json.loads(result.stdout)
    lab.case_evidence.setdefault("old_program", []).append({"rejected": rejected,
        "exit_code": result.returncode, "reply": reply, "snapshot_sha256_before": before,
        "snapshot_sha256_after": snapshot(lab)})
    check(not result.stderr and result.returncode == int(rejected) and reply["ok"] is not rejected
          and snapshot(lab) == before, "旧程序没有按格式边界拒绝或改变快照")
    if rejected:
        check(reply["error"]["code"] == "state_decoding", "旧程序未明确拒绝新顶层终态格式")


def compatibility(lab):
    prepare(lab)
    old_program(lab, rejected=False)
    proof = close(lab, close_request(lab))
    persist(lab, proof)
    old_program(lab, rejected=True)
    successor(lab, proof)
    old_program(lab, rejected=True)


def successor_save(lab, *, point):
    prepare(lab)
    proof = close(lab, close_request(lab))
    persist(lab, proof)
    before = snapshot(lab)
    exit_code = {"before_save": 83, "before_rename": 84, "after_save": 85}[point]
    lab.rust("a1", "wire_send", logical_message_id="M1", attempt_id="P2", payload="closure payload",
             replaces_attempt_id="P1", closure_id=proof["closure_id"], failpoint=point, expected_exit=exit_code)
    after = snapshot(lab)
    state = lab.rust("a1", "wire_inspect")
    lab.case_evidence["successor_fault"] = {"point": point, "exit_code": exit_code,
        "snapshot_sha256_before": before, "snapshot_sha256_after": after, "state_after": state}
    check((after == before) is (point != "after_save"), "后继保存未符合真实提交边界")
    pending = state["send_order"]["pending"]
    check(pending["attempt_id"] == ("P2" if point == "after_save" else "P1"), "后继链尾部分推进")
    blocked(lab)
    packet = successor(lab, proof)
    check(packet["reused"] is (point == "after_save"), "后继恢复没有按已持久原包重试")
    accepted = accept(lab, packet, "M1", "P2", replaces_attempt_id="P1", closure_id=proof["closure_id"])
    receive(lab, [("M1", "P2", "closure payload", packet, accepted)])


def signer_failure(lab):
    prepare(lab)
    request = close_request(lab)
    before, client_before = relay_records(lab), snapshot(lab)
    held = lab.receipt_key.with_suffix(".held")
    lab.receipt_key.rename(held)
    try:
        error = close(lab, request, expected=503)
    finally:
        held.rename(lab.receipt_key)
    after = relay_records(lab)
    lab.case_evidence["signer_failure"] = {"error": error, "relay_before": before,
        "relay_after": after, "snapshot_sha256_before": client_before,
        "snapshot_sha256_after": snapshot(lab)}
    check(error["code"] == "receipt_signer_unavailable" and before == after
          and snapshot(lab) == client_before, "签名器实际失败留下部分封口")
    blocked(lab)
    proof = close(lab, request)
    persist(lab, proof)
    packet = successor(lab, proof)
    accepted = accept(lab, packet, "M1", "P2", replaces_attempt_id="P1", closure_id=proof["closure_id"])
    receive(lab, [("M1", "P2", "closure payload", packet, accepted)])


CASES = [("closure_lifecycle", lifecycle), ("closure_max_successor", partial(chain, exhaust=False)),
         ("closure_successor_limit", partial(chain, exhaust=True)), ("closure_old_program", compatibility),
         ("closure_signer_failure", signer_failure)]
CASES += [("closure_successor_" + point, partial(successor_save, point=point))
          for point in ("before_save", "before_rename", "after_save")]
