"""真实 state_stale 拒绝、权限补齐顺序与混合终态有界恢复。"""

from functools import partial

from . import closure_support
from .deletion_observer import relay_records
from .fixture import check
from .permission_recovery_cases import records
from .stale_delivery import receive
from .stale_support import (accept, advance, blocked, catch_up, pending, persist,
                            prepare, reject, snapshot, statement, successor)


def finish(lab, proof, *, attempt="P2", devices=("a2", "b1")):
    catch_up(lab, "a1", *devices)
    packet = successor(lab, proof, attempt=attempt)
    retry = successor(lab, proof, attempt=attempt)
    check(not packet["reused"] and retry["reused"] and packet["envelope"] == retry["envelope"],
          "后继没有重用持久原始密文")
    accepted = accept(lab, packet, "M1", attempt,
                      replaces_attempt_id=proof["attempt_id"], closure_id=proof["closure_id"])
    receive(lab, [("M1", attempt, "stale payload", packet, accepted)], devices=devices)


def lifecycle(lab, *, recover_first):
    first = prepare(lab)
    advance(lab)
    proof = reject(lab, first)
    if recover_first:
        catch_up(lab, "a1")
        blocked(lab, logical="M1", attempt="P2", payload="stale payload",
                replaces_attempt_id="P1", closure_id=proof["closure_id"])
    result = persist(lab, proof)
    check(not result["duplicate"], "首次拒绝误记为重复")
    pending(lab, "rejected_awaiting_successor" if recover_first else "rejected_awaiting_checkpoint")
    if not recover_first:
        blocked(lab, logical="M1", attempt="P2", payload="stale payload",
                code="rejection_checkpoint_required", replaces_attempt_id="P1", closure_id=proof["closure_id"])
    before = snapshot(lab)
    check(persist(lab, proof)["duplicate"] and snapshot(lab) == before, "重复拒绝重写原快照")
    blocked(lab)
    finish(lab, proof)


def descendant(lab):
    first = prepare(lab)
    advance(lab)
    proof = reject(lab, first)
    persist(lab, proof)
    catch_up(lab, "a2")
    advance(lab, "R0-descendant", {"kind": "remove_member", "account_id": "bob"})
    catch_up(lab, "a1", "a2")
    state = pending(lab, "rejected_awaiting_successor")
    check(statement(proof)["required_authorization_version"] == "2"
          and state["configuration"]["authorization_version"] == "3", "没有跨越原最低权限版本")
    rows = relay_records(lab)
    check(lab.attempt("M1") == proof and lab.submit(first, expected=409)["rejection_receipt"] == proof["rejection_receipt"]
          and relay_records(lab) == rows, "权限再次变化重签或改写原拒绝floor")
    finish(lab, proof, devices=("a2",))


def partial_chain(lab):
    first = prepare(lab)
    advance(lab)
    catch_up(lab, "a2")
    advance(lab, "R0-floor-three", {"kind": "remove_member", "account_id": "bob"})
    proof = reject(lab, first)
    check(statement(proof)["required_authorization_version"] == "3", "拒绝未绑定原事务版本3")
    persist(lab, proof)
    page = records(lab, device="a1", after="1", limit="1")
    check(page["has_more"] and len(page["records"]) == 1, "未实际分页到部分权限链")
    recovered = lab.rust("a1", "permission_recover", record=page["records"][0])
    lab.case_evidence["partial_chain"] = {"page": page, "result": recovered}
    pending(lab, "rejected_awaiting_checkpoint")
    blocked(lab, logical="M1", attempt="P2", payload="stale payload",
            code="rejection_checkpoint_required", replaces_attempt_id="P1", closure_id=proof["closure_id"])
    finish(lab, proof, devices=("a2",))


def mixed_chain(lab, *, exhaust):
    first = prepare(lab)
    advance(lab)
    proof = reject(lab, first)
    persist(lab, proof)
    catch_up(lab, "a1", "a2", "b1")
    packet = successor(lab, proof)
    for index in range(2, 5):
        proof = closure_support.close(lab, closure_support.close_request(lab, attempt=f"P{index}"))
        closure_support.persist(lab, proof, attempt=f"P{index}")
        packet = successor(lab, proof, attempt=f"P{index + 1}")
    if not exhaust:
        accepted = accept(lab, packet, "M1", "P5", replaces_attempt_id="P4", closure_id=proof["closure_id"])
        receive(lab, [("M1", "P5", "stale payload", packet, accepted)])
        return
    predecessor = proof
    advance(lab, "R0-exhaust", {"kind": "remove_member", "account_id": "bob"})
    proof = reject(lab, packet, attempt="P5", replaces_attempt_id="P4", closure_id=predecessor["closure_id"])
    persist(lab, proof, attempt="P5")
    catch_up(lab, "a1", "a2")
    blocked(lab, logical="M1", attempt="P6", payload="stale payload", code="send_order_successor_limit",
            replaces_attempt_id="P5", closure_id=proof["closure_id"])
    blocked(lab)
    rows = relay_records(lab)
    check(rows["counts"]["attempts"] == 5 and rows["counts"]["accepted"] == rows["counts"]["events"] == 0,
          "混合链耗尽预算后重复接受或投递")
    lab.case_evidence.update(final_relay=rows, successor_limit=4, progress="BLOCKED_LIMIT_EXPLICIT")


CASES = [("stale_before_r1", partial(lifecycle, recover_first=False)),
         ("stale_after_r1", partial(lifecycle, recover_first=True)),
         ("stale_trusted_descendant", descendant), ("stale_partial_chain", partial_chain),
         ("stale_mixed_accept", partial(mixed_chain, exhaust=False)),
         ("stale_mixed_limit", partial(mixed_chain, exhaust=True))]
