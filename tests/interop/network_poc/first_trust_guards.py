"""F09：核验元数据不解除权限、一致性及旧密文外发门禁。"""

from functools import partial

from .fixture import check, identity
from .first_trust_evidence import state
from .first_trust_fixture import inspect, reject, roundtrip
from .first_trust_session import TrustSession, public_identity
from .permission_cases import prepare
from .permission_recovery_cases import accept, recover


def original_guards(lab, *, gate):
    from .consistency_cases import begin, current_head, fork_fixture, observe
    lab.group()
    actor = "b1" if gate.startswith("consistency") else ("c1" if gate == "access_removed" else "a1")
    packet, accepted = roundtrip(lab, "before-guard", sender=actor)
    with TrustSession(lab, actor) as session:
        target = "a1" if actor != "a1" else "b1"
        display = session.request("identity_trust_prepare", target=identity(target), purpose="verify")["display"]
        fields = {"display": display, "independent_identity": public_identity(lab, target),
                  "verification": "synthetic_local"}
        if gate == "permission_pending":
            record = accept(lab, prepare(lab, "guard-pending")["change"])
            code = "permission_pending"
        elif gate == "access_removed":
            record = accept(lab, prepare(lab, "guard-remove")["change"])
            recover(lab, record, "a1", "a2", "b1", "c1")
            code = "access_removed"
        elif gate == "consistency_checking":
            begin(lab, actor)
            code = "consistency_paused"
        elif gate == "consistency_fork":
            left, right, _, _ = fork_fixture(lab)
            begin(lab, actor)
            lab.rust(actor, "consistency_observe_fork", predecessor=lab.checkpoint, left=left, right=right)
            code = "consistency_paused"
        else:
            raise AssertionError(gate)
        before = state(lab)
        if gate.startswith("consistency"):
            session.request("identity_trust_confirm", expected_error=code, **fields)
            check(state(lab) == before, "一致性暂停被核验输入覆盖")
        else:
            permission_before = lab.rust(actor, "permission_inspect")
            result = session.request("identity_trust_confirm", **fields)
            check(result["record"]["status"] == "verified" and
                  lab.rust(actor, "permission_inspect") == permission_before, "核验越过权限状态")
        check(inspect(lab, actor, target)["status"] == "verified", "准确核验查询丢失")
        reject(lab, device=actor, codes=(code,))
        reject(lab, device=actor, codes=(code,), logical_message_id="before-guard", attempt_id="P1",
               payload="synthetic-first-trust-before-guard")
    if gate == "permission_pending":
        recover(lab, record, "a1", "a2", "b1")
        repeated = lab.rust(actor, "wire_send", logical_message_id="before-guard", attempt_id="P1",
                            payload="synthetic-first-trust-before-guard")
        check(repeated["envelope"] == packet["envelope"], "合法恢复后旧请求重建了密文")
        roundtrip(lab, "guard-recovered", recipients=("a1", "a2", "b1"))
    elif gate == "consistency_checking":
        observe(lab, current_head(lab, actor), actor)
        repeated = lab.rust(actor, "wire_send", logical_message_id="before-guard", attempt_id="P1",
                            payload="synthetic-first-trust-before-guard")
        check(repeated["envelope"] == packet["envelope"], "一致性恢复后改写原密文")
        roundtrip(lab, "q02-recovered", sender=actor)
    else:
        lab.restart()
        reject(lab, device=actor, codes=(code,))
    lab.case_evidence.update(original_gate=gate, gate_code=code, original_envelope=packet["envelope"],
                            original_acceptance=accepted, boundary="no verification command lifts the original gate")


CASES = [("Q01.F09." + gate, partial(original_guards, gate=gate))
         for gate in ("permission_pending", "access_removed", "consistency_checking", "consistency_fork")]
