"""F06：展示的真实进程、实例/账号范围、完整对象及版本绑定。"""

from functools import partial

from .fixture import check, identity
from .first_trust_evidence import state
from .first_trust_fixture import confirm, inspect, observe
from .first_trust_session import TrustSession, public_identity


def stale_display(lab, *, cause):
    observe(lab)
    with TrustSession(lab, "a1") as session:
        display = session.request("identity_trust_prepare", target=identity("b1"), purpose="verify")["display"]
        fields = {"display": display, "independent_identity": public_identity(lab, "b1"),
                  "verification": "synthetic_local"}
        if cause == "process_restart":
            session.close(kill=True)
            with TrustSession(lab, "a1") as reopened:
                before = state(lab)
                error = reopened.request("identity_trust_confirm", expected_error="identity_confirmation_stale", **fields)
        else:
            if cause == "scope_switch":
                session.request("identity_trust_inspect", device="b1")
                session.request("identity_trust_inspect")
            elif cause == "candidate_revision":
                session.request("identity_trust_observe", identity=public_identity(lab, "b1") |
                                {"signature_key": lab.public["d1"]["signature_key"]})
            else:
                raise AssertionError(cause)
            before = state(lab)
            error = session.request("identity_trust_confirm", expected_error="identity_confirmation_stale", **fields)
        check(state(lab) == before, "迟到展示改写快照或 Relay")
    check(inspect(lab)["status"] != "verified", "失效展示仍然确认成功")
    if cause != "candidate_revision":
        check(confirm(lab)["record"]["status"] == "verified", "新进程新展示不能正常核验")
    lab.case_evidence.update(stale_cause=cause, original_display=display, error=error,
                            before_rejected_confirmation=before, after_rejected_confirmation=before)


def object_binding(lab):
    observe(lab)
    with TrustSession(lab, "a1") as session:
        display = session.request("identity_trust_prepare", target=identity("b1"), purpose="verify")["display"]
        original = public_identity(lab, "b1")
        for changes in ({"service_id": "other-service"}, {"account_id": "other-account"},
                        {"device_id": "other-device"}, {"signature_key": lab.public["d1"]["signature_key"]}):
            before = state(lab)
            session.request("identity_trust_confirm", display=display, independent_identity=original | changes,
                            verification="synthetic_local", expected_error="identity_context")
            check(state(lab) == before, "非准确公开对象提交改变状态")
        result = session.request("identity_trust_confirm", display=display,
                                 independent_identity=original, verification="synthetic_local")
        check(result["record"]["status"] == "verified", "正确原件未恢复成功")
    lab.case_evidence["bound_fields"] = ["service_id", "account_id", "device_id", "signature_key"]


COMMON_CASES = [("Q01.F06.process_restart", partial(stale_display, cause="process_restart")),
                ("Q01.F06.candidate_revision", partial(stale_display, cause="candidate_revision")),
                ("Q01.F06.object_binding", object_binding)]
CASES = COMMON_CASES + [("Q01.F06.scope_switch", partial(stale_display, cause="scope_switch"))]
