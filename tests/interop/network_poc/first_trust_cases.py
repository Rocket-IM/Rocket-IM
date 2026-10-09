"""F04/F05/F07/F08：独立对象绑定、连续会话、显式重置及逐设备外发门禁。"""

import base64
import copy

from .fixture import CONVERSATION, check, identity
from .first_trust_evidence import state
from .first_trust_fixture import DEVICES, confirm, inspect, observe, reject, roundtrip
from .first_trust_session import TrustSession, public_identity, verify_public
from .permission_cases import prepare
from .permission_recovery_cases import accept, recover


def directory_substitution(lab):
    lab.register_all()
    impostor = public_identity(lab, "b1") | {"signature_key": lab.public["d1"]["signature_key"]}
    record = lab.rust("a1", "identity_trust_observe", identity=impostor)["record"]
    check(record["status"] == "unverified" and record["verification"] is None,
          "首次目录公钥直接成为已核验")
    with TrustSession(lab, "a1") as session:
        display = session.request("identity_trust_prepare", target=identity("b1"), purpose="verify")["display"]
        before = state(lab)
        error = session.request("identity_trust_confirm", display=display,
            independent_identity=public_identity(lab, "b1"), verification="synthetic_local",
            expected_error="identity_context")
        check(state(lab) == before, "不匹配独立对象改变身份状态")
        forged = dict(display, identity=public_identity(lab, "b1"))
        session.request("identity_trust_confirm", display=forged,
            independent_identity=public_identity(lab, "b1"), verification="synthetic_local",
            expected_error="identity_confirmation_stale")
        check(state(lab) == before, "宿主改造展示绕过原对象绑定")
        session.request("identity_trust_confirm", display=display, independent_identity=impostor,
                        verification="risk_accepted", expected_error="invalid_request")
        session.request("identity_trust_confirm", display=display,
                        independent_identity=impostor | {"service_verified": True},
                        verification="synthetic_local", expected_error="invalid_request")
        check(state(lab) == before, "风险接受或 Service 布尔输入被当成独立核验")
    observe(lab)
    check(inspect(lab)["status"] == "changed", "真实公钥观察静默覆盖首次错误绑定")
    confirm(lab, purpose="reset")
    check(inspect(lab)["status"] == "unverified", "reset 本身自动核验")
    lab.group()
    roundtrip(lab)
    lab.case_evidence.update(directory_impostor=impostor, independent_object_rejection=error,
        boundary="independent fixture public objects simulate human exchange; Service claims are not verification")


def legitimate_continuity(lab):
    lab.group()
    with TrustSession(lab, "a1") as session:
        display = session.request("identity_trust_prepare", target=identity("b1"), purpose="verify")["display"]
        fields = {"display": display, "independent_identity": public_identity(lab, "b1"),
                  "verification": "synthetic_local"}
        first = session.request("identity_trust_confirm", **fields)
        saved = state(lab)
        repeated = session.request("identity_trust_confirm", **fields)
        check(not first["duplicate"] and repeated["duplicate"] and state(lab) == saved,
              "同进程精确确认重复改写快照")
    original = inspect(lab)
    roundtrip(lab, "before-epoch")
    record = accept(lab, prepare(lab, "normal-epoch-change")["change"])
    recover(lab, record, "a1", "a2", "b1")
    check(inspect(lab) == original, "合法 MLS/权限后继更换未变设备的身份核验")
    roundtrip(lab, "after-epoch", recipients=("a1", "a2", "b1"))
    lab.case_evidence.update(verified_before_epoch=original, verified_after_epoch=inspect(lab),
        key_package_refresh="NOT_EXECUTED_IN_JOINT_FIXTURE_NO_REFRESH_COMMAND")


def changed_reset(lab):
    lab.group()
    packet, accepted = roundtrip(lab, "original-cached")
    original = inspect(lab)
    replacement = public_identity(lab, "b1") | {"signature_key": lab.public["d1"]["signature_key"]}
    lab.rust("a1", "identity_trust_observe", identity=replacement)
    lab.restart()
    changed = inspect(lab)
    check(changed["status"] == "changed" and changed["history"] == "gap"
          and changed["identity"] == original["identity"] and changed["verification"] == original["verification"],
          "身份变化没有持久保留旧绑定及暂停状态")
    reject(lab)
    reject(lab, logical_message_id="original-cached", attempt_id="P1",
           payload="synthetic-first-trust-original-cached")
    reset = confirm(lab, purpose="reset", independent=replacement)["record"]
    check(reset["status"] == "unverified" and reset["history"] == "reset"
          and reset["identity"] == replacement and reset["retired"][-1]["identity"] == original["identity"],
          "显式 reset 丢失旧绑定或直接恢复外发")
    reject(lab)
    verified = confirm(lab, independent=replacement)["record"]
    check(verified["status"] == "verified" and verified["history"] == "reset", "重新核验伪造历史连续")
    reject(lab, codes=("identity_changed",))
    check(lab.submit(packet) == accepted, "身份重置修改旧 Service 接受原件")
    lab.case_evidence.update(original=original, changed=changed, reset=reset, verified_replacement=verified,
        boundary="new key independently verified, but old group binding remains incompatible; no automatic group migration/history")


def same_account_device(lab):
    from .device_join_cases import join_device, no_old_history, prepare_device, request, setup
    from .join_cases import accept_add
    lab.group()
    old = roundtrip(lab, "before-device", sender="b1")
    setup(lab)
    reject(lab, "permission_prepare_device", device="b1", **request(lab, "new-device"))
    verify_public(lab, "b1", "b2")
    candidate = prepare_device(lab, "new-device")
    missing_before = state(lab)
    error = lab.http("b2", "get_join_material", {"service_id": lab.service,
        "conversation_id": CONVERSATION, "change_id": "new-device"}, expected=403)
    check(error["code"] == "permission_denied" and state(lab) == missing_before,
          "未接受授权可以领取 Welcome")
    record = accept_add(lab, candidate, "b1")
    if not lab.helper:
        forged = copy.deepcopy(record)
        signature = bytearray(base64.b64decode(forged["receipt"]["signature_bytes"]))
        signature[0] ^= 1
        forged["receipt"]["signature_bytes"] = base64.b64encode(signature).decode()
        reject(lab, "permission_join", device="b2", codes=("permission_signature",),
               record=forged, join=candidate["join"])
    recover(lab, record, *DEVICES)
    join_device(lab, "new-device")
    check(lab.rust("b2", "wire_inspect")["history"]["past_epochs"] == [],
          "新设备继承了同账号旧历史密钥")
    if not lab.helper:
        no_old_history(lab, old)
    else:
        lab.case_evidence["isolated_negative_cases"] = ["Q01.F08.invalid_join_preserves_anchor_pause",
                                                       "Q01.F08.old_history_preserves_anchor_pause"]
    reject(lab)  # a1 核验 b1 不代表已经核验同账号 b2；所有目标中仅 b2 未核验。
    check(inspect(lab, "a1", "b1")["status"] == "verified", "其他准确目标被误降级")
    for observer in DEVICES:
        verify_public(lab, observer, "b2")
        verify_public(lab, "b2", observer)
    roundtrip(lab, "after-device", recipients=(*DEVICES, "b2"))
    roundtrip(lab, "from-new-device", sender="b2", recipients=(*DEVICES, "b2"))
    lab.case_evidence["scope"] = "each exact device independently verified; no account-wide key or inherited history"


CASES = [("Q01.F04.directory_substitution", directory_substitution),
         ("Q01.F05.legitimate_continuity", legitimate_continuity),
         ("Q01.F07.changed_reset", changed_reset),
         ("Q01.F08.same_account_device", same_account_device)]
