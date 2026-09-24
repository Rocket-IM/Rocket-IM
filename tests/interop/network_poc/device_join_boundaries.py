"""设备授权的撤销、公开锚和端/服务原子持久化边界。"""

import copy
import http.client

from .device_join_cases import join_device, no_old_history, prepare_device, request, setup
from .fixture import ACCOUNTS, check
from .history_cases import publish, receive_record
from .join_cases import accept_add, material, submit_add
from .permission_cases import prepare, reject_unchanged, version
from .permission_recovery_cases import accept, inspect, records, recover


def client_atomicity(lab):
    setup(lab)
    before = (lab.directory / "b1/state.enc").read_bytes()
    for point, code in (("before_save", 83), ("before_rename", 84)):
        prepare_device(lab, "atomic_device", failpoint=point, expected_exit=code)
        check((lab.directory / "b1/state.enc").read_bytes() == before, "未提交批准却写入信任或密码状态")
    prepare_device(lab, "atomic_device", failpoint="after_save", expected_exit=85)
    candidate = prepare_device(lab, "atomic_device")
    check(prepare_device(lab, "atomic_device") == candidate, "重启未复用精确设备授权和 Welcome")
    record = accept_add(lab, candidate, "b1")
    for device in ("b1", "a1"):
        before = (lab.directory / device / "state.enc").read_bytes()
        recover(lab, record, device, failpoint="before_rename", expected_exit=84)
        check((lab.directory / device / "state.enc").read_bytes() == before, "应用授权留下部分群信任")
        recover(lab, record, device, failpoint="after_save", expected_exit=85)
        recover(lab, record, device)
    bundle = material(lab, "atomic_device", "b2")
    before = (lab.directory / "b2/state.enc").read_bytes()
    for point, code in (("before_save", 83), ("before_rename", 84)):
        lab.rust("b2", "permission_join", **bundle, failpoint=point, expected_exit=code)
        check((lab.directory / "b2/state.enc").read_bytes() == before, "失败入群消耗 KP 或部分写入新设备状态")
    lab.rust("b2", "permission_join", **bundle, failpoint="after_save", expected_exit=85)
    check(lab.rust("b2", "permission_join", **bundle)["duplicate"], "成功保存后重试被当成第二次授权")
    receive_record(lab, "a1", publish(lab, "after_device_crash", "b2"))


def removed_authorizer(lab):
    setup(lab)
    candidate = prepare_device(lab, "before_bob_removed")
    removal = accept(lab, prepare(lab, "remove_bob_authorizer",
                                 {"kind": "remove_member", "account_id": "bob"})["change"])
    recover(lab, removal, "a1", "a2", "c1", "b1")
    check(inspect(lab, "b1")["recovery_status"] == "access_removed", "被移除签署者仍可重新批准")
    submit_add(lab, candidate, "b1", expected=403)
    reject_unchanged(lab, "b1", "permission_prepare_device", **request(lab, "removed_signer_retry"))
    material(lab, "before_bob_removed", "b2", expected=403)
    lab.restart()
    check(records(lab, "a1")["records"] == [removal], "已移除旧设备的迟到授权复活了新设备")


def revoke_joined_device(lab):
    setup(lab)
    candidate = prepare_device(lab, "device_before_revocation")
    accepted = submit_add(lab, candidate, "b1")
    record = {"change": candidate["change"], "receipt": accepted["receipt"]}
    recover(lab, record, *ACCOUNTS)
    join_device(lab, "device_before_revocation")
    removal = accept(lab, prepare(lab, "revoke_b2",
        {"kind": "revoke_device", "account_id": "bob", "device_id": "b2"}, "b1")["change"], "b1")
    recover(lab, removal, *ACCOUNTS, "b2")
    reject_unchanged(lab, "b1", "permission_prepare_device", **request(lab, "readd_revoked_b2"))
    reject_unchanged(lab, "b2", "wire_send", logical_message_id="revoked_b2_send", attempt_id="P1", payload="synthetic")
    lab.restart()
    material(lab, "device_before_revocation", "b2", expected=403)
    check(submit_add(lab, candidate, "b1") == accepted, "查询旧接受结果应保持原事实")
    sent = publish(lab, "after_b2_revocation", "b1")
    check(all(d["device_id"] != "b2" for d in sent[1]["recipients"]), "旧批准的重放复活了已撤销设备")
    receive_record(lab, "a1", sent)


def revoke_old_device_after_join(lab):
    setup(lab)
    candidate = prepare_device(lab, "b2_before_old_revoked")
    record = accept_add(lab, candidate, "b1")
    recover(lab, record, *ACCOUNTS)
    join_device(lab, "b2_before_old_revoked")
    removal = accept(lab, prepare(lab, "b2_revokes_b1",
        {"kind": "revoke_device", "account_id": "bob", "device_id": "b1"}, "b2")["change"], "b2")
    recover(lab, removal, "a1", "a2", "c1", "b2", "b1")
    lab.pull("b1", expected=403)
    lab.restart()
    receive_record(lab, "a1", publish(lab, "new_device_after_old_revoked", "b2"))
    receive_record(lab, "b2", publish(lab, "old_revocation_does_not_remove_new"))
    check(material(lab, "b2_before_old_revoked", "b2")["record"] == record,
          "撤销旧签署者追溯取消了已接受新设备的独立权限")


def group_anchor_and_history(lab):
    setup(lab)
    before_roster = lab.rust("b2", "inspect")["roster_version"]
    changed = copy.deepcopy(lab.checkpoint); changed["owner_account_id"] = "bob"
    for checkpoint, key in ((changed, lab.relay_receipt_key), (lab.checkpoint, lab.public["a1"]["signature_key"])):
        reject_unchanged(lab, "b2", "permission_device_join_anchor", checkpoint=checkpoint, relay_receipt_key=key)
    predecessor = accept(lab, prepare(lab, "before_b2_public_advance")["change"])
    recover(lab, predecessor, "a1", "a2", "b1")
    state = lab.rust("b2", "permission_join_advance", record=predecessor)
    check(state["checkpoint"] is None and state["admission"]["public_checkpoint"]["authorization_version"] == "2",
          "公开链伪装成本机已完成的群密码状态")
    check(lab.rust("b2", "inspect")["group_id"] is None
          and lab.rust("b2", "inspect")["roster_version"] == before_roster, "公开锚扩充了账号信任或群状态")
    old = publish(lab, "before_b2_actual_join")
    candidate = prepare_device(lab, "after_b2_public_advance")
    record = accept_add(lab, candidate, "b1")
    reject_unchanged(lab, "b2", "permission_join_advance", record=record)
    recover(lab, record, "a1", "a2", "b1")
    bundle = material(lab, "after_b2_public_advance", "b2")
    for device in ("a1", "a2", "b1"):
        material(lab, "after_b2_public_advance", device, expected=403)
    lab.rust("b2", "permission_join", **bundle)
    no_old_history(lab, old)
    own_history = publish(lab, "b2_eligible_history")
    removal = accept(lab, prepare(lab, "after_b2_revoke_a2",
        {"kind": "revoke_device", "account_id": "alice", "device_id": "a2"})["change"])
    recover(lab, removal, "a1", "b1", "b2")
    history = lab.rust("b2", "wire_inspect")["history"]["past_epochs"]
    check(len(history) == 1 and history[0]["authorization_version"] == "3", "新设备积累了加入之前的历史状态")
    check(receive_record(lab, "b2", own_history)["historical"], "新设备加入后的合法历史不可接收")
    no_old_history(lab, old)
    before = lab.rust("b2", "wire_inspect")
    check(lab.rust("b2", "permission_join", **bundle)["duplicate"], "旧加入原记录无法重复查询")
    check(lab.rust("b2", "wire_inspect") == before and version(lab, "b2") == "4", "重复加入覆盖后续撤销状态")


def service_atomicity(lab):
    setup(lab)
    candidate = prepare_device(lab, "device_transaction")
    saved = lab.receipt_key.with_suffix(".saved")
    lab.receipt_key.rename(saved)
    try:
        check(submit_add(lab, candidate, "b1", expected=503)["code"] == "receipt_signer_unavailable",
              "Service 签名失败被静默接受")
        check(records(lab)["records"] == [], "Service 签名失败留下部分授权")
    finally:
        saved.rename(lab.receipt_key)
    for hook, code in (("before_commit_exit", 86), ("after_commit_exit", 87)):
        lab.control("hook", hook=hook)
        try:
            submit_add(lab, candidate, "b1")
            raise AssertionError("受控退出却返回成功")
        except (http.client.RemoteDisconnected, ConnectionResetError):
            pass
        check(lab.process.wait(timeout=10) == code, "设备授权事务退出点错误")
        lab.restart()
        page = records(lab)
        check(page["authorization_version"] == ("1" if code == 86 else "2")
              and len(page["records"]) == (0 if code == 86 else 1), "授权事务没有保持全有或全无")
        if code == 86:
            material(lab, "device_transaction", "b2", expected=403)
    accepted = submit_add(lab, candidate, "b1")
    bundle = material(lab, "device_transaction", "b2")
    check(bundle == {"record": {"change": candidate["change"], "receipt": accepted["receipt"]},
                     "join": candidate["join"]}, "事务恢复改写了原授权、回执或材料")
    recover(lab, bundle["record"], *ACCOUNTS)
    lab.rust("b2", "permission_join", **bundle)
    receive_record(lab, "a1", publish(lab, "device_after_service_recovery", "b2"))


def service_lost_response(lab):
    setup(lab)
    candidate = prepare_device(lab, "device_lost_response")
    lab.control("hook", hook="drop_after_commit")
    try:
        submit_add(lab, candidate, "b1")
        raise AssertionError("服务丢响应装置没有生效")
    except (http.client.RemoteDisconnected, ConnectionResetError):
        pass
    original = material(lab, "device_lost_response", "b2")
    lab.restart()
    accepted = submit_add(lab, candidate, "b1")
    check(material(lab, "device_lost_response", "b2") == original
          and accepted["receipt"] == original["record"]["receipt"]
          and records(lab)["records"] == [original["record"]], "响应丢失导致重新签名或重复授权")
    recover(lab, original["record"], *ACCOUNTS)
    lab.rust("b2", "permission_join", **original)
    receive_record(lab, "b1", publish(lab, "device_after_lost_response", "b2"))
