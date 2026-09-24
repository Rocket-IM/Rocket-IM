"""真实设备签名、HTTP 权限接受与 MLS 状态提交；初始信任仍来自合成 fixture。"""

import base64
import copy
from concurrent.futures import ThreadPoolExecutor
import json
import http.client
import shutil

from .fixture import CONVERSATION, SERVICE, check


REMOVE_CHARLIE = {"kind": "remove_member", "account_id": "charlie"}
REVOKE_A2 = {"kind": "revoke_device", "account_id": "alice", "device_id": "a2"}


def prepare(lab, ident, action=REMOVE_CHARLIE, device="a1", **options):
    return lab.rust(device, "permission_prepare", change_id=ident, action=action, **options)


def submit(lab, change, device="a1", expected=200):
    return lab.http(device, "submit_permission_change",
                    {"service_id": SERVICE, "conversation_id": CONVERSATION, "change": change},
                    expected=expected)


def changes(lab, after="1", limit="32", device="b1", expected=200):
    return lab.http(device, "get_permission_changes",
                    {"service_id": SERVICE, "conversation_id": CONVERSATION,
                     "after_version": after, "limit": limit}, expected=expected)


def version(lab, device):
    return lab.rust(device, "wire_inspect")["configuration"]["authorization_version"]


def reject_unchanged(lab, device, operation, **fields):
    before = (lab.directory / device / "state.enc").read_bytes()
    error = lab.rust(device, operation, expected_exit=1, **fields)
    check(bool(error["code"]), "拒绝必须有明确原因")
    check((lab.directory / device / "state.enc").read_bytes() == before,
          operation + " 拒绝后改变了有效快照")
    return error


def apply(lab, change, devices):
    for device in devices:
        lab.rust(device, "permission_apply", change=change)


def signed_removal(lab):
    old = lab.prepare("before_permission")
    old_accepted = lab.submit(old)
    late = lab.prepare("late_permission")
    change = prepare(lab, "remove_charlie")["change"]
    check(prepare(lab, "remove_charlie")["change"] == change,
          "重启 CLI 后必须复用已持久化的签名与 Commit 原字节")
    reject_unchanged(lab, "a1", "wire_send", logical_message_id="paused",
                     attempt_id="P1", payload="synthetic-paused")
    accepted = submit(lab, change)
    check(accepted["outcome"] == "accepted" and accepted["authorization_version"] == "2",
          "R0 没有接受唯一后继权限版本")
    check(version(lab, "a1") == "1", "R0 服务接受不应冒充端侧 R1")
    check(lab.submit(late, expected=409)["outcome"] == "rejected_final",
          "R0 后旧版本首次提交必须终态拒绝")
    removed_page = lab.pull("c1")
    check(removed_page["events"] and all(slot["availability"] == "access_removed" and "event" not in slot
                                        for slot in removed_page["events"]),
          "被移除者只能取得无载荷的访问移除槽位")
    changes(lab, device="c1", expected=403)
    page = lab.pull("b1")
    check(page["events"][0]["event"]["acceptance_id"] == old_accepted["acceptance_id"],
          "仍授权成员丢失了变更前已接受记录")
    lab.receive("b1", old)
    apply(lab, change, ("a1", "a2", "b1"))
    check({version(lab, d) for d in ("a1", "a2", "b1")} == {"2"}, "R1 未共同推进")
    packet = lab.prepare("after_permission")
    lab.submit(packet)
    lab.receive("b1", packet)
    check(lab.submit(old)["acceptance_id"] == old_accepted["acceptance_id"],
          "已接受旧尝试应保持原始结果")
    lab.restart()
    check(submit(lab, change) == accepted, "Relay 重启后签名变更不幂等")
    check(changes(lab)["changes"] == [change], "持久授权链与接受证据不一致")


def tampering(lab):
    for device, action in (("b1", REMOVE_CHARLIE), ("c1", REVOKE_A2)):
        reject_unchanged(lab, device, "permission_prepare", change_id="unauthorized", action=action)
    change = prepare(lab, "bound_fields")["change"]
    check(submit(lab, change, device="b1", expected=403)["code"] == "permission_denied",
          "请求凭证必须与真实签名者相同")
    for field in ("signature_bytes", "commit_bytes"):
        bad = copy.deepcopy(change)
        raw = bytearray(base64.b64decode(bad[field])); raw[-1] ^= 1
        bad[field] = base64.b64encode(raw).decode()
        submit(lab, bad, expected=403)
        reject_unchanged(lab, "b1", "permission_apply", change=bad)
    for field, value in (("service_id", "other-service"), ("conversation_id", "other-group"),
                         ("authorization_version", "3"), ("to_state_ref", "0" * 64)):
        bad = copy.deepcopy(change)
        statement = json.loads(base64.b64decode(bad["statement_bytes"]))
        statement[field] = value
        bad["statement_bytes"] = base64.b64encode(json.dumps(statement).encode()).decode()
        submit(lab, bad, expected=(403, 409))
        reject_unchanged(lab, "b1", "permission_apply", change=bad)
    check(changes(lab)["authorization_version"] == "1", "拒绝的请求推进了服务权限")
    check(changes(lab)["changes"] == [], "拒绝的请求写入了接受链")
    altered = copy.deepcopy(lab.checkpoint); altered["owner_account_id"] = "bob"
    reject_unchanged(lab, "b1", "permission_bootstrap", checkpoint=altered)
    reject_unchanged(lab, "b1", "wire_configure", conversation_id=CONVERSATION,
                     authorization_version="2")
    for action, fields in (
        ("set_state", {"authorization_version": "2", "crypto_state_ref": "0" * 64,
                       "members": lab.fixture["conversation"]["members"]}),
        ("revoke_device", {"account_id": "charlie", "device_id": "c1"}),
        ("add_control", {}),
    ):
        check(lab.control(action, expected=403, **fields)["code"] == "permission_denied",
              "可信权限模式不能从测试入口改写状态")
    submit(lab, change)
    apply(lab, change, ("a1", "b1"))
    bad = copy.deepcopy(change)
    raw = bytearray(base64.b64decode(bad["signature_bytes"])); raw[0] ^= 1
    bad["signature_bytes"] = base64.b64encode(raw).decode()
    check(submit(lab, bad, expected=409)["code"] == "idempotency_conflict", "同 ID 异证明不能覆盖")
    reject_unchanged(lab, "b1", "permission_apply", change=bad)


def device_revocation(lab):
    change = prepare(lab, "revoke_a2", REVOKE_A2)["change"]
    submit(lab, change)
    check(lab.pull("a2", expected=403)["code"] == "device_revoked", "撤销后旧凭证仍有效")
    apply(lab, change, ("a1", "b1", "c1"))
    packet = lab.prepare("after_revoke")
    accepted = lab.submit(packet)
    check(all(d["device_id"] != "a2" for d in accepted["recipients"]), "新版本仍包含撤销设备")
    lab.receive("b1", packet)
    lab.receive("c1", packet)
    lab.restart()
    changes(lab, device="a2", expected=403)
    check(changes(lab)["authorization_version"] == "2", "重启覆盖了权限检查点")


def offline_chain(lab):
    one = prepare(lab, "chain_remove")["change"]
    submit(lab, one)
    apply(lab, one, ("a1", "a2"))
    two = prepare(lab, "chain_revoke", REVOKE_A2)["change"]
    submit(lab, two)
    apply(lab, two, ("a1",))
    packet = lab.prepare("after_two_changes")
    lab.submit(packet)
    page = lab.pull("b1")
    lab.download("b1", page)
    waiting = lab.rust("b1", "wire_process")
    check(waiting["sync"]["pending_count"] == 1 and not waiting["deliveries"],
          "没有权限链的新版本不能标为解密成功")
    old_channel = lab.http("b1", "get_crypto_dependencies", {"service_id": SERVICE,
                           "conversation_id": CONVERSATION, "from_state_ref": lab.state_ref,
                           "to_state_ref": lab.rust("a1", "wire_inspect")["crypto_state_ref"], "limit": "1"},
                           expected=409)
    check(old_channel["code"] == "permission_chain_required", "签名模式必须明确引导验证权限链")
    first = changes(lab, limit="1")
    check(first["changes"] == [one] and first["next_after_version"] == "2" and first["has_more"],
          "权限分页没有按实际返回证据推进")
    apply(lab, one, ("b1",))
    apply(lab, one, ("b1",))
    last = changes(lab, after=first["next_after_version"], limit="1")
    check(last["changes"] == [two] and last["next_after_version"] == "3" and not last["has_more"],
          "独立权限链缺失后继")
    apply(lab, two, ("b1",))
    processed = lab.rust("b1", "wire_process")
    check(len(processed["deliveries"]) == 1 and processed["sync"]["pending_count"] == 0,
          "补全权限链后没有恢复待处理消息")


def atomic_changes(lab):
    incoming = lab.rust("b1", "wire_send", logical_message_id="queued_during_prepare",
                        attempt_id="P1", payload="synthetic-queued")
    lab.submit(incoming, device="b1")
    for point, code in (("before_save", 83), ("before_rename", 84)):
        before = (lab.directory / "a1/state.enc").read_bytes()
        prepare(lab, "atomic_change", failpoint=point, expected_exit=code)
        check((lab.directory / "a1/state.enc").read_bytes() == before, "准备失败破坏有效状态")
    prepare(lab, "atomic_change", failpoint="after_save", expected_exit=85)
    change = prepare(lab, "atomic_change")["change"]
    check(version(lab, "a1") == "1", "prepared 候选不能提前成为有效状态")
    page = lab.pull("a1")
    lab.download("a1", page)
    reject_unchanged(lab, "a1", "wire_process")
    submit(lab, change)
    for device in ("a1", "b1"):
        for point, code in (("before_save", 83), ("before_rename", 84)):
            before = (lab.directory / device / "state.enc").read_bytes()
            lab.rust(device, "permission_apply", change=change, failpoint=point, expected_exit=code)
            check((lab.directory / device / "state.enc").read_bytes() == before,
                  "R1 失败不应只提交密码或权限其中一半")
        lab.rust(device, "permission_apply", change=change, failpoint="after_save", expected_exit=85)
        check(version(lab, device) == "2", "R1 持久成功后缺少版本")
        apply(lab, change, (device,))
        check(version(lab, device) == "2", "R1 响应丢失重试推进了两次")
    check(lab.rust("a1", "wire_inspect")["sync"]["download_cursor"] == page["next_after_seq"],
          "应用候选密码状态覆盖了准备期间已下载的队列")
    packet = lab.prepare("after_atomic")
    lab.submit(packet)
    lab.receive("b1", packet)


def competing_changes(lab):
    left = prepare(lab, "competing_a1")["change"]
    right = prepare(lab, "competing_a2", device="a2")["change"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(submit, lab, proof, device, (200, 409))
                   for device, proof in (("a1", left), ("a2", right))]
        replies = [future.result(timeout=20) for future in futures]
    accepted = [i for i, result in enumerate(replies) if result.get("outcome") == "accepted"]
    check(len(accepted) == 1, "同一前驱并发提交不能接受两个后继")
    winner = accepted[0]; winner_device, loser_device = (("a1", "a2") if winner == 0 else ("a2", "a1"))
    proof = (left, right)[winner]
    check(changes(lab)["changes"] == [proof], "服务接受链出现分叉")
    apply(lab, proof, (winner_device, "b1"))
    reject_unchanged(lab, loser_device, "permission_apply", change=proof)
    reject_unchanged(lab, loser_device, "wire_send", logical_message_id="conflict_paused",
                     attempt_id="P1", payload="synthetic-conflict")
    check(version(lab, loser_device) == "1", "未协调的候选不应被静默覆盖")


def verifier_unavailable(lab):
    change = prepare(lab, "verifier_failure")["change"]
    executable = lab.directory / "public-verifier"
    shutil.copy2(lab.permission_verifier, executable)
    lab.permission_verifier = executable
    lab.restart()
    unavailable = executable.with_suffix(".offline")
    executable.rename(unavailable)
    try:
        error = submit(lab, change, expected=503)
        check(error["code"] == "permission_verifier_unavailable" and error["outcome"] == "not_recorded",
              "验证器失败不能接受或降级")
        check(changes(lab)["authorization_version"] == "1" and not changes(lab)["changes"],
              "验证器失败写入了部分权限")
    finally:
        unavailable.rename(executable)
    submit(lab, change)
    apply(lab, change, ("a1", "b1"))


def relay_interruptions(lab):
    one = prepare(lab, "relay_atomic_remove")["change"]
    for hook, exit_code in (("before_commit_exit", 86), ("drop_after_commit", None)):
        lab.control("hook", hook=hook)
        try:
            submit(lab, one)
            raise AssertionError("故障点不应返回 HTTP 成功")
        except (http.client.RemoteDisconnected, ConnectionResetError):
            pass
        if exit_code is not None:
            check(lab.process.wait(timeout=10) == exit_code, "Relay 未在约定事务点退出")
        lab.restart()
        expected = "1" if exit_code == 86 else "2"
        chain = changes(lab)
        check(chain["authorization_version"] == expected, "R0 事务退出留下部分权限版本")
        check(chain["changes"] == ([] if exit_code == 86 else [one]), "R0 链与权限版本不同步")
    accepted = submit(lab, one)
    check(accepted["authorization_version"] == "2", "响应丢失重试不能产生第二后继")
    apply(lab, one, ("a1", "a2", "b1"))
    two = prepare(lab, "relay_atomic_revoke", REVOKE_A2)["change"]
    lab.control("hook", hook="after_commit_exit")
    try:
        submit(lab, two)
        raise AssertionError("提交后退出不应返回 HTTP 成功")
    except (http.client.RemoteDisconnected, ConnectionResetError):
        pass
    check(lab.process.wait(timeout=10) == 87, "Relay 提交后退出点不符")
    lab.restart()
    check(changes(lab)["changes"] == [one, two], "R0 提交后的两步链未完整持久化")
    lab.pull("a2", expected=403)
    check(submit(lab, two)["authorization_version"] == "3", "事务恢复后不能重复接受")
    apply(lab, two, ("a1", "b1"))
    packet = lab.prepare("after_relay_permission_recovery")
    lab.submit(packet)
    lab.receive("b1", packet)


def all_member_devices(lab):
    action = {"kind": "remove_member", "account_id": "alice"}
    change = prepare(lab, "remove_all_alice_devices", action, device="b1")["change"]
    submit(lab, change, device="b1")
    apply(lab, change, ("b1", "c1"))
    members = lab.rust("c1", "wire_inspect")["configuration"]["members"]
    check({d["device_id"] for d in members} == {"b1", "c1"},
          "按账号移除必须排除该账号全部群设备")
    for device in ("a1", "a2"):
        changes(lab, device=device, expected=403)
    packet = lab.rust("b1", "wire_send", logical_message_id="remaining_accounts",
                      attempt_id="P1", payload="synthetic-two-accounts")
    lab.submit(packet, device="b1")
    lab.receive("c1", packet)
