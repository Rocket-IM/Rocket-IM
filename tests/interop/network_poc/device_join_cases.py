"""同账号旧设备批准独立新设备；公开群信任不回填账号 roster。"""

import base64
import copy
import hashlib
import json
import secrets
import time

from .fixture import ACCOUNTS, CONVERSATION, SERVICE, check, identity
from .history_cases import publish, receive_record
from .join_cases import accept_add, material, mutate_bytes, statement, submit_add
from .permission_cases import prepare, reject_unchanged, version
from .permission_recovery_cases import accept, close, inspect, pause, records, recover


def member(lab, target="b2"):
    return {**identity(target), "signature_key": lab.public[target]["signature_key"]}


def request(lab, ident, target="b2", **fields):
    return {"change_id": ident, "member": member(lab, target),
            "key_package": lab.public[target]["key_package"], "history_policy": "from_join", **fields}


def setup(lab, target="b2"):
    lab.rust(target, "permission_device_join_anchor", checkpoint=lab.checkpoint,
             relay_receipt_key=lab.relay_receipt_key)


def prepare_device(lab, ident, actor="b1", target="b2", **fields):
    return lab.rust(actor, "permission_prepare_device", **request(lab, ident, target, **fields))


def join_device(lab, ident, target="b2", **options):
    return lab.rust(target, "permission_join", **material(lab, ident, target), **options)


def no_old_history(lab, old, target="b2"):
    packet, accepted = old
    reject_unchanged(lab, target, "wire_receive", **packet["envelope"],
                     acceptance_id=accepted["acceptance_id"], acceptance_receipt=accepted["acceptance_receipt"])


def future_device_flow(lab):
    setup(lab)
    original_rosters = {d: lab.rust(d, "inspect")["roster_version"] for d in (*ACCOUNTS, "b2")}
    old = publish(lab, "before_device_join", "b1")
    old_page = lab.pull("b1")
    candidate = prepare_device(lab, "bob_device_join")
    lab.public_fixture_directory.mkdir(parents=True, exist_ok=True)
    (lab.public_fixture_directory / "device-join-public-fixture.json").write_text(json.dumps(
        {"checkpoint": lab.checkpoint, "change": candidate["change"], "join": candidate["join"]}, indent=2))
    record = accept_add(lab, candidate, "b1")
    check(version(lab, "b1") == "1", "Service 接受不能代替旧设备完成本机提交")
    pause(lab, "b1")
    recover(lab, record, "b1", "a1", "a2")
    current = publish(lab, "after_device_join", "b1")
    join_device(lab, "bob_device_join")
    check(version(lab, "b2") == "2" and lab.rust("b2", "wire_inspect")["history"]["past_epochs"] == [],
          "同账号新设备自动继承了加入前密码历史")
    no_old_history(lab, old)
    check(lab.http("b2", "pull_events", {"service_id": SERVICE, "after_seq": "0", "limit": "100",
               "stream_id": old_page["stream_id"]}, expected=409)["code"] == "cursor_invalid",
          "Service 允许新设备沿用同账号旧设备游标")
    page = lab.pull("b2")
    check(len(page["events"]) == 1 and page["stream_id"] != old_page["stream_id"],
          "新设备继承了同账号旧设备消息或游标空间")
    lab.download("b2", page)
    error = reject_unchanged(lab, "b2", "wire_download_signed", **old_page.signed_input())
    check(error["code"] == "stream_page_context", "同账号旧设备签名页没有按目标设备拒绝")
    check(receive_record(lab, "b2", current)["duplicate"] is False, "新设备无法解密授权后消息")
    check(receive_record(lab, "b2", current)["duplicate"] is True, "新设备接收没有去重")
    recover(lab, record, "c1")
    reply = publish(lab, "new_bob_device_reply", "b2")
    for device in ACCOUNTS:
        receive_record(lab, device, reply)
        check(lab.rust(device, "inspect")["roster_version"] == original_rosters[device],
              "本群设备授权改写了独立账号 roster")
    check(lab.rust("b2", "inspect")["roster_version"] == original_rosters["b2"],
          "同账号公开群检查点被导入新设备的全局 roster")
    check(lab.submit(old[0], device="b1") == old[1], "添加设备改写了旧消息原接受事实")
    lab.restart()
    check(submit_add(lab, candidate, "b1")["receipt"] == record["receipt"], "重启后旧授权不幂等")


def authority_and_modes(lab):
    for device in ("a1", "a2", "c1", "b2"):
        reject_unchanged(lab, device, "permission_prepare_device", **request(lab, "wrong_actor"))
    for device in ("a1", "b1"):
        reject_unchanged(lab, device, "permission_prepare_add", **request(lab, "wrong_join_kind"))
    reject_unchanged(lab, "b2", "permission_join_anchor", checkpoint=lab.checkpoint,
                     relay_receipt_key=lab.relay_receipt_key)
    lab.http("b2", "get_permission_records", {"service_id": SERVICE, "conversation_id": CONVERSATION,
             "after_version": "1", "limit": "32"}, expected=403)
    setup(lab)
    now = int(time.time())
    legacy = {"service": SERVICE, "account": "bob", "signer_device": "b1", "new_device": "b2",
              "new_signature_key": list(base64.b64decode(lab.public["b2"]["signature_key"])),
              "key_package_sha256": list(hashlib.sha256(base64.b64decode(lab.public["b2"]["key_package"])).digest()),
              "expected_roster_version": lab.rust("b1", "inspect")["roster_version"],
              "nonce": list(secrets.token_bytes(32)), "issued_at_unix_secs": now, "expires_at_unix_secs": now + 120}
    signed = lab.rust("b1", "sign_authorization", request=legacy)["authorization"]
    for device in ("b1", "b2"):
        reject_unchanged(lab, device, "authorize", authorization=signed,
                         key_package=lab.public["b2"]["key_package"], now_unix_secs=now)
    for device in ("a1", "b1", "b2"):
        reject_unchanged(lab, device, "permission_device_join_anchor", checkpoint=lab.checkpoint,
                         relay_receipt_key=lab.relay_receipt_key)
    for fields in ({"history_policy": "all"}, {"member": member(lab, "a3")},
                   {"key_package": lab.public["a3"]["key_package"]},
                   {"member": {**member(lab), "signature_key": lab.public["a3"]["signature_key"]}}):
        reject_unchanged(lab, "b1", "permission_prepare_device", **request(lab, "wrong_binding", **fields))
    candidate = prepare_device(lab, "correct_device_authority")
    action = statement(candidate)["action"]
    check(action["kind"] == "add_device", "新设备授权混进新账号邀请动作")
    reject_unchanged(lab, "b1", "permission_prepare", change_id="raw_add_device", action=action)
    for device in ("a1", "b2"):
        submit_add(lab, candidate, device, expected=403)
    record = accept_add(lab, candidate, "b1")
    recover(lab, record, *ACCOUNTS)
    join_device(lab, "correct_device_authority")
    receive_record(lab, "a1", publish(lab, "authorized_device", "b2"))


def bound_proof_and_material(lab):
    setup(lab)
    candidate = prepare_device(lab, "bound_device_authorization")
    for field in ("key_package", "welcome"):
        bad = copy.deepcopy(candidate); bad["join"][field] = mutate_bytes(bad["join"][field])
        submit_add(lab, bad, "b1", expected=(400, 403))
    for path, value in (("actor", identity("a1")), ("service_id", "other-service"),
                        ("conversation_id", "other-group"), ("from_state_ref", "0" * 64),
                        ("nonce", "0" * 64)):
        bad = copy.deepcopy(candidate); payload = statement(bad); payload[path] = value
        bad["change"]["statement_bytes"] = base64.b64encode(json.dumps(payload).encode()).decode()
        submit_add(lab, bad, "b1", expected=(400, 403, 409))
    check(records(lab)["records"] == [], "无效授权消耗了候选、KP 或推进了群权限")
    record = accept_add(lab, candidate, "b1")
    bundle = material(lab, "bound_device_authorization", "b2")
    for field in ("key_package", "welcome"):
        bad = copy.deepcopy(bundle); bad["join"][field] = mutate_bytes(bad["join"][field])
        reject_unchanged(lab, "b2", "permission_join", **bad)
    bad = copy.deepcopy(bundle)
    bad["record"]["receipt"]["signature_bytes"] = mutate_bytes(bad["record"]["receipt"]["signature_bytes"])
    reject_unchanged(lab, "b2", "permission_join", **bad)
    recover(lab, record, *ACCOUNTS)
    lab.rust("b2", "permission_join", **bundle)
    bad = copy.deepcopy(candidate); bad["join"]["welcome"] = mutate_bytes(bad["join"]["welcome"])
    check(submit_add(lab, bad, "b1", expected=409)["code"] == "idempotency_conflict", "接受后异材料覆盖原授权")
    receive_record(lab, "b2", publish(lab, "after_device_rejections"))


def same_device_competition(lab):
    setup(lab, "a3")
    loser = prepare_device(lab, "a3_loser", "a1", "a3")
    winner = prepare_device(lab, "a3_winner", "a2", "a3")
    record = accept_add(lab, winner, "a2")
    submit_add(lab, loser, "a1", expected=409)
    recover(lab, record, *ACCOUNTS)
    check(inspect(lab)["recovery_status"] == "ready", "同账号同设备的合法胜者未完成原意图")
    reject_unchanged(lab, "a3", "permission_join", record=record, join=loser["join"])
    join_device(lab, "a3_winner", "a3")
    receive_record(lab, "a1", publish(lab, "same_device_winner", "a3"))


def different_action_competition(lab):
    setup(lab)
    original = prepare_device(lab, "before_other_change")
    winner = accept(lab, prepare(lab, "remove_before_new_device")["change"])
    submit_add(lab, original, "b1", expected=409)
    recover(lab, winner, "a1", "a2", "b1")
    check(inspect(lab, "b1")["recovery_status"] == "needs_reprepare", "其他群变更吞掉设备授权意图")
    pause(lab, "b1")
    current = prepare_device(lab, "after_other_change")
    before, after = statement(original), statement(current)
    check(before["action"]["member"] == after["action"]["member"]
          and before["action"]["key_package_sha256"] == after["action"]["key_package_sha256"]
          and before["action"]["welcome_sha256"] != after["action"]["welcome_sha256"]
          and before["nonce"] != after["nonce"] and after["previous_authorization_version"] == "2",
          "重新批准未绑定新前驱或错误复用旧 Welcome")
    record = accept_add(lab, current, "b1")
    recover(lab, record, "a1", "a2", "b1")
    lab.rust("b2", "permission_join_advance", record=winner)
    reject_unchanged(lab, "b2", "permission_join", record=record, join=original["join"])
    join_device(lab, "after_other_change")
    receive_record(lab, "b1", publish(lab, "device_after_competition", "b2"))


def closed_device_candidate(lab):
    setup(lab)
    original = prepare_device(lab, "closed_device")
    closed = close(lab, lab.rust("b1", "permission_close_request"), "b1")
    recover(lab, closed, "b1")
    pause(lab, "b1")
    check(submit_add(lab, original, "b1", expected=409)["code"] == "permission_closed", "封口后设备授权被复活")
    reject_unchanged(lab, "b2", "permission_join", record=closed, join=original["join"])
    candidate = prepare_device(lab, "after_closed_device")
    record = accept_add(lab, candidate, "b1")
    recover(lab, record, *ACCOUNTS)
    join_device(lab, "after_closed_device")
    receive_record(lab, "b2", publish(lab, "device_after_close"))
