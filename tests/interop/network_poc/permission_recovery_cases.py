"""固定服务公钥下的权限终态恢复；候选结束不等于撤销意图完成。"""

import base64
import copy
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
import time

from .fixture import CONVERSATION, SERVICE, check
from .permission_cases import REMOVE_CHARLIE, REVOKE_A2, prepare, reject_unchanged, submit, version


def inspect(lab, device="a1"):
    return lab.rust(device, "permission_inspect")


def pause(lab, device="a1"):
    return reject_unchanged(lab, device, "wire_send", logical_message_id="recovery_paused",
                            attempt_id="P1", payload="synthetic-not-yet-complete")


def accept(lab, change, device="a1"):
    result = submit(lab, change, device)
    check("receipt" in result, "恢复模式的接受必须带持久签名回执")
    return {"change": change, "receipt": result["receipt"]}


def close(lab, request, device="a1", expected=200):
    return lab.http(device, "close_permission_change", {"service_id": SERVICE,
                    "conversation_id": CONVERSATION, **request}, expected=expected)


def recover(lab, record, *devices, **options):
    for device in devices:
        lab.rust(device, "permission_recover", record=record, **options)


def records(lab, device="b1", after="1", limit="32"):
    return lab.http(device, "get_permission_records", {"service_id": SERVICE,
                    "conversation_id": CONVERSATION, "after_version": after, "limit": limit})


def receipt_statement(record):
    return json.loads(base64.b64decode(record["receipt"]["statement_bytes"]))


def communicate(lab, logical, sender="a1", receiver="b1"):
    packet = lab.rust(sender, "wire_send", logical_message_id=logical, attempt_id="P1",
                      payload="synthetic-recovery-" + logical)
    lab.submit(packet, device=sender)
    lab.receive(receiver, packet)


def same_intent(lab):
    loser = prepare(lab, "same_loser")["change"]
    winner = prepare(lab, "same_winner", device="a2")["change"]
    accepted = accept(lab, winner, "a2")
    submit(lab, loser, expected=409)
    check(inspect(lab)["pending_change"] == loser, "HTTP 冲突不能直接丢弃本地候选")
    pause(lab)
    recover(lab, accepted, "a2", "a1", "b1")
    check(inspect(lab)["recovery_status"] == "ready", "相同意图的真实胜者没有完成恢复")
    check(inspect(lab)["needs_reprepare"] is None and version(lab, "a1") == "2",
          "恢复状态与已验证权限版本不一致")
    communicate(lab, "same_intent_done")
    reject_unchanged(lab, "a1", "permission_prepare", change_id="same_loser", action=REMOVE_CHARLIE)
    reject_unchanged(lab, "a1", "permission_apply", change=loser)


def different_intent(lab):
    original = prepare(lab, "original_revoke", REVOKE_A2)["change"]
    winner = prepare(lab, "other_remove", device="a2")["change"]
    accepted = accept(lab, winner, "a2")
    recover(lab, accepted, "a2", "a1", "b1")
    state = inspect(lab)
    check(state["recovery_status"] == "needs_reprepare" and state["needs_reprepare"]["action"] == REVOKE_A2,
          "采用其他胜者时丢失了尚未完成的设备撤销")
    pause(lab)
    reject_unchanged(lab, "a1", "permission_prepare", change_id="wrong_intent", action=REMOVE_CHARLIE)
    second = prepare(lab, "reprepared_revoke", REVOKE_A2)["change"]
    old_statement = json.loads(base64.b64decode(original["statement_bytes"]))
    new_statement = json.loads(base64.b64decode(second["statement_bytes"]))
    check(new_statement["nonce"] != old_statement["nonce"] and new_statement["previous_authorization_version"] == "2",
          "重准备必须使用新挑战和已验证后继状态")
    pause(lab)
    applied = accept(lab, second)
    recover(lab, applied, "a1", "b1")
    check(inspect(lab)["recovery_status"] == "ready", "原意图完成后未恢复")
    lab.pull("a2", expected=403)
    communicate(lab, "different_intent_done")
    chain = records(lab, limit="1")
    check(chain["records"] == [accepted] and chain["next_after_version"] == "2" and chain["has_more"],
          "接受证明分页必须携带匹配的原回执")
    check(records(lab, after="2")["records"] == [applied], "权限接受回执没有连续持久化")


def expiry_close(lab):
    original = prepare(lab, "expiring_candidate", validity_secs=1)["change"]
    expiry = int(json.loads(base64.b64decode(original["statement_bytes"]))["expires_at_unix_secs"])
    time.sleep(max(0, expiry - time.time()) + 0.03)
    check(submit(lab, original, expected=403)["code"] == "permission_expired", "真实时钟到期后首次接受未拒绝")
    check(inspect(lab)["pending_change"] == original, "过期错误不能单独结束候选")
    pause(lab)
    request = lab.rust("a1", "permission_close_request")
    check(lab.rust("a1", "permission_close_request") == request, "封口请求重试必须复用原字节")
    closed = close(lab, request)
    check(receipt_statement(closed)["outcome"] == "closed", "未接受的旧候选没有永久封口")
    recover(lab, closed, "a1")
    check(inspect(lab)["recovery_status"] == "needs_reprepare", "封口不应被当作撤销已完成")
    pause(lab)
    check(submit(lab, original, expected=409)["code"] == "permission_closed", "封口后迟到原请求复活")
    second = prepare(lab, "after_expiry")["change"]
    accepted = accept(lab, second)
    recover(lab, accepted, "a1", "b1")
    communicate(lab, "expired_intent_done")
    check(close(lab, request) == closed, "重启 CLI 后封口回执不稳定")


def accepted_close(lab):
    change = prepare(lab, "lost_acceptance")["change"]
    lab.control("hook", hook="drop_after_commit")
    try:
        submit(lab, change)
        raise AssertionError("已设置丢响应但仍返回成功")
    except (http.client.RemoteDisconnected, ConnectionResetError):
        pass
    pause(lab)
    request = lab.rust("a1", "permission_close_request")
    accepted = close(lab, request)
    check(receipt_statement(accepted)["outcome"] == "accepted", "封口不能撤销已经接受的权限变更")
    lab.restart()
    check(close(lab, request) == accepted, "重启后没有返回同一接受回执")
    check(submit(lab, change)["receipt"] == accepted["receipt"], "提交重试与封口查询结果矛盾")
    recover(lab, accepted, "a1", "b1")
    communicate(lab, "accepted_after_lost_reply")


def tampered_receipts(lab):
    original = prepare(lab, "original_close")["change"]
    request = lab.rust("a1", "permission_close_request")
    bad_close = copy.deepcopy(request)
    raw = bytearray(base64.b64decode(bad_close["close"]["signature_bytes"]))
    raw[0] ^= 1
    bad_close["close"]["signature_bytes"] = base64.b64encode(raw).decode()
    close(lab, bad_close, expected=403)
    closed = close(lab, request)
    for field in ("signature_bytes", "statement_bytes"):
        bad = copy.deepcopy(closed)
        raw = bytearray(base64.b64decode(bad["receipt"][field]))
        raw[-1] ^= 1
        bad["receipt"][field] = base64.b64encode(raw).decode()
        reject_unchanged(lab, "a1", "permission_recover", record=bad)
    other_key = lab.directory / "other-relay.key"
    other_public = lab.relay_key("init", key_path=str(other_key))["signature_key"]
    wrong = lab.relay_key("sign", key_path=str(other_key), expected_signature_key=other_public,
                          statement=receipt_statement(closed))["receipt"]
    reject_unchanged(lab, "a1", "permission_recover", record={"change": original, "receipt": wrong})
    for field, value in (("service_id", "other-service"), ("proof_sha256", "0" * 64)):
        statement = receipt_statement(closed)
        statement[field] = value
        signed = lab.relay_key("sign", expected_signature_key=lab.relay_receipt_key, statement=statement)["receipt"]
        reject_unchanged(lab, "a1", "permission_recover", record={"change": original, "receipt": signed})
    recover(lab, closed, "a1")
    second = prepare(lab, "new_after_closed")["change"]
    recover(lab, closed, "a1")
    check(inspect(lab)["pending_change"] == second, "旧封口回执覆盖了新的候选")
    pause(lab)
    forged_statement = receipt_statement(closed)
    proof_statement = json.loads(base64.b64decode(original["statement_bytes"]))
    forged_statement.update(outcome="accepted", authorization_version=proof_statement["authorization_version"],
                            crypto_state_ref=proof_statement["to_state_ref"])
    contradiction = lab.relay_key("sign", expected_signature_key=lab.relay_receipt_key,
                                  statement=forged_statement)["receipt"]
    reject_unchanged(lab, "a1", "permission_recover", record={"change": original, "receipt": contradiction})
    valid = accept(lab, second)
    recover(lab, valid, "a1", "b1")
    communicate(lab, "after_invalid_receipts")


def submit_close_race(lab):
    change = prepare(lab, "racing_candidate")["change"]
    request = lab.rust("a1", "permission_close_request")
    with ThreadPoolExecutor(max_workers=2) as pool:
        sending = pool.submit(submit, lab, change, "a1", (200, 409))
        closing = pool.submit(close, lab, request)
        submission, resolution = sending.result(timeout=15), closing.result(timeout=15)
    outcome = receipt_statement(resolution)["outcome"]
    check(outcome in ("accepted", "closed"), "竞争结果不是持久终态")
    if outcome == "accepted":
        check(submission["outcome"] == "accepted" and submission["receipt"] == resolution["receipt"],
              "接受胜出时两条路径必须返回同一回执")
        recover(lab, resolution, "a1", "b1")
    else:
        check(submission["code"] == "permission_closed", "封口胜出后提交不能接受")
        recover(lab, resolution, "a1")
        pause(lab)
        replacement = prepare(lab, "race_replacement")["change"]
        accepted = accept(lab, replacement)
        recover(lab, accepted, "a1", "b1")
    check(close(lab, request) == resolution, "并发裁决结果在重试时变化")
    communicate(lab, "after_submit_close_race")
