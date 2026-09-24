"""M05：不可信 HTTP 页替换后的逐字段校验、持久隔离与原件异槽恢复。

Relay 保存正常占位消息和合法原件；仅测试传输夹具替换第一页的信封。
不宣称 Relay 持久化了坏包，也不扩充公开协议或绕过签名回执模式。
"""

import base64
import copy
from functools import partial
import hashlib
import json

from .fixture import SERVICE, check
from .message_cases import changed_header, header


def digest(value):
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def envelope_digests(envelope):
    return {key: hashlib.sha256(base64.b64decode(value)).hexdigest()
            for key, value in envelope.items()}


def public_state(value):
    return {key: value[key] for key in ("crypto_state_ref", "epoch", "group_id", "active", "configuration")}


def assert_state(lab, expected, cursor, quarantined, inbox):
    value = lab.rust("b1", "wire_inspect")
    check(public_state(value) == expected, "拒绝或恢复改变了权限/群公共状态")
    check(value["inbox_count"] == inbox, "有效消息数量错误")
    sync = value["sync"]
    check(sync["download_cursor"] == str(cursor) and sync["processed_cursor"] == str(cursor),
          "重启后的下载/处理游标不一致")
    check(sync["quarantined_count"] == quarantined and sync["pending_count"] == 0
          and not sync["halted"] and sync["slot_count"] == cursor, "隔离/待处理槽位状态错误")
    return value


def altered(packet, field, value):
    if field == "raw_aad":
        result = copy.deepcopy(packet)
        result["envelope"]["header_bytes"] = base64.b64encode(
            json.dumps(header(packet), sort_keys=True, indent=1).encode()).decode()
        return result
    if field == "sender_account":
        value = {**header(packet)["sender"], "account_id": value}
        field = "sender"
    elif field == "sender_device":
        value = {**header(packet)["sender"], "device_id": value}
        field = "sender"
    elif field.startswith("recipients_"):
        targets = header(packet)["recipients"]
        value = {"recipients_remove": targets[:-1],
                 "recipients_add": targets + [{"account_id": "zulu", "device_id": "z1"}],
                 "recipients_duplicate": targets + [targets[-1]],
                 "recipients_sender": [header(packet)["sender"]] + targets}[field]
        field = "recipients"
    return changed_header(packet, **{field: value})


def recover_distinct_slot(lab, *, field, value, code, message, boundary):
    evidence = {"field": field, "boundary": boundary, "expected_code": code,
                "transport": "real HTTP pull then fixture replaces only slot1.event.envelope",
                "receipt_mode": "original M fixture without pinned acceptance signing key",
                "checks": []}
    lab.case_evidence = evidence
    # 首槽提供真实流位置；第二槽保留原件的真实接受记录，恢复后向它报告送达。
    placeholder = lab.prepare("m05_placeholder")
    placeholder_acceptance = lab.submit(placeholder)
    packet = lab.prepare("m05_original", payload="synthetic-M05-合法原件")
    accepted = lab.submit(packet)
    bad = altered(packet, field, value)
    good_header, bad_header = header(packet), header(bad)
    changed = sorted(key for key in good_header if good_header[key] != bad_header[key])
    expected_field = ("sender" if field.startswith("sender_") else
                      "recipients" if field.startswith("recipients_") else field)
    check(changed == ([] if field == "raw_aad" else [expected_field]), "夹具误改了额外字段")
    if field.startswith("sender_"):
        nested = [key for key in good_header["sender"]
                  if good_header["sender"][key] != bad_header["sender"][key]]
        check(nested == ["account_id" if field == "sender_account" else "device_id"],
              "发送账号与设备必须各自独立篡改")
        check(bad_header["sender"] not in bad_header["recipients"], "发送身份测试被无关目标校验截断")
    check(packet["envelope"]["payload_bytes"] == bad["envelope"]["payload_bytes"], "篡改了原密文")
    check(packet["envelope"]["header_bytes"] != bad["envelope"]["header_bytes"], "未改变原始头")
    evidence.update(changed_header_fields=changed, good_input=envelope_digests(packet["envelope"]),
                    bad_input=envelope_digests(bad["envelope"]),
                    same_logical_message_id=good_header["logical_message_id"] == bad_header["logical_message_id"])

    before = lab.rust("b1", "wire_inspect")
    expected = public_state(before)
    snapshot = (lab.directory / "b1/state.enc").read_bytes()
    rejected = lab.receive("b1", bad, expected_exit=1)
    check(rejected["code"] == code and rejected["message"] == message,
          f"未触达预期 {boundary}: {rejected}")
    check((lab.directory / "b1/state.enc").read_bytes() == snapshot, "直接拒绝改变了已保存快照")
    evidence["direct_error"] = rejected
    evidence["checks"].append("direct_exact_error_and_unchanged_snapshot")

    original_page = lab.pull("b1", "0", "1")
    bad_page = copy.deepcopy(original_page)
    bad_slot = bad_page["events"][0]
    check(bad_slot["event_seq"] == "1" and original_page["watermark"] == "2", "初始流位置不符")
    check(bad_slot["event"]["acceptance_id"] == placeholder_acceptance["acceptance_id"], "占位接受不符")
    bad_slot["event"]["envelope"] = bad["envelope"]
    evidence.update(original_page_sha256=digest(original_page), bad_page_sha256=digest(bad_page),
                    bad_event_id=bad_slot["event_id"], bad_acceptance_id=bad_slot["event"]["acceptance_id"])
    # 用实验 Service 钥显式签署坏消息页，保留消息内部身份/AAD 校验的测试路径。
    bad_page = lab.sign_test_page(bad_page)
    lab.download("b1", bad_page)
    lab.download("b1", bad_page)
    downloaded = lab.rust("b1", "wire_inspect")
    check(downloaded["sync"]["download_cursor"] == "1"
          and downloaded["sync"]["processed_cursor"] == "0" and downloaded["inbox_count"] == 0,
          "下载即错误地产生有效消息或推进处理游标")
    processed = lab.rust("b1", "wire_process")
    check(processed["results"] == [{"event_seq": "1", "event_id": bad_slot["event_id"],
                                     "result": {"status": "quarantined", "code": code}}],
          "坏槽未按预期错误持久隔离")
    check(processed["deliveries"] == [], "坏槽产生了送达确认")
    after_bad = assert_state(lab, expected, 1, 1, 0)
    repeated = lab.rust("b1", "wire_process")
    check(repeated["results"] == [] and repeated["deliveries"] == [], "重启后重复处理坏槽或伪造送达")
    check(lab.control("stats")["receipts"] == "0", "Relay 已保存错误回执")
    evidence.update(after_bad=after_bad, bad_processing=processed)
    evidence["checks"].append("bad_slot_persisted_restart_no_inbox_no_delivery")

    lab.restart()
    good_page = lab.pull("b1", "1", "1")
    good_slot = good_page["events"][0]
    check(good_slot["event_seq"] == "2" and good_slot["event_id"] != bad_slot["event_id"], "不是独立好槽")
    check(good_slot["event"]["envelope"] == packet["envelope"]
          and good_slot["event"]["acceptance_id"] == accepted["acceptance_id"], "Relay 重启改变了合法原件")
    lab.download("b1", good_page)
    recovered = lab.rust("b1", "wire_process")
    results = recovered["results"]
    check(len(results) == 1 and results[0]["event_seq"] == "2", "重复处理隔离槽或遗漏合法原件")
    message_result = results[0]["result"]
    check(message_result["status"] == "valid" and message_result["message"]["duplicate"] is False
          and message_result["message"]["logical_message_id"] == "m05_original"
          and message_result["message"]["payload_sha256"] == hashlib.sha256("synthetic-M05-合法原件".encode()).hexdigest(),
          "合法原件未成功解密一次")
    expected_delivery = {"acceptance_id": accepted["acceptance_id"], "attempt_id": "P1", "event_id": good_slot["event_id"]}
    check(recovered["deliveries"] == [expected_delivery], "送达包含坏槽或错绑合法消息")
    after_good = assert_state(lab, expected, 2, 1, 1)
    lab.download("b1", good_page)
    again = lab.rust("b1", "wire_process")
    check(again["results"] == [] and again["deliveries"] == [expected_delivery], "重复页造成二次业务结果")
    check(lab.receive("b1", packet)["duplicate"] is True, "原件重放未被去重")
    assert_state(lab, expected, 2, 1, 1)
    first_receipt = lab.http("b1", "report_delivery", {"service_id": SERVICE, **expected_delivery})
    second_receipt = lab.http("b1", "report_delivery", {"service_id": SERVICE, **expected_delivery})
    check(first_receipt == second_receipt and first_receipt["read"] is False, "送达重报不幂等或自动已读")
    stats = lab.control("stats")
    check(stats["receipts"] == "1", "坏消息产生回执或好消息重复确认")
    evidence.update(good_page_sha256=digest(good_page), good_event_id=good_slot["event_id"],
                    good_acceptance_id=accepted["acceptance_id"], after_good=after_good,
                    good_processing=recovered, final_receipt=first_receipt, relay_receipt_count=stats["receipts"])
    evidence["checks"].extend(["original_distinct_slot_after_relay_restart", "one_message_after_cli_restart_and_replay",
                               "only_good_slot_http_receipt_idempotent"])


FIELDS = [
    ("service", "service_id", "another-service", "identity_mismatch", "实例或会话上下文不匹配", "service_context"),
    ("conversation", "conversation_id", "G2", "identity_mismatch", "实例或会话上下文不匹配", "conversation_context"),
    ("account", "sender_account", "unknown-account", "identity_mismatch", "发送者不属于消息对应的已验证群", "verified_sender_membership"),
    ("device", "sender_device", "unknown-device", "identity_mismatch", "发送者不属于消息对应的已验证群", "verified_sender_membership"),
    ("mode", "security_mode", "server_readable", "unsupported_mode", "本实验只支持 MLS E2EE", "header_mode"),
    ("version", "protocol_version", "rim-poc-2", "unsupported_version", "协议版本不支持", "header_version"),
    ("profile", "crypto_profile", "unknown-profile", "unsupported_crypto_profile", "不支持此密码实验配置", "header_crypto_profile"),
    ("target_remove", "recipients_remove", None, "recipient_set_mismatch", "目标集合与消息epoch的真实成员不符", "epoch_recipient_set"),
    ("target_add", "recipients_add", None, "recipient_set_mismatch", "目标集合与消息epoch的真实成员不符", "epoch_recipient_set"),
    ("target_duplicate", "recipients_duplicate", None, "invalid_envelope", "目标必须排序、唯一且不含发送设备", "header_recipient_unique"),
    ("target_sender", "recipients_sender", None, "invalid_envelope", "目标必须排序、唯一且不含发送设备", "header_recipient_sender_exclusion"),
    ("authorization", "authorization_version", "99", "state_context_mismatch", "消息epoch与头中权限/密码引用不符", "epoch_authorization"),
    ("crypto_state", "crypto_state_ref", "0" * 64, "state_context_mismatch", "消息epoch与头中权限/密码引用不符", "epoch_crypto_state"),
    ("aad", "raw_aad", None, "identity_mismatch", "完整原始头与密码认证AAD不同", "authenticated_raw_aad"),
]

CASES = [("M05." + ident, "逐字段异槽恢复：" + field,
          partial(recover_distinct_slot, field=field, value=value, code=code, message=message, boundary=boundary))
         for ident, field, value, code, message, boundary in FIELDS]
