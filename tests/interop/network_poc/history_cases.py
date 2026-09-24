"""权限变化后的历史接收；只用普通 MLS 接收 API，不恢复旧发送快照。"""

import base64
import copy
import hashlib
import json

from .fixture import SERVICE, check
from .message_cases import changed_header, header
from .permission_cases import REMOVE_CHARLIE, REVOKE_A2, prepare, reject_unchanged, version
from .permission_recovery_cases import accept, communicate, recover


def publish(lab, name, device="a1"):
    packet = lab.rust(device, "wire_send", logical_message_id=name, attempt_id="P1",
                      payload="synthetic-history-" + name)
    return packet, lab.submit(packet, device=device)


def receive_record(lab, device, record, **options):
    packet, accepted = record
    return lab.rust(device, "wire_receive", **packet["envelope"],
                    acceptance_id=accepted["acceptance_id"],
                    acceptance_receipt=accepted["acceptance_receipt"], **options)


def signed_for_packet(lab, packet, accepted, **changes):
    """合成 Service 为异常证据签名，只用于区分服务承诺与实际 MLS 校验。"""
    statement = json.loads(base64.b64decode(accepted["acceptance_receipt"]["statement_bytes"]))
    digest = hashlib.sha256(b"Rockets-IM/POC/message-envelope/v1\0")
    for field in ("header_bytes", "payload_bytes"):
        raw = base64.b64decode(packet["envelope"][field])
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    statement.update(envelope_sha256=digest.hexdigest(), **changes)
    return lab.relay_key("sign", expected_signature_key=lab.relay_receipt_key, statement=statement)["receipt"]


def advance(lab, name, action=REMOVE_CHARLIE, devices=("a1", "a2", "b1")):
    change = prepare(lab, name, action)["change"]
    accepted = accept(lab, change)
    recover(lab, accepted, *devices)
    return accepted


def checkpoint(lab, device="b1"):
    state = lab.rust(device, "wire_inspect")
    return {k: state[k] for k in ("epoch", "crypto_state_ref", "configuration")}


def assert_valid(result, count):
    check(len(result["results"]) == count and all(item["result"]["status"] == "valid"
          for item in result["results"]), "合法旧消息仍在等待或被隔离: " + json.dumps(result, ensure_ascii=False))


def offline_after_change(lab):
    packet, accepted = publish(lab, "offline_before_removal")
    advance(lab, "remove_before_receive")
    lab.restart()
    before = checkpoint(lab)
    page = lab.pull("b1")
    check(page["events"][0]["event"]["envelope"] == packet["envelope"], "R0 改写了旧信封")
    lab.download("b1", page)
    processed = lab.rust("b1", "wire_process")
    assert_valid(processed, 1)
    check(processed["results"][0]["result"]["message"]["payload_sha256"] ==
          hashlib.sha256(b"synthetic-history-offline_before_removal").hexdigest(), "历史消息解密摘要不同")
    check(checkpoint(lab) == before, "历史接收回退了当前发送检查点")
    lab.download("b1", page)
    repeated = lab.rust("b1", "wire_process")
    check(repeated["results"] == [] and repeated["deliveries"] == processed["deliveries"],
          "重复下载制造了第二次展示或丢失可重报的回执")
    for delivery in repeated["deliveries"]:
        lab.http("b1", "report_delivery", {"service_id": SERVICE, **delivery})
        lab.http("b1", "report_delivery", {"service_id": SERVICE, **delivery})
    check(lab.control("stats")["receipts"] == "1", "旧消息重复送达报告未去重")
    check(lab.attempt("offline_before_removal")["acceptance_id"] == accepted["acceptance_id"],
          "旧消息接受记录在权限变化后被替换")
    communicate(lab, "current_after_old_receive", sender="b1", receiver="a1")


def queued_atomic_receive(lab):
    publish(lab, "queued_old")
    lab.download("b1", lab.pull("b1"))
    advance(lab, "advance_with_local_queue")
    before = (lab.directory / "b1/state.enc").read_bytes()
    for point, code in (("before_save", 83), ("before_rename", 84)):
        lab.rust("b1", "wire_process", failpoint=point, expected_exit=code)
        check((lab.directory / "b1/state.enc").read_bytes() == before, "历史接收未提交却消耗了去重或密码状态")
    lab.rust("b1", "wire_process", failpoint="after_save", expected_exit=85)
    result = lab.rust("b1", "wire_process")
    state = lab.rust("b1", "wire_inspect")
    check(state["inbox_count"] == 1 and state["sync"]["processed_cursor"] == "1"
          and len(result["deliveries"]) == 1 and result["results"] == [], "重启后没有共同恢复旧消息、去重与游标")
    check(version(lab, "b1") == "2", "历史提交改变了当前权限版本")
    communicate(lab, "current_after_history_crash", sender="b1", receiver="a1")


def two_epochs_out_of_order(lab):
    oldest = [publish(lab, "oldest_" + str(i)) for i in range(2)]
    advance(lab, "first_history_step")
    middle = publish(lab, "middle_epoch")
    advance(lab, "second_history_step", REVOKE_A2, devices=("a1", "b1"))
    current = publish(lab, "current_epoch")
    before = checkpoint(lab)
    for record in (current, middle, oldest[1], oldest[0]):
        check(not receive_record(lab, "b1", record)["duplicate"], "不同历史消息错误去重")
    check(receive_record(lab, "b1", oldest[0])["duplicate"], "跨 epoch 重复没有复用成功记录")
    check(checkpoint(lab) == before, "乱序接收回退了当前 epoch")
    lab.download("b1", lab.pull("b1"))
    result = lab.rust("b1", "wire_process")
    assert_valid(result, 4)
    check(all(item["result"]["message"]["duplicate"] for item in result["results"]), "流补拉重复展示了已接收历史")
    check(lab.rust("b1", "wire_inspect")["inbox_count"] == 4, "历史去重条目数不符")
    communicate(lab, "after_history_reordering", sender="b1", receiver="a1")


def removed_sender(lab):
    packet, accepted = publish(lab, "before_sender_removed", "c1")
    advance(lab, "remove_historical_sender")
    page = lab.pull("b1")
    event = page["events"][0]["event"]
    check(event["envelope"] == packet["envelope"] and event["acceptance_receipt"] == accepted["acceptance_receipt"],
          "正常 Relay 不应把已接受原记录改成别的证据")
    lab.download("b1", page)
    processed = lab.rust("b1", "wire_process")
    check(processed["results"][0]["result"]["status"] == "quarantined"
          and processed["results"][0]["result"]["code"] == "history_sender_revoked"
          and processed["deliveries"] == [], "Service 接受签名错误地授予已移除发送者历史权限")
    check(lab.rust("b1", "wire_inspect")["sync"]["pending_count"] == 0, "已知不能接受的旧身份消息永久等待")
    check(lab.rust("b1", "wire_inspect")["inbox_count"] == 0, "未授权历史抢占了成功去重")
    communicate(lab, "after_history_sender_rejection")


def receipt_binding(lab):
    first, second = publish(lab, "receipt_first"), publish(lab, "receipt_second")
    unbound = publish(lab, "received_without_acceptance_id")
    lab.receive("b1", unbound[0])
    reject_unchanged(lab, "b1", "wire_receive", **unbound[0]["envelope"],
                     acceptance_id="unsigned_id_must_not_bind")
    check(receive_record(lab, "b1", unbound)["duplicate"], "无签名重放抢绑接受ID，阻止了真实接受证明")
    # 提供签名时，即使仍是当前 epoch 也须核对，不能等历史分支才检查。
    packet, accepted = first
    reject_unchanged(lab, "b1", "wire_receive", **packet["envelope"],
                     acceptance_id=second[1]["acceptance_id"], acceptance_receipt=accepted["acceptance_receipt"])
    advance(lab, "advance_before_receipt_checks")
    check(receive_record(lab, "b1", unbound)["duplicate"], "已绑定成功记录在R1后不能重报")
    for receipt in (None, second[1]["acceptance_receipt"]):
        fields = {"acceptance_id": accepted["acceptance_id"]}
        if receipt is not None:
            fields["acceptance_receipt"] = receipt
        reject_unchanged(lab, "b1", "wire_receive", **packet["envelope"], **fields)
    bad_receipt = copy.deepcopy(accepted["acceptance_receipt"])
    raw = bytearray(base64.b64decode(bad_receipt["signature_bytes"]))
    raw[0] ^= 1
    bad_receipt["signature_bytes"] = base64.b64encode(raw).decode()
    reject_unchanged(lab, "b1", "wire_receive", **packet["envelope"],
                     acceptance_id=accepted["acceptance_id"], acceptance_receipt=bad_receipt)
    check(not receive_record(lab, "b1", first)["duplicate"], "错误接受证据提前消费了合法消息")
    reject_unchanged(lab, "b1", "wire_receive", **packet["envelope"],
                     acceptance_id=second[1]["acceptance_id"], acceptance_receipt=accepted["acceptance_receipt"])
    check(receive_record(lab, "b1", first)["duplicate"], "证据拒绝破坏了已成功记录")
    receive_record(lab, "b1", second)
    communicate(lab, "after_history_receipt_checks")


def unknown_and_wrong_state(lab):
    record = publish(lab, "original_history_binding")
    advance(lab, "change_for_history_binding")
    packet, accepted = record
    variants = [dict(service_id="another_service"), dict(conversation_id="another_group"),
                dict(authorization_version="2"), dict(crypto_state_ref="0" * 64),
                dict(recipients=[{"account_id": "bob", "device_id": "b1"}])]
    for fields in variants:
        bad = changed_header(packet, **fields)
        reject_unchanged(lab, "b1", "wire_receive", **bad["envelope"],
                         acceptance_id=accepted["acceptance_id"], acceptance_receipt=accepted["acceptance_receipt"])
    for fields in (dict(authorization_version="2"), dict(crypto_state_ref="0" * 64)):
        bad = changed_header(packet, **fields)
        proof = signed_for_packet(lab, bad, accepted, **fields)
        error = reject_unchanged(lab, "b1", "wire_receive", **bad["envelope"],
                                 acceptance_id=accepted["acceptance_id"], acceptance_receipt=proof)
        check(error["code"] == "history_context_mismatch", "Service 签名替代了本机实际已验证的历史检查点")
    receive_record(lab, "b1", record)
    check(header(packet)["authorization_version"] == "1" and version(lab, "b1") == "2",
          "历史头或当前配置被就地修改")
    communicate(lab, "after_history_binding_checks")
