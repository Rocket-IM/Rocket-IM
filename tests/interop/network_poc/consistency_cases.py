"""Q02：独立公开证据、当前视图与实际 MLS 状态的本机对照。"""

import base64
import copy
import hashlib
import json

from .fixture import CONVERSATION, SERVICE, check, identity
from .permission_cases import prepare, reject_unchanged
from .permission_recovery_cases import accept, recover


def inspect(lab, device="b1"):
    return lab.rust(device, "consistency_inspect")


def begin(lab, device="b1"):
    return lab.rust(device, "consistency_challenge")


def current_head(lab, device="b1"):
    challenge = begin(lab, device)
    return lab.http(device, "get_consistency_head", challenge)["head"]


def sign_head(lab, checkpoint, device="b1", challenge=None, **changes):
    statement = {"protocol_version": "rim-consistency-head-1", "service_id": SERVICE,
                 "conversation_id": CONVERSATION, "actor": identity(device),
                 "challenge": challenge or begin(lab, device)["challenge"],
                 "checkpoint": checkpoint, **changes}
    return lab.relay_key("sign", expected_signature_key=lab.relay_receipt_key,
                         statement=statement)["receipt"]


def observe(lab, head, device="b1", **options):
    return lab.rust(device, "consistency_observe_head", head=head, **options)


def assert_status(lab, status, device="b1"):
    result = inspect(lab, device)
    check(result["status"] == status, f"一致性状态应为 {status}: {result}")
    check(result["freshness"] == "unknown", "当前视图不能证明全局最新或持续隔离分叉不存在")
    return result


def blocked(lab, device="b1", **fields):
    error = reject_unchanged(lab, device, "wire_send", logical_message_id="q02_paused",
                             attempt_id="P1", payload="synthetic-must-not-encrypt", **fields)
    check(error["code"] == "consistency_paused", "新密文必须由一致性暂停明确拒绝")


def send(lab, device="b1", logical="q02_ready"):
    return lab.rust(device, "wire_send", logical_message_id=logical, attempt_id="P1",
                    payload="synthetic-consistency-" + logical)


def mutate_bytes(encoded):
    raw = bytearray(base64.b64decode(encoded))
    raw[-1] ^= 1
    return base64.b64encode(raw).decode()


def accepted_witness(lab, proof):
    """控制器模拟 Service 双签；只处理公开证明，不读取任何设备私钥。"""
    statement = json.loads(base64.b64decode(proof["statement_bytes"]))
    digest = hashlib.sha256(b"Rocket-IM/POC/permission-proof/v1\0")
    for field in ("statement_bytes", "signature_bytes", "commit_bytes"):
        raw = base64.b64decode(proof[field])
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    receipt = {"protocol_version": "rim-permission-receipt-1", "service_id": SERVICE,
               "conversation_id": CONVERSATION, "actor": statement["actor"],
               "change_id": statement["change_id"], "proof_sha256": digest.hexdigest(),
               "outcome": "accepted", "authorization_version": statement["authorization_version"],
               "crypto_state_ref": statement["to_state_ref"]}
    signed = lab.relay_key("sign", expected_signature_key=lab.relay_receipt_key,
                           statement=receipt)["receipt"]
    return {"change": proof, "receipt": signed}


def fork_fixture(lab):
    left = prepare(lab, "q02_left")["change"]
    right = prepare(lab, "q02_right", device="a2")["change"]
    left_record, right_record = accept(lab, left), accepted_witness(lab, right)
    recover(lab, left_record, "a1", "b1")
    recover(lab, right_record, "a2")
    left_cp = lab.rust("a1", "permission_inspect")["checkpoint"]
    right_cp = lab.rust("a2", "permission_inspect")["checkpoint"]
    check(left_cp["authorization_version"] == right_cp["authorization_version"] == "2"
          and left_cp["crypto_state_ref"] != right_cp["crypto_state_ref"],
          "两份独立签名的合法候选必须实际建立不同的 MLS 后继")
    # 独立设备已完成另一支 R1；控制器通过带外公开文件交付证据。
    witness_path = lab.directory / "independent-public-witness.json"
    witness_path.write_text(json.dumps(right_record))
    return left_record, json.loads(witness_path.read_text()), left_cp, right_cp


def normal_and_binding(lab):
    assert_status(lab, "no_known_conflict")
    challenge = begin(lab)
    check(begin(lab) == challenge, "检查中重启 CLI 必须复用未消费挑战")
    blocked(lab)
    head = current_head(lab)
    bad = copy.deepcopy(head)
    bad["signature_bytes"] = mutate_bytes(bad["signature_bytes"])
    reject_unchanged(lab, "b1", "consistency_observe_head", head=bad)
    for changes in ({"actor": identity("a1")}, {"challenge": "0" * 64}):
        reject_unchanged(lab, "b1", "consistency_observe_head",
                         head=sign_head(lab, lab.checkpoint, **changes))
    other_key = lab.directory / "q02-other-service.key"
    other_public = lab.relay_key("init", key_path=str(other_key))["signature_key"]
    wrong = lab.relay_key("sign", key_path=str(other_key), expected_signature_key=other_public,
                         statement=json.loads(base64.b64decode(head["statement_bytes"])))["receipt"]
    reject_unchanged(lab, "b1", "consistency_observe_head", head=wrong)
    blocked(lab)
    observe(lab, head)
    assert_status(lab, "no_known_conflict")
    observe(lab, head)  # 已消费证据精确重试不能重新开闸或重复写入证据。
    send(lab)
    next_challenge = begin(lab)
    check(next_challenge["challenge"] != challenge["challenge"], "已消费挑战被再次使用")
    replay = observe(lab, head)
    check(replay["duplicate"] and inspect(lab)["checking"],
          "已消费 head 精确重试解除或消费了后来开始的检查")
    blocked(lab)
    observe(lab, current_head(lab))
    assert_status(lab, "no_known_conflict")


def rollback_and_resume(lab):
    record = accept(lab, prepare(lab, "rollback_r1")["change"])
    recover(lab, record, "a1", "b1")
    before = lab.rust("b1", "wire_inspect")
    old = sign_head(lab, lab.checkpoint)
    observe(lab, old)
    assert_status(lab, "rollback_detected")
    check(lab.rust("b1", "wire_inspect") == before, "旧 head 改写了实际密码状态")
    blocked(lab)
    lab.restart()
    blocked(lab)
    observe(lab, old)
    blocked(lab)
    observe(lab, current_head(lab))
    assert_status(lab, "rollback_detected")
    blocked(lab)
    lab.rust("b1", "consistency_resume", head=current_head(lab))
    assert_status(lab, "no_known_conflict")
    packet = send(lab, logical="rollback_resumed")
    lab.submit(packet, device="b1")
    lab.receive("a1", packet)


def head_floor_and_sync(lab):
    record = accept(lab, prepare(lab, "ahead_r1")["change"])
    recover(lab, record, "a1")
    actual = lab.rust("b1", "permission_inspect")["checkpoint"]
    observe(lab, current_head(lab))
    assert_status(lab, "needs_sync")
    check(lab.rust("b1", "permission_inspect")["checkpoint"] == actual,
          "签名 head 冒充实际验证的 MLS 权限检查点")
    blocked(lab)
    observe(lab, sign_head(lab, lab.checkpoint))
    assert_status(lab, "rollback_detected")
    blocked(lab)
    # 即使退回本机旧版本，也不能把曾观察到的更高水位抹掉。
    head = current_head(lab)
    lab.rust("b1", "consistency_resume", head=head)
    blocked(lab)
    recover(lab, record, "b1")
    blocked(lab)
    lab.rust("b1", "consistency_resume", head=current_head(lab))
    assert_status(lab, "no_known_conflict")
    send(lab)


def independent_fork(lab):
    left, right, _, right_cp = fork_fixture(lab)
    # 只有各自自洽的分支时没有独立对照；不得谎报已排除分叉。
    observe(lab, current_head(lab))
    observe(lab, sign_head(lab, right_cp, "a2"), "a2")
    assert_status(lab, "no_known_conflict")
    assert_status(lab, "no_known_conflict", "a2")
    send(lab)
    send(lab, "a2")
    begin(lab)
    lab.rust("b1", "consistency_observe_fork", predecessor=lab.checkpoint, left=left, right=right)
    assert_status(lab, "fork_detected")
    blocked(lab)
    lab.restart()
    blocked(lab)
    # 同支真实记录重试和新的正确 head 均不能解除已证实分叉。
    recover(lab, left, "b1")
    lab.rust("b1", "consistency_resume", head=current_head(lab))
    assert_status(lab, "fork_detected")
    blocked(lab)


def invalid_fork_evidence(lab):
    left, right, _, _ = fork_fixture(lab)
    reject_unchanged(lab, "b1", "consistency_observe_fork",
                     predecessor=lab.checkpoint, left=left, right=right)
    begin(lab)
    for field in ("signature_bytes", "commit_bytes"):
        bad = copy.deepcopy(right)
        bad["change"][field] = mutate_bytes(bad["change"][field])
        reject_unchanged(lab, "b1", "consistency_observe_fork",
                         predecessor=lab.checkpoint, left=left, right=bad)
    bad = copy.deepcopy(right)
    bad["receipt"]["signature_bytes"] = mutate_bytes(bad["receipt"]["signature_bytes"])
    reject_unchanged(lab, "b1", "consistency_observe_fork",
                     predecessor=lab.checkpoint, left=left, right=bad)
    unknown = copy.deepcopy(lab.checkpoint)
    unknown["crypto_state_ref"] = "0" * 64
    reject_unchanged(lab, "b1", "consistency_observe_fork", predecessor=unknown, left=left, right=right)
    reject_unchanged(lab, "b1", "consistency_observe_fork",
                     predecessor=lab.checkpoint, left=left, right=left)
    closed = copy.deepcopy(right)
    statement = json.loads(base64.b64decode(closed["receipt"]["statement_bytes"]))
    statement["outcome"] = "closed"
    closed["receipt"] = lab.relay_key("sign", expected_signature_key=lab.relay_receipt_key,
                                     statement=statement)["receipt"]
    reject_unchanged(lab, "b1", "consistency_observe_fork",
                     predecessor=lab.checkpoint, left=left, right=closed)
    oversized = copy.deepcopy(right)
    oversized["change"]["commit_bytes"] = "A" * (1024 * 1024)
    error = reject_unchanged(lab, "b1", "consistency_observe_fork",
                             predecessor=lab.checkpoint, left=left, right=oversized)
    check(error["code"] == "input_limit", "双证明请求绕过原有总输入限额")
    blocked(lab)
    observe(lab, current_head(lab))
    assert_status(lab, "no_known_conflict")
    send(lab)


def head_equivocation(lab):
    _, _, _, right_cp = fork_fixture(lab)
    observe(lab, sign_head(lab, right_cp))
    assert_status(lab, "fork_detected")
    blocked(lab)
    lab.rust("b1", "consistency_resume", head=current_head(lab))
    assert_status(lab, "fork_detected")
    blocked(lab)
