"""Q05/Q02 外置锚跨进程验收；所有控制器、可信配置与目录均为本机合成装置。"""

import base64
from concurrent.futures import ThreadPoolExecutor
import copy
import json
import shutil

from .anchor_fixture import sha256
from .consistency_cases import accepted_witness
from .fixture import check
from .permission_cases import prepare
from .permission_recovery_cases import recover


def ordinary_retry(lab):
    lab.enable()
    first = lab.send("normal")
    second = lab.send("normal")
    check(first["ciphertext"] == second["ciphertext"] and second["reused"],
          "锚启用后没有复用已经保存的密文")
    lab.rust("b1", "receive", id="normal", ciphertext=second["ciphertext"])
    result = lab.rust("a1", "anchor_inspect")
    check(result["freshness"] == "unknown", "锚不得夸大为全局最新证明")
    check(result["anchor_head"] == sha256(lab.snapshot()), "锚没有承诺实际完整快照")
    check(result["active_txn"] is None, "正常结束遗留预约")
    lab.evidence["exact_retry"] = "已存原密文由独立接收设备实际解密"


def complete_rollback(lab):
    lab.enable()
    lab.send("cached_old")
    old = lab.backup("old-device", lab.directory / "a1")
    lab.send("new_state")
    latest = lab.backup("latest-device", lab.directory / "a1")
    lab.restore(old, lab.directory / "a1")
    error = lab.blocked(id="next", payload="synthetic-next")
    check(error["code"] == "anchor_conflict", "旧完整快照未由独立锚摘要冲突拒绝")
    lab.blocked(id="cached_old", payload="synthetic-anchor-cached_old")
    lab.blocked(operation="anchor_resume")
    check(lab.rust("a1", "anchor_inspect")["paused"], "重启检查没有保留暂停")
    # 只恢复完整、已被锚接受的本机副本，不导入 MLS 秘密或信任较大数字。
    gate = (lab.directory / "a1/anchor-gate.enc").read_bytes()
    lab.restore(latest, lab.directory / "a1")
    (lab.directory / "a1/anchor-gate.enc").write_bytes(gate)
    (lab.directory / "a1/anchor-gate.enc").chmod(0o600)
    lab.blocked()
    lab.resume()
    lab.send("after_exact_restore")
    lab.evidence["rollback_scope"] = "整个设备目录含 key/snapshot/门禁/日志一并还原；锚及可信配置保留"


def unavailable(lab):
    lab.enable()
    lab.config_change(helper_path=str(lab.directory / "missing-helper"))
    lab.blocked()
    lab.config_restore()
    lab.blocked()
    check(lab.rust("a1", "anchor_inspect")["paused"], "锚恢复可达就自动解除暂停")
    lab.resume()
    lab.send("after_available")


def wrong_scope(lab):
    lab.enable()
    original = lab.materials["a1"]["config"]
    authority = lab.materials["a1"]["authority"]
    saved_device = lab.backup("scope-device", lab.directory / "a1")
    saved_authority = lab.backup("scope-authority", authority)
    for key in ("service", "account", "device", "identity_key", "store_id"):
        # 每个错误输入使用独立初始fixture，不让上次的暂停挡住本次真实边界检查。
        lab.restore(saved_device, lab.directory / "a1")
        lab.restore(saved_authority, authority)
        scope = copy.deepcopy(original["scope"])
        scope[key] = "ab" * 32 if key.endswith("key") or key == "store_id" else "other"
        lab.config_change(scope=scope)
        check(lab.blocked()["code"] != "anchor_paused", "前次暂停遮住本次范围检查")
    lab.config_restore()
    lab.evidence["scope_substitutions"] = ["service", "account", "device", "identity_key", "store_id"]


def wrong_key(lab):
    lab.enable()
    authority = lab.materials["a1"]["authority"]
    saved_device = lab.backup("key-device", lab.directory / "a1")
    saved_authority = lab.backup("key-authority", authority)
    for key in ("anchor_public_key", "client_seed"):
        lab.restore(saved_device, lab.directory / "a1")
        lab.restore(saved_authority, authority)
        lab.config_restore()
        lab.config_change(**{key: "cd" * 32})
        check(lab.blocked()["code"] != "anchor_paused", "前次暂停遮住本次错钥检查")
    lab.restore(saved_device, lab.directory / "a1")
    lab.restore(saved_authority, authority)
    lab.config_restore()
    lab.send("wrong_journal_key", expected_exit=87, env={"RIM_ANCHOR_FAILPOINT": "after_journal"})
    lab.config_change(journal_key="cd" * 32)
    check(lab.blocked(operation="anchor_resume")["code"] == "anchor_unresolved", "错钥日志被接受为可恢复提交")
    lab.config_restore()


def missing_state(lab):
    lab.enable()
    lab.snapshot().unlink()
    lab.blocked(operation="init")
    lab.blocked()
    check(not lab.snapshot().exists(), "缺失快照被重新初始化覆盖")
    authority = lab.materials["a1"]["authority"]
    before = sha256(authority / "state.enc")
    lab.anchor(lab.materials["a1"]["bootstrap"], expected_exit=1)
    check(sha256(authority / "state.enc") == before, "重复bootstrap替换已固定的锚")


def clone_race(lab):
    lab.enable()
    clone = lab.backup("clone", lab.directory / "a1")
    paths = [lab.directory / "a1", clone]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda path: lab.raw_rust(
            "a1", "send", directory=path, id="racing", payload="synthetic-racing"), paths))
    check(sum(r.returncode == 0 for r in results) == 1, "同一锚同一旧状态的两个克隆同时获准加密")
    winner = next(i for i, result in enumerate(results) if result.returncode == 0)
    packet = json.loads(results[winner].stdout)["result"]
    lab.rust("b1", "receive", id="racing", ciphertext=packet["ciphertext"])
    lab.evidence["clone_winners"] = 1
    lab.evidence["loser_error"] = json.loads(results[1 - winner].stdout)["error"]["code"]


def signed_replay(lab):
    lab.enable()
    capture = lab.forwarding_helper()
    lab.send("record_request")
    captured = json.loads(capture.read_text())
    authority = lab.materials["a1"]["authority"] / "state.enc"
    before = authority.read_bytes()
    replay = lab.anchor(captured["request"])
    signed = replay.get("response", replay)
    statement = json.loads(base64.b64decode(signed["statement_bytes"]))
    check(statement["status"] == "conflict", "已结束的旧reserve请求重新获得加密预约")
    bad = copy.deepcopy(captured["request"])
    signature = bytearray(base64.b64decode(bad["request"]["signature_bytes"]))
    signature[-1] ^= 1
    bad["request"]["signature_bytes"] = base64.b64encode(signature).decode()
    check(lab.anchor(bad, expected_exit=1)["code"] == "anchor_signature", "伪造请求没有在验签处拒绝")
    check(authority.read_bytes() == before, "重放或伪造请求改变锚状态")
    lab.forwarding_helper("replay")
    error = lab.blocked()
    check(error["code"] == "anchor_response" and "anchor_response_binding" in error["message"],
          "旧签名响应未按新挑战绑定拒绝")


def unsafe_configuration(lab):
    lab.enable()
    config = lab.configs["a1"]
    config.chmod(0o644)
    lab.blocked()
    config.chmod(0o600)
    trusted = lab.materials["a1"]["trusted"]
    trusted.chmod(0o755)
    lab.blocked()
    trusted.chmod(0o700)
    stored = config.read_bytes()
    config.unlink()
    lab.blocked()
    config.write_bytes(stored)
    config.chmod(0o600)
    inside = lab.directory / "a1/config.json"
    shutil.copy2(config, inside)
    lab.configs["a1"] = inside
    lab.blocked()


def bounded_input(lab):
    lab.enable()
    before = lab.snapshot().read_bytes()
    result = lab.raw_rust("a1", "send", id="huge", payload="x" * (1024 * 1024))
    check(result.returncode == 1 and json.loads(result.stdout)["error"]["code"] == "input_limit",
          "原CLI 1 MiB边界失效")
    capture = lab.forwarding_helper(action="inspect")
    lab.rust("a1", "anchor_inspect")
    lab.config_restore()
    request = json.loads(capture.read_text())["request"]
    encoded = json.dumps(request)
    boundary = encoded + " " * (32 * 1024 - len(encoded.encode()))
    authority = lab.materials["a1"]["authority"] / "state.enc"
    anchor_before = authority.read_bytes()
    accepted = lab.anchor(request, raw=boundary)
    statement = json.loads(base64.b64decode(accepted["response"]["statement_bytes"]))
    check(len(boundary.encode()) == 32768 and statement["status"] == "inspected",
          "32768字节合法已签Inspect未在正边界成功")
    check(lab.anchor(request, raw=boundary + " ", expected_exit=1)["code"] == "anchor_invalid",
          "32769字节合法JSON未由锚输入上限拒绝")
    check(authority.read_bytes() == anchor_before, "输入边界验证改变了锚状态")
    check(lab.snapshot().read_bytes() == before, "超限请求改变密码快照")
    lab.evidence["anchor_input_boundary"] = {"valid_signed_json_32768": "PASS",
                                             "valid_signed_json_32769": "REJECTED",
                                             "anchor_state_unchanged": True}


def common_controller_rollback(lab):
    lab.enable()
    lab.send("prior")
    device = lab.backup("device", lab.directory / "a1")
    authority_path = lab.materials["a1"]["authority"]
    authority = lab.backup("authority", authority_path)
    lab.send("consumed")
    lab.restore(device, lab.directory / "a1")
    lab.restore(authority, authority_path)
    lab.send("after_double_rollback")
    lab.evidence["independence_negative_control"] = (
        "EXPECTED_UNDETECTABLE: 同机控制器可同时回滚设备与锚；本案例未执行原始旧钥攻击，"
        "不证明生产故障域或硬件不可回滚")


def preserved_pause(lab, kind):
    device = "b1" if kind != "permission" else "a1"
    if kind == "checking":
        lab.rust(device, "consistency_challenge")
    elif kind == "fork":
        left = accepted_witness(lab, prepare(lab, "left")["change"])
        right = accepted_witness(lab, prepare(lab, "right", device="a2")["change"])
        recover(lab, left, "a1", "b1")
        recover(lab, right, "a2")
        lab.rust(device, "consistency_challenge")
        lab.rust(device, "consistency_observe_fork", predecessor=lab.checkpoint, left=left, right=right)
    else:
        prepare(lab, "pending")
    inspect_op = "permission_inspect" if kind == "permission" else "consistency_inspect"
    prior = lab.rust(device, inspect_op)
    if kind == "fork":
        check(prior["status"] == "fork_detected" and prior["fork_evidence_count"] > 0,
              "装置必须已经保存真实分叉证据，不能只用checking门禁冒充分叉暂停")
        lab.evidence["preserved_fork"] = {"status": prior["status"],
                                          "fork_evidence_count": prior["fork_evidence_count"]}
    lab.enable(device)
    lab.config_change(device, helper_path=str(lab.directory / "missing-helper"))
    lab.blocked(device)
    lab.config_restore(device)
    lab.resume(device)
    check(lab.rust(device, inspect_op) == prior, "锚恢复清除或改变既有Q02/权限暂停")
    error = lab.blocked(device, "wire_send", logical_message_id="still_paused",
                        attempt_id="P1", payload="synthetic-still-paused")
    check(error["code"] == ("permission_pending" if kind == "permission" else "consistency_paused"),
          "恢复锚后没有保留原业务门禁")
