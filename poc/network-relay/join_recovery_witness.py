"""W1 受信启动配置及分配前门禁；HTTP 参数不能建立策略授权。"""
import hashlib
import os
from pathlib import Path

from contract import decode_bytes, fields, parse_json, validate_id, validate_state_ref
from key_package_storage import fail
from key_packages import registered
from permission_contract import validate_member
from join_recovery_witness_storage import current, scope_key

MAX_CONFIG_BYTES = 64 * 1024
REQUEST_VERSION = "rim-recovery-request-2"


def decode_config(raw, verifier):
    """格式/关联校验不提供授权；调用者另以启动者独立摘要固定原件。"""
    if not 1 <= len(raw) <= MAX_CONFIG_BYTES:
        raise ValueError("W1启动配置超过64KiB")
    if verifier is None:
        raise ValueError("W1配置需要真实公共格式验证器")
    value = parse_json(raw)
    fields(value, ("activation_bytes", "policy_bytes", "control_domains"))
    decode_bytes(value["activation_bytes"], "activation_bytes", 16384)
    activation = verifier._call({"operation": "verify_witness_activation",
                                "activation_bytes": value["activation_bytes"]})["statement"]
    domains = value["control_domains"]
    if not isinstance(domains, list) or not 2 <= len(domains) <= 6:
        raise ValueError("W1控制域配置须含2—6个准确设备")
    identities, keys = [], []
    for row in domains:
        fields(row, ("member", "control_domain_id"))
        member = validate_member(row["member"])
        validate_id(row["control_domain_id"], "control_domain_id")
        identities.append((member["account_id"], member["device_id"]))
        keys.append(member["signature_key"])
    if identities != sorted(set(identities)) or len(keys) != len(set(keys)):
        raise ValueError("W1控制域设备必须排序、唯一且不复用钥")
    if activation["target"] not in [row["member"] for row in domains]:
        raise ValueError("W1受信配置缺少准确目标控制域")
    policy = None
    if activation["policy_ref"] is None:
        if value["policy_bytes"] is not None:
            raise ValueError("无策略Activation不得夹带未绑定策略")
    else:
        decode_bytes(value["policy_bytes"], "policy_bytes", 8192)
        checked = verifier._call({"operation": "verify_witness_policy", "policy": {
            "policy_ref": activation["policy_ref"], "policy_bytes": value["policy_bytes"]}})
        policy = checked["statement"]
        if (checked["reference"] != activation["policy_ref"]
                or policy["scope"] != activation["scope"] or policy["target"] != activation["target"]):
            raise ValueError("W1策略与可信启用范围不符")
        witness_domain = next((row["control_domain_id"] for row in domains
                               if row["member"] == policy["witness"]), None)
        if witness_domain != policy["independence"]["control_domain_id"]:
            raise ValueError("W1策略的见证独立域未由启动配置确认")
    return {"raw": raw, "sha256": hashlib.sha256(raw).hexdigest(),
            "activation": activation, "policy": policy, "control_domains": domains}


def load_config(path, verifier):
    if path is None:
        return None
    path = Path(path)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError("W1配置必须为非符号链接的绝对文件路径")
    pin = os.environ.get("RIM_RECOVERY_WITNESS_CONFIG_SHA256")
    if pin is None:
        raise ValueError("W1启动配置缺少独立摘要固定")
    validate_state_ref(pin)
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != pin:
        raise ValueError("W1启动配置与独立固定摘要不符")
    return decode_config(raw, verifier)


def install(store, db, path):
    from join_recovery_witness_storage import validate, enroll
    validate(store, db)
    config = load_config(path, store.permission_verifier)
    if config is not None:
        activation = config["activation"]
        conversation = db.execute("SELECT id FROM conversation").fetchone()[0]
        if (activation["scope"]["service_id"] != store.meta(db, "service_id")
                or activation["scope"]["conversation_id"] != conversation):
            raise ValueError("W1受信配置不属于当前Service会话")
    enroll(store, db, config)


def policy_for(store, db, intent, first_use=True):
    saved = current(db, intent["scope"], intent["signer"])
    modern = intent["protocol_version"] == REQUEST_VERSION
    if not modern:
        if first_use and saved is not None:
            fail("w1_policy_upgrade_required")
        return None
    if saved is None:
        fail("w1_policy_missing")
    if first_use:
        config = store.recovery_witness_records[saved["config_sha256"]]
        if config["policy"] is None:
            fail("w1_policy_missing")
        if config["activation"]["policy_ref"] != intent["policy_ref"]:
            fail("w1_policy_mismatch")
        return config
    # 关闭/精确重试保留候选原策略；策略修订不能使旧占用无法正规终结。
    binding = db.execute("SELECT config_sha256 FROM recovery_witness_bindings WHERE recovery_id=?",
                         (intent["request_id"],)).fetchone()
    if binding is not None:
        config = store.recovery_witness_records[binding[0]]
        if config["activation"]["policy_ref"] != intent["policy_ref"]:
            fail("w1_policy_mismatch")
        return config
    key = scope_key(intent["scope"], intent["signer"])
    for row in db.execute("SELECT config_sha256 FROM recovery_witness_configs WHERE scope_key=?", (key,)):
        config = store.recovery_witness_records[row[0]]
        if config["activation"]["policy_ref"] == intent["policy_ref"]:
            return config
    fail("w1_policy_mismatch")


def eligible(store, db, intent, checkpoint):
    bound = db.execute("SELECT 1 FROM recovery_witness_bindings WHERE recovery_id=?",
                       (intent["request_id"],)).fetchone()
    config = policy_for(store, db, intent, first_use=bound is None)
    if config is None:
        return None
    policy = config["policy"]
    witness, actor, target = policy["witness"], intent["actor"], intent["signer"]
    if (policy["target"] != target or policy["scope"] != intent["scope"]
            or witness in (actor, target) or witness not in checkpoint["members"]
            or witness["signature_key"] in (actor["signature_key"], target["signature_key"])):
        fail("w1_witness_ineligible", 403)
    domains = {tuple(row["member"][key] for key in ("account_id", "device_id", "signature_key")):
               row["control_domain_id"] for row in config["control_domains"]}
    selected = [domains.get(tuple(member[key] for key in ("account_id", "device_id", "signature_key")))
                for member in (actor, target, witness)]
    if None in selected or selected[2] in selected[:2]:
        fail("w1_witness_ineligible", 403)
    if sorted({m["account_id"] for m in (actor, target, witness)}) != [
            ref["account_id"] for ref in intent["directory_refs"]]:
        fail("w1_binding_mismatch")
    registered(db, witness)
    # 在线状态不是受信输入；W离线时保留固定W，目标等待真实见证。
    return config
