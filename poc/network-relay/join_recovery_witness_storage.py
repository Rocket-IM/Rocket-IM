"""W1 的追加配置与候选固定关联；与原恢复账本共用启动/业务事务。"""
import hashlib
import json

from join_recovery_storage import encoded
from key_package_storage import fail

TABLES = ("recovery_witness_configs", "recovery_witness_bindings")
SCHEMA = """
CREATE TABLE recovery_witness_configs (
    scope_key TEXT NOT NULL, version TEXT NOT NULL,
    config_sha256 TEXT NOT NULL UNIQUE, config_bytes BLOB NOT NULL,
    PRIMARY KEY(scope_key,version));
CREATE TABLE recovery_witness_bindings (
    recovery_id TEXT PRIMARY KEY REFERENCES recovery_attempts(recovery_id),
    config_sha256 TEXT NOT NULL REFERENCES recovery_witness_configs(config_sha256),
    policy_ref TEXT NOT NULL);
"""


def install(db):
    if not db.in_transaction:
        raise ValueError("见证迁移必须在启动事务内")
    version = db.execute("SELECT value FROM meta WHERE key='recovery_schema'").fetchone()[0]
    present = {row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    if version == "1":
        if present.intersection(TABLES):
            raise ValueError("旧恢复版本存在未标记见证账本")
        for statement in SCHEMA.strip().split(";"):
            if statement.strip():
                db.execute(statement)
        db.execute("UPDATE meta SET value='2' WHERE key='recovery_schema'")
    elif version != "2":
        raise ValueError("恢复账本版本不支持")
    for table in TABLES:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
            raise ValueError("见证持久账本缺失")


def scope_key(scope, target):
    return encoded([scope["service_id"], scope["conversation_id"], scope["group_id"],
                    target["account_id"], target["device_id"], target["signature_key"]])


def configurations(db):
    return db.execute("SELECT * FROM recovery_witness_configs").fetchall()


def current(db, scope, target):
    rows = db.execute("SELECT * FROM recovery_witness_configs WHERE scope_key=?",
                      (scope_key(scope, target),)).fetchall()
    return max(rows, key=lambda row: int(row["version"])) if rows else None


def enroll(store, db, trusted):
    """授权来源只有启动时已核验独立摘要的配置，不从请求建立授权。"""
    rows = configurations(db)
    if trusted is None:
        if rows:
            raise ValueError("W1已启用，重启必须提供原受信配置及独立摘要")
        return
    activation = trusted["activation"]
    key = scope_key(activation["scope"], activation["target"])
    # 单会话 POC 只配置一个目标；不能以换目标配置遗忘已有保护。
    if any(row["scope_key"] != key for row in rows):
        raise ValueError("W1配置不得更换已固定目标范围")
    old = current(db, activation["scope"], activation["target"])
    version = activation["activation_version"]
    if old is not None:
        if int(version) < int(old["version"]):
            fail("w1_activation_rollback")
        if int(version) == int(old["version"]):
            if old["config_sha256"] != trusted["sha256"] or bytes(old["config_bytes"]) != trusted["raw"]:
                fail("w1_activation_unauthorized", 403)
            return
        previous = store.recovery_witness_records[old["config_sha256"]]
        old_policy, new_policy = previous["policy"], trusted["policy"]
        if old_policy is not None:
            if new_policy is None:
                fail("w1_policy_mismatch")
            if old_policy == new_policy and previous["control_domains"] != trusted["control_domains"]:
                fail("w1_policy_mismatch")
            if old_policy != new_policy and int(new_policy["policy_version"]) <= int(old_policy["policy_version"]):
                fail("w1_policy_mismatch")
    stored_bytes = sum(len(row["config_bytes"]) for row in rows)
    if stored_bytes + len(trusted["raw"]) > 8 * 1024 * 1024:
        fail("resource_exhausted", 429)
    db.execute("INSERT INTO recovery_witness_configs VALUES (?,?,?,?)",
               (key, version, trusted["sha256"], trusted["raw"]))
    store.recovery_witness_records[trusted["sha256"]] = trusted


def bind(db, intent, trusted):
    if intent["protocol_version"] != "rim-recovery-request-2":
        return
    if trusted is None:
        fail("w1_policy_missing")
    value = (intent["request_id"], trusted["sha256"], encoded(intent["policy_ref"]))
    old = db.execute("SELECT recovery_id,config_sha256,policy_ref FROM recovery_witness_bindings "
                     "WHERE recovery_id=?", (intent["request_id"],)).fetchone()
    if old is not None:
        if tuple(old) != value:
            fail("w1_policy_mismatch")
        return
    db.execute("INSERT INTO recovery_witness_bindings VALUES (?,?,?)", value)


def validate(store, db):
    from join_recovery_contract import signed
    from join_recovery_witness import decode_config
    store.recovery_witness_records = {}
    for row in configurations(db):
        raw = bytes(row["config_bytes"])
        if hashlib.sha256(raw).hexdigest() != row["config_sha256"]:
            raise ValueError("见证配置原件摘要损坏")
        config = decode_config(raw, store.permission_verifier)
        activation = config["activation"]
        if (row["scope_key"] != scope_key(activation["scope"], activation["target"])
                or row["version"] != activation["activation_version"]):
            raise ValueError("见证配置范围或版本损坏")
        store.recovery_witness_records[row["config_sha256"]] = config
    for row in db.execute("SELECT * FROM recovery_attempts"):
        intent = signed(json.loads(row["intent"]))
        binding = db.execute("SELECT * FROM recovery_witness_bindings WHERE recovery_id=?",
                             (row["recovery_id"],)).fetchone()
        if intent["protocol_version"] != "rim-recovery-request-2":
            if binding is not None:
                raise ValueError("不能给旧恢复原件补造见证策略")
            continue
        if binding is None:
            raise ValueError("W1恢复缺少原固定策略")
        config = store.recovery_witness_records.get(binding["config_sha256"])
        if (config is None or config["policy"] is None
                or json.loads(binding["policy_ref"]) != intent["policy_ref"]
                or config["activation"]["policy_ref"] != intent["policy_ref"]
                or config["activation"]["target"] != intent["signer"]
                or config["activation"]["scope"] != intent["scope"]):
            raise ValueError("W1恢复策略关联损坏")
    if db.execute("SELECT 1 FROM recovery_witness_bindings b LEFT JOIN recovery_attempts a "
                  "ON a.recovery_id=b.recovery_id WHERE a.recovery_id IS NULL").fetchone():
        raise ValueError("见证策略关联缺少原恢复尝试")
