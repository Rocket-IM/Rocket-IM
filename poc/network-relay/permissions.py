"""把已验证的公开权限证据与 R0 权限投影共同提交；不证明 MLS 已进入 R1。"""

import json
import time

from contract import ProtocolError, encode_json, parse_u64
from permission_contract import JOIN_ACTIONS, validate_proof
from permission_records import (check_record_capacity, existing_resolution, proof_json, require_receipts, save_resolution)
from join_materials import existing_join, install_join_schema, prepare_join, require_join, save_join
from storage import replace_members, revoke_device, subject
from synchronization import MAX_PAGE_BYTES

SCHEMA_VERSION = "rim-poc-storage-6"
PERMISSION_SCHEMA = """
CREATE TABLE permission_checkpoint (singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    initial_version TEXT NOT NULL, checkpoint TEXT NOT NULL);
CREATE TABLE permission_changes (change_id TEXT PRIMARY KEY, version_offset INTEGER UNIQUE NOT NULL,
    authorization_version TEXT UNIQUE NOT NULL, actor_account TEXT NOT NULL, actor_device TEXT NOT NULL,
    nonce TEXT NOT NULL UNIQUE, proof TEXT NOT NULL, result TEXT NOT NULL,
    UNIQUE(actor_account,actor_device,nonce));
"""
RECEIPT_SCHEMA = """
CREATE TABLE permission_resolutions (change_id TEXT PRIMARY KEY, actor_account TEXT NOT NULL,
    actor_device TEXT NOT NULL, proof TEXT NOT NULL, outcome TEXT NOT NULL CHECK(outcome IN ('accepted','closed')),
    receipt TEXT NOT NULL);
"""


def install_schema(db, old_version, fixture_checkpoint, new_database, receipt_key=None, fixture_devices=()):
    if old_version not in {"rim-poc-1", "rim-poc-storage-2", "rim-poc-storage-3", "rim-poc-storage-4", "rim-poc-storage-5", SCHEMA_VERSION}:
        raise ValueError("不支持该实验数据库版本")
    if not db.in_transaction:
        db.execute("BEGIN IMMEDIATE")
    try:
        if old_version == "rim-poc-1":
            if fixture_checkpoint is not None and not new_database:
                raise ValueError("不能用启动 fixture 为已有 legacy 数据库注入权限检查点")
            for statement in PERMISSION_SCHEMA.strip().split(";"):
                if statement.strip():
                    db.execute(statement)
            if fixture_checkpoint is not None:
                db.execute("INSERT INTO permission_checkpoint VALUES (1,?,?)", (fixture_checkpoint["authorization_version"], encode_json(fixture_checkpoint).decode()))
        if old_version in {"rim-poc-1", "rim-poc-storage-2"}:
            for statement in RECEIPT_SCHEMA.strip().split(";"):
                if statement.strip():
                    db.execute(statement)
        has_checkpoint = db.execute("SELECT 1 FROM permission_checkpoint").fetchone() is not None
        if fixture_checkpoint is not None and not has_checkpoint:
            raise ValueError("不能用启动 fixture 为已有 legacy 数据库注入权限检查点")
        pinned = db.execute("SELECT value FROM meta WHERE key='relay_receipt_key'").fetchone()
        if pinned is None and receipt_key is not None:
            if not new_database or not has_checkpoint:
                raise ValueError("只有具备权限检查点的新空库可以固定 Service 凭证公钥")
            db.execute("INSERT INTO meta VALUES ('relay_receipt_key',?)", (receipt_key,))
        elif pinned is not None and pinned["value"] != receipt_key:
            raise ValueError("Service 凭证密钥缺失或与持久公钥不匹配")
        if old_version in {"rim-poc-1", "rim-poc-storage-2", "rim-poc-storage-3"}:
            install_join_schema(db, new_database, fixture_devices)
        if old_version in {"rim-poc-1", "rim-poc-storage-2", "rim-poc-storage-3", "rim-poc-storage-4"}:
            from history_transfers import HISTORY_SCHEMA
            db.execute(HISTORY_SCHEMA)
        if old_version != SCHEMA_VERSION:
            from lifecycle_backfill import install
            install(db)
            db.execute("UPDATE meta SET value=? WHERE key='schema'", (SCHEMA_VERSION,))
        else:
            from lifecycle_backfill import validate_schema
            validate_schema(db)
        if not new_database:
            db.commit()
        return has_checkpoint
    except BaseException:
        db.rollback()
        raise


def checkpoint_record(db):
    row = db.execute("SELECT initial_version,checkpoint FROM permission_checkpoint WHERE singleton=1").fetchone()
    if row is None:
        raise ProtocolError("permission_not_enabled", "此实验实例尚未固定签名权限检查点", status=409)
    return row, json.loads(row["checkpoint"])


def get_consistency_head(store, db, device, req):
    """签署此事务所见的当前权限视图，不证明全局最新或孤立分叉不存在。"""
    conv = store.context(db, device, req["service_id"], req["conversation_id"])
    require_receipts(store)
    _, checkpoint = checkpoint_record(db)
    if (any(checkpoint[name] != req[name] for name in ("service_id", "conversation_id"))
            or any(checkpoint[name] != conv[name] for name in ("authorization_version", "crypto_state_ref"))
            or [(member["account_id"], member["device_id"]) for member in checkpoint["members"]] != store.members(db)):
        raise ProtocolError("permission_conflict", "持久权限检查点与会话投影不一致", status=409)
    statement = {"protocol_version": "rim-consistency-head-1", "service_id": req["service_id"],
                 "conversation_id": req["conversation_id"], "actor": {"account_id": device["account"], "device_id": device["device"]},
                 "challenge": req["challenge"], "checkpoint": checkpoint}
    return {"head": store.receipt_signer.sign(statement)}



def submit_permission_change(store, db, device, req):
    conv = store.context(db, device, req["service_id"], req["conversation_id"])
    record, checkpoint = checkpoint_record(db)
    statement = validate_proof(req["change"])
    resolved = existing_resolution(store, db, device, req["change"], statement)
    if resolved is not None and resolved["outcome"] == "closed":
        raise ProtocolError("permission_closed", "该权限候选已永久封口，不能迟到接受", status=409)
    existing = db.execute("SELECT actor_account,actor_device,proof,result FROM permission_changes WHERE change_id=?", (statement["change_id"],)).fetchone()
    actor = (device["account"], device["device"])
    encoded_proof = proof_json(req["change"])
    if existing:
        if (existing["actor_account"], existing["actor_device"]) != actor:
            raise ProtocolError("permission_denied", "凭证与原权限变更发起设备不一致", status=403)
        if existing["proof"] != encoded_proof:
            raise ProtocolError("idempotency_conflict", "同一权限变更标识不可改变证据字节", status=409)
        if statement["action"]["kind"] in JOIN_ACTIONS:
            existing_join(db, statement["change_id"], req["join"])
        return json.loads(existing["result"])
    if store.permission_verifier is None:
        raise ProtocolError("permission_verifier_unavailable", "未配置公共权限验证器", status=503)
    if statement["action"]["kind"] in JOIN_ACTIONS:
        require_join(store, db)
        validated = store.permission_verifier.verify(checkpoint, req["change"], statement, join=req["join"])
    else:
        validated = store.permission_verifier.verify(checkpoint, req["change"], statement)
    statement = validated["statement"]
    if subject(statement["actor"]) != actor:
        raise ProtocolError("permission_denied", "凭证与签名发起设备不一致", status=403)
    if statement["service_id"] != req["service_id"] or statement["conversation_id"] != req["conversation_id"]:
        raise ProtocolError("permission_context", "请求与签名上下文不一致", status=403)
    if checkpoint["authorization_version"] != conv["authorization_version"] or checkpoint["crypto_state_ref"] != conv["crypto_state_ref"]:
        raise ProtocolError("permission_conflict", "持久权限检查点与会话投影不一致", status=409)
    if statement["action"]["kind"] in JOIN_ACTIONS:
        prepare_join(store, db, checkpoint, statement, req["join"])
    now = int(time.time())
    if not int(statement["issued_at_unix_secs"]) <= now < int(statement["expires_at_unix_secs"]):
        raise ProtocolError("permission_expired", "首次接受不在权限声明有效期内", status=403)
    if db.execute("SELECT 1 FROM permission_changes WHERE nonce=?", (statement["nonce"],)).fetchone():
        raise ProtocolError("permission_replay", "该设备权限声明 nonce 已使用", status=409)
    check_record_capacity(db)
    next_checkpoint = validated["checkpoint"]
    next_version = next_checkpoint["authorization_version"]
    value = {"outcome": "accepted", "change_id": statement["change_id"], "authorization_version": next_version,
             "crypto_state_ref": next_checkpoint["crypto_state_ref"]}
    if store.receipt_enabled:
        value["receipt"] = save_resolution(store, db, req["change"], statement, next_checkpoint, "accepted")
    offset = int(next_version) - int(record["initial_version"])
    db.execute("INSERT INTO permission_changes VALUES (?,?,?,?,?,?,?,?)", (statement["change_id"], offset, next_version,
               *actor, statement["nonce"], encoded_proof, encode_json(value).decode()))
    if statement["action"]["kind"] in JOIN_ACTIONS:
        save_join(db, statement, req["change"], value["receipt"], req["join"])
    db.execute("UPDATE permission_checkpoint SET checkpoint=? WHERE singleton=1", (encode_json(next_checkpoint).decode(),))
    replace_members(db, [(m["account_id"], m["device_id"]) for m in next_checkpoint["members"]])
    db.execute("UPDATE conversation SET authorization_version=?,crypto_state_ref=?", (next_version, next_checkpoint["crypto_state_ref"]))
    if statement["action"]["kind"] == "revoke_device":
        revoke_device(db, (statement["action"]["account_id"], statement["action"]["device_id"]))
    return value


def permission_page(store, db, device, req, records=False):
    store.context(db, device, req["service_id"], req["conversation_id"])
    if records:
        require_receipts(store)
    record, checkpoint = checkpoint_record(db)
    current = int(checkpoint["authorization_version"])
    initial = int(record["initial_version"])
    after = parse_u64(req["after_version"], "after_version")
    if not initial <= after <= current:
        raise ProtocolError("cursor_invalid", "权限链游标不属于已保留的检查点范围", status=409)
    rows = db.execute("SELECT authorization_version,proof,result FROM permission_changes WHERE version_offset>? ORDER BY version_offset LIMIT ?",
                      (after - initial, parse_u64(req["limit"], "limit")))
    entries, size, next_version = [], 0, after
    for row in rows:
        proof = json.loads(row["proof"])
        item = proof
        if records:
            receipt = json.loads(row["result"]).get("receipt")
            if receipt is None:
                raise ProtocolError("permission_conflict", "已接受记录缺少终态凭证", status=409)
            item = {"change": proof, "receipt": receipt}
        item_size = len(encode_json(item))
        if entries and size + item_size > MAX_PAGE_BYTES:
            break
        if int(row["authorization_version"]) != next_version + 1:
            raise ProtocolError("permission_conflict", "持久权限链不连续", status=409)
        entries.append(item)
        size += item_size
        next_version = int(row["authorization_version"])
    return {"records" if records else "changes": entries, "next_after_version": str(next_version),
            "authorization_version": str(current), "has_more": next_version < current}


def get_permission_changes(store, db, device, req):
    return permission_page(store, db, device, req)


def get_permission_records(store, db, device, req):
    return permission_page(store, db, device, req, records=True)
