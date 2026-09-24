"""重建后继的启动信任与唯一设备流；只允许新空库固定，重启不得补授信。"""

import json
import unicodedata

from contract import ProtocolError, decode_bytes, encode_json, fields, invalid, validate_id, validate_state_ref
from permission_contract import validate_checkpoint

SCHEMA = """CREATE TABLE IF NOT EXISTS rebuild_streams (
    account TEXT NOT NULL, device TEXT NOT NULL, trusted TEXT NOT NULL,
    old_scope TEXT NOT NULL UNIQUE, registration TEXT, request_sha256 TEXT UNIQUE,
    plan_sha256 TEXT UNIQUE, stream_id TEXT UNIQUE, binding TEXT,
    PRIMARY KEY(account,device), FOREIGN KEY(account,device) REFERENCES devices(account,device),
    CHECK ((registration IS NULL AND request_sha256 IS NULL AND plan_sha256 IS NULL AND stream_id IS NULL AND binding IS NULL)
        OR (registration IS NOT NULL AND request_sha256 IS NOT NULL AND plan_sha256 IS NOT NULL AND stream_id IS NOT NULL AND binding IS NOT NULL)))"""


def scope(value, old=False):
    fields(value, ("service", "account", "device", "identity_key", "store_id"))
    for name in ("service", "account", "device"):
        if old:
            text = value[name]
            try:
                length = len(text.encode("utf-8")) if isinstance(text, str) else 0
            except UnicodeError:
                invalid("旧锚范围标识不是有效Unicode")
            if (not isinstance(text, str) or not text or length > 128
                    or any(unicodedata.category(char) == "Cc" for char in text)):
                invalid("旧锚范围标识无效")
        else:
            validate_id(value[name], name)
    for name in ("identity_key", "store_id"):
        validate_state_ref(value[name])
    return value


def validate_trust(value):
    fields(value, ("old_scope", "anchor_public_key", "trust"))
    old = scope(value["old_scope"], old=True)
    validate_state_ref(value["anchor_public_key"])
    trust = value["trust"]
    fields(trust, ("authorizer", "checkpoint", "relay_receipt_key"))
    checkpoint = validate_checkpoint(trust["checkpoint"])
    authorizer = trust["authorizer"]
    fields(authorizer, ("account_id", "device_id", "signature_key"))
    if (authorizer not in checkpoint["members"] or checkpoint["service_id"] != old["service"]
            or authorizer["account_id"] != old["account"] or authorizer["device_id"] == old["device"]
            or any((m["account_id"], m["device_id"]) == (old["account"], old["device"])
                   or decode_bytes(m["signature_key"], "signature_key", 32).hex() == old["identity_key"] for m in checkpoint["members"])):
        invalid("重建信任来源与旧范围或固定成员不一致")
    if len(decode_bytes(trust["relay_receipt_key"], "relay_receipt_key", 32)) != 32:
        invalid("重建 Service 公钥必须为32字节")
    return value


def validate_fixture_device(device, fixture):
    trusted = validate_trust(device["rebuild_trust"])
    old, trust = trusted["old_scope"], trusted["trust"]
    checkpoint = fixture.get("permission_checkpoint")
    pair = (device["account_id"], device["device_id"])
    if (checkpoint != trust["checkpoint"] or fixture.get("relay_receipt_key") != trust["relay_receipt_key"]
            or old["service"] != fixture["service_id"] or old["account"] != pair[0] or old["device"] == pair[1]
            or "signature_key" not in device
            or decode_bytes(device["signature_key"], "signature_key", 32).hex() == old["identity_key"]
            or any((m["account_id"], m["device_id"]) == pair or m["signature_key"] == device["signature_key"] for m in checkpoint["members"])):
        invalid("重建设备须是固定新群之外的同账号新身份")


def install(db, fixture, new_database):
    expected = {(d["account_id"], d["device_id"]): d for d in fixture["devices"] if "rebuild_trust" in d}
    scope_keys = {pair: json.dumps(d["rebuild_trust"]["old_scope"], sort_keys=True, separators=(",", ":")) for pair, d in expected.items()}
    if len(set(scope_keys.values())) != len(scope_keys):
        raise ValueError("同一个旧锚范围只能预置一个后继设备")
    if not db.in_transaction:
        db.execute("BEGIN IMMEDIATE")
    version = db.execute("SELECT value FROM meta WHERE key='rebuild_stream_schema'").fetchone()
    has_table = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='rebuild_streams'").fetchone()
    if version is None:
        if has_table or (expected and not new_database):
            raise ValueError("旧数据库不能补重建信任，已有重建表也不能缺少版本")
        db.execute(SCHEMA)
        db.execute("INSERT INTO meta VALUES ('rebuild_stream_schema','rim-rebuild-stream-1')")
    elif version["value"] != "rim-rebuild-stream-1" or not has_table:
        raise ValueError("重建流版本无效或持久表丢失，不能降级成普通流")
    existing = {(r["account"], r["device"]): json.loads(r["trusted"]) for r in db.execute("SELECT account,device,trusted FROM rebuild_streams")}
    if new_database:
        if existing:
            raise ValueError("新库不能存在重建信任记录")
        for pair, device in expected.items():
            trusted = device["rebuild_trust"]
            db.execute("INSERT INTO rebuild_streams(account,device,trusted,old_scope) VALUES (?,?,?,?)",
                       (*pair, encode_json(trusted).decode(), scope_keys[pair]))
    elif existing != {pair: d["rebuild_trust"] for pair, d in expected.items()}:
        raise ValueError("重建启动信任缺失、改变或试图向已有数据库补登记")
    for pair, device in expected.items():
        row = db.execute("SELECT signature_key FROM device_public_keys WHERE account=? AND device=?", pair).fetchone()
        if row is None or row["signature_key"] != device["signature_key"]:
            raise ValueError("重建目标的启动设备公钥改变或缺失")


def row_for(db, pair):
    return db.execute("SELECT * FROM rebuild_streams WHERE account=? AND device=?", pair).fetchone()


def authorize_operation(db, device, operation):
    row = row_for(db, (device["account"], device["device"]))
    if row is None:
        return
    if operation in {"pull_events", "pull_events_signed", "submit_history_transfer", "get_history_transfer"}:
        raise ProtocolError("rebuild_stream_denied", "重建设备不能使用普通设备流或历史迁移", status=403)
    pending_allowed = {"register_rebuild_stream", "get_join_material", "get_permission_changes", "get_permission_records", "get_consistency_head"}
    if row["binding"] is None and operation not in pending_allowed:
        raise ProtocolError("rebuild_stream_pending", "后继设备尚未完成唯一设备流授权", status=409)
