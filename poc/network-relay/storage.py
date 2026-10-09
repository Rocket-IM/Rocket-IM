"""阶段 0 本机 Relay 的 SQLite 持久化；不作为正式 Service 存储层。"""

import hashlib
import json
import sqlite3
import time
import uuid
from contextlib import closing, contextmanager
from pathlib import Path

from contract import ProtocolError, decode_bytes, encode_json, parse_u64, validate_id

MAX_ATTEMPTS = 10000
MAX_EVENTS = 60000
MAX_STREAM_EVENTS = 10000
RETENTION_MS = 30 * 24 * 60 * 60 * 1000
SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE devices (account TEXT, device TEXT, token_hash TEXT UNIQUE NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0, stream_id TEXT UNIQUE NOT NULL,
    PRIMARY KEY(account,device));
CREATE TABLE conversation (id TEXT PRIMARY KEY, authorization_version TEXT NOT NULL,
    crypto_state_ref TEXT NOT NULL);
CREATE TABLE members (account TEXT, device TEXT, PRIMARY KEY(account,device));
CREATE TABLE logical_messages (key TEXT PRIMARY KEY, tail TEXT NOT NULL,
    accepted_attempt TEXT);
CREATE TABLE attempts (logical_key TEXT, attempt_id TEXT, header BLOB, payload BLOB,
    outcome TEXT NOT NULL, closure_id TEXT, successor TEXT, result TEXT NOT NULL,
    acceptance_id TEXT UNIQUE, availability TEXT NOT NULL DEFAULT 'available',
    PRIMARY KEY(logical_key,attempt_id));
CREATE TABLE events (account TEXT, device TEXT, seq INTEGER, event_id TEXT UNIQUE,
    content TEXT NOT NULL, acceptance_id TEXT, availability TEXT NOT NULL DEFAULT 'available',
    PRIMARY KEY(account,device,seq));
CREATE TABLE receipts (acceptance_id TEXT, account TEXT, device TEXT, delivered INTEGER,
    is_read INTEGER, PRIMARY KEY(acceptance_id,account,device));
CREATE TABLE controls (control_id TEXT PRIMARY KEY, from_ref TEXT UNIQUE NOT NULL,
    to_ref TEXT UNIQUE NOT NULL, payload TEXT NOT NULL, recipients TEXT NOT NULL);
"""


def now_ms():
    return int(time.time() * 1000)


def identifier():
    return uuid.uuid4().hex


def token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def subject(value):
    if not isinstance(value, dict) or set(value) != {"account_id", "device_id"}:
        raise ProtocolError("invalid_request", "设备主体字段不正确")
    return (validate_id(value["account_id"], "account_id"),
            validate_id(value["device_id"], "device_id"))


def public_subject(pair):
    return {"account_id": pair[0], "device_id": pair[1]}


def check_fixture(fixture):
    required = {"service_id", "controller_token", "devices", "conversation"}
    if not required <= set(fixture) or set(fixture) - required - {"permission_checkpoint", "relay_receipt_key"}:
        raise ValueError("fixture 字段不正确")
    validate_id(fixture["service_id"], "service_id")
    if not isinstance(fixture["controller_token"], str) or not 16 <= len(fixture["controller_token"]) <= 256:
        raise ValueError("controller_token 必须为 16—256 字符的合成凭证")
    devices = fixture["devices"]
    if not isinstance(devices, list) or not 2 <= len(devices) <= 6:
        raise ValueError("fixture devices 数量须为 2—6")
    seen, tokens, public_keys = set(), {fixture["controller_token"]}, set()
    for item in devices:
        if not isinstance(item, dict) or not {"account_id", "device_id", "token"} <= set(item) or set(item) - {"account_id", "device_id", "token", "signature_key", "rebuild_trust"}:
            raise ValueError("fixture device 字段不正确")
        pair = subject({k: item[k] for k in ("account_id", "device_id")})
        token = item["token"]
        if not isinstance(token, str) or not 16 <= len(token) <= 256 or token in tokens or pair in seen:
            raise ValueError("fixture device 或凭证重复/无效")
        if "signature_key" in item:
            key = decode_bytes(item["signature_key"], "signature_key", 32)
            if len(key) != 32 or key in public_keys:
                raise ValueError("设备公钥必须为不复用的 32 字节")
            public_keys.add(key)
        seen.add(pair)
        tokens.add(token)
    conv = fixture["conversation"]
    if not isinstance(conv, dict) or set(conv) != {"conversation_id", "members", "authorization_version", "crypto_state_ref"}:
        raise ValueError("fixture conversation 字段不正确")
    validate_id(conv["conversation_id"], "conversation_id")
    parse_u64(conv["authorization_version"], "authorization_version")
    ref = conv["crypto_state_ref"]
    if not isinstance(ref, str) or len(ref) != 64 or any(c not in "0123456789abcdef" for c in ref):
        raise ValueError("crypto_state_ref 必须为 64 位小写十六进制")
    members = [subject(m) for m in conv["members"]]
    if len(members) < 2 or len(set(members)) != len(members) or not set(members) <= seen:
        raise ValueError("fixture members 缺少设备或重复")
    if "permission_checkpoint" in fixture:
        from permission_contract import validate_checkpoint
        checkpoint = validate_checkpoint(fixture["permission_checkpoint"])
        if checkpoint["service_id"] != fixture["service_id"] or any(checkpoint[name] != conv[name] for name in ("conversation_id", "authorization_version", "crypto_state_ref")):
            raise ValueError("启动权限检查点与会话上下文不一致")
        if [(m["account_id"], m["device_id"]) for m in checkpoint["members"]] != sorted(members):
            raise ValueError("启动权限检查点与会话成员不一致")
        devices_by_id = {(d["account_id"], d["device_id"]): d for d in devices}
        if any(devices_by_id[(m["account_id"], m["device_id"])].get("signature_key") != m["signature_key"] for m in checkpoint["members"]):
            raise ValueError("启动权限检查点缺少与设备记录一致的签名公钥")
    if "relay_receipt_key" in fixture and len(decode_bytes(fixture["relay_receipt_key"], "relay_receipt_key", 32)) != 32:
        raise ValueError("Service凭证公钥必须为32字节")
    from rebuild_stream_storage import validate_fixture_device
    for item in devices:
        if "rebuild_trust" in item:
            validate_fixture_device(item, fixture)
    return fixture


class Store:
    def __init__(self, path, fixture, permission_verifier=None, receipt_signer=None):
        self.permission_verifier = permission_verifier
        self.receipt_signer = receipt_signer
        self.path = Path(path).absolute()
        check_fixture(fixture)
        receipt_key = receipt_signer.public_key() if receipt_signer is not None else None
        if "relay_receipt_key" in fixture and fixture["relay_receipt_key"] != receipt_key:
            raise ValueError("启动Service凭证公钥与实际密钥不一致")
        self.receipt_enabled = receipt_key is not None
        if receipt_signer is not None:
            receipt_signer.signature_key = receipt_key
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.is_symlink():
            raise ValueError("数据库路径不得为符号链接")
        with closing(self.connect()) as db:
            tables = db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            if not tables:
                db.executescript("BEGIN IMMEDIATE;\n" + SCHEMA)
                db.executemany("INSERT INTO meta VALUES (?,?)", [
                    ("schema", "rim-poc-1"), ("service_id", fixture["service_id"]),
                    ("controller_hash", token_hash(fixture["controller_token"]))])
                for device in fixture["devices"]:
                    db.execute("INSERT INTO devices(account,device,token_hash,stream_id) VALUES (?,?,?,?)",
                               (device["account_id"], device["device_id"], token_hash(device["token"]), identifier()))
                conv = fixture["conversation"]
                db.execute("INSERT INTO conversation VALUES (?,?,?)", (conv["conversation_id"],
                           conv["authorization_version"], conv["crypto_state_ref"]))
                db.executemany("INSERT INTO members VALUES (?,?)", [subject(m) for m in conv["members"]])
            if self.meta(db, "service_id") != fixture["service_id"]:
                raise ValueError("已有数据库服务实例不匹配")
            from permissions import install_schema
            previous_schema = self.meta(db, "schema")
            self.permission_enabled = install_schema(db, previous_schema, fixture.get("permission_checkpoint"), not tables, receipt_key, fixture["devices"])
            from rebuild_stream_storage import install
            install(db, fixture, not tables)
            from reclamation_storage import install as install_reclamation
            install_reclamation(db, previous_schema)
            from registration_storage import install as install_registration
            install_registration(db, previous_schema)
            db.commit()
        self.path.chmod(0o600)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=6, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA foreign_keys=ON")
        return db

    @contextmanager
    def transaction(self):
        db = self.connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def meta(db, key):
        row = db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        if row is None:
            raise ValueError("数据库初始化未完成")
        return row["value"]

    def authenticate(self, db, token):
        row = db.execute("SELECT account,device,revoked,stream_id FROM devices WHERE token_hash=?", (token_hash(token),)).fetchone()
        if row is None:
            raise ProtocolError("unauthenticated", "设备凭证无效", status=401)
        if row["revoked"]:
            raise ProtocolError("device_revoked", "设备已撤销", status=403)
        return row

    def context(self, db, device, service_id, conversation_id=None):
        if service_id != self.meta(db, "service_id"):
            raise ProtocolError("permission_denied", "服务实例不匹配", status=403)
        conv = db.execute("SELECT id,authorization_version,crypto_state_ref FROM conversation").fetchone()
        if conversation_id is not None and conversation_id != conv["id"]:
            raise ProtocolError("permission_denied", "会话不可访问", status=403)
        member = db.execute("SELECT 1 FROM members WHERE account=? AND device=?", (device["account"], device["device"])).fetchone()
        if conversation_id is not None and member is None:
            raise ProtocolError("permission_denied", "设备没有当前会话权限", status=403)
        return conv

    @staticmethod
    def append_event(db, pair, event, acceptance_id=None):
        from reclamation_storage import watermarks
        if db.execute("SELECT COUNT(*) FROM events WHERE compacted=0").fetchone()[0] >= MAX_EVENTS:
            raise ProtocolError("resource_exhausted", "实验事件总量已达上限", status=429, retry_after_ms="1000")
        marks = watermarks(db, pair)
        seq = marks["high_watermark"] + 1
        if db.execute("SELECT COUNT(*) FROM events WHERE account=? AND device=? AND compacted=0", pair).fetchone()[0] >= MAX_STREAM_EVENTS:
            raise ProtocolError("resource_exhausted", "设备事件流已达实验上限", status=429, retry_after_ms="1000")
        if seq > (1 << 63) - 1:
            raise ProtocolError("resource_exhausted", "SQLite设备流序号已达整数上限", status=429)
        db.execute("INSERT INTO events(account,device,seq,event_id,content,acceptance_id) VALUES (?,?,?,?,?,?)",
                   (*pair, seq, identifier(), encode_json(event).decode(), acceptance_id))
        db.execute("UPDATE stream_watermarks SET high_watermark=? WHERE account=? AND device=?", (seq, *pair))

    @staticmethod
    def members(db):
        return [(r["account"], r["device"]) for r in db.execute("SELECT account,device FROM members ORDER BY account,device")]


def logical_key(service_id, conversation_id, device, logical_id):
    return json.dumps([service_id, conversation_id, device["account"], device["device"], logical_id], separators=(",", ":"))


def remove_access(db, pair):
    db.execute("UPDATE events SET availability='access_removed' WHERE account=? AND device=? AND availability='available'", pair)


def replace_members(db, members):
    current = {(r["account"], r["device"]) for r in db.execute("SELECT account,device FROM members")}
    for removed in current - set(members):
        remove_access(db, removed)
    db.execute("DELETE FROM members")
    db.executemany("INSERT INTO members VALUES (?,?)", members)


def revoke_device(db, pair):
    db.execute("UPDATE devices SET revoked=1 WHERE account=? AND device=?", pair)
    db.execute("DELETE FROM members WHERE account=? AND device=?", pair)
    remove_access(db, pair)
