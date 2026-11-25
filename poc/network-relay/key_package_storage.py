"""材料与请求墓碑同库事务；迁移不把旧单份KeyPackage或裸公钥变成库存。"""
import base64
import hashlib
import json
from contract import ProtocolError, encode_json, parse_json
from key_package_contract import request, signed, digest, receipt

SCHEMA = """
CREATE TABLE kp_requests (account TEXT NOT NULL,device TEXT NOT NULL,request_id TEXT NOT NULL,
    proof TEXT NOT NULL,receipt TEXT NOT NULL,kind TEXT NOT NULL,target_account TEXT,target_device TEXT,
    change_id TEXT,created_ms INTEGER NOT NULL,
    PRIMARY KEY(account,device,request_id), UNIQUE(account,device,change_id),
    FOREIGN KEY(account,device) REFERENCES devices(account,device));
CREATE TABLE kp_materials (hash TEXT PRIMARY KEY,account TEXT NOT NULL,device TEXT NOT NULL,
    encoded TEXT NOT NULL,metadata TEXT NOT NULL,init_key TEXT NOT NULL UNIQUE,ref TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK(state IN ('available','allocated','accepted','retired')),
    allocation TEXT UNIQUE,accepted_change TEXT UNIQUE,
    FOREIGN KEY(account,device) REFERENCES devices(account,device),
    FOREIGN KEY(accepted_change) REFERENCES permission_changes(change_id) DEFERRABLE INITIALLY DEFERRED);
CREATE TABLE kp_directories (account TEXT NOT NULL,version INTEGER NOT NULL,bytes TEXT NOT NULL,hash TEXT NOT NULL,
    PRIMARY KEY(account,version),UNIQUE(account,hash));
CREATE TABLE kp_inventory (account TEXT NOT NULL,device TEXT NOT NULL,version INTEGER NOT NULL,
    PRIMARY KEY(account,device),FOREIGN KEY(account,device) REFERENCES devices(account,device));
"""
TABLES = ("kp_requests", "kp_materials", "kp_directories", "kp_inventory")

def fail(code, status=409):
    raise ProtocolError(code, "目录或一次性材料不满足当前约束", status=status)

def capacity(db):
    rows = {table: db.execute(f"SELECT * FROM {table}").fetchall() for table in TABLES}
    if (len(rows["kp_requests"]) > 64 or len(rows["kp_materials"]) > 32
            or sum(len(encode_json(dict(row))) for values in rows.values() for row in values) > 2 * 1024 * 1024):
        fail("resource_exhausted", 429)

def inventory(db, pair, advance=False):
    row = db.execute("SELECT version FROM kp_inventory WHERE account=? AND device=?", pair).fetchone()
    version = row[0] if row else 0
    if advance:
        version += 1
        db.execute("INSERT INTO kp_inventory VALUES (?,?,?) ON CONFLICT(account,device) DO UPDATE SET version=excluded.version", (*pair, version))
    return str(version)

def directory_update(db, account):
    rows = db.execute("SELECT r.proof_json,d.revoked FROM device_registrations r JOIN devices d ON d.account=r.account AND d.device=r.device WHERE r.account=? AND r.proof_json IS NOT NULL ORDER BY r.device", (account,)).fetchall()
    if not rows: return
    if len(rows) > 8: fail("resource_exhausted", 429)
    devices = [{"status": "revoked" if row["revoked"] else "active", "registration": json.loads(row["proof_json"])} for row in rows]
    previous = db.execute("SELECT * FROM kp_directories WHERE account=? ORDER BY version DESC LIMIT 1", (account,)).fetchone()
    if previous and parse_json(base64.b64decode(previous["bytes"]))["devices"] == devices: return
    version = previous["version"] + 1 if previous else 1
    if version > 16: fail("resource_exhausted", 429)
    value = {"protocol_version": "rim-device-directory-1", "service_id": db.execute("SELECT value FROM meta WHERE key='service_id'").fetchone()[0],
             "account_id": account, "version": str(version), "previous_sha256": previous["hash"] if previous else "0" * 64,
             "authorization_source": "synthetic-registration-poc", "devices": devices}
    raw = encode_json(value)
    if len(raw) > 16384: fail("resource_exhausted", 429)
    db.execute("INSERT INTO kp_directories VALUES (?,?,?,?)", (account, version, base64.b64encode(raw).decode(), hashlib.sha256(raw).hexdigest()))
    capacity(db)

def revoke(db, pair):
    # 已接受是历史事实；未接受材料永久退役，均不退回可用池。
    changed = db.execute("UPDATE kp_materials SET state='retired' WHERE account=? AND device=? AND state IN ('available','allocated')", pair).rowcount
    if changed: inventory(db, pair, True)
    directory_update(db, pair[0])

def install(db, old_version):
    if not db.in_transaction: raise ValueError("生命周期迁移必须在启动事务内")
    marker = db.execute("SELECT value FROM meta WHERE key='key_package_schema'").fetchone()
    if marker is None:
        if old_version in {"rim-poc-storage-9", "rim-poc-storage-10"}: raise ValueError("生命周期账本标记缺失")
        for statement in SCHEMA.strip().split(";"):
            if statement.strip(): db.execute(statement)
        db.execute("INSERT INTO meta VALUES ('key_package_schema','1')")
        # 仅由已完成注册原件建立候选目录；不从fixture公钥推测。
        for row in db.execute("SELECT DISTINCT account FROM device_registrations WHERE proof_json IS NOT NULL").fetchall():
            directory_update(db, row[0])
    elif marker[0] != "1": raise ValueError("生命周期账本版本不支持")
    try:
        capacity(db)
        for row in db.execute("SELECT * FROM kp_requests"):
            statement = request(json.loads(row["proof"]))
            result = receipt(signed(json.loads(row["receipt"])))
            if (statement["request_id"] != row["request_id"] or statement["actor"]["account_id"] != row["account"]
                    or statement["actor"]["device_id"] != row["device"] or statement["action"]["kind"] != row["kind"]
                    or result["request_sha256"] != digest(json.loads(row["proof"]))): raise ValueError("请求账本损坏")
        for row in db.execute("SELECT * FROM kp_materials"):
            metadata = json.loads(row["metadata"])
            if (hashlib.sha256(base64.b64decode(row["encoded"], validate=True)).hexdigest() != row["hash"]
                    or metadata["key_package_sha256"] != row["hash"] or metadata["init_key"] != row["init_key"]
                    or metadata["key_package_ref"] != row["ref"] or (row["state"] == "accepted") != (row["accepted_change"] is not None)
                    or (row["state"] in ("allocated", "accepted") and row["allocation"] is None)):
                raise ValueError("材料账本损坏")
        accounts = db.execute("SELECT DISTINCT account FROM kp_directories").fetchall()
        for account in accounts:
            previous = "0" * 64
            for version, row in enumerate(db.execute("SELECT * FROM kp_directories WHERE account=? ORDER BY version", (account[0],)), 1):
                raw = base64.b64decode(row["bytes"], validate=True); value = parse_json(raw)
                if version > 16 or row["version"] != version or value["version"] != str(version) or value["previous_sha256"] != previous or hashlib.sha256(raw).hexdigest() != row["hash"]:
                    raise ValueError("目录链损坏")
                previous = row["hash"]
    except (ProtocolError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise ValueError("生命周期持久格式损坏") from error
