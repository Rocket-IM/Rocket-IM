"""有界注册原件账本；预留完成态成本，旧公钥不自动获得私钥持有证明。"""

import base64
import json

from contract import ProtocolError, encode_json
from registration_contract import challenge, proof, registered

VERSION = "rim-registration-storage-1"
MAX_REGISTRATIONS = 128
MAX_DEVICE_REGISTRATIONS = 32
MAX_REGISTRATION_BYTES = 2 * 1024 * 1024
SCHEMA = """
CREATE TABLE device_registrations (
    account TEXT NOT NULL, device TEXT NOT NULL, registration_id TEXT NOT NULL,
    challenge_bytes TEXT NOT NULL, proof_json TEXT, result_json TEXT,
    PRIMARY KEY(account,device,registration_id),
    FOREIGN KEY(account,device) REFERENCES devices(account,device),
    CHECK ((proof_json IS NULL AND result_json IS NULL)
        OR (proof_json IS NOT NULL AND result_json IS NOT NULL)));
CREATE UNIQUE INDEX completed_device_registration ON device_registrations(account,device)
    WHERE proof_json IS NOT NULL;
"""


def reserved_bytes(row):
    """计入全部逻辑行字段；固定64B签名和完成结果保证完成操作不增加预留成本。"""
    record = dict(row)
    statement = challenge(record["challenge_bytes"])
    # 所有规范Base64签名长度相同；JSON不会转义其字母表，因此占用完全相等。
    record["proof_json"] = encode_json({"statement_bytes": record["challenge_bytes"],
                                       "signature_bytes": base64.b64encode(bytes(64)).decode()}).decode()
    record["result_json"] = encode_json(registered(statement)).decode()
    return len(encode_json(record))


def capacity(db, candidate):
    rows = db.execute("SELECT * FROM device_registrations").fetchall()
    pair = (candidate["account"], candidate["device"])
    if (len(rows) >= MAX_REGISTRATIONS
            or sum((row["account"], row["device"]) == pair for row in rows) >= MAX_DEVICE_REGISTRATIONS
            or sum(reserved_bytes(row) for row in rows) + reserved_bytes(candidate) > MAX_REGISTRATION_BYTES):
        raise ProtocolError("resource_exhausted", "注册挑战账本已达实验上限", status=429)


def install(db, previous_schema):
    if not db.in_transaction:
        raise ValueError("注册迁移必须使用原启动事务")
    marker = db.execute("SELECT value FROM meta WHERE key='registration_schema'").fetchone()
    if marker is None:
        if previous_schema == "rim-poc-storage-8":
            raise ValueError("注册版本标记缺失，禁止补造注册事实")
        for statement in SCHEMA.strip().split(";"):
            if statement.strip():
                db.execute(statement)
        db.execute("INSERT INTO meta VALUES ('registration_schema',?)", (VERSION,))
        return
    if marker["value"] != VERSION:
        raise ValueError("不支持此注册存储版本")
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='device_registrations'").fetchone():
        raise ValueError("注册持久账本缺失，禁止重新生成")
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='index' AND name='completed_device_registration'").fetchone():
        raise ValueError("注册唯一完成约束缺失")
    rows = db.execute("SELECT * FROM device_registrations").fetchall()
    counts = {}
    try:
        for row in rows:
            statement = challenge(row["challenge_bytes"])
            pair = (row["account"], row["device"])
            counts[pair] = counts.get(pair, 0) + 1
            if (statement["service_id"] != db.execute("SELECT value FROM meta WHERE key='service_id'").fetchone()[0]
                    or pair != (statement["account_id"], statement["device_id"])
                    or row["registration_id"] != statement["registration_id"]
                    or not db.execute("SELECT 1 FROM devices WHERE account=? AND device=?", pair).fetchone()
                    or (row["proof_json"] is None) != (row["result_json"] is None)):
                raise ValueError("注册持久记录范围或完成状态无效")
            if row["proof_json"] is not None:
                saved = json.loads(row["proof_json"])
                key = db.execute("SELECT signature_key FROM device_public_keys WHERE account=? AND device=?", pair).fetchone()
                if (proof(saved) != statement or saved["statement_bytes"] != row["challenge_bytes"]
                        or json.loads(row["result_json"]) != registered(statement)
                        or row["proof_json"] != encode_json({name: saved[name] for name in ("statement_bytes", "signature_bytes")}).decode()
                        or row["result_json"] != encode_json(registered(statement)).decode()
                        or key is None or key["signature_key"] != statement["signature_key"]):
                    raise ValueError("注册完成事实与原挑战或设备公钥不一致")
        if (len(rows) > MAX_REGISTRATIONS or any(count > MAX_DEVICE_REGISTRATIONS for count in counts.values())
                or sum(reserved_bytes(row) for row in rows) > MAX_REGISTRATION_BYTES):
            raise ValueError("注册持久账本超过实验上限")
    except (ProtocolError, TypeError, KeyError, json.JSONDecodeError) as error:
        raise ValueError("注册持久材料无效") from error
