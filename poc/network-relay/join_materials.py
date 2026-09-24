"""账号邀请与同账号设备加入的目录约束、一次性材料及访问；不授予旧历史。"""

import hashlib
import json

from contract import ProtocolError, encode_json
from permission_contract import JOIN_ACTIONS, validate_join, validate_proof
from permission_records import require_receipts

MAX_MATERIAL_RESPONSE = 900 * 1024
JOIN_SCHEMA = """
CREATE TABLE device_public_keys (account TEXT, device TEXT, signature_key TEXT NOT NULL UNIQUE,
    PRIMARY KEY(account,device), FOREIGN KEY(account,device) REFERENCES devices(account,device));
CREATE TABLE membership_history (account TEXT, device TEXT, PRIMARY KEY(account,device),
    FOREIGN KEY(account,device) REFERENCES devices(account,device));
CREATE TABLE join_materials (change_id TEXT PRIMARY KEY REFERENCES permission_changes(change_id),
    account TEXT NOT NULL, device TEXT NOT NULL, key_package TEXT NOT NULL, welcome TEXT NOT NULL,
    key_package_sha256 TEXT NOT NULL UNIQUE,
    FOREIGN KEY(account,device) REFERENCES devices(account,device));
"""


def install_join_schema(db, new_database, fixture_devices):
    for statement in JOIN_SCHEMA.strip().split(";"):
        if statement.strip():
            db.execute(statement)
    row = db.execute("SELECT checkpoint FROM permission_checkpoint").fetchone()
    members = json.loads(row["checkpoint"])["members"] if row else []
    # 旧库的初始成员历史不完整，保留原功能但禁用Add；不能从重启fixture补信任。
    devices = fixture_devices if new_database else members
    for device in devices:
        if "signature_key" in device:
            db.execute("INSERT INTO device_public_keys VALUES (?,?,?)", (device["account_id"], device["device_id"], device["signature_key"]))
    db.executemany("INSERT INTO membership_history VALUES (?,?)", [(m["account_id"], m["device_id"]) for m in members])
    db.execute("INSERT INTO meta VALUES ('join_enabled',?)", ("1" if new_database and row else "0",))


def existing_join(db, change_id, join):
    row = db.execute("SELECT key_package,welcome FROM join_materials WHERE change_id=?", (change_id,)).fetchone()
    if row is None:
        raise ProtocolError("permission_conflict", "已接受的入群记录缺少同事务材料", status=409)
    if dict(row) != join:
        raise ProtocolError("idempotency_conflict", "已接受的入群材料不可改变字节", status=409)


def require_join(store, db):
    require_receipts(store)
    if store.meta(db, "join_enabled") != "1":
        raise ProtocolError("join_not_enabled", "旧实验库缺少完整成员历史，不能接受首次入群", status=409)


def prepare_join(store, db, checkpoint, statement, join):
    action, actor = statement["action"], statement["actor"]
    member = action["member"]
    if action["kind"] == "add_member":
        if actor["account_id"] != checkpoint["owner_account_id"]:
            raise ProtocolError("permission_denied", "只有当前群主账号设备可以邀请新账号", status=403)
        known = db.execute("SELECT 1 FROM membership_history WHERE account=?", (member["account_id"],)).fetchone()
    elif action["kind"] == "add_device":
        if actor["account_id"] != member["account_id"] or actor["device_id"] == member["device_id"]:
            raise ProtocolError("permission_denied", "同账号新设备必须由该账号当前有效旧设备授权", status=403)
        known = db.execute("SELECT 1 FROM membership_history WHERE account=? AND device=?", (member["account_id"], member["device_id"])).fetchone()
    else:
        raise ProtocolError("permission_denied", "此操作不能授予入群材料", status=403)
    row = db.execute("SELECT d.revoked,k.signature_key FROM devices d LEFT JOIN device_public_keys k ON k.account=d.account AND k.device=d.device WHERE d.account=? AND d.device=?",
                     (member["account_id"], member["device_id"])).fetchone()
    if row is None or row["revoked"] or row["signature_key"] != member["signature_key"]:
        raise ProtocolError("permission_denied", "入群目标缺少匹配的已登记有效设备公钥", status=403)
    if known:
        raise ProtocolError("permission_denied", "该账号或设备曾经加入，不可通过此动作重复授权", status=403)
    if db.execute("SELECT 1 FROM join_materials WHERE key_package_sha256=?", (action["key_package_sha256"],)).fetchone():
        raise ProtocolError("permission_replay", "入群 KeyPackage 已被接受使用", status=409)
    for name, raw in zip(("key_package", "welcome"), validate_join(join)):
        if hashlib.sha256(raw).hexdigest() != action[name + "_sha256"]:
            raise ProtocolError("join_material_mismatch", "入群材料与签名声明摘要不一致", status=400)


def save_join(db, statement, change, receipt, join):
    result = {"record": {"change": change, "receipt": receipt}, "join": join}
    if len(encode_json({"ok": True, "result": result})) > MAX_MATERIAL_RESPONSE:
        raise ProtocolError("resource_exhausted", "完整入群材料响应超过 900 KiB", status=429)
    member = statement["action"]["member"]
    pair = (member["account_id"], member["device_id"])
    db.execute("INSERT INTO join_materials VALUES (?,?,?,?,?,?)", (statement["change_id"], *pair,
               join["key_package"], join["welcome"], statement["action"]["key_package_sha256"]))
    db.execute("INSERT INTO membership_history VALUES (?,?)", pair)


def get_join_material(store, db, device, req):
    store.context(db, device, req["service_id"], req["conversation_id"])
    row = db.execute("SELECT j.account,j.device,j.key_package,j.welcome,p.proof,p.result FROM join_materials j JOIN permission_changes p ON p.change_id=j.change_id WHERE j.change_id=?",
                     (req["change_id"],)).fetchone()
    if row is None or (row["account"], row["device"]) != (device["account"], device["device"]):
        raise ProtocolError("permission_denied", "入群材料仅允许原目标且当前有效的成员设备领取", status=403)
    change = json.loads(row["proof"])
    statement = validate_proof(change)
    if (statement["action"]["kind"] not in JOIN_ACTIONS or statement["change_id"] != req["change_id"]
            or statement["service_id"] != req["service_id"] or statement["conversation_id"] != req["conversation_id"]
            or (statement["action"]["member"]["account_id"], statement["action"]["member"]["device_id"]) != (row["account"], row["device"])):
        raise ProtocolError("permission_conflict", "持久材料与接受动作或目标不一致", status=409)
    return {"record": {"change": change, "receipt": json.loads(row["result"])["receipt"]},
            "join": {"key_package": row["key_package"], "welcome": row["welcome"]}}
