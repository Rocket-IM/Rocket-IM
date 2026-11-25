"""生命周期动作在原 Relay BEGIN IMMEDIATE 内执行；提交前不返回公开成功。"""
import json
import time
from contract import encode_json
from key_package_contract import request, digest, receipt
from key_package_storage import fail, capacity, inventory
from permission_records import require_receipts
from permissions import checkpoint_record

def registered(db, member):
    row = db.execute("SELECT d.revoked,k.signature_key,r.proof_json FROM devices d LEFT JOIN device_public_keys k ON k.account=d.account AND k.device=d.device LEFT JOIN device_registrations r ON r.account=d.account AND r.device=d.device AND r.proof_json IS NOT NULL WHERE d.account=? AND d.device=?", (member["account_id"], member["device_id"])).fetchone()
    if row is None or row["revoked"] or row["signature_key"] != member["signature_key"] or row["proof_json"] is None:
        fail("key_package_identity", 403)

def scope(store, db, device, statement):
    action = statement["action"]
    if action["kind"] == "directory":
        account = action["account_id"]
        if account == device["account"]: return
        _, cp = checkpoint_record(db)
        store.context(db, device, statement["service_id"], cp["conversation_id"])
        if account not in {m["account_id"] for m in cp["members"]} and device["account"] != cp["owner_account_id"]:
            fail("permission_denied", 403)
        if not db.execute("SELECT 1 FROM devices WHERE account=?", (account,)).fetchone(): fail("permission_denied", 403)
    elif action["kind"] == "claim":
        registered(db, action["target"])
        store.context(db, device, statement["service_id"], action["conversation_id"])
        _, cp = checkpoint_record(db)
        if action["join_kind"] == "add_member":
            if device["account"] != cp["owner_account_id"]: fail("permission_denied", 403)
        elif action["target"]["account_id"] != device["account"] or action["target"]["device_id"] == device["device"]:
            fail("permission_denied", 403)

def publish(store, db, statement):
    actor = statement["actor"]; pair = (actor["account_id"], actor["device_id"])
    hashes, fresh = [], []
    for encoded in statement["action"]["packages"]:
        material = store.permission_verifier._call({"operation": "verify_key_package", "key_package": encoded,
            "service_id": statement["service_id"], "owner": actor})["material"]
        hashes.append(material["key_package_sha256"])
        old = db.execute("SELECT * FROM kp_materials WHERE hash=? OR init_key=? OR ref=?", (material["key_package_sha256"], material["init_key"], material["key_package_ref"])).fetchone()
        if old:
            if old["hash"] != material["key_package_sha256"] or old["encoded"] != encoded or old["state"] != "available" or (old["account"], old["device"]) != pair:
                fail("key_package_reuse")
        else: fresh.append((encoded, material))
    available = sum(int(json.loads(row[0])["not_after"]) > int(time.time()) for row in db.execute("SELECT metadata FROM kp_materials WHERE account=? AND device=? AND state='available'", pair))
    if available + len(fresh) > 8: fail("resource_exhausted", 429)
    for encoded, material in fresh:
        db.execute("INSERT INTO kp_materials VALUES (?,?,?,?,?,?,?,'available',NULL,NULL)", (material["key_package_sha256"], *pair, encoded, encode_json(material).decode(), material["init_key"], material["key_package_ref"]))
    return {"kind": "published", "hashes": hashes, "inventory_version": inventory(db, pair, bool(fresh))}

def claim(store, db, device, statement, now):
    action = statement["action"]; target = action["target"]; pair = (target["account_id"], target["device_id"])
    _, cp = checkpoint_record(db)
    if any(cp[name] != action[name] for name in ("conversation_id", "authorization_version", "crypto_state_ref")):
        fail("key_package_predecessor")
    history_sql = "SELECT 1 FROM membership_history WHERE account=?" + (" AND device=?" if action["join_kind"] == "add_device" else "")
    if db.execute(history_sql, pair if action["join_kind"] == "add_device" else (pair[0],)).fetchone(): fail("permission_denied", 403)
    head = db.execute("SELECT version,hash FROM kp_directories WHERE account=? ORDER BY version DESC LIMIT 1", (pair[0],)).fetchone()
    if head is None or str(head["version"]) != action["directory_version"] or head["hash"] != action["directory_sha256"]:
        fail("directory_stale")
    for sql, args in (("account=? AND device=?", (device["account"], device["device"])), ("target_account=? AND target_device=?", pair)):
        if db.execute(f"SELECT count(*) FROM kp_requests WHERE kind='claim' AND created_ms>? AND {sql}", (now - 60000, *args)).fetchone()[0] >= 16:
            fail("resource_exhausted", 429)
    if db.execute("SELECT 1 FROM kp_requests WHERE account=? AND device=? AND change_id=?", (device["account"], device["device"], action["change_id"])).fetchone():
        fail("key_package_change_conflict")
    for row in db.execute("SELECT * FROM kp_materials WHERE account=? AND device=? AND state='available' ORDER BY hash", pair).fetchall():
        material = json.loads(row["metadata"])
        if int(material["not_before"]) <= now // 1000 < int(material["not_after"]):
            # 事务内再次交给真实库验证；有效期可能在辅助程序运行期间到达。
            store.permission_verifier._call({"operation": "verify_key_package", "key_package": row["encoded"], "service_id": statement["service_id"], "owner": target})
            if not int(material["not_before"]) <= int(time.time()) < int(material["not_after"]): fail("key_package_expired")
            db.execute("UPDATE kp_materials SET state='allocated' WHERE hash=? AND state='available'", (row["hash"],))
            return {"kind": "allocated", "key_package": row["encoded"], "key_package_sha256": row["hash"],
                    "inventory_version": inventory(db, pair, True), "allocated_at_ms": str(now)}
    return {"kind": "unavailable", "inventory_version": inventory(db, pair)}

def execute(store, db, device, req):
    statement = request(req["proof"])
    store.context(db, device, statement["service_id"])
    actor = statement["actor"]; pair = (device["account"], device["device"])
    if pair != (actor["account_id"], actor["device_id"]): fail("key_package_identity", 403)
    registered(db, actor); scope(store, db, device, statement); require_receipts(store)
    if store.permission_verifier is None: fail("permission_verifier_unavailable", 503)
    validated = store.permission_verifier._call({"operation": "verify_key_package_request", "proof": req["proof"]})
    if validated != {"statement": statement}: fail("permission_verifier_unavailable", 503)
    exact = encode_json({k: req["proof"][k] for k in ("statement_bytes", "signature_bytes")}).decode()
    old = db.execute("SELECT proof,receipt FROM kp_requests WHERE account=? AND device=? AND request_id=?", (*pair, statement["request_id"])).fetchone()
    if old:
        if old["proof"] != exact: fail("idempotency_conflict")
        return {"receipt": json.loads(old["receipt"])}
    if db.execute("SELECT count(*) FROM kp_requests").fetchone()[0] >= 64: fail("resource_exhausted", 429)
    action = statement["action"]; kind = action["kind"]; now = int(time.time() * 1000)
    if kind == "publish": result = publish(store, db, statement)
    elif kind == "claim": result = claim(store, db, device, statement, now)
    elif kind == "directory":
        snapshots = [r[0] for r in db.execute("SELECT bytes FROM kp_directories WHERE account=? ORDER BY version", (action["account_id"],))]
        if not snapshots: fail("directory_required")
        result = {"kind": "directory", "challenge": action["challenge"], "snapshots": snapshots}
    else:
        row = db.execute("SELECT * FROM kp_materials WHERE hash=?", (action["key_package_sha256"],)).fetchone()
        if row is None or (row["account"], row["device"]) != pair: fail("key_package_identity", 403)
        if row["state"] not in ("available", "retired") or row["allocation"] is not None: fail("key_package_allocated")
        db.execute("UPDATE kp_materials SET state='retired' WHERE hash=?", (row["hash"],))
        result = {"kind": "retired", "key_package_sha256": row["hash"], "inventory_version": inventory(db, pair, row["state"] == "available")}
    value = {"protocol_version": "rim-key-package-receipt-1", "service_id": statement["service_id"], "request_sha256": digest(req["proof"]), "result": result}
    receipt(value)
    signed_result = store.receipt_signer.sign(value)
    target = action.get("target", {})
    db.execute("INSERT INTO kp_requests VALUES (?,?,?,?,?,?,?,?,?,?)", (*pair, statement["request_id"], exact, encode_json(signed_result).decode(), kind, target.get("account_id"), target.get("device_id"), action.get("change_id"), now))
    if result["kind"] == "allocated":
        db.execute("UPDATE kp_materials SET allocation=? WHERE hash=?", (digest(signed_result), result["key_package_sha256"]))
    capacity(db)
    if result["kind"] in ("published", "allocated"):
        from key_package_commit import TimedResult
        hashes = result.get("hashes", [result.get("key_package_sha256")])
        deadline = min(int(json.loads(db.execute("SELECT metadata FROM kp_materials WHERE hash=?", (hash_value,)).fetchone()[0])["not_after"]) for hash_value in hashes)
        return TimedResult({"receipt": signed_result}, deadline)
    return {"receipt": signed_result}
