"""过期入群恢复的公开业务事务；真实 MLS 安装只在客户端发生。"""
import json
import time
from contract import encode_json
from key_packages import registered
from key_package_storage import fail, inventory
from key_package_commit import TimedResult
from permission_records import require_receipts, proof_json
from permissions import checkpoint_record
from join_recovery_contract import signed, signed_digest, candidate_digest, admission_ref
from join_recovery_storage import encoded, root, capacity, check_request, reserve_request


def floor(cp):
    return {k: cp[k] for k in ("authorization_version", "crypto_state_ref")}


def access(store, db, device, intent):
    scope = intent["scope"]
    store.context(db, device, scope["service_id"], scope["conversation_id"])
    _, cp = checkpoint_record(db)
    who = next((m for m in (intent["signer"], intent["actor"]) if
                (m["account_id"], m["device_id"]) == (device["account"], device["device"])), None)
    if who is None or who not in cp["members"]: fail("permission_denied", 403)
    registered(db, who)
    return cp, who


def eligible(store, db, intent, cp, root_row, original):
    from join_recovery_witness import eligible as witness_eligible
    witness_config = witness_eligible(store, db, intent, cp)
    for member in (intent["signer"], intent["actor"]):
        registered(db, member)
        if member not in cp["members"]: fail("permission_denied", 403)
    account = intent["signer"]["account_id"] if original["add_device"] else cp["owner_account_id"]
    if intent["actor"]["account_id"] != account: fail("permission_denied", 403)
    if json.loads(root_row["current_ref"]) != intent["current_admission"]: fail("recovery_superseded")
    if floor(cp) != intent["predecessor"]: fail("recovery_predecessor_changed")
    for directory in intent["directory_refs"]:
        row = db.execute("SELECT version,hash FROM kp_directories WHERE account=? ORDER BY version DESC LIMIT 1", (directory["account_id"],)).fetchone()
        if row is None or (str(row["version"]), row["hash"]) != (directory["version"], directory["sha256"]):
            fail("directory_stale")
    old = db.execute("SELECT metadata FROM kp_materials WHERE hash=? AND state='accepted'", (root_row["current_package"],)).fetchone()
    if old is None: fail("recovery_invalid", 400)
    if int(time.time()) < int(json.loads(old[0])["not_after"]): fail("recovery_not_expired")
    return witness_config


def statement(intent, proof, result):
    modern = intent["protocol_version"] == "rim-recovery-request-2"
    value = {"protocol_version": "rim-recovery-receipt-2" if modern else "rim-recovery-receipt-1", "scope": intent["scope"],
            "recovery_id": intent["request_id"], "change_id": intent["change_id"],
            "root_admission": intent["root_admission"], "current_admission": intent["current_admission"],
            "target": intent["signer"], "actor": intent["actor"], "intent_sha256": signed_digest(proof), "result": result}
    if modern:
        value.update(witness_profile="E10C-W1", policy_ref=intent["policy_ref"])
    return value


def response(db, row, reader=None):
    _, cp = checkpoint_record(db)
    result = {"state": "absent" if row is None else row["state"], "head": cp}
    if row is not None:
        result.update({"intent": json.loads(row["intent"]), "allocation": json.loads(row["allocation"]) if row["allocation"] else None,
                       "receipt": json.loads(row["terminal"]) if row["terminal"] else None,
                       "record": {"bundle": json.loads(row["bundle"]), "receipt": json.loads(row["terminal"])} if row["bundle"] else None})
        if row["allocation"]:
            intent = signed(json.loads(row["intent"]))
            result["key_package"] = db.execute("SELECT encoded FROM kp_materials WHERE hash=?", (intent["key_package_sha256"],)).fetchone()[0]
    if row is not None and row["state"] == "accepted" and reader is not None:
        intent = signed(json.loads(row["intent"]))
        current = db.execute("SELECT current_ref FROM recovery_roots WHERE root_id=?", (row["root_id"],)).fetchone()[0]
        if reader == intent["signer"] and current != encoded(admission_ref(json.loads(row["bundle"])["change"], json.loads(row["terminal"]))):
            result["record"] = None
            result.pop("key_package", None)
    if len(encode_json({"ok": True, "result": result})) > 900 * 1024: fail("resource_exhausted", 429)
    return result


def row_for(db, recovery_id):
    return db.execute("SELECT * FROM recovery_attempts WHERE recovery_id=?", (recovery_id,)).fetchone()


def timed(value, intent, material, candidate=None):
    starts = [intent["issued_at_unix_secs"], material["not_before"]]
    ends = [intent["expires_at_unix_secs"], material["not_after"]]
    if candidate:
        starts.append(candidate["issued_at_unix_secs"]); ends.append(candidate["expires_at_unix_secs"])
    return TimedResult(value, min(map(int, ends)), max(map(int, starts)), "recovery_expired")


def allocate(store, db, intent, proof, claim, root_row, original, cp):
    witness_config = eligible(store, db, intent, cp, root_row, original)
    if db.execute("SELECT 1 FROM recovery_active WHERE root_id=? AND current_ref=?", (root_row["root_id"], encoded(intent["current_admission"]))).fetchone():
        fail("recovery_busy")
    row = db.execute("SELECT * FROM kp_materials WHERE hash=?", (intent["key_package_sha256"],)).fetchone()
    if row is None or row["state"] != "available" or (row["account"], row["device"]) != (intent["signer"]["account_id"], intent["signer"]["device_id"]):
        fail("key_package_unavailable")
    material = store.permission_verifier._call({"operation": "verify_key_package", "key_package": row["encoded"],
        "service_id": intent["scope"]["service_id"], "owner": intent["signer"]})["material"]
    result = {"kind": "allocated", "claim_sha256": signed_digest(claim), "key_package_sha256": row["hash"],
              "key_package_ref": material["key_package_ref"], "predecessor": intent["predecessor"]}
    receipt = store.receipt_signer.sign(statement(intent, proof, result))
    db.execute("INSERT INTO recovery_attempts VALUES (?,?,?,?,?,?,?,?,?,'allocated',NULL,NULL)", (intent["request_id"], intent["change_id"],
        root_row["root_id"], encoded(intent["current_admission"]), encoded(intent["signer"]), encoded(proof), encoded(cp), encoded(claim), encoded(receipt)))
    db.execute("INSERT INTO recovery_active VALUES (?,?,?)", (root_row["root_id"], encoded(intent["current_admission"]), intent["request_id"]))
    from join_recovery_witness_storage import bind
    bind(db, intent, witness_config)
    db.execute("UPDATE kp_materials SET state='allocated',allocation=? WHERE hash=?", (signed_digest(receipt), row["hash"]))
    inventory(db, (row["account"], row["device"]), True)
    return timed(response(db, row_for(db, intent["request_id"])), intent, material)


def close(store, db, intent, proof, control, control_proof, row, cp, root_row):
    if row is not None and row["state"] != "allocated": return response(db, row, control["signer"])
    from join_recovery_witness import policy_for
    witness_config = policy_for(store, db, intent, first_use=False)
    allocation = json.loads(row["allocation"]) if row else None
    result = {"kind": "closed", "close_sha256": signed_digest(control_proof), "reason": control["reason"],
              "checkpoint": cp, "allocation_sha256": signed_digest(allocation) if allocation else None}
    receipt = store.receipt_signer.sign(statement(intent, proof, result))
    if row is None:
        db.execute("INSERT INTO recovery_attempts VALUES (?,?,?,?,?,?,?,NULL,NULL,'closed',NULL,?)", (intent["request_id"], intent["change_id"],
            root_row["root_id"], encoded(intent["current_admission"]), encoded(intent["signer"]), encoded(proof), encoded(cp), encoded(receipt)))
        from join_recovery_witness_storage import bind
        bind(db, intent, witness_config)
    else:
        db.execute("UPDATE recovery_attempts SET state='closed',terminal=? WHERE recovery_id=?", (encoded(receipt), intent["request_id"]))
        db.execute("DELETE FROM recovery_active WHERE recovery_id=?", (intent["request_id"],))
        changed = db.execute("UPDATE kp_materials SET state='retired' WHERE allocation=? AND state='allocated'", (signed_digest(allocation),)).rowcount
        if changed: inventory(db, (intent["signer"]["account_id"], intent["signer"]["device_id"]), True)
    return response(db, row_for(db, intent["request_id"]))


def execute(store, db, device, req):
    require_receipts(store)
    if store.permission_verifier is None: fail("permission_verifier_unavailable", 503)
    if req["kind"] == "get":
        store.context(db, device, req["service_id"], req["conversation_id"])
        row = row_for(db, req["recovery_id"])
        if row is not None:
            intent = signed(json.loads(row["intent"])); _, who = access(store, db, device, intent)
            if intent["scope"]["service_id"] != req["service_id"] or intent["scope"]["conversation_id"] != req["conversation_id"]: fail("permission_denied", 403)
            current = db.execute("SELECT current_ref FROM recovery_roots WHERE root_id=?", (row["root_id"],)).fetchone()[0]
            if row["state"] == "accepted" and who == intent["signer"] and current != encoded(admission_ref(json.loads(row["bundle"])["change"], json.loads(row["terminal"]))):
                fail("recovery_superseded")
        return response(db, row)
    if req["kind"] == "accept":
        from join_recovery_accept import accept
        return accept(store, db, device, req["bundle"])
    verified = store.permission_verifier._call({"operation": "verify_recovery_control", "proof": req["proof"], "intent": req["intent"]})
    intent, control = verified["intent"], verified["statement"]
    if control["kind"] != req["kind"]: fail("recovery_invalid", 400)
    cp, who = access(store, db, device, intent)
    if control["signer"] != who: fail("permission_denied", 403)
    root_row, _, original = root(store, db, intent)
    row = row_for(db, intent["request_id"])
    if row is not None:
        if json.loads(row["intent"]) != req["intent"]: fail("idempotency_conflict")
        if req["kind"] == "claim" and row["claim"] and json.loads(row["claim"]) != req["proof"]: fail("idempotency_conflict")
    else:
        if db.execute("SELECT 1 FROM recovery_attempts WHERE change_id=? UNION SELECT 1 FROM permission_resolutions WHERE change_id=? UNION SELECT 1 FROM permission_changes WHERE change_id=?", (intent["change_id"],)*3).fetchone():
            fail("idempotency_conflict")
        capacity(db, intent["signer"])
    if req["kind"] == "close" and row is not None and row["state"] == "accepted":
        check_request(db, intent, req["intent"])
        check_request(db, control, req["proof"])
        return response(db, row, control["signer"])
    reserve_request(db, intent, req["intent"], intent["request_id"])
    reserve_request(db, control, req["proof"], intent["request_id"])
    if req["kind"] == "close": return close(store, db, intent, req["intent"], control, req["proof"], row, cp, root_row)
    if row is not None: return response(db, row)
    return allocate(store, db, intent, req["intent"], req["proof"], root_row, original, cp)
