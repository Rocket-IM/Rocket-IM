"""恢复 R0：原件、材料、后继、权限 head 在原 Relay 事务中一并提交。"""
import json
from key_package_storage import fail
from permission_records import proof_json
from join_recovery_contract import signed_digest, candidate_digest, admission_ref
from join_recovery_storage import root, encoded
from join_recovery import access, eligible, statement, response, row_for, timed


def accept(store, db, device, bundle):
    verified_intent = store.permission_verifier._call({"operation": "verify_recovery_request", "proof": bundle["intent"]})["statement"]
    if verified_intent["kind"] != "intent": fail("recovery_invalid", 400)
    intent = verified_intent
    cp, who = access(store, db, device, intent)
    if who != intent["actor"]: fail("permission_denied", 403)
    row = row_for(db, intent["request_id"])
    if row is None: fail("key_package_unavailable")
    if (json.loads(row["intent"]) != bundle["intent"] or row["change_id"] != intent["change_id"]): fail("idempotency_conflict")
    if row["state"] == "closed": return response(db, row)
    if json.loads(row["claim"]) != bundle["claim"] or json.loads(row["allocation"]) != bundle["allocation"]: fail("idempotency_conflict")
    if row["state"] == "accepted":
        if json.loads(row["bundle"]) != bundle: fail("idempotency_conflict")
        return response(db, row)
    root_row, record, original = root(store, db, intent)
    eligible(store, db, intent, cp, root_row, original)
    validated = store.permission_verifier._call({"operation": "verify_recovery_candidate", "checkpoint": cp,
        "root": record, "source_key": store.receipt_signer.signature_key, "bundle": bundle})
    next_cp, candidate = validated["checkpoint"], validated["statement"]
    material = db.execute("SELECT * FROM kp_materials WHERE hash=?", (intent["key_package_sha256"],)).fetchone()
    if (material is None or material["state"] != "allocated" or material["allocation"] != signed_digest(bundle["allocation"])
            or material["encoded"] != bundle["key_package"]): fail("key_package_unavailable")
    if db.execute("SELECT 1 FROM permission_changes WHERE nonce=?", (candidate["nonce"],)).fetchone(): fail("permission_replay")
    result = {"kind": "accepted", "allocation_sha256": signed_digest(bundle["allocation"]),
              "candidate_sha256": candidate_digest(bundle["change"]), "checkpoint": next_cp}
    receipt = store.receipt_signer.sign(statement(intent, bundle["intent"], result))
    from synchronization import MAX_PAGE_BYTES
    from contract import encode_json
    public = {"recovery": {"bundle": {k: bundle[k] for k in ("intent", "claim", "allocation", "change")}, "receipt": receipt}}
    if len(encode_json(public)) > MAX_PAGE_BYTES: fail("resource_exhausted", 429)
    successor = encoded(admission_ref(bundle["change"], receipt))
    value = {"outcome": "accepted", "change_id": intent["change_id"], "authorization_version": next_cp["authorization_version"],
             "crypto_state_ref": next_cp["crypto_state_ref"], "receipt": receipt}
    initial = db.execute("SELECT initial_version FROM permission_checkpoint WHERE singleton=1").fetchone()[0]
    actor = intent["actor"]
    db.execute("INSERT INTO permission_changes VALUES (?,?,?,?,?,?,?,?)", (intent["change_id"], int(next_cp["authorization_version"]) - int(initial),
        next_cp["authorization_version"], actor["account_id"], actor["device_id"], candidate["nonce"], proof_json(bundle["change"]), encoded(value)))
    db.execute("INSERT INTO permission_resolutions VALUES (?,?,?,?,?,?)", (intent["change_id"], actor["account_id"], actor["device_id"], proof_json(bundle["change"]), "accepted", encoded(receipt)))
    db.execute("UPDATE recovery_attempts SET state='accepted',bundle=?,terminal=? WHERE recovery_id=?", (encoded(bundle), encoded(receipt), intent["request_id"]))
    db.execute("INSERT INTO recovery_edges VALUES (?,?,?,?)", (row["root_id"], row["current_ref"], successor, intent["request_id"]))
    changed = db.execute("UPDATE recovery_roots SET current_ref=?,current_package=? WHERE root_id=? AND current_ref=?",
                        (successor, intent["key_package_sha256"], row["root_id"], row["current_ref"])).rowcount
    if changed != 1: fail("recovery_superseded")
    db.execute("DELETE FROM recovery_active WHERE recovery_id=?", (intent["request_id"],))
    db.execute("UPDATE kp_materials SET state='accepted',accepted_change=? WHERE hash=?", (intent["change_id"], intent["key_package_sha256"]))
    db.execute("UPDATE permission_checkpoint SET checkpoint=? WHERE singleton=1", (encoded(next_cp),))
    db.execute("UPDATE conversation SET authorization_version=?,crypto_state_ref=?", (next_cp["authorization_version"], next_cp["crypto_state_ref"]))
    # 成员及 membership_history 不变；沿原权限链公布唯一 R0。旧消息槽不重新分配。
    return timed(response(db, row_for(db, intent["request_id"])), intent, json.loads(material["metadata"]), candidate)
