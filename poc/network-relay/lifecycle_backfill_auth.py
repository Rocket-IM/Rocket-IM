"""核对既有验签持久事实的关联；不重验历史签名或从启动 fixture 补信任。"""

import hashlib
import json

from contract import ProtocolError, decode_bytes, parse_u64, MAX_PAYLOAD_BYTES
from permission_contract import validate_checkpoint, validate_proof
from receipt_contract import terminal_statement, validate_receipt
from storage import Store, subject


def untrusted():
    return ProtocolError("lifecycle_backfill_untrusted", "历史回填缺少一致的权限与接受证据", status=409)


def authority(store, db):
    """返回版本对应密码状态和历史动作；信任来源仍为此前已验证并持久化的链。"""
    try:
        return _authority(store, db)
    except (ProtocolError, ValueError, KeyError, TypeError, AttributeError):
        raise untrusted() from None


def _authority(store, db):
    record = db.execute("SELECT initial_version,checkpoint FROM permission_checkpoint WHERE singleton=1").fetchone()
    pinned = db.execute("SELECT value FROM meta WHERE key='relay_receipt_key'").fetchone()
    if (record is None or pinned is None or not store.permission_enabled or not store.receipt_enabled
            or store.receipt_signer is None or store.receipt_signer.signature_key != pinned["value"]):
        raise untrusted()
    checkpoint = validate_checkpoint(json.loads(record["checkpoint"]))
    current = parse_u64(checkpoint["authorization_version"])
    initial = parse_u64(record["initial_version"])
    conv = db.execute("SELECT id,authorization_version,crypto_state_ref FROM conversation").fetchone()
    if (conv is None or initial > current or checkpoint["service_id"] != Store.meta(db, "service_id")
            or checkpoint["conversation_id"] != conv["id"]
            or any(checkpoint[name] != conv[name] for name in ("authorization_version", "crypto_state_ref"))
            or [subject({k: member[k] for k in ("account_id", "device_id")}) for member in checkpoint["members"]] != Store.members(db)):
        raise untrusted()
    records = db.execute("SELECT change_id,version_offset,authorization_version,actor_account,actor_device,nonce,proof,result "
                         "FROM permission_changes ORDER BY version_offset").fetchall()
    if len(records) != current - initial:
        raise untrusted()
    refs, statements = {current: checkpoint["crypto_state_ref"]}, []
    previous_ref = None
    for offset, row in enumerate(records, 1):
        change, result = json.loads(row["proof"]), json.loads(row["result"])
        statement = validate_proof(change)
        version = initial + offset
        if (row["version_offset"] != offset or row["authorization_version"] != str(version)
                or statement["authorization_version"] != str(version)
                or statement["previous_authorization_version"] != str(version - 1)
                or statement["change_id"] != row["change_id"] or statement["nonce"] != row["nonce"]
                or subject(statement["actor"]) != (row["actor_account"], row["actor_device"])
                or any(statement[name] != checkpoint[name] for name in ("service_id", "conversation_id"))
                or (previous_ref is not None and statement["from_state_ref"] != previous_ref)
                or statement["commit_sha256"] != hashlib.sha256(decode_bytes(change["commit_bytes"], "commit_bytes", MAX_PAYLOAD_BYTES)).hexdigest()
                or result.get("outcome") != "accepted" or result.get("change_id") != row["change_id"]
                or result.get("authorization_version") != str(version) or result.get("crypto_state_ref") != statement["to_state_ref"]):
            raise untrusted()
        expected = terminal_statement(statement, change, {"authorization_version": str(version),
                                      "crypto_state_ref": statement["to_state_ref"]}, "accepted")
        if validate_receipt(result["receipt"]) != expected:
            raise untrusted()
        resolution = db.execute("SELECT actor_account,actor_device,proof,outcome,receipt FROM permission_resolutions WHERE change_id=?",
                                (row["change_id"],)).fetchone()
        if (resolution is None or resolution["outcome"] != "accepted" or resolution["proof"] != row["proof"]
                or (resolution["actor_account"], resolution["actor_device"]) != subject(statement["actor"])
                or json.loads(resolution["receipt"]) != result["receipt"]):
            raise untrusted()
        refs[version - 1], refs[version] = statement["from_state_ref"], statement["to_state_ref"]
        previous_ref = statement["to_state_ref"]
        statements.append(statement)
    if refs[current] != checkpoint["crypto_state_ref"]:
        raise untrusted()
    return checkpoint, refs, statements


def lost_access(statements, message_version, pair):
    for statement in statements:
        if int(statement["authorization_version"]) <= message_version:
            continue
        action = statement["action"]
        if action["kind"] == "remove_member" and action["account_id"] == pair[0]:
            return True
        if action["kind"] == "revoke_device" and (action["account_id"], action["device_id"]) == pair:
            return True
    return False
