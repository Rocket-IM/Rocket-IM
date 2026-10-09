"""真实挑战与私钥持有证明；业务token、联系人核验及群授权分别处理。"""

import base64
import json
import secrets

from contract import ProtocolError, encode_json
from registration_contract import PROTOCOL_VERSION, PURPOSE, TTL_MS, challenge, proof, registered
from registration_storage import capacity
from storage import now_ms


def conflict():
    raise ProtocolError("registration_conflict", "注册原件或既有设备身份不可改变", status=409)


def context(store, db, device, service_id, statement=None):
    if service_id != store.meta(db, "service_id") or (statement is not None and
            (statement["service_id"], statement["account_id"], statement["device_id"]) !=
            (service_id, device["account"], device["device"])):
        raise ProtocolError("registration_context", "注册实例或设备主体不匹配", status=403)


def check_key(db, pair, signature_key):
    own = db.execute("SELECT signature_key FROM device_public_keys WHERE account=? AND device=?", pair).fetchone()
    other = db.execute("SELECT account,device FROM device_public_keys WHERE signature_key=?", (signature_key,)).fetchone()
    if (own is not None and own["signature_key"] != signature_key
            or other is not None and (other["account"], other["device"]) != pair):
        conflict()
    return own


def check_validity(statement):
    current = now_ms()
    if not int(statement["issued_at_ms"]) <= current < int(statement["expires_at_ms"]):
        raise ProtocolError("registration_expired", "注册挑战不在有效期内", status=409)


def begin_device_registration(store, db, device, req):
    context(store, db, device, req["service_id"])
    pair = (device["account"], device["device"])
    old = db.execute("SELECT * FROM device_registrations WHERE account=? AND device=? AND registration_id=?",
                     (*pair, req["registration_id"])).fetchone()
    if old is not None:
        if challenge(old["challenge_bytes"])["signature_key"] != req["signature_key"]:
            conflict()
        return {"challenge_bytes": old["challenge_bytes"]}
    if db.execute("SELECT 1 FROM device_registrations WHERE account=? AND device=? AND proof_json IS NOT NULL", pair).fetchone():
        conflict()
    check_key(db, pair, req["signature_key"])
    issued = now_ms()
    statement = {"protocol_version": PROTOCOL_VERSION, "service_id": req["service_id"],
                 "account_id": pair[0], "device_id": pair[1], "registration_id": req["registration_id"],
                 "signature_key": req["signature_key"], "purpose": PURPOSE,
                 "challenge_nonce": base64.b64encode(secrets.token_bytes(32)).decode(),
                 "issued_at_ms": str(issued), "expires_at_ms": str(issued + TTL_MS)}
    encoded = base64.b64encode(encode_json(statement)).decode()
    challenge(encoded)
    candidate = {"account": pair[0], "device": pair[1], "registration_id": req["registration_id"],
                 "challenge_bytes": encoded, "proof_json": None, "result_json": None}
    capacity(db, candidate)
    db.execute("INSERT INTO device_registrations VALUES (?,?,?,?,NULL,NULL)",
               (*pair, req["registration_id"], encoded))
    return {"challenge_bytes": encoded}


def complete_device_registration(store, db, device, req):
    statement = proof(req["proof"])
    context(store, db, device, req["service_id"], statement)
    pair = (device["account"], device["device"])
    row = db.execute("SELECT * FROM device_registrations WHERE account=? AND device=? AND registration_id=?",
                     (*pair, statement["registration_id"])).fetchone()
    if row is None or row["challenge_bytes"] != req["proof"]["statement_bytes"]:
        conflict()
    # 固定内部编码避免外层JSON键顺序改变造成假的幂等冲突；认证声明原字节不变。
    exact = encode_json({name: req["proof"][name] for name in ("statement_bytes", "signature_bytes")}).decode()
    if row["proof_json"] is not None:
        if row["proof_json"] != exact:
            conflict()
        if check_key(db, pair, statement["signature_key"]) is None:
            conflict()
        return json.loads(row["result_json"])
    if db.execute("SELECT 1 FROM device_registrations WHERE account=? AND device=? AND proof_json IS NOT NULL", pair).fetchone():
        conflict()
    check_validity(statement)
    own = check_key(db, pair, statement["signature_key"])
    if store.permission_verifier is None:
        raise ProtocolError("permission_verifier_unavailable", "注册公共验证器未配置", status=503)
    store.permission_verifier.verify_device_registration(req["proof"])
    # 公共helper是有界进程调用；首次接受不能跨过其执行期间到达的有效期边界。
    check_validity(statement)
    if own is None:
        db.execute("INSERT INTO device_public_keys VALUES (?,?,?)", (*pair, statement["signature_key"]))
    result = registered(statement)
    db.execute("UPDATE device_registrations SET proof_json=?,result_json=? WHERE account=? AND device=? AND registration_id=?",
               (exact, encode_json(result).decode(), *pair, statement["registration_id"]))
    return result
