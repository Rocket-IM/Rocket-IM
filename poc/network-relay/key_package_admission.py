"""分配状态与原权限/Commit/Welcome事务共同提交；旧协议不能消费池内材料。"""
import json
import time
from key_package_contract import request, digest, signed
from key_package_storage import fail, inventory

def check(db, statement, join):
    row = db.execute("SELECT * FROM kp_materials WHERE hash=?", (statement["action"]["key_package_sha256"],)).fetchone()
    allocation = join.get("allocation")
    if statement.get("allocation_sha256") is None:
        if row is not None or allocation is not None: fail("key_package_allocation_required")
        return
    if row is None or allocation is None or row["state"] != "allocated": fail("key_package_reuse")
    proof = allocation["request"]; claim = request(proof); action = claim["action"]
    stored = db.execute("SELECT proof,receipt FROM kp_requests WHERE account=? AND device=? AND request_id=?", (claim["actor"]["account_id"], claim["actor"]["device_id"], claim["request_id"])).fetchone()
    if (stored is None or json.loads(stored["proof"]) != proof or json.loads(stored["receipt"]) != allocation["receipt"]
            or digest(allocation["receipt"]) != statement["allocation_sha256"] or row["allocation"] != statement["allocation_sha256"]
            or action["change_id"] != statement["change_id"] or row["encoded"] != join["key_package"]): fail("key_package_context")
    material = json.loads(row["metadata"])
    if not int(material["not_before"]) <= int(time.time()) < int(material["not_after"]): fail("key_package_expired")

def accept(db, statement):
    if statement.get("allocation_sha256") is not None:
        changed = db.execute("UPDATE kp_materials SET state='accepted',accepted_change=? WHERE allocation=? AND state='allocated'", (statement["change_id"], statement["allocation_sha256"])).rowcount
        if changed != 1: fail("key_package_reuse")
    # 已提交后继使旧前驱的其他候选确定失效；保留占用与原领取回执。
    for row in db.execute("SELECT m.hash,m.allocation,m.account,m.device,r.proof,r.receipt FROM kp_materials m JOIN kp_requests r ON m.account=r.target_account AND m.device=r.target_device WHERE m.state='allocated' AND r.kind='claim'").fetchall():
        action = request(json.loads(row["proof"]))["action"]
        if (row["allocation"] == digest(json.loads(row["receipt"])) and action["conversation_id"] == statement["conversation_id"]
                and int(action["authorization_version"]) < int(statement["authorization_version"])):
            db.execute("UPDATE kp_materials SET state='retired' WHERE hash=? AND state='allocated'", (row["hash"],))

def close(db, statement):
    if statement.get("allocation_sha256") is not None:
        row = db.execute("SELECT account,device FROM kp_materials WHERE allocation=? AND state='allocated'", (statement["allocation_sha256"],)).fetchone()
        if row:
            db.execute("UPDATE kp_materials SET state='retired' WHERE allocation=? AND state='allocated'", (statement["allocation_sha256"],))
            inventory(db, (row[0], row[1]), True)

def allocation_for(db, statement):
    if statement.get("allocation_sha256") is None: return {}
    row = db.execute("SELECT r.proof,r.receipt FROM kp_requests r JOIN kp_materials m ON m.account=r.target_account AND m.device=r.target_device AND m.accepted_change=r.change_id WHERE m.accepted_change=? AND m.allocation=?", (statement["change_id"], statement["allocation_sha256"])).fetchone()
    if row is None or digest(json.loads(row["receipt"])) != statement["allocation_sha256"]: fail("key_package_state")
    return {"allocation": {"request": json.loads(row["proof"]), "receipt": json.loads(row["receipt"])}}
