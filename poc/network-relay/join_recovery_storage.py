"""恢复账本：ID 永久占用，活动槽与接受边分别唯一，不改旧入群事实。"""
import json
from contract import encode_json
from key_package_storage import fail
from join_recovery_contract import signed, signed_digest, admission_ref

SCHEMA = """
CREATE TABLE recovery_roots (root_id TEXT PRIMARY KEY REFERENCES permission_changes(change_id),
    reference TEXT NOT NULL UNIQUE,scope TEXT NOT NULL,target TEXT NOT NULL,
    current_ref TEXT NOT NULL,current_package TEXT NOT NULL);
CREATE TABLE recovery_attempts (recovery_id TEXT PRIMARY KEY,change_id TEXT NOT NULL UNIQUE,
    root_id TEXT NOT NULL REFERENCES recovery_roots(root_id),current_ref TEXT NOT NULL,
    target TEXT NOT NULL,intent TEXT NOT NULL,predecessor TEXT NOT NULL,
    claim TEXT,allocation TEXT,state TEXT NOT NULL CHECK(state IN ('allocated','accepted','closed')),
    bundle TEXT,terminal TEXT,
    CHECK((state='allocated' AND terminal IS NULL) OR (state!='allocated' AND terminal IS NOT NULL)),
    CHECK((claim IS NULL AND allocation IS NULL) OR (claim IS NOT NULL AND allocation IS NOT NULL)));
CREATE TABLE recovery_active (root_id TEXT NOT NULL,current_ref TEXT NOT NULL,
    recovery_id TEXT NOT NULL UNIQUE REFERENCES recovery_attempts(recovery_id),PRIMARY KEY(root_id,current_ref));
CREATE TABLE recovery_edges (root_id TEXT NOT NULL,current_ref TEXT NOT NULL,successor_ref TEXT NOT NULL UNIQUE,
    recovery_id TEXT NOT NULL UNIQUE REFERENCES recovery_attempts(recovery_id),PRIMARY KEY(root_id,current_ref));
CREATE TABLE recovery_requests (signer TEXT NOT NULL,request_id TEXT NOT NULL,nonce TEXT NOT NULL,
    recovery_id TEXT NOT NULL REFERENCES recovery_attempts(recovery_id) DEFERRABLE INITIALLY DEFERRED,
    proof TEXT NOT NULL,PRIMARY KEY(signer,request_id),UNIQUE(signer,nonce));
"""
TABLES = ("recovery_roots", "recovery_attempts", "recovery_active", "recovery_edges", "recovery_requests")
# 每个尝试永久预留：完整候选/终态/最多五份请求，终态不依赖新配额。
RESERVED_BYTES = 1536 * 1024
MAX_BYTES = 48 * 1024 * 1024
MAX_REQUESTS = 5


def encoded(value):
    return encode_json(value).decode()


def namespace(db, change_id):
    if db.execute("SELECT 1 FROM recovery_attempts WHERE change_id=?", (change_id,)).fetchone():
        fail("idempotency_conflict")


def capacity(db, target):
    count = db.execute("SELECT count(*) FROM recovery_attempts").fetchone()[0]
    per_target = db.execute("SELECT count(*) FROM recovery_attempts WHERE target=?", (encoded(target),)).fetchone()[0]
    reserved = db.execute("SELECT count(*) FROM recovery_attempts WHERE state!='accepted'").fetchone()[0]
    permissions = db.execute("SELECT (SELECT count(*) FROM permission_changes)+(SELECT count(*) FROM permission_resolutions WHERE outcome='closed')").fetchone()[0]
    if per_target >= 64 or (count + 1) * RESERVED_BYTES > MAX_BYTES or permissions + reserved >= 10000:
        fail("resource_exhausted", 429)


def check_request(db, value, proof):
    """只校验已占用的请求 ID/nonce；终态读取不能因新请求增加写入或配额。"""
    signer = encoded(value["signer"])
    previous = db.execute("SELECT proof FROM recovery_requests WHERE signer=? AND (request_id=? OR nonce=?)",
                          (signer, value["request_id"], value["nonce"])).fetchall()
    if previous:
        if len(previous) != 1 or json.loads(previous[0][0]) != proof: fail("idempotency_conflict")
        return True
    return False


def reserve_request(db, value, proof, recovery_id):
    if check_request(db, value, proof): return
    if db.execute("SELECT count(*) FROM recovery_requests WHERE recovery_id=?", (recovery_id,)).fetchone()[0] >= MAX_REQUESTS:
        fail("resource_exhausted", 429)
    db.execute("INSERT INTO recovery_requests VALUES (?,?,?,?,?)", (encoded(value["signer"]), value["request_id"], value["nonce"], recovery_id, encoded(proof)))


def original(store, db, reference):
    row = db.execute("SELECT p.proof,p.result,j.key_package,j.welcome FROM permission_changes p JOIN join_materials j ON j.change_id=p.change_id WHERE p.change_id=?", (reference["change_id"],)).fetchone()
    if row is None: fail("recovery_invalid", 400)
    record = {"change": json.loads(row["proof"]), "receipt": json.loads(row["result"])["receipt"]}
    from permission_contract import validate_proof
    from key_package_admission import allocation_for
    statement = validate_proof(record["change"])
    allocation = allocation_for(db, statement)
    if not allocation: fail("recovery_invalid", 400)
    validated = store.permission_verifier._call({"operation": "verify_recovery_root", "record": record,
        "source_key": store.receipt_signer.signature_key, "join": {"key_package": row["key_package"], "welcome": row["welcome"], **allocation}})
    if validated["reference"] != reference: fail("recovery_invalid", 400)
    material = db.execute("SELECT * FROM kp_materials WHERE hash=? AND state='accepted' AND accepted_change=?",
                          (validated["key_package_sha256"], reference["change_id"])).fetchone()
    if material is None or material["encoded"] != row["key_package"]: fail("recovery_invalid", 400)
    return record, validated


def root(store, db, intent):
    record, validated = original(store, db, intent["root_admission"])
    if validated["target"] != intent["signer"] or validated["group_id"] != intent["scope"]["group_id"]:
        fail("recovery_invalid", 400)
    root_id = intent["root_admission"]["change_id"]
    row = db.execute("SELECT * FROM recovery_roots WHERE root_id=?", (root_id,)).fetchone()
    if row is None:
        db.execute("INSERT INTO recovery_roots VALUES (?,?,?,?,?,?)", (root_id, encoded(intent["root_admission"]),
            encoded(intent["scope"]), encoded(intent["signer"]), encoded(intent["root_admission"]), validated["key_package_sha256"]))
        row = db.execute("SELECT * FROM recovery_roots WHERE root_id=?", (root_id,)).fetchone()
    if any(json.loads(row[name]) != intent[field] for name, field in (("reference", "root_admission"), ("scope", "scope"), ("target", "signer"))):
        fail("recovery_invalid", 400)
    if intent["current_admission"] != intent["root_admission"] and not db.execute(
            "SELECT 1 FROM recovery_edges WHERE root_id=? AND successor_ref=?", (root_id, encoded(intent["current_admission"]))).fetchone():
        fail("recovery_invalid", 400)
    return row, record, validated


def install(db, previous_schema):
    if not db.in_transaction: raise ValueError("恢复迁移必须在原启动事务内")
    marker = db.execute("SELECT value FROM meta WHERE key='recovery_schema'").fetchone()
    if marker is None:
        if previous_schema == "rim-poc-storage-10": raise ValueError("恢复账本标记缺失")
        for statement in SCHEMA.strip().split(";"):
            if statement.strip(): db.execute(statement)
        db.execute("INSERT INTO meta VALUES ('recovery_schema','1')")
    elif marker[0] not in {"1", "2"}: raise ValueError("恢复账本版本不支持")
    for table in TABLES:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
            raise ValueError("恢复持久账本缺失")
    validate(db)
    from join_recovery_witness_storage import install as install_witness
    install_witness(db)


def validate(db):
    """启动时不以重建/删除方式修复账本；范围、终态、边和活动槽必须整体一致。"""
    for row in db.execute("SELECT * FROM recovery_attempts"):
        intent = signed(json.loads(row["intent"]))
        if (intent["request_id"] != row["recovery_id"] or intent["change_id"] != row["change_id"]
                or encoded(intent["signer"]) != row["target"] or encoded(intent["current_admission"]) != row["current_ref"]
                or intent["root_admission"]["change_id"] != row["root_id"]): raise ValueError("恢复尝试范围损坏")
        active = db.execute("SELECT * FROM recovery_active WHERE recovery_id=?", (row["recovery_id"],)).fetchone()
        edge = db.execute("SELECT * FROM recovery_edges WHERE recovery_id=?", (row["recovery_id"],)).fetchone()
        if (active is not None) != (row["state"] == "allocated") or (edge is not None) != (row["state"] == "accepted"):
            raise ValueError("恢复活动槽或接受边损坏")
        for link in (active, edge):
            if link is not None and (link["root_id"], link["current_ref"]) != (row["root_id"], row["current_ref"]):
                raise ValueError("恢复边范围损坏")
        if row["terminal"]:
            receipt = signed(json.loads(row["terminal"]))
            if receipt["result"]["kind"] != row["state"] or receipt["intent_sha256"] != signed_digest(json.loads(row["intent"])):
                raise ValueError("恢复终态损坏")
        if row["state"] == "accepted":
            bundle = json.loads(row["bundle"])
            if encoded(admission_ref(bundle["change"], json.loads(row["terminal"]))) != edge["successor_ref"]:
                raise ValueError("恢复后继摘要损坏")
    for row in db.execute("SELECT * FROM recovery_roots"):
        current = row["reference"]; visited = set()
        while current not in visited:
            visited.add(current)
            edge = db.execute("SELECT successor_ref FROM recovery_edges WHERE root_id=? AND current_ref=?", (row["root_id"], current)).fetchone()
            if edge is None: break
            current = edge[0]
        else: raise ValueError("恢复链有环")
        if current != row["current_ref"]: raise ValueError("恢复当前端点损坏")
        if len(visited) != 1 + db.execute("SELECT count(*) FROM recovery_edges WHERE root_id=?", (row["root_id"],)).fetchone()[0]:
            raise ValueError("恢复存在孤立接受边")
        if current == row["reference"]:
            expected = db.execute("SELECT hash FROM kp_materials WHERE accepted_change=?", (row["root_id"],)).fetchone()
        else:
            expected = db.execute("SELECT hash FROM kp_materials WHERE accepted_change=?", (json.loads(current)["change_id"],)).fetchone()
        if expected is None or row["current_package"] != expected[0]: raise ValueError("恢复端点材料损坏")


def verify_persisted(store, db):
    """重启同样检查原件签名和关联，不能因已经落盘绕过公共契约。"""
    rows = db.execute("SELECT * FROM recovery_attempts").fetchall()
    if not rows: return
    if store.permission_verifier is None or store.receipt_signer is None:
        raise ValueError("恢复账本需要原公共验证器和回执钥")
    if len(rows) * RESERVED_BYTES > MAX_BYTES: raise ValueError("恢复账本超过预留预算")
    source = store.receipt_signer.signature_key
    for row in rows:
        proof = json.loads(row["intent"])
        intent = store.permission_verifier._call({"operation": "verify_recovery_request", "proof": proof})["statement"]
        root_record, root_info = original(store, db, intent["root_admission"])
        saved_root = db.execute("SELECT * FROM recovery_roots WHERE root_id=?", (row["root_id"],)).fetchone()
        if (saved_root is None or root_info["target"] != intent["signer"] or root_info["group_id"] != intent["scope"]["group_id"]
                or json.loads(saved_root["scope"]) != intent["scope"] or json.loads(saved_root["target"]) != intent["signer"]):
            raise ValueError("恢复根范围损坏")
        if row["claim"]:
            store.permission_verifier._call({"operation": "verify_recovery_control", "proof": json.loads(row["claim"]), "intent": proof})
        for field in ("allocation", "terminal"):
            if row[field]:
                receipt = store.permission_verifier._call({"operation": "verify_recovery_receipt", "source_key": source, "proof": json.loads(row[field])})["statement"]
                modern = intent["protocol_version"] == "rim-recovery-request-2"
                expected_version = "rim-recovery-receipt-2" if modern else "rim-recovery-receipt-1"
                if (receipt["protocol_version"] != expected_version or
                        (modern and (receipt["witness_profile"] != intent["witness_profile"]
                                     or receipt["policy_ref"] != intent["policy_ref"]))):
                    raise ValueError("恢复回执版本或固定见证策略损坏")
                if any(receipt[a] != intent[b] for a,b in (("scope","scope"),("recovery_id","request_id"),("change_id","change_id"),("target","signer"),("actor","actor"),("root_admission","root_admission"),("current_admission","current_admission"))):
                    raise ValueError("恢复回执关联损坏")
                if receipt["intent_sha256"] != signed_digest(proof): raise ValueError("恢复回执意图损坏")
                if field == "allocation" and (receipt["result"]["kind"] != "allocated" or receipt["result"]["claim_sha256"] != signed_digest(json.loads(row["claim"]))
                        or receipt["result"]["key_package_sha256"] != intent["key_package_sha256"] or receipt["result"]["predecessor"] != intent["predecessor"]):
                    raise ValueError("恢复领取关联损坏")
        if row["state"] == "accepted":
            record = {"bundle": json.loads(row["bundle"]), "receipt": json.loads(row["terminal"])}
            validated = store.permission_verifier._call({"operation": "verify_recovery_accepted", "checkpoint": json.loads(row["predecessor"]),
                "root": root_record, "source_key": source, "record": record})
            accepted = db.execute("SELECT proof,result FROM permission_changes WHERE change_id=?", (row["change_id"],)).fetchone()
            resolution = db.execute("SELECT proof,outcome,receipt FROM permission_resolutions WHERE change_id=?", (row["change_id"],)).fetchone()
            material = db.execute("SELECT state,accepted_change,allocation FROM kp_materials WHERE hash=?", (intent["key_package_sha256"],)).fetchone()
            if (accepted is None or resolution is None or material is None or json.loads(accepted["proof"]) != record["bundle"]["change"]
                    or json.loads(accepted["result"])["receipt"] != record["receipt"] or json.loads(resolution["proof"]) != record["bundle"]["change"]
                    or resolution["outcome"] != "accepted" or json.loads(resolution["receipt"]) != record["receipt"]
                    or tuple(material) != ("accepted", row["change_id"], signed_digest(json.loads(row["allocation"])))
                    or validated["intent"] != intent): raise ValueError("恢复接受关联损坏")
        requests = db.execute("SELECT * FROM recovery_requests WHERE recovery_id=?", (row["recovery_id"],)).fetchall()
        if not 1 <= len(requests) <= MAX_REQUESTS: raise ValueError("恢复请求预留损坏")
        for request in requests:
            raw = json.loads(request["proof"])
            value = store.permission_verifier._call({"operation": "verify_recovery_request", "proof": raw})["statement"]
            if (value["request_id"] != request["request_id"] or value["nonce"] != request["nonce"] or encoded(value["signer"]) != request["signer"]):
                raise ValueError("恢复去重账本损坏")
            if value["kind"] == "intent":
                if raw != proof: raise ValueError("恢复目标意图损坏")
            else:
                store.permission_verifier._call({"operation": "verify_recovery_control", "proof": raw, "intent": proof})

        raw_requests = [json.loads(request["proof"]) for request in requests]
        if proof not in raw_requests or (row["claim"] and json.loads(row["claim"]) not in raw_requests):
            raise ValueError("恢复缺少原目标或领取请求")
        if row["state"] == "closed":
            result = signed(json.loads(row["terminal"]))["result"]
            controls = [signed(raw) for raw in raw_requests if signed_digest(raw) == result["close_sha256"]]
            allocation_hash = signed_digest(json.loads(row["allocation"])) if row["allocation"] else None
            if len(controls) != 1 or controls[0]["kind"] != "close" or controls[0]["reason"] != result["reason"] or result["allocation_sha256"] != allocation_hash:
                raise ValueError("恢复关闭原件关联损坏")
