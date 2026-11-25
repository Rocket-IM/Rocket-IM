"""K矩阵：真实设备私有状态、原注册/核验、HTTP/SQLite及公开证据摘要。"""
import base64
import copy
import hashlib
import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from .fixture import ACCOUNTS, CONVERSATION, check, identity
from .first_trust_fixture import FirstTrustLab, roundtrip
from .first_trust_session import verify_public
from .first_trust_evidence import state, database

def decode(record):
    return json.loads(base64.b64decode(record["statement_bytes"]))

def sha(value):
    return hashlib.sha256(value).hexdigest()

@contextmanager
def transaction(lab):
    db = sqlite3.connect(lab.directory / "relay.sqlite", isolation_level=None, timeout=8)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON"); db.execute("BEGIN IMMEDIATE")
    try:
        yield db
        db.commit()
    except BaseException:
        db.rollback(); raise
    finally:
        db.close()

class KeyPackageLab(FirstTrustLab):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        from pathlib import Path
        self.relay_entrypoint=Path(__file__).with_name("key_package_relay.py")
        self.barrier=self.directory/"barrier";self.barrier.mkdir()
        self.relay_args=(*self.relay_args,"--lifecycle-barrier-directory",str(self.barrier))

    def member(self, target):
        return {**identity(target), "signature_key": self.public[target]["signature_key"]}

    def initialize(self):
        super().initialize(); self.group()

    def pool(self, target="d1"):
        return self.rust(target, "key_package_inspect")

    def generate(self, ident="publish-1", target="d1", count=2, ttl=3600, **options):
        now = int(time.time())
        fields = {"request_id": ident, "count": count, "not_before": str(now - 1), "not_after": str(now + ttl),
                  "source_key": self.relay_receipt_key, **options}
        return self.rust(target, "key_package_generate", **fields)

    def remote(self, actor, proof, **options):
        return self.http(actor, "key_package_lifecycle", {"proof": proof}, **options)

    def response(self, actor, proof, result, **options):
        return self.rust(actor, "key_package_response", request_id=decode(proof)["request_id"], receipt=result["receipt"], **options)

    def publish(self, ident="publish-1", target="d1", **options):
        proof = self.generate(ident, target, **options)["proof"]
        result = self.remote(target, proof); self.response(target, proof, result)
        return proof, result

    def request(self, actor, ident, action, **options):
        return self.rust(actor, "key_package_request", request_id=ident, action=action,
                         source_key=self.relay_receipt_key, **options)["proof"]

    def fetch_directory(self, actor="a1", target="d1", ident=None):
        proof = self.request(actor, ident or "directory-" + target, {"kind": "directory", "account_id": identity(target)["account_id"], "challenge": secrets.token_hex(32)})
        result = self.remote(actor, proof); self.response(actor, proof, result)
        return proof, result

    def claim_action(self, actor="a1", target="d1", change_id="join-1"):
        head = self.pool(actor)["directories"][identity(target)["account_id"]]["snapshots"][-1]
        parsed = json.loads(base64.b64decode(head))
        cp = self.rust(actor, "permission_inspect")["checkpoint"]
        return {"kind": "claim", "target": self.member(target), "conversation_id": CONVERSATION,
                "join_kind": "add_device" if identity(actor)["account_id"] == identity(target)["account_id"] else "add_member",
                "change_id": change_id, "directory_version": parsed["version"], "directory_sha256": sha(base64.b64decode(head)),
                "authorization_version": cp["authorization_version"], "crypto_state_ref": cp["crypto_state_ref"]}

    def ready(self, actor="a1", target="d1", ident=None):
        verify_public(self, actor, target)
        self.fetch_directory(actor, target, ident)

    def claim(self, ident="claim-1", actor="a1", target="d1", change_id="join-1", **options):
        proof = self.request(actor, ident, self.claim_action(actor, target, change_id))
        result = self.remote(actor, proof, **options)
        if "receipt" in result: self.response(actor, proof, result)
        return proof, result

    def prepare_join(self, claim_id="claim-1", actor="a1", target="d1"):
        for device in ACCOUNTS:
            verify_public(self, device, target)
            if identity(device)["account_id"] != identity(target)["account_id"]:
                self.rust(device, "permission_pin_member", member=self.member(target))
            verify_public(self, target, device)
        mode = "permission_device_join_anchor" if identity(actor)["account_id"] == identity(target)["account_id"] else "permission_join_anchor"
        self.rust(target, mode, checkpoint=self.checkpoint, relay_receipt_key=self.relay_receipt_key)
        return self.rust(actor, "permission_prepare_claim", request_id=claim_id)

    def submit_join(self, candidate, actor="a1", **options):
        return self.http(actor, "submit_permission_change", {"service_id": self.service, "conversation_id": CONVERSATION,
                         "change": candidate["change"], "join": candidate["join"]}, **options)

    def accepted_bundle(self, candidate, actor="a1", target="d1"):
        accepted = self.submit_join(candidate, actor)
        record = {"change": candidate["change"], "receipt": accepted["receipt"]}
        for device in ACCOUNTS: self.rust(device, "permission_recover", record=record)
        bundle = self.http(target, "get_join_material", {"service_id": self.service, "conversation_id": CONVERSATION,
            "change_id": decode(candidate["change"])["change_id"]})
        check(bundle == {"record": record, "join": candidate["join"]}, "接受后材料原件不同")
        return bundle

    def rows(self, table):
        check(table in ("kp_requests", "kp_materials", "kp_directories", "kp_inventory", "permission_changes", "permission_resolutions", "join_materials"), "未知测试表")
        with transaction(self) as db:
            return [dict(row) for row in db.execute(f"SELECT * FROM {table} ORDER BY rowid")]

    def continued(self, ident="continued", **options):
        roundtrip(self, ident, **options)
        self.case_evidence["database"] = database(self)

    def simultaneous(self, calls):
        from concurrent.futures import ThreadPoolExecutor
        for path in self.barrier.glob("*.ready"):path.unlink()
        (self.barrier/"armed").touch()
        with ThreadPoolExecutor(max_workers=len(calls)) as executor:
            futures=[executor.submit(call) for call in calls]
            deadline=time.monotonic()+8
            try:
                while len(list(self.barrier.glob("*.ready")))<len(calls):
                    check(time.monotonic()<deadline,"请求未全部到达真实事务入口屏障")
                    time.sleep(.01)
                self.case_evidence.setdefault("barriers",[]).append({"arrived":len(list(self.barrier.glob("*.ready"))),"phase":"before_begin_immediate"})
            finally:(self.barrier/"armed").unlink()
            return [future.result(timeout=15) for future in futures]

    def ordered(self,calls):
        from concurrent.futures import ThreadPoolExecutor
        for path in self.barrier.glob("*"):path.unlink()
        (self.barrier/"armed").touch();arrivals=[]
        with ThreadPoolExecutor(max_workers=len(calls)) as executor:
            futures=[]
            try:
                for call in calls:
                    futures.append(executor.submit(call));deadline=time.monotonic()+8
                    while len(list(self.barrier.glob("*.ready")))<=len(arrivals):
                        check(time.monotonic()<deadline,"顺序屏障未到达");time.sleep(.01)
                    arrivals.append(next(p for p in self.barrier.glob("*.ready") if p not in arrivals))
                results=[]
                for ready,future in zip(arrivals,futures):
                    ready.with_suffix(".release").touch();results.append(future.result(timeout=15))
                self.case_evidence.setdefault("ordered_barriers",[]).append({"arrived_before_release":len(arrivals),"commit_order":list(range(len(arrivals)))})
                return results
            finally:(self.barrier/"armed").unlink()

    def probe(self,actor,mode,request_id,original):
        check(getattr(self,"probe_binary",None),"缺少显式恶意客户端实验程序")
        normal=self.binary
        try:
            self.binary=self.probe_binary
            return self.rust(actor,"key_package_probe",mode=mode,request_id=request_id,original=original)
        finally:self.binary=normal
