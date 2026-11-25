"""真实注册、旧 Add、过期等待及专用恢复的联合验收装置。"""
import base64
import hashlib
import json
import secrets
import time
from .fixture import ACCOUNTS, CONVERSATION, check, identity
from .key_package_fixture import KeyPackageLab, decode, transaction
from .first_trust_evidence import database


def signed_digest(proof):
    value=hashlib.sha256(b"Rocket-IM/POC/recovery-signed-record/v1\0")
    for field in ("statement_bytes","signature_bytes"):
        raw=base64.b64decode(proof[field]);value.update(len(raw).to_bytes(8,"big"));value.update(raw)
    return value.hexdigest()


class RecoveryLab(KeyPackageLab):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        from pathlib import Path
        self.relay_entrypoint=Path(__file__).with_name("join_recovery_relay.py")
        self.check_directory=self.directory/"commit-check";self.check_directory.mkdir()
        self.relay_args=(*self.relay_args,"--recovery-check-directory",str(self.check_directory))

    def sign_probe(self, device, value):
        check(self.probe_binary,"需要显式测试特性程序")
        previous=self.binary
        try:
            self.binary=self.probe_binary
            return self.rust(device,"join_recovery_sign_probe",request=value)["proof"]
        finally:self.binary=previous

    def recovery(self, device, kind, **fields):
        options={k:fields.pop(k) for k in ("failpoint","expected_exit","env") if k in fields}
        return self.rust(device,"join_recovery",command={"kind":kind,**fields},**options)

    def remote_recovery(self, device, kind, **fields):
        options={k:fields.pop(k) for k in ("expected","raw") if k in fields}
        return self.http(device,"join_recovery",{"kind":kind,**fields},**options)

    def setup_expired(self, target="d1",actor="a1", *, original_ttl=10):
        self.target,self.actor=target,actor
        self.publish("original-package",target,count=1,ttl=original_ttl)
        self.ready(actor,target);self.claim("original-claim",actor,target,"original-add")
        candidate=self.prepare_join("original-claim",actor,target)
        self.original=self.accepted_bundle(candidate,actor,target)
        if getattr(self,"before_recovery_root",None): self.before_recovery_root()
        for device in (*ACCOUNTS,target):
            result=self.recovery(device,"root",**self.original)
            self.root=result["reference"]
        for device in (actor,target):
            for member in (actor,target):self.fetch_directory(device,member,"recovery-directory-"+member)
        self.scope={"service_id":self.service,"conversation_id":CONVERSATION,"group_id":self.rust(actor,"inspect")["group_id"]}
        from .first_trust_fixture import roundtrip
        self.old_packet,self.old_acceptance=roundtrip(self,"before-recovery",recipients=tuple(ACCOUNTS))
        self.before_original={t:database(self)["tables"][t] for t in ("membership_history","join_materials","attempts","events")}
        with transaction(self) as db:
            self.original_rows={t:[dict(r) for r in db.execute("SELECT * FROM "+t+" WHERE "+col+"=?",("original-add",))]
                                for t,col in (("permission_changes","change_id"),("permission_resolutions","change_id"),("kp_materials","accepted_change"))}
        old=next(iter(self.pool(target)["packages"].values()))
        deadline=int(old["material"]["not_after"])
        while int(time.time())<deadline:time.sleep(min(.2,deadline-time.time()+.01))
        self.case_evidence["original_admission"]=self.root

    def intent(self, ident="recovery-1", actor=None, ttl=120, package_ttl=3600):
        actor=actor or self.actor
        proof,_=self.publish("publish-"+ident,self.target,count=1,ttl=package_ttl)
        package=decode(proof)["action"]["packages"][0]
        pool=self.pool(self.target)
        current=self.recovery(self.target,"inspect")["roots"]["original-add"]
        cp=self.recovery(self.target,"inspect")["public_head"]
        floor={k:cp[k] for k in ("authorization_version","crypto_state_ref")}
        directories=[]
        for account in sorted({identity(actor)["account_id"],identity(self.target)["account_id"]}):
            raw=base64.b64decode(pool["directories"][account]["snapshots"][-1])
            directories.append({"account_id":account,"version":json.loads(raw)["version"],"sha256":hashlib.sha256(raw).hexdigest()})
        now=int(time.time())
        value={"protocol_version":"rim-recovery-request-1","kind":"intent","scope":self.scope,"request_id":ident,
            "signer":self.member(self.target),"nonce":secrets.token_hex(32),"change_id":"change-"+ident,
            "root_admission":self.root,"current_admission":current,"actor":self.member(actor),"predecessor":floor,"known_floor":floor,
            "directory_refs":directories,"key_package_sha256":hashlib.sha256(base64.b64decode(package)).hexdigest(),
            "history_policy":"from_recovery","issued_at_unix_secs":str(now),"expires_at_unix_secs":str(now+ttl)}
        return self.recovery(self.target,"sign",request=value,intent=None)["proof"]

    def control_proof(self, intent, kind="claim", device=None, ident=None):
        device=device or self.actor;i=decode(intent)
        request={"protocol_version":"rim-recovery-request-1","kind":kind,"scope":self.scope,"request_id":ident or kind+"-"+i["request_id"],
            "signer":self.member(device),"nonce":secrets.token_hex(32),"recovery_id":i["request_id"],"change_id":i["change_id"],
            "intent_sha256":signed_digest(intent),"reason":"cancelled" if kind=="close" else None}
        return self.recovery(device,"sign",request=request,intent=intent)["proof"]

    def prepare_recovery(self, ident="recovery-1", **options):
        intent=self.intent(ident,**options);claim=self.control_proof(intent)
        allocated=self.remote_recovery(self.actor,"claim",intent=intent,proof=claim)
        bundle=self.recovery(self.actor,"prepare",intent=intent,claim=claim,allocation=allocated["allocation"],key_package=allocated["key_package"])["bundle"]
        return intent,claim,allocated,bundle

    def accept_recovery(self,bundle):
        return self.remote_recovery(self.actor,"accept",bundle=bundle)

    def get_recovery(self, intent, device=None):
        return self.remote_recovery(device or self.target,"get",service_id=self.service,conversation_id=CONVERSATION,recovery_id=decode(intent)["request_id"])

    def install_recovery(self,record,devices=None):
        for device in devices or (*ACCOUNTS,self.target):
            actual=record
            if device not in (self.target,self.actor):
                after=decode(record["bundle"]["change"])["previous_authorization_version"]
                page=self.http(device,"get_permission_records",{"service_id":self.service,"conversation_id":CONVERSATION,"after_version":after,"limit":"1"})
                actual=page["records"][0]["recovery"]
                check(set(actual["bundle"])=={"intent","claim","allocation","change"},"公共权限页泄露目标 Welcome 材料")
            self.recovery(device,"observe",record=actual)
            self.recovery(device,"apply",record=actual)

    def unchanged_original(self):
        current=database(self)["tables"]
        check(all(current[t]==value for t,value in self.before_original.items()),"恢复改写原成员历史、材料或消息槽")
        with transaction(self) as db:
            for t,col in (("permission_changes","change_id"),("permission_resolutions","change_id"),("kp_materials","accepted_change")):
                check([dict(r) for r in db.execute("SELECT * FROM "+t+" WHERE "+col+"=?",("original-add",))]==self.original_rows[t],"恢复改写原接受事实")
            self.case_evidence["ledger_counts"]={table:db.execute("SELECT count(*) FROM "+table).fetchone()[0] for table in ("recovery_attempts","recovery_active","recovery_edges","recovery_roots")}
