"""K01—K07目录/库存/单次分配正反向量；每项检查拒绝后的持久状态。"""
import base64
import copy
import json
import secrets
import time
from .fixture import ACCOUNTS, CONVERSATION, check, identity
from .first_trust_session import verify_public
from .first_trust_evidence import state, database
from .key_package_fixture import decode, sha

def reject_rust(lab,device,operation,**fields):
    before=state(lab);error=lab.rust(device,operation,expected_exit=1,**fields)
    check(state(lab)==before,"明确拒绝改变有效状态")
    lab.case_evidence.setdefault("rejections",[]).append({"operation":operation,"error":error})
    return error

def tamper(proof,field,value):
    modified=copy.deepcopy(proof);raw=decode(proof);raw[field]=value
    modified["statement_bytes"]=base64.b64encode(json.dumps(raw,separators=(',',':')).encode()).decode();return modified

def k01(lab):
    proof,result=lab.publish();lab.fetch_directory()
    action=lab.claim_action()
    check(reject_rust(lab,"a1","key_package_request",request_id="unverified",action=action,source_key=lab.relay_receipt_key)["code"]=="identity_unverified","目录冒充信任")
    for name,value in (("identity_generation","1"),("verified",True),("service_id","S2"),("actor",lab.member("c1"))):
        before=database(lab);lab.remote("d1",tamper(proof,name,value),expected=(400,403));check(database(lab)==before,"坏请求改变目录或库存")
    lab.remote("c1",proof,expected=403)
    verify_public(lab,"a1","d1")
    reject_rust(lab,"a1","key_package_request",request_id="bad-source",action={"kind":"directory","account_id":"david","challenge":"00"*32},source_key=lab.public["c1"]["signature_key"])
    lab.claim();candidate=lab.prepare_join();bundle=lab.accepted_bundle(candidate)
    lab.rust("d1","permission_join",**bundle)
    check(sum(p["consumed"] for p in lab.pool()["packages"].values())==1,"没有恰好消费一个bundle")
    lab.continued(recipients=(*ACCOUNTS,"d1"))

def forged_directory(lab,actor,ident,transform,account=None):
    proof=lab.request(actor,ident,{"kind":"directory","account_id":account or identity("d1")["account_id"],"challenge":secrets.token_hex(32)})
    actual=lab.remote(actor,proof);statement=decode(actual["receipt"]);transform(statement)
    signed=lab.relay_key("sign",statement=statement,expected_signature_key=lab.relay_receipt_key)
    return proof,signed

def encode_snapshot(value):return base64.b64encode(json.dumps(value,separators=(',',':')).encode()).decode()

def k02(lab):
    lab.fetch_directory();lab.restart();original=lab.pool("a1")["directories"]
    def successor(statement):
        chain=statement["result"]["snapshots"];head=json.loads(base64.b64decode(chain[-1]));head["version"]="2";head["previous_sha256"]=sha(base64.b64decode(chain[-1]));chain.append(encode_snapshot(head))
    proof,result=forged_directory(lab,"a1","successor",successor);lab.response("a1",proof,result)
    check(len(lab.pool("a1")["directories"][identity("d1")["account_id"]]["snapshots"])==2,"完整后继未整体保存")
    proof,result=forged_directory(lab,"a1","stale",lambda _:None)
    reject_rust(lab,"a1","key_package_response",request_id="stale",receipt=result["receipt"])
    for name,transform in (("gap",lambda s:s["result"]["snapshots"].__setitem__(0,encode_snapshot(json.loads(base64.b64decode(s["result"]["snapshots"][0]))|{"version":"3"}))),
                           ("truncated",lambda s:s["result"].__setitem__("snapshots",s["result"]["snapshots"][:1]))):
        proof,result=forged_directory(lab,"a1",name,transform);reject_rust(lab,"a1","key_package_response",request_id=name,receipt=result["receipt"])
    lab.fetch_directory("a1","a1","alice-original")
    def omission(statement):
        chain=statement["result"]["snapshots"];head=json.loads(base64.b64decode(chain[-1]));head["devices"]=head["devices"][1:];head["version"]=str(int(head["version"])+1);head["previous_sha256"]=sha(base64.b64decode(chain[-1]));chain.append(encode_snapshot(head))
    proof,result=forged_directory(lab,"a1","omission",omission,account="alice")
    check(reject_rust(lab,"a1","key_package_response",request_id="omission",receipt=result["receipt"])["code"]=="directory_omission","遗漏已知设备未拒绝")
    lab.fetch_directory("a2")
    def fork(statement):
        head=json.loads(base64.b64decode(statement["result"]["snapshots"][0]));head["devices"][0]["status"]="revoked";statement["result"]["snapshots"][0]=encode_snapshot(head)
    proof,result=forged_directory(lab,"a2","fork",fork);value=lab.response("a2",proof,result)
    check(value["directory_status"]=="conflict","同版本分叉没有持久暂停")
    lab.restart();proof,result=forged_directory(lab,"a2","after-fork",successor);lab.response("a2",proof,result)
    check(lab.pool("a2")["directories"][identity("d1")["account_id"]]["conflict"],"高版本清除了冲突")
    check(lab.pool("a1")["freshness"]=="unknown","错误宣称全局新鲜")
    lab.continued()

def k03(lab):
    before_key=lab.public["d1"]["signature_key"]
    generated=lab.generate();proof=generated["proof"];before=lab.pool();lab.restart()
    result=lab.remote("d1",proof);lab.response("d1",proof,result)
    check(lab.remote("d1",proof)==result,"精确发布不稳定")
    check(len(lab.rows("kp_materials"))==2 and len(lab.pool()["packages"])==2,"bundle与公开材料未一一对应")
    materials=list(before["packages"].values())
    check(len({p["material"]["init_key"] for p in materials})==2 and len({p["material"]["leaf_key"] for p in materials})==2,"新包复用了init或leaf钥")
    alias=lab.request("d1","alias",decode(proof)["action"]);lab.remote("d1",alias)
    check(len(lab.rows("kp_materials"))==2,"换发布ID制造重复库存")
    bad=copy.deepcopy(proof);raw=bytearray(base64.b64decode(bad["signature_bytes"]));raw[0]^=1;bad["signature_bytes"]=base64.b64encode(raw).decode()
    unchanged=database(lab);lab.remote("d1",bad,expected=403);check(database(lab)==unchanged,"坏签名写入了记录")
    original=decode(proof)["action"]["packages"][0]
    for mode in ("reuse_init","bad_signature","wrong_suite","wrong_identity","excess_lifetime","last_resort"):
        malicious=lab.probe("d1",mode,"adversarial-"+mode,original)
        before=database(lab);error=lab.remote("d1",malicious["proof"],expected=(400,403,409))
        check(database(lab)==before,"恶意批次留下部分发布")
        if mode=="reuse_init":check(error["code"]=="key_package_reuse","真实重签init复用未被唯一约束拒绝")
        lab.case_evidence.setdefault("adversarial_materials",[]).append({"mode":mode,"error":error,"proof":malicious["proof"]})
    lab.publish("four",count=4)
    three=lab.generate("over-quota",count=3)["proof"];unchanged=database(lab)
    lab.remote("d1",three,expected=429);check(database(lab)==unchanged,"超限批次部分发布")
    lab.publish("two",count=2)
    check(lab.rust("d1","init")["signature_key"]==before_key,"补充材料重置身份")
    lab.continued()

def k04(lab):
    lab.publish(count=1);lab.ready();lab.ready("a2")
    proofs=[lab.request(actor,"race-"+actor,lab.claim_action(actor,change_id="join-"+actor)) for actor in ("a1","a2")]
    replies=lab.simultaneous([lambda:lab.remote("a1",proofs[0]),lambda:lab.remote("a2",proofs[1])])
    check(sorted(decode(r["receipt"])["result"]["kind"] for r in replies)==["allocated","unavailable"],"一次性材料分配给了两个请求")
    lab.restart()
    for actor,proof,result in zip(("a1","a2"),proofs,replies):
        check(lab.remote(actor,proof)==result,"重启丢失原竞争结果");lab.response(actor,proof,result)
    winner=next(a for a,r in zip(("a1","a2"),replies) if decode(r["receipt"])["result"]["kind"]=="allocated")
    loser="a2" if winner=="a1" else "a1"
    reject_rust(lab,loser,"permission_prepare_claim",request_id="race-"+loser)
    candidate=lab.prepare_join("race-"+winner,actor=winner);bundle=lab.accepted_bundle(candidate,actor=winner);lab.rust("d1","permission_join",**bundle)
    lab.publish("same-publish",target="b2",count=1);lab.ready("b1","b2")
    proof=lab.request("b1","same-race",lab.claim_action("b1","b2","same-join"))
    replies=lab.simultaneous([lambda:lab.remote("b1",proof),lambda:lab.remote("b1",proof)])
    check(replies[0]==replies[1] and decode(replies[0]["receipt"])["result"]["kind"]=="allocated","同请求并发结果不一致")
    check(len(lab.rows("permission_changes"))==1,"单份材料形成了两个可接受加入")
    lab.continued(recipients=(*ACCOUNTS,"d1"))

def k06(lab):
    lab.ready();proof,empty=lab.claim("empty",change_id="empty-join")
    check(decode(empty["receipt"])["result"]["kind"]=="unavailable","空库存伪成功")
    lab.publish(count=1)
    check(lab.remote("a1",proof)==empty,"补货改写原失败结果")
    lab.claim("refilled",change_id="refilled-join")
    _,empty2=lab.claim("allocated-empty",change_id="allocated-empty-join")
    check(decode(empty2["receipt"])["result"]["kind"]=="unavailable","已分配库存仍然可领")
    future=lab.generate("future",count=1,not_before=str(int(time.time())+60),not_after=str(int(time.time())+3600))["proof"]
    lab.remote("d1",future,expected=400)
    expired=lab.generate("expired",count=1,ttl=1)["proof"]
    end=int(next(p["material"]["not_after"] for p in lab.pool()["packages"].values() if p["encoded"]==decode(expired)["action"]["packages"][0]))
    while time.time()<end:time.sleep(.05)
    lab.remote("d1",expired,expected=400)
    reject_rust(lab,"d1","key_package_generate",request_id="too-long",count=1,not_before="1",not_after="86402",source_key=lab.relay_receipt_key)
    lab.continued()

def k07(lab):
    lab.publish();lab.ready();proof,result=lab.claim()
    for actor in ("c1","a2"):lab.remote(actor,proof,expected=403)
    candidate=lab.prepare_join()
    for field,value in (("service_id","S2"),("conversation_id","other-group"),("change_id","other-candidate"),("actor",lab.member("c1"))):
        bad=copy.deepcopy(candidate);bad["change"]=tamper(bad["change"],field,value)
        before=database(lab);lab.submit_join(bad,expected=(400,403,409));check(database(lab)==before,"改绑候选留下部分接受")
        lab.case_evidence.setdefault("allocation_binding_rejections",[]).append(field)
    for field,value in (("target",lab.member("b2")),("change_id","other-claim"),("conversation_id","other-group")):
        bad=copy.deepcopy(candidate);allocation=bad["join"]["allocation"];action=decode(allocation["request"])["action"]|{field:value}
        allocation["request"]=tamper(allocation["request"],"action",action)
        before=database(lab);lab.submit_join(bad,expected=(400,403,409));check(database(lab)==before,"改绑分配留下部分接受")
    bad=copy.deepcopy(candidate)
    bad["join"]["key_package"]=next(p["encoded"] for p in lab.pool()["packages"].values() if p["encoded"]!=candidate["join"]["key_package"])
    before=database(lab);lab.submit_join(bad,expected=(400,403,409));check(database(lab)==before,"替换材料留下部分接受")
    for field in ("request","receipt"):
        bad=copy.deepcopy(candidate);encoded=bad["join"]["allocation"][field]["signature_bytes"]
        raw=bytearray(base64.b64decode(encoded));raw[0]^=1;bad["join"]["allocation"][field]["signature_bytes"]=base64.b64encode(raw).decode()
        before=database(lab);lab.submit_join(bad,expected=(400,403,409));check(database(lab)==before,"改绑材料留下部分接受")
    original=lab.rows("kp_materials")
    republish=lab.request("d1","republish",{"kind":"publish","packages":[decode(result["receipt"])["result"]["key_package"]]})
    lab.remote("d1",republish,expected=409);check(lab.rows("kp_materials")==original,"已分配材料重新上架")
    closed_request=lab.rust("a1","permission_close_request")
    closed=lab.http("a1","close_permission_change",{"service_id":lab.service,"conversation_id":CONVERSATION,**closed_request})
    lab.rust("a1","permission_recover",record=closed)
    lab.submit_join(candidate,expected=409)
    check(any(r["state"]=="retired" and r["allocation"] for r in lab.rows("kp_materials")),"封口释放了分配占用")
    lab.claim("fresh-claim",change_id="fresh-join")
    candidate=lab.rust("a1","permission_prepare_claim",request_id="fresh-claim")
    bundle=lab.accepted_bundle(candidate);lab.rust("d1","permission_join",**bundle)
    check(lab.submit_join(candidate)["receipt"]==bundle["record"]["receipt"],"原接受结果不稳定")
    lab.continued(recipients=(*ACCOUNTS,"d1"))

from .key_package_faults import k05,k08,k10,k11,k12,k09
CASES={"K01":k01,"K02":k02,"K03":k03,"K04":k04,"K05":k05,"K06":k06,"K07":k07,"K08":k08,"K09":k09,"K10":k10,"K11":k11,"K12":k12}
