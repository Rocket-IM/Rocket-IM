"""K05/K08—K12故障、R0排序、旧程序、锚与期限证据。"""
import base64
import copy
import http.client
import json
from pathlib import Path
import subprocess
import sys
import time
from .fixture import ACCOUNTS,check,identity,CONVERSATION
from .first_trust_evidence import database,state
from .first_trust_session import verify_public,public_identity
from .key_package_fixture import decode,transaction


def k05(lab):
    for index,hook in enumerate(("before_commit_exit","after_commit_exit","drop_after_commit")):
        proof=lab.generate("lost-publish-"+str(index),count=1)["proof"];before=database(lab)
        lab.control("hook",hook=hook)
        try:lab.remote("d1",proof);raise AssertionError("故障仍返回成功")
        except (http.client.RemoteDisconnected,ConnectionResetError):pass
        if hook!="drop_after_commit":check(lab.process.wait(timeout=10)==(86 if hook=="before_commit_exit" else 87),"服务退出点不符")
        if hook=="before_commit_exit":check(database(lab)==before,"服务提交前退出部分写入")
        lab.restart();result=lab.remote("d1",proof);check(lab.remote("d1",proof)==result,"发布原件不稳定")
        saved=state(lab)
        lab.response("d1",proof,result,failpoint="before_save",expected_exit=83);check(state(lab)==saved,"客户端提交前已保存成功")
        lab.response("d1",proof,result,failpoint="after_save",expected_exit=85);lab.response("d1",proof,result)
    lab.ready()
    for index,hook in enumerate(("before_commit_exit","after_commit_exit","drop_after_commit")):
        proof=lab.request("a1","lost-claim-"+str(index),lab.claim_action(change_id="lost-join-"+str(index)))
        before=database(lab);lab.control("hook",hook=hook)
        try:lab.remote("a1",proof);raise AssertionError("故障仍返回成功")
        except (http.client.RemoteDisconnected,ConnectionResetError):pass
        if hook!="drop_after_commit":lab.process.wait(timeout=10)
        if hook=="before_commit_exit":check(database(lab)==before,"领取部分提交")
        lab.restart();result=lab.remote("a1",proof);check(lab.remote("a1",proof)==result,"领取重试换材料")
        lab.response("a1",proof,result,failpoint="before_save",expected_exit=83);lab.response("a1",proof,result)
    check(len(lab.rows("kp_materials"))==3 and all(r["state"]=="allocated" for r in lab.rows("kp_materials")),"丢响应制造多份材料或多次领取")
    lab.continued()


def k08(lab):
    lab.publish(count=1);lab.ready();lab.claim();candidate=lab.prepare_join()
    for table,verb,condition in (("permission_resolutions","INSERT","1"),("permission_changes","INSERT","1"),("kp_materials","UPDATE","NEW.state='accepted'")):
        before=database(lab)
        with transaction(lab) as db:db.execute(f"CREATE TRIGGER kp_fault BEFORE {verb} ON {table} WHEN {condition} BEGIN SELECT RAISE(ABORT,'synthetic fault'); END")
        lab.submit_join(candidate,expected=503)
        with transaction(lab) as db:db.execute("DROP TRIGGER kp_fault")
        check(database(lab)==before,"接受事务材料/权限/回执部分提交")
    bundle=lab.accepted_bundle(candidate);saved=(lab.directory/"d1/state.enc").read_bytes()
    for point,code in (("after_welcome_keys",83),("after_welcome_validation",84),("before_save",83),("before_rename",84)):
        lab.rust("d1","permission_join",**bundle,failpoint=point,expected_exit=code)
        check((lab.directory/"d1/state.enc").read_bytes()==saved,"Welcome故障消费有效bundle")
        check(not next(iter(lab.pool()["packages"].values()))["consumed"],"失败被标为已消费")
    lab.rust("d1","permission_join",**bundle,failpoint="after_save",expected_exit=85)
    check(lab.rust("d1","permission_join",**bundle)["duplicate"],"输出丢失无法恢复原结果")
    lab.continued(recipients=(*ACCOUNTS,"d1"));saved=(lab.directory/"d1/state.enc").read_bytes()
    lab.rust("d1","permission_join",**bundle);check((lab.directory/"d1/state.enc").read_bytes()==saved,"重复加入重写后来状态")


def k09(lab):
    from .key_package_cases import reject_rust
    lab.publish(count=1);lab.ready();old=lab.rust("a1","identity_trust_inspect",target=identity("d1"))
    lab.publish("rotation",count=1);lab.claim()
    check(lab.rust("a1","identity_trust_inspect",target=identity("d1"))==old,"材料轮换需要重新核验")
    request={"directory":str(lab.directory/"changed-identity"),"service":lab.service,"account":identity("d1")["account_id"],"device":"d1","operation":"init"}
    replacement=subprocess.run([str(lab.binary)],input=json.dumps(request),text=True,capture_output=True,timeout=20)
    check(replacement.returncode==0,"新身份装置初始化失败")
    changed=public_identity(lab,"d1")|{"signature_key":json.loads(replacement.stdout)["result"]["signature_key"]}
    lab.rust("a1","identity_trust_observe",identity=changed);lab.restart()
    error=reject_rust(lab,"a1","permission_prepare_claim",request_id="claim-1")
    check(error["code"]=="identity_changed","变更身份未持续阻断")
    from .first_trust_fixture import confirm
    confirm(lab,target="d1",purpose="reset",independent=changed)
    confirm(lab,target="d1",independent=changed)
    reject_rust(lab,"a1","permission_prepare_claim",request_id="claim-1")
    # 代际字段不能作为v1隐含扩展。
    reject_rust(lab,"a2","identity_trust_observe",identity=public_identity(lab,"d1")|{"identity_generation":"2"})
    # 原设备ID仍不可通过不同钥重新注册；新设备独立注册/核验正例使用b2。
    lab.http("d1","begin_device_registration",{"service_id":lab.service,"registration_id":"rebind","signature_key":changed["signature_key"]},expected=409)
    lab.publish("new-device",target="b2",count=1);lab.ready("b1","b2");lab.claim("new-device-claim",actor="b1",target="b2",change_id="new-device-join")
    candidate=lab.prepare_join("new-device-claim",actor="b1",target="b2")
    bundle=lab.accepted_bundle(candidate,actor="b1",target="b2");lab.rust("b2","permission_join",**bundle)
    # 已变化的d1是非群成员，不影响原有效会话。
    lab.continued(sender="a2",recipients=(*ACCOUNTS,"b2"))


def start_legacy_server(lab,entry,database_path):
    process=subprocess.Popen([sys.executable,str(entry),"--database",str(database_path),"--fixture",str(lab.fixture_path),"--port","0"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    line=process.stdout.readline()
    if not line:
        error=process.stderr.read();process.wait(timeout=5);raise AssertionError("旧库程序启动失败: "+error[:400])
    process.terminate();process.wait(timeout=10)
    for stream in (process.stdout,process.stderr):stream.close()


def k11(lab):
    from .key_package_cases import reject_rust
    from .key_package_boundaries import child
    for mode in ("missing_bundle","corrupt_snapshot"):
        with child(lab,mode) as corrupted:
            generated=corrupted.generate(count=1)["proof"];original=decode(generated)["action"]["packages"][0]
            if mode=="missing_bundle":corrupted.probe("d1",mode,"corrupt",original)
            else:
                path=corrupted.directory/"d1/state.enc";data=bytearray(path.read_bytes());data[-1]^=1;path.write_bytes(data)
            saved=(corrupted.directory/"d1/state.enc").read_bytes()
            error=corrupted.rust("d1","key_package_inspect",expected_exit=1)
            check(error["code"] in ("key_package_missing","snapshot_load"),"损坏材料未明确失败")
            check((corrupted.directory/"d1/state.enc").read_bytes()==saved,"拒载补造了材料")
            corrupted.case_evidence["corruption_error"]=error
    check(lab.old_binary and lab.old_relay,"K11须提供真实旧程序和旧Relay来源")
    legacy=lab.directory/"legacy-client";request={"directory":str(legacy),"service":lab.service,"account":"old","device":"old1","operation":"init"}
    old=subprocess.run([str(lab.old_binary)],input=json.dumps(request),text=True,capture_output=True,timeout=20);check(old.returncode==0,"旧程序未创建真实快照")
    request["operation"]="key_package_inspect"
    new=subprocess.run([str(lab.binary)],input=json.dumps(request),text=True,capture_output=True,timeout=20)
    check(new.returncode==0 and json.loads(new.stdout)["result"]["enabled"] is False,"旧快照补造库存")
    request.update(operation="key_package_generate",request_id="legacy-new",count=1,not_before=str(int(time.time())-1),not_after=str(int(time.time())+3600),source_key=lab.relay_receipt_key)
    generated=subprocess.run([str(lab.binary)],input=json.dumps(request),text=True,capture_output=True,timeout=20);check(generated.returncode==0,"迁移后不能生成独立新材料")
    request={k:request[k] for k in ("directory","service","account","device")}|{"operation":"init"}
    before=(legacy/"state.enc").read_bytes();old=subprocess.run([str(lab.old_binary)],input=json.dumps(request),text=True,capture_output=True,timeout=20)
    check(old.returncode==1 and (legacy/"state.enc").read_bytes()==before,"旧程序忽略新消费账本")
    database_path=lab.directory/"legacy-relay.sqlite"
    start_legacy_server(lab,lab.old_relay/"server.py",database_path)
    with sqlite_read(database_path) as db:check(db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()[0]=="rim-poc-storage-8","未使用真实旧库")
    start_legacy_server(lab,Path(__file__).resolve().parents[3]/"poc/network-relay/server.py",database_path)
    with sqlite_read(database_path) as db:
        check(db.execute("SELECT count(*) FROM kp_materials").fetchone()[0]==0,"旧数据库迁移补造材料")
    with sqlite_read(database_path) as db:before=list(db.iterdump())
    old_server=subprocess.run([sys.executable,str(lab.old_relay/"server.py"),"--database",str(database_path),"--fixture",str(lab.fixture_path),"--port","0"],capture_output=True,text=True,timeout=10)
    with sqlite_read(database_path) as db:after=list(db.iterdump())
    check(old_server.returncode!=0 and before==after,"旧Relay忽略新账本版本或改写新库")
    with child(lab,"old-verifier") as legacy_contract:
        legacy_contract.publish(count=1);legacy_contract.ready();legacy_contract.claim();candidate=legacy_contract.prepare_join()
        public_input={"checkpoint":legacy_contract.checkpoint,"change":candidate["change"],"join":candidate["join"]}
        old_verify=subprocess.run([str(lab.old_binary.with_name("openmls-permission-verify"))],input=json.dumps(public_input),text=True,capture_output=True,timeout=10)
        new_verify=subprocess.run([str(lab.permission_verifier)],input=json.dumps(public_input),text=True,capture_output=True,timeout=10)
        check(old_verify.returncode==1 and new_verify.returncode==0,"新旧验证器未按同一公开v2输入明确区分")
        legacy_contract.case_evidence["old_verifier_error"]=json.loads(old_verify.stdout)["error"]
        bundle=legacy_contract.accepted_bundle(candidate);legacy_contract.rust("d1","permission_join",**bundle)
        legacy_contract.continued(recipients=(*ACCOUNTS,"d1"))
    # 待提交意图保留；服务和本机满额均不删除原结果。
    pending=lab.generate("pending",count=1)["proof"];check(lab.pool()["requests"]["pending"]["receipt"] is None,"未决请求被伪完成")
    first=None
    for i in range(64):
        actor="a1" if i<32 else "a2"
        proof=lab.request(actor,"full-"+str(i),{"kind":"directory","account_id":"alice","challenge":str(i).zfill(64)})
        result=lab.remote(actor,proof)
        if first is None:first=(proof,result)
    proof=lab.request("a1","over-server",{"kind":"directory","account_id":"alice","challenge":"ab"*32});lab.remote("a1",proof,expected=429)
    check(lab.remote("a1",first[0])==first[1],"满账本原请求失效")
    check(lab.pool()["requests"]["pending"]["receipt"] is None,"满账本删除了未决请求")
    with child(lab,"local-ledger-full") as full:
        action={"kind":"directory","account_id":"alice","challenge":"cd"*32}
        original=full.request("a1","local-0",action)
        for index in range(1,64):full.request("a1","local-"+str(index),action)
        before=state(full)
        error=reject_rust(full,"a1","key_package_request",request_id="over-local",action=action,source_key=full.relay_receipt_key)
        check(error["code"]=="resource_exhausted" and state(full)==before,"本机满账本删除了意图或留下半状态")
        check(full.request("a1","local-0",action)==original and state(full)==before,"本机满账本原请求不可重试")
        full.continued()
    # 真实独立锚：完整日志可Finish，缺日志保持暂停。
    lab.helper=lab.binary.with_name("openmls-rollback-anchor");check(lab.helper.is_file(),"缺少真实锚程序")
    lab.enable("d1")
    anchored=state(lab)
    error=lab.rust("d1","key_package_generate",request_id="wrong-anchor-source",count=1,not_before=str(int(time.time())-1),not_after=str(int(time.time())+3600),source_key=lab.public["c1"]["signature_key"],expected_exit=1)
    check(error["code"]=="key_package_source" and state(lab)==anchored and lab.rust("d1","anchor_inspect")["active_txn"] is None,"确定的来源拒绝留下未决锚预约")
    now=int(time.time());fields={"request_id":"journal","count":1,"not_before":str(now-1),"not_after":str(now+3600),"source_key":lab.relay_receipt_key}
    lab.rust("d1","key_package_generate",**fields,env={"RIM_ANCHOR_FAILPOINT":"after_journal"},expected_exit=87)
    lab.resume("d1");check("journal" in lab.pool()["requests"],"完整日志丢失原意图")
    lab.enable("a2")
    lab.rust("a2","key_package_generate",**(fields|{"request_id":"missing-journal"}),env={"RIM_ANCHOR_FAILPOINT":"after_reserve"},expected_exit=86)
    for _ in range(2):
        check(lab.blocked("a2","anchor_resume")["code"]=="anchor_unresolved","缺日志锚被释放")
        lab.restart()
    lab.continued(recipients=("a1","b1","c1"))

from contextlib import contextmanager
@contextmanager
def sqlite_read(path):
    import sqlite3
    db=sqlite3.connect(path,isolation_level=None);db.execute("BEGIN")
    try:yield db;db.commit()
    finally:db.close()


from .key_package_boundaries import k10,k12
