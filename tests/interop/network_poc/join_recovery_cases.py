"""E 矩阵业务子集：全部使用真实 Rust 设备及同一 HTTP/SQLite Relay。"""
from .fixture import ACCOUNTS, check
from .first_trust_evidence import state
from .first_trust_evidence import database
from .join_recovery_fixture import signed_digest
from .key_package_fixture import decode, transaction
import copy
import http.client
import secrets
import time


def basic(lab):
    lab.setup_expired()
    intent,claim,allocated,bundle=lab.prepare_recovery()
    check(lab.remote_recovery(lab.actor,"claim",intent=intent,proof=claim)==allocated,"分配重试改变原件")
    check(lab.recovery(lab.actor,"prepare",intent=intent,claim=claim,allocation=allocated["allocation"],key_package=allocated["key_package"])["bundle"]==bundle,"构造重试重新生成")
    result=lab.accept_recovery(bundle);check(result["state"]=="accepted","没有 R0")
    check(lab.accept_recovery(bundle)==result,"接受重试改变原件")
    check(lab.get_recovery(intent)==result,"查询原件不一致")
    lab.restart();check(lab.get_recovery(intent)==result,"重启丢失唯一终态")
    lab.install_recovery(result["record"])
    before=state(lab)
    for device in (*ACCOUNTS,lab.target):check(lab.recovery(device,"apply",record=result["record"])["duplicate"],"R1 重试非原结果")
    check(state(lab)==before,"精确重试重写快照")
    lab.unchanged_original()
    before=state(lab)
    error=lab.receive(lab.target,lab.old_packet,acceptance_id=lab.old_acceptance["acceptance_id"],acceptance_receipt=lab.old_acceptance["acceptance_receipt"],expected_exit=1)
    check(error["code"]=="history_unavailable" and state(lab)==before,"恢复自动获得了旧历史或改写失败状态")
    lab.continued("after-recovery",recipients=(*ACCOUNTS,lab.target))


def close_order(lab,accept_first):
    lab.setup_expired();intent,claim,allocated,bundle=lab.prepare_recovery()
    close=lab.control_proof(intent,"close",lab.target)
    accept=lambda:lab.accept_recovery(bundle)
    cancel=lambda:lab.remote_recovery(lab.target,"close",intent=intent,proof=close)
    results=lab.ordered([accept,cancel] if accept_first else [cancel,accept])
    check(results[0]["receipt"]==results[1]["receipt"],"竞争产生两个不同终态")
    check(results[0]["state"]==("accepted" if accept_first else "closed"),"事务屏障先后未决定终态")
    if accept_first:lab.install_recovery(results[0]["record"])
    else:
        for device in (lab.actor,lab.target):lab.recovery(device,"resolve",intent=intent,receipt=results[0]["receipt"])
        check(lab.recovery(lab.actor,"inspect")["pending"] is None,"关闭未解除原候选")
        check(lab.remote_recovery(lab.actor,"claim",intent=intent,proof=claim)["receipt"]==results[0]["receipt"],"迟到领取复活关闭")
    lab.unchanged_original()

def tombstone(lab):
    lab.setup_expired();intent=lab.intent();claim=lab.control_proof(intent)
    close=lab.control_proof(intent,"close",lab.target)
    result=lab.remote_recovery(lab.target,"close",intent=intent,proof=close)
    check(result["state"]=="closed" and result["allocation"] is None,"未领取关闭不准确")
    check(lab.remote_recovery(lab.actor,"claim",intent=intent,proof=claim)["receipt"]==result["receipt"],"墓碑未封迟到请求")
    with transaction(lab) as db:
        check(db.execute("SELECT count(*) FROM recovery_active").fetchone()[0]==0,"墓碑占用活动槽")
        check(db.execute("SELECT state FROM kp_materials WHERE hash=?",(decode(intent)["key_package_sha256"],)).fetchone()[0]=="available","未领取关闭消耗材料")
    lab.unchanged_original()

def concurrency(lab):
    lab.setup_expired();first=lab.intent();claim1=lab.control_proof(first)
    value=decode(first);value.update(request_id="rival",change_id="change-rival",nonce=secrets.token_hex(32),actor=lab.member("a2"))
    second=lab.sign_probe(lab.target,value)
    request=decode(claim1);request.update(request_id="claim-rival",recovery_id="rival",change_id="change-rival",signer=lab.member("a2"),intent_sha256=signed_digest(second),nonce=secrets.token_hex(32))
    claim2=lab.sign_probe("a2",request)
    results=lab.simultaneous([lambda:lab.remote_recovery("a1","claim",intent=first,proof=claim1,expected=(200,409)),lambda:lab.remote_recovery("a2","claim",intent=second,proof=claim2,expected=(200,409))])
    check(sum(r.get("state")=="allocated" for r in results)==1 and sum(r.get("code")=="recovery_busy" for r in results)==1,"两个 actor 竞争未唯一分配")
    winner=0 if results[0].get("state")=="allocated" else 1
    intent,claim,actor=(first,claim1,"a1") if winner==0 else (second,claim2,"a2")
    repeated=lab.simultaneous([lambda:lab.remote_recovery(actor,"claim",intent=intent,proof=claim)]*2)
    check(repeated[0]==repeated[1]==results[winner],"并发重复领取新增结果")
    with transaction(lab) as db:
        check(db.execute("SELECT count(*) FROM recovery_attempts").fetchone()[0]==1,"失败竞争保存半记录")
        check(db.execute("SELECT count(*) FROM recovery_active").fetchone()[0]==1,"活动槽不唯一")
    # 同 ID 不同原件必须失败，即使签名仍然正确。
    changed=decode(intent);changed["nonce"]=secrets.token_hex(32);changed=lab.sign_probe(lab.target,changed)
    request=decode(claim);request["intent_sha256"]=signed_digest(changed);request["nonce"]=secrets.token_hex(32)
    altered_claim=lab.sign_probe(actor,request)
    before=database(lab)
    check(lab.remote_recovery(actor,"claim",intent=changed,proof=altered_claim,expected=409)["code"]=="idempotency_conflict","同 ID 异字节未拒绝")
    check(database(lab)==before,"冲突改变账本")
    lab.unchanged_original()

def authorization(lab,device_root=False):
    lab.setup_expired("b2","b1") if device_root else lab.setup_expired()
    intent=lab.intent();claim=lab.control_proof(intent)
    value=decode(intent);wrong="a1" if device_root else "b1"
    value["actor"]=lab.member(wrong)
    # 先保持目录引用，资格必须在新 actor 授权时被拒绝，不依赖原邀请人。
    for directory in (wrong,lab.target):lab.fetch_directory(lab.target,directory,"auth-dir-"+directory)
    value["directory_refs"]=[]
    for account,d in sorted(lab.pool(lab.target)["directories"].items()):
        if account in {value["actor"]["account_id"],value["signer"]["account_id"]}:
            import base64,hashlib,json
            raw=base64.b64decode(d["snapshots"][-1]);value["directory_refs"].append({"account_id":account,"version":json.loads(raw)["version"],"sha256":hashlib.sha256(raw).hexdigest()})
    bad=lab.sign_probe(lab.target,value);request=decode(claim)
    request.update(signer=lab.member(wrong),intent_sha256=signed_digest(bad))
    wrong_claim=lab.sign_probe(wrong,request)
    before=database(lab)
    check(lab.remote_recovery(wrong,"claim",intent=bad,proof=wrong_claim,expected=403)["code"]=="permission_denied","错误批准角色通过")
    check(database(lab)==before,"拒绝修改原事实")
    allocated=lab.remote_recovery(lab.actor,"claim",intent=intent,proof=claim)
    bundle=lab.recovery(lab.actor,"prepare",intent=intent,claim=claim,allocation=allocated["allocation"],key_package=allocated["key_package"])["bundle"]
    result=lab.accept_recovery(bundle);lab.install_recovery(result["record"])
    lab.unchanged_original()

def service_faults(lab):
    lab.setup_expired();intent=lab.intent();claim=lab.control_proof(intent)
    for hook in ("before_commit_exit","after_commit_exit","drop_after_commit"):
        before=database(lab);lab.control("hook",hook=hook)
        try:lab.remote_recovery(lab.actor,"claim",intent=intent,proof=claim);raise AssertionError("注入故障仍交付成功")
        except (http.client.RemoteDisconnected,ConnectionResetError):pass
        if hook!="drop_after_commit":lab.process.wait(timeout=10)
        if hook=="before_commit_exit":check(database(lab)==before,"分配半提交")
        lab.restart()
    allocated=lab.remote_recovery(lab.actor,"claim",intent=intent,proof=claim)
    bundle=lab.recovery(lab.actor,"prepare",intent=intent,claim=claim,allocation=allocated["allocation"],key_package=allocated["key_package"])["bundle"]
    for table,verb,condition in (("permission_changes","INSERT","1"),("permission_resolutions","INSERT","1"),("recovery_attempts","UPDATE","NEW.state='accepted'"),
                                  ("recovery_edges","INSERT","1"),("recovery_roots","UPDATE","1"),("kp_materials","UPDATE","NEW.state='accepted'"),("permission_checkpoint","UPDATE","1"),("conversation","UPDATE","1")):
        before=database(lab)
        with transaction(lab) as db:db.execute(f"CREATE TRIGGER recovery_fault BEFORE {verb} ON {table} WHEN {condition} BEGIN SELECT RAISE(ABORT,'synthetic fault'); END")
        lab.remote_recovery(lab.actor,"accept",bundle=bundle,expected=503)
        with transaction(lab) as db:db.execute("DROP TRIGGER recovery_fault")
        check(database(lab)==before,"接受故障导致部分写入: "+table)
    for hook in ("before_commit_exit","after_commit_exit","drop_after_commit"):
        before=database(lab);lab.control("hook",hook=hook)
        try:lab.accept_recovery(bundle);raise AssertionError("故障仍交付成功")
        except (http.client.RemoteDisconnected,ConnectionResetError):pass
        if hook!="drop_after_commit":lab.process.wait(timeout=10)
        if hook=="before_commit_exit":check(database(lab)==before,"接受半提交")
        lab.restart()
    result=lab.accept_recovery(bundle);check(lab.get_recovery(intent)["record"]==result["record"],"故障后未精确恢复")
    lab.install_recovery(result["record"]);lab.unchanged_original()

def client_faults(lab):
    lab.setup_expired();intent=lab.intent();claim=lab.control_proof(intent)
    allocated=lab.remote_recovery(lab.actor,"claim",intent=intent,proof=claim)
    arguments=dict(intent=intent,claim=claim,allocation=allocated["allocation"],key_package=allocated["key_package"])
    before=state(lab)
    lab.recovery(lab.actor,"prepare",**arguments,failpoint="before_save",expected_exit=83)
    check(state(lab)==before,"候选未保存却推进状态")
    lab.recovery(lab.actor,"prepare",**arguments,failpoint="after_save",expected_exit=85)
    bundle=lab.recovery(lab.actor,"prepare",**arguments)["bundle"]
    check(lab.recovery(lab.actor,"prepare",**arguments)["bundle"]==bundle,"保存后丢响应重造候选")
    result=lab.accept_recovery(bundle);record=result["record"]
    for device in (*ACCOUNTS,lab.target):lab.recovery(device,"observe",record=record)
    for device in (lab.actor,"b1",lab.target):
        before=state(lab)
        points=(("after_welcome_keys",83),("after_welcome_validation",84)) if device==lab.target else ()
        for point,code in (*points,("before_save",83),("before_rename",84)):
            lab.recovery(device,"apply",record=record,failpoint=point,expected_exit=code)
            check(state(lab)==before,"失败改变正式快照或消费 bundle")
        lab.recovery(device,"apply",record=record,failpoint="after_save",expected_exit=85)
        check(lab.recovery(device,"apply",record=record)["duplicate"],"保存成功丢响应没有原成功")
    for device in ("a2","c1"):lab.recovery(device,"apply",record=record)
    lab.unchanged_original();lab.continued("after-faults",recipients=(*ACCOUNTS,lab.target))

def successor(lab):
    lab.setup_expired()
    intent,claim,allocated,bundle=lab.prepare_recovery("first",package_ttl=6)
    first=lab.accept_recovery(bundle);lab.install_recovery(first["record"],tuple(ACCOUNTS))
    lab.recovery(lab.target,"observe",record=first["record"])
    deadline=int(lab.pool(lab.target)["packages"][decode(intent)["key_package_sha256"]]["material"]["not_after"])
    while int(time.time())<deadline:time.sleep(.1)
    check(lab.recovery(lab.target,"apply",record=first["record"],expected_exit=1)["code"]=="key_package_expired","迟到 Welcome 被消费")
    second_intent,_,_,second_bundle=lab.prepare_recovery("second")
    check(decode(second_intent)["current_admission"]!=lab.root,"第二次恢复错误回到原入口")
    second=lab.accept_recovery(second_bundle);lab.install_recovery(second["record"])
    check(lab.accept_recovery(bundle)["receipt"]==first["receipt"],"原 accepted 被第二次覆盖")
    lab.get_recovery(second_intent)
    close=lab.control_proof(intent,"close",lab.target,ident="close-superseded")
    old_terminal=lab.remote_recovery(lab.target,"close",intent=intent,proof=close)
    check(old_terminal["receipt"]==first["receipt"] and old_terminal["record"] is None and "key_package" not in old_terminal,"旧 accepted 通过 close 泄露已替代的首次入群材料")
    lab.remote_recovery(lab.target,"get",service_id=lab.service,conversation_id=lab.scope["conversation_id"],recovery_id="first",expected=409)
    with transaction(lab) as db:
        check(db.execute("SELECT count(*) FROM recovery_edges").fetchone()[0]==2,"不是两条精确后继边")
        check(db.execute("SELECT count(*) FROM recovery_active").fetchone()[0]==0,"终态仍占槽")
    lab.unchanged_original();lab.continued("second-recovery",recipients=(*ACCOUNTS,lab.target))

def predecessor(lab):
    lab.setup_expired();intent,claim,allocated,bundle=lab.prepare_recovery()
    change=lab.rust("a2","permission_prepare",change_id="unrelated",action={"kind":"remove_member","account_id":"charlie"})["change"]
    result=lab.http("a2","submit_permission_change",{"service_id":lab.service,"conversation_id":lab.scope["conversation_id"],"change":change})
    record={"change":change,"receipt":result["receipt"]}
    check(lab.remote_recovery(lab.actor,"accept",bundle=bundle,expected=409)["code"]=="recovery_predecessor_changed","无关先提交仍接受旧前驱")
    check(lab.get_recovery(intent)["state"]=="allocated","拒绝被当成已关闭")
    close=lab.control_proof(intent,"close",lab.target)
    closed=lab.remote_recovery(lab.target,"close",intent=intent,proof=close)
    for device in (lab.actor,lab.target):lab.recovery(device,"resolve",intent=intent,receipt=closed["receipt"])
    for device in ACCOUNTS:lab.rust(device,"permission_recover",record=record)
    lab.recovery(lab.target,"advance",record=record)
    from .recovery_consistency_cases import resume
    for device in (lab.actor,lab.target):resume(lab,device)
    # 成员移除拥有自己的合法历史变化；随后恢复必须保持该完整前驱历史。
    lab.before_original={t:database(lab)["tables"][t] for t in lab.before_original}
    _,_,_,fresh=lab.prepare_recovery("new-predecessor")
    accepted=lab.accept_recovery(fresh)
    lab.install_recovery(accepted["record"],("a1","a2","b1",lab.target))
    lab.unchanged_original()

def expiry(lab,after_check=False):
    lab.setup_expired();intent,claim,allocated,bundle=lab.prepare_recovery(ttl=5)
    deadline=int(decode(intent)["expires_at_unix_secs"])
    before=database(lab)
    if after_check:
        (lab.check_directory/"after-check-until").write_text(str(deadline+.1))
        accepted=lab.accept_recovery(bundle)
        observed=float((lab.check_directory/"checked-at").read_text())
        released=float((lab.check_directory/"released-at").read_text())
        check(int(observed)<deadline<=released and accepted["state"]=="accepted","取样/提交跨期限语义错误")
        lab.case_evidence["clock_boundary"]={"checked_at":observed,"expires":deadline,"released_at":released}
        check(lab.accept_recovery(bundle)["receipt"]==accepted["receipt"],"过期重试改写真实 accepted")
        lab.install_recovery(accepted["record"])
    else:
        delay=max(1,int((deadline-time.time()+.1)*1000))
        lab.control("hook",hook="delay_before_commit",delay_ms=str(delay))
        check(lab.remote_recovery(lab.actor,"accept",bundle=bundle,expected=409)["code"]=="recovery_expired","最后重验未覆盖意图期限")
        check(database(lab)==before,"期限失败保存了半接受")
        check(lab.get_recovery(intent)["state"]=="allocated","超时自动释放未决槽")
        close=lab.control_proof(intent,"close",lab.target)
        result=lab.remote_recovery(lab.target,"close",intent=intent,proof=close)
        check(result["state"]=="closed","过期后不能明确关闭")
    lab.unchanged_original()

def anchored(lab):
    from pathlib import Path
    lab.setup_expired();lab.helper=lab.binary.with_name("openmls-rollback-anchor")
    check(lab.helper.is_file(),"缺少真实独立锚程序")
    lab.enable(lab.actor);lab.enable(lab.target)
    intent=lab.intent();claim=lab.control_proof(intent)
    allocated=lab.remote_recovery(lab.actor,"claim",intent=intent,proof=claim)
    arguments=dict(intent=intent,claim=claim,allocation=allocated["allocation"],key_package=allocated["key_package"])
    lab.recovery(lab.actor,"prepare",**arguments,env={"RIM_ANCHOR_FAILPOINT":"after_journal"},expected_exit=87)
    lab.resume(lab.actor)
    bundle=lab.recovery(lab.actor,"prepare",**arguments)["bundle"]
    check(lab.recovery(lab.actor,"prepare",**arguments)["bundle"]==bundle,"Finish 恢复重新构造候选")
    accepted=lab.accept_recovery(bundle);record=accepted["record"]
    lab.recovery(lab.target,"observe",record=record)
    lab.forwarding_helper("drop","finish",device=lab.target)
    error=lab.recovery(lab.target,"apply",record=record,expected_exit=1)
    check(error["code"]=="anchor_response","Finish 丢响应提前交付成功")
    lab.config_restore(lab.target);saved=state(lab)
    lab.resume(lab.target)
    check(lab.recovery(lab.target,"apply",record=record)["duplicate"] and state(lab)==saved,"完整日志未恢复唯一 R1")
    lab.enable("c1")
    lab.recovery("c1","observe",record=record,env={"RIM_ANCHOR_FAILPOINT":"after_reserve"},expected_exit=86)
    before=state(lab)
    for _ in range(2):
        check(lab.blocked("c1","anchor_resume")["code"]=="anchor_unresolved","缺 journal 被释放")
        lab.restart()
    check(state(lab)==before,"未决锚偷偷改写状态")
    lab.case_evidence["anchor"]={"complete_journal":"exact_candidate_and_r1","missing_journal":"persistently_paused","finish_response_lost":error}
    lab.unchanged_original()

def revoked_after_claim(lab):
    lab.setup_expired();intent,claim,allocated,bundle=lab.prepare_recovery()
    close=lab.control_proof(intent,"close",lab.target)
    change=lab.rust("a2","permission_prepare",change_id="remove-target",action={"kind":"remove_member","account_id":"david"})["change"]
    lab.http("a2","submit_permission_change",{"service_id":lab.service,"conversation_id":lab.scope["conversation_id"],"change":change})
    before=database(lab)
    for device,kind,fields in ((lab.actor,"accept",{"bundle":bundle}),(lab.target,"close",{"intent":intent,"proof":close}),
                              (lab.target,"get",{"service_id":lab.service,"conversation_id":lab.scope["conversation_id"],"recovery_id":decode(intent)["request_id"]})):
        check(lab.remote_recovery(device,kind,**fields,expected=403)["code"]=="permission_denied","失权后仍能接受、关闭或读取")
    check(database(lab)==before,"失权拒绝改变账本")
    actor_close=lab.control_proof(intent,"close",lab.actor)
    result=lab.remote_recovery(lab.actor,"close",intent=intent,proof=actor_close)
    lab.recovery(lab.actor,"resolve",intent=intent,receipt=result["receipt"])
    check(result["state"]=="closed","仍有访问权的指定 actor 不能封口")

def capacity_terminal(lab):
    lab.setup_expired();intent,claim,allocated,bundle=lab.prepare_recovery()
    control=decode(lab.control_proof(intent,"close",lab.target))
    for index in range(1,33):
        value=decode(intent);value.update(request_id="quota-"+str(index),change_id="quota-change-"+str(index),nonce=secrets.token_hex(32))
        proof=lab.sign_probe(lab.target,value)
        c=copy.deepcopy(control);c.update(request_id="quota-close-"+str(index),recovery_id=value["request_id"],change_id=value["change_id"],intent_sha256=signed_digest(proof),nonce=secrets.token_hex(32))
        close=lab.sign_probe(lab.target,c)
        before=database(lab)
        result=lab.remote_recovery(lab.target,"close",intent=proof,proof=close,expected=429 if index==32 else 200)
        if index==32:check(result["code"]=="resource_exhausted" and database(lab)==before,"满额仍新建或破坏历史")
        else:check(result["state"]=="closed","墓碑未持久保存")
    accepted=lab.accept_recovery(bundle)
    lab.restart();check(lab.get_recovery(intent)==accepted,"满额或重启丢失原终态")
    lab.install_recovery(accepted["record"]);lab.unchanged_original()

def migration(lab):
    import subprocess,sys
    from pathlib import Path
    from .join_recovery_fixture import RecoveryLab
    check(lab.old_binary and lab.old_relay,"需要真实旧程序与冻结旧 Relay")
    directory=lab.directory/"old-client";directory.mkdir()
    old=RecoveryLab(lab.old_binary,directory,lab.old_binary.with_name("openmls-permission-verify"),lab.old_binary.with_name("openmls-relay-receipt"))
    new_entry,new_args=old.relay_entrypoint,old.relay_args
    old.relay_entrypoint=lab.old_relay;old.relay_args=old.relay_args[:-2]
    def upgrade():
        old.stop();before=database(old)
        with transaction(old) as db:check(db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()[0]=="rim-poc-storage-9","未使用真实旧 schema")
        old.binary=lab.binary;old.permission_verifier=lab.permission_verifier;old.receipt_signer=lab.receipt_signer
        old.relay_entrypoint=new_entry;old.relay_args=new_args;old.start()
        after=database(old)
        for table in before["tables"]:
            if table!="meta":check(before["tables"][table]==after["tables"][table],"升级改变原表: "+table)
        old.case_evidence["migration"]={"old_schema":"9","new_schema":"10","prior_tables_unchanged":True}
    old.before_recovery_root=upgrade
    try:
        old.initialize();old.setup_expired();old.probe_binary=lab.probe_binary
        intent,_,_,bundle=old.prepare_recovery();accepted=old.accept_recovery(bundle);old.install_recovery(accepted["record"])
        before=state(old);new_binary=old.binary;old.binary=lab.old_binary
        try:check(old.rust(old.target,"inspect",expected_exit=1)["code"] in ("wrong_context","state_decoding"),"旧客户端未拒绝新格式")
        finally:old.binary=new_binary
        check(state(old)==before,"旧客户端改写新格式")
        old.stop();before=database(old)
        cmd=[sys.executable,"-B",str(lab.old_relay),"--database",str(directory/"relay.sqlite"),"--fixture",str(old.fixture_path),"--port","0","--permission-verifier",str(lab.old_binary.with_name("openmls-permission-verify")),"--receipt-signer",str(lab.old_binary.with_name("openmls-relay-receipt")),"--receipt-key",str(old.receipt_key)]
        result=subprocess.run(cmd+["--enable-test-controls",*new_args[:-2]],capture_output=True,text=True,timeout=20)
        (directory/"old-relay-rejection.log").write_text(result.stderr)
        check(result.returncode!=0 and "不支持该实验数据库版本" in result.stderr,"旧 Relay 未明确拒绝新 schema")
        check(database(old)==before,"旧 Relay 改写新账本")
        old.start();check(old.get_recovery(intent)["receipt"]==accepted["receipt"],"重新打开丢原终态")
        old.continued("after-migration",recipients=(*ACCOUNTS,old.target))
    finally:
        old.stop();lab.case_evidence["legacy_migration"]=old.case_evidence

def accepted_bad_commit(lab):
    import base64,hashlib
    lab.setup_expired();intent,claim,allocated,bundle=lab.prepare_recovery()
    malicious=copy.deepcopy(bundle);raw=bytearray(base64.b64decode(bundle["change"]["commit_bytes"]));raw[-1]^=1
    statement=decode(bundle["change"]);statement["commit_sha256"]=hashlib.sha256(raw).hexdigest()
    original_binary=lab.binary
    try:
        lab.binary=lab.probe_binary
        malicious["change"]=lab.rust(lab.actor,"join_recovery_change_probe",statement=statement,commit_bytes=base64.b64encode(raw).decode())["change"]
    finally:lab.binary=original_binary
    result=lab.accept_recovery(malicious);check(result["state"]=="accepted","公共验证器应只作公开授权验证")
    record=result["record"]
    for device in (lab.actor,"b1"):
        lab.recovery(device,"observe",record=record);before=state(lab)
        error=lab.recovery(device,"apply",record=record,expected_exit=1)
        check(error["code"] in ("pending_conflict","recovery_commit"),"错误 Commit 通过真实 R1")
        check(state(lab)==before,"MLS 失败损坏前驱或已存 R0")
        lab.restart();check(lab.recovery(device,"observe",record=record)["duplicate"],"重启丢失 R0")
        lab.case_evidence.setdefault("r1_rejections",{})[device]=error
    check(lab.get_recovery(intent)["receipt"]==result["receipt"],"密码失败撤回公开 accepted")
    lab.unchanged_original()

CASES={"E01_E08_business_roundtrip":basic,"E04_member_authorization":authorization,
       "E04_device_authorization":lambda l:authorization(l,True),"E05_concurrent_claims":concurrency,
       "E06_close_before_accept":lambda l:close_order(l,False),"E06_accept_before_close":lambda l:close_order(l,True),
       "E06_close_before_claim":tombstone,"E12_service_faults":service_faults,"E13_client_faults":client_faults,
       "E05_E07_second_successor":successor,"E06_unrelated_predecessor":predecessor,
       "E07_expired_at_final_check":expiry,"E07_commit_crosses_expiry":lambda l:expiry(l,True),"E14_anchor_recovery":anchored,"E04_revoked_after_claim":revoked_after_claim,"E16_capacity_terminal":capacity_terminal,"E16_real_legacy_migration":migration,"E11_accepted_bad_commit":accepted_bad_commit}

from .join_review_regressions import claim_missing_pin, claim_expired, claim_predecessor, public_recovery_chain
CASES.update(R01_claim_missing_pin=claim_missing_pin, R02_claim_expired=claim_expired,
             R03_public_recovery_chain=public_recovery_chain,
             R04_public_recovery_anchor=lambda l: public_recovery_chain(l, True),
             R05_claim_predecessor=claim_predecessor)

from .history_anchor_cases import CASES as HISTORY_ANCHOR_CASES
CASES.update(HISTORY_ANCHOR_CASES)

from .recovery_consistency_cases import CASES as RECOVERY_CONSISTENCY_CASES
CASES.update(RECOVERY_CONSISTENCY_CASES)

from .recovery_review_cases import CASES as RECOVERY_REVIEW_CASES
CASES.update(RECOVERY_REVIEW_CASES)

from .recovery_capacity_cases import CASES as RECOVERY_CAPACITY_CASES
CASES.update(RECOVERY_CAPACITY_CASES)

from .recovery_retry_cases import CASES as RECOVERY_RETRY_CASES
CASES.update(RECOVERY_RETRY_CASES)

from .recovery_watermark_cases import CASES as RECOVERY_WATERMARK_CASES
CASES.update(RECOVERY_WATERMARK_CASES)

from .recovery_competition_cases import CASES as RECOVERY_COMPETITION_CASES
CASES.update(RECOVERY_COMPETITION_CASES)

from .recovery_close_cases import CASES as RECOVERY_CLOSE_CASES
CASES.update(RECOVERY_CLOSE_CASES)

from .recovery_expiry_cases import CASES as RECOVERY_EXPIRY_CASES
CASES.update(RECOVERY_EXPIRY_CASES)

from .recovery_welcome_cases import CASES as RECOVERY_WELCOME_CASES
CASES.update(RECOVERY_WELCOME_CASES)

from .recovery_old_copy_cases import CASES as RECOVERY_OLD_COPY_CASES
CASES.update(RECOVERY_OLD_COPY_CASES)

from .recovery_offline_cases import CASES as RECOVERY_OFFLINE_CASES
CASES.update(RECOVERY_OFFLINE_CASES)

from .recovery_survivor_cases import CASES as RECOVERY_SURVIVOR_CASES
CASES.update(RECOVERY_SURVIVOR_CASES)

from .recovery_bundle_cases import CASES as RECOVERY_BUNDLE_CASES
CASES.update(RECOVERY_BUNDLE_CASES)

from .recovery_path_cases import CASES as RECOVERY_PATH_CASES
CASES.update(RECOVERY_PATH_CASES)
