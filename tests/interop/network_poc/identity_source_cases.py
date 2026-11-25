"""I01—I10真实进程断言；不把目录签名和控制器核验当全局身份保证。"""
import base64
import copy
import hashlib
import json
import sqlite3
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from .fixture import check,identity,ROOT
from .first_trust_session import verify_public,TrustSession,public_identity
from .identity_source_fixture import decode,digest

def assert_case(lab,name,ok):
    check(ok,name);lab.case_evidence.setdefault('assertions',[]).append(name)
def state(lab,d='a1'):return hashlib.sha256((lab.directory/d/'state.enc').read_bytes()).hexdigest()
def backend(lab,req,expected=200):return lab.http('a1','identity_source',req,token=lab.backend_token,expected=expected)
def rejected(lab,d,kind,codes,**fields):
    before=state(lab,d);e=lab.source(d,kind,expected_exit=1,**fields)
    assert_case(lab,'拒绝不修改端侧状态: '+e['code'],e['code'] in codes and state(lab,d)==before);return e

def i01(lab):
    lab.register('a1');lab.register('b1')
    lab.fetch_source('a1','alice',False);r=lab.fetch_source('a1','bob',False)
    assert_case(lab,'仅Service完整授权链仍为freshness_unknown',r[-1]['status']=='freshness_unknown')
    peers=[{'account':'bob','device':'b1','signature_key':lab.public['b1']['signature_key'],'key_package':lab.public['b1']['key_package']}]
    before=state(lab);error=lab.rust('a1','create',peers=peers,expected_exit=1)
    assert_case(lab,'无独立对照不创建群或外发Welcome',error['code']=='directory_comparison_required' and state(lab)==before)
    lab.group();lab.restart();lab.continued('after-restart')
    assert_case(lab,'没有预填群权限检查点',not lab.rows_source('permission_checkpoint'))

def i02(lab):
    req=lab.prepare_registration('a1');initial=lab.rows_source('identity_source_entries')
    for field,value in [('issuer','evil'),('audience','evil'),('service_id','evil'),('subject','other')]:
        forged=copy.deepcopy(req);doc=decode(forged['permit']);doc['body'][field]=value;forged['permit']=lab.sign_doc(doc,business=True)
        e=backend(lab,{'kind':'complete',**forged},(403,409));assert_case(lab,'拒绝错误许可 '+field,e['code'] in ('identity_source_root','identity_subject_inactive'))
    forged=copy.deepcopy(req);doc=decode(forged['permit']);doc['body']['target']['device_id']='a2';forged['permit']=lab.sign_doc(doc,business=True)
    e=backend(lab,{'kind':'complete',**forged},409);assert_case(lab,'拒绝许可目标改绑',e['code']=='identity_source_binding')
    forged=copy.deepcopy(req);forged['permit']=lab.sign_doc(decode(req['permit']))
    e=backend(lab,{'kind':'complete',**forged},(403,409));assert_case(lab,'Relay钥不能代业务根',e['code']=='permission_signature')
    roots=lab.roots|{'receipt_key':lab.roots['business_key']}
    rejected(lab,'a1','configure',('identity_source_root',),roots=roots)
    assert_case(lab,'错误请求无注册半状态',initial==lab.rows_source('identity_source_entries'))
    unauthorized=lab.issuer('/challenge','alice',{'device_id':'a1','signature_key':lab.public['a1']['signature_key'],'registration_id':'unauth','purpose':'first_device'},expected=401,token='bad-business-token')
    assert_case(lab,'未认证业务请求不能取得许可',unauthorized['code']=='unauthenticated')
    issuer_challenge_substitution(lab,req)
    lab.register('a1');lab.group()

def i03(lab):
    lab.register('a1')
    c=lab.challenge('a3',purpose='add_device')
    # A stolen business session can request a pending permit; no old-device approval means no registration.
    proof=lab.prove_registration('a3',{'challenge_bytes':c['challenge_bytes']})
    req={'permit':c['permit'],'registration':proof,'approval':None,'access_token':lab.tokens['a3']}
    e=lab.issuer('/complete','alice',req,expected=409);assert_case(lab,'只有业务会话和新设备PoP不能获旧账号设备授权',e['code']=='identity_source_approval')
    c1=lab.registrations['a1']['registration']['statement_bytes'];before=state(lab,'b1')
    e=lab.rust('b1','device_registration_prove',challenge_bytes=c1,expected_exit=1)
    assert_case(lab,'无原设备钥不能签准确挑战',e['code']=='registration_context' and state(lab,'b1')==before)
    lab.register('b1');lab.fetch_source('a1','alice',False);lab.fetch_source('a1','bob',False)
    e=lab.rust('a1','identity_trust_inspect',target=identity('b1'),expected_exit=1);assert_case(lab,'业务许可不产生联系人核验',e['code']=='identity_not_found')
    lab.group()

def i04(lab):
    requests={d:lab.prepare_registration(d,purpose='first_device') for d in ('a1','a2')}
    barrier=threading.Barrier(2)
    def call(d):barrier.wait(timeout=5);return d,backend(lab,{'kind':'complete',**requests[d]},(200,409))
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(call,requests))
    winners=[d for d,v in results if v.get('status')=='registered'];assert_case(lab,'两个真实并发首次请求至多一个接受',len(winners)==1 and len(lab.rows_source('identity_source_entries'))==1)
    d=winners[0];req=requests[d];original=backend(lab,{'kind':'complete',**req});again=backend(lab,{'kind':'complete',**req})
    assert_case(lab,'已消费许可准确重试返回原件',again==original)
    changed=copy.deepcopy(req);changed['access_token']=lab.tokens['b1'];e=backend(lab,{'kind':'complete',**changed},409);assert_case(lab,'精确重试禁止改变凭证结果',e['code']=='idempotency_conflict')
    lab.registrations[d]=req
    b_req=lab.prepare_registration('b1');bad=copy.deepcopy(b_req);doc=decode(bad['permit']);doc['body']['issued_at_ms']='1000';doc['body']['expires_at_ms']='301000';bad['permit']=lab.sign_doc(doc,business=True)
    e=backend(lab,{'kind':'complete',**bad},409);assert_case(lab,'有效签名的过期许可不能登记',e['code']=='identity_source_expired')
    lab.register('b1')
    # Winner may be a2; normal positive MLS is separately exercised by I01 and I10.
    assert_case(lab,'并发失败不消费其他账号许可',len(lab.rows_source('identity_source_entries'))==2)

def i05(lab):
    lab.register('a1');planned=lab.prepare_registration('a2')
    foreign=decode(planned['approval'])['body'];foreign['actor']=lab.member('b1')
    rejected(lab,'b1','approve',('identity_source_approval',),approval=foreign)
    lab.register('a2');assert_case(lab,'合法旧设备批准新增',len(lab.rows_source('identity_source_entries'))==2)
    req=lab.prepare_registration('a3');before=len(lab.rows_source('identity_source_entries'))
    backend(lab,{'kind':'revoke',**identity('a1')})
    e=lab.issuer('/complete','alice',req,expected=409);assert_case(lab,'批准后接受前撤销不接受新设备',e['code']=='identity_source_approval' and len(lab.rows_source('identity_source_entries'))==before)
    backend(lab,{'kind':'revoke',**identity('a2')})
    c=lab.challenge('a3','first_device',ident='cannot-reset');proof=lab.prove_registration('a3',{'challenge_bytes':c['challenge_bytes']})
    e=lab.issuer('/complete','alice',{'permit':c['permit'],'registration':proof,'approval':None,'access_token':lab.tokens['a3']},expected=409)
    assert_case(lab,'全部旧设备丢失仍不能走首次',e['code']=='identity_account_recovery_required')
    error=lab.http('a1','begin_device_registration',{'service_id':lab.service,'registration_id':'bypass','signature_key':lab.public['a1']['signature_key']},token=lab.tokens['a1'],expected=403)
    assert_case(lab,'显式来源模式禁止旧入口旁路',error['code']=='identity_source_required')

def i06(lab):
    lab.register('a1');lab.register('b1');lab.fetch_source('a1','alice',False)
    request,receipt,_,_=lab.fetch_source('a1','bob',False)
    original=decode(receipt)
    for field,value in [('challenge','1'*64),('account_id','alice'),('request_id','unasked')]:
        doc=copy.deepcopy(original);doc['body'][field]=value
        rejected(lab,'a1','respond',('identity_source_binding',),request_id=request['request_id'],receipt=lab.sign_doc(doc),witness=None)
    doc=copy.deepcopy(original);doc['body']['snapshots'][0]['devices'][0]['status']='invalid'
    rejected(lab,'a1','respond',('identity_source_binding',),request_id=request['request_id'],receipt=lab.sign_doc(doc),witness=None)
    doc=copy.deepcopy(original);doc['body']['snapshots'][0]['devices']=[]
    rejected(lab,'a1','respond',('identity_source_directory',),request_id=request['request_id'],receipt=lab.sign_doc(doc),witness=None)
    doc=copy.deepcopy(original);registration=doc['body']['snapshots'][0]['devices'][0]['registration'];changed=decode(registration);changed['signature_key']=lab.public['c1']['signature_key'];registration['statement_bytes']=base64.b64encode(json.dumps(changed,separators=(',',':')).encode()).decode()
    rejected(lab,'a1','respond',('registration_signature',),request_id=request['request_id'],receipt=lab.sign_doc(doc),witness=None)
    bad=copy.deepcopy(receipt);bad['signature_bytes']=base64.b64encode(bytes(64)).decode()
    rejected(lab,'a1','respond',('permission_signature',),request_id=request['request_id'],receipt=bad,witness=None)
    lab.group()

def i07(lab):
    lab.register('a1');lab.register('b1');verify_public(lab,'a1','b1');lab.fetch_source('b1','bob',False)
    request,receipt,_,_=lab.fetch_source('a1','bob',False)
    witness=lab.source('b1','export_head',**{k:request[k] for k in ('account_id','requester','request_id','challenge')})['proof']
    result=lab.source('a1','respond',request_id=request['request_id'],receipt=receipt,witness=witness)
    assert_case(lab,'真实独立端准确head满足当前已知对照',result['status']=='known_comparison_satisfied')
    # Advance the actual authority while both observers still hold v1. A fresh challenge cannot reveal the hidden v2.
    lab.register('b2')
    isolated=lab.source('a1','request',account_id='bob',request_id='isolated-fresh-challenge')
    body={**isolated,'snapshots':decode(receipt)['body']['snapshots']}
    hidden=lab.sign_doc({'protocol_version':'rim-authorized-directory-response-1','body':body})
    stale_witness=lab.source('b1','export_head',**{k:isolated[k] for k in ('account_id','requester','request_id','challenge')})['proof']
    result=lab.source('a1','respond',request_id=isolated['request_id'],receipt=hidden,witness=stale_witness)
    actual_versions=[row for row in lab.rows_source('identity_source_directories') if row[0]=='bob']
    assert_case(lab,'真实权威已到v2但双方隔离时新挑战仍只能证明所知v1',result['status']=='known_comparison_satisfied' and len(actual_versions)==2)
    lab.case_evidence['isolation_negative']={'result':'EXPECTED_UNDETECTABLE','authority_version':'2','observer_versions':['1','1'],'fresh_challenge':isolated['challenge'],'service_response':hidden,'actual_stale_observer_head':stale_witness}
    lab.fetch_source('b1','bob',False)
    newer=lab.source('b1','export_head',**{k:request[k] for k in ('account_id','requester','request_id','challenge')})['proof']
    result=lab.source('a1','respond',request_id=request['request_id'],receipt=receipt,witness=newer)
    assert_case(lab,'更高独立head先持久缺链',result['status']=='directory_gap')
    latest=lab.http('a1','identity_source',{'kind':'directory',**request})['receipt'];result=lab.source('a1','respond',request_id=request['request_id'],receipt=latest,witness=newer)
    assert_case(lab,'真实授权链补齐后满足已知水位',result['status']=='known_comparison_satisfied')
    rejected(lab,'a1','respond',('directory_stale',),request_id=request['request_id'],receipt=receipt,witness=None)
    # Valid but different same-version status projection: Service cannot overwrite a known branch.
    doc=decode(latest);doc['body']['snapshots'][-1]['devices'][1]['status']='revoked'
    result=lab.source('a1','respond',request_id=request['request_id'],receipt=lab.sign_doc(doc),witness=None)
    assert_case(lab,'合法签名的同版本异摘要持久冲突',result['status']=='directory_conflict')
    lab.restart();result=lab.source('a1','respond',request_id=request['request_id'],receipt=latest,witness=None)
    assert_case(lab,'重启和正确head不清除冲突',result['status']=='directory_conflict')

def i08(lab):
    lab.register('a1');lab.register('b1');verify_public(lab,'a1','b1')
    with TrustSession(lab,'a1') as session:
        display=session.request('identity_trust_prepare',target=identity('b1'),purpose='verify')['display']
        changed=public_identity(lab,'b1')|{'signature_key':lab.public['c1']['signature_key']}
        session.request('identity_trust_observe',identity=changed)
        session.request('identity_trust_confirm',display=display,independent_identity=public_identity(lab,'b1'),verification='synthetic_local',expected_error=('identity_display_stale','identity_changed','identity_verification','identity_confirmation_stale'))
    with TrustSession(lab,'a1') as session:
        display=session.request('identity_trust_prepare',target=identity('b1'),purpose='reset')['display']
        session.request('inspect',device='b1')
        session.request('identity_trust_reset',display=display,independent_identity=changed,verification='synthetic_local',expected_error='identity_confirmation_stale')
    records=lab.rust('a1','identity_trust_inspect',target=identity('b1'))['records'];assert_case(lab,'候选换钥后原核验不转移',records[0]['status']=='changed')
    before=lab.rust('b1','identity_trust_inspect')['records']
    verify_public(lab,'b1','a1');trusted=lab.rust('b1','identity_trust_inspect')['records']
    generated=lab.generate('same-identity-rotation',target='a1',count=1)
    assert_case(lab,'同身份真实KeyPackage更新保持身份公钥及已核验事实',bool(generated['proof']) and lab.rust('b1','identity_trust_inspect')['records']==trusted)
    lab.issuer_settings['sessions'][0]['active']=False;lab.write_private(lab.issuer_config,lab.issuer_settings)
    req=lab.registrations['a1'];e=lab.issuer('/complete','alice',req,expected=401);assert_case(lab,'业务会话失效不由旧许可恢复',e['code']=='unauthenticated')
    e=backend(lab,{'kind':'complete',**req},403);assert_case(lab,'Service亦重查业务有效性',e['code']=='identity_subject_inactive')

def i09(lab):
    req=lab.prepare_registration('a1');before=lab.rows_source('identity_source_entries')
    lab.control('hook',hook='before_commit_exit')
    try:backend(lab,{'kind':'complete',**req});raise AssertionError('预期事务提交前断开')
    except (OSError,__import__('http.client',fromlist=['RemoteDisconnected']).RemoteDisconnected):pass
    lab.process.wait(timeout=10);lab.restart()
    assert_case(lab,'Service提交前退出无半注册',lab.rows_source('identity_source_entries')==before)
    lab.control('hook',hook='drop_after_commit')
    try:backend(lab,{'kind':'complete',**req});raise AssertionError('预期提交后丢输出')
    except (OSError,__import__('http.client',fromlist=['RemoteDisconnected']).RemoteDisconnected):pass
    result=backend(lab,{'kind':'complete',**req});lab.registrations['a1']=req
    assert_case(lab,'Service提交后丢输出准确查询恢复',result['status']=='registered' and len(lab.rows_source('identity_source_entries'))==1)
    lab.register('b1');request,receipt,_,_=lab.fetch_source('a1','bob',False)
    before=state(lab)
    lab.source('a1','respond',request_id=request['request_id'],receipt=receipt,witness=None,failpoint='before_save',expected_exit=83)
    assert_case(lab,'端侧保存前失败保留原件',state(lab)==before)
    result=lab.source('a1','respond',request_id=request['request_id'],receipt=receipt,witness=None)
    assert_case(lab,'端侧失败后精确恢复',result['status']=='freshness_unknown')

def i10(lab):
    lab.register('a1');lab.register('b1');lab.group()
    old=ROOT/'dist/reviews/2026-10-15-recovery-capacity/release/normal/bin/openmls-state-lab'
    before=state(lab);current=lab.binary;lab.binary=old
    try:e=lab.rust('a1','inspect',expected_exit=1)
    finally:lab.binary=current
    assert_case(lab,'真实旧Rust拒读新账本且不改原快照',state(lab)==before)
    receipt=lab.fetch_source('a1','bob',False)[1]
    old_verifier=old.with_name('openmls-permission-verify')
    e=lab.helper_call(old_verifier,{'operation':'verify_identity_source','proof':receipt,'key':lab.relay_receipt_key,'roots':lab.roots},expected=1)
    assert_case(lab,'真实旧验证器拒新协议',bool(e['code']))
    peers=[{'account':'bob','device':'b1','signature_key':lab.public['b1']['signature_key'],'key_package':lab.public['b1']['key_package']}]
    before=state(lab,'a3');e=lab.rust('a3','create',peers=peers,expected_exit=1)
    assert_case(lab,'空本机/只配置根不补造业务登记',e['code']=='identity_source_required' and state(lab,'a3')==before)
    # Actually run the preserved pre-change Relay storage against this new database; no rewrite.
    old_source=ROOT/'dist/network-relay/q01-identity-source/baseline/source/poc/network-relay'
    fixture={'service_id':lab.service,'controller_token':'x'*32,'devices':[{'account_id':'alice','device_id':'a1','token':'a'*32},{'account_id':'bob','device_id':'b1','token':'b'*32}],'conversation':{'conversation_id':'G1','members':[identity('a1'),identity('b1')],'authorization_version':'1','crypto_state_ref':'0'*64}}
    script='import sys;sys.path.insert(0,'+repr(str(old_source))+');from storage import Store;Store('+repr(str(lab.directory/'relay.sqlite'))+','+repr(fixture)+')'
    before_rows=lab.rows_source('identity_source_entries')
    p=subprocess.run([__import__('sys').executable,'-c',script],capture_output=True,text=True,timeout=10)
    assert_case(lab,'真实旧Relay拒绝新数据库且保留原件',p.returncode!=0 and '不支持该实验数据库版本' in p.stderr and before_rows==lab.rows_source('identity_source_entries'))
    lab.restart();lab.continued('compatibility-restart')

CASES=[('I01_normal',i01),('I02_subject_roots',i02),('I03_stolen_credentials',i03),('I04_concurrency_replay',i04),('I05_approval_revocation',i05),('I06_directory_tamper',i06),('I07_continuity_isolation',i07),('I08_lifecycle',i08),('I09_failures',i09),('I10_compatibility',i10)]

def i09_anchor(lab):
    check(lab.helper is not None,'I09独立锚子集要求显式helper')
    lab.register('a1');lab.register('b1');request,receipt,_,_=lab.fetch_source('a1','bob',False)
    lab.enable('a1')
    before=lab.rust('a1','anchor_inspect')
    bad=copy.deepcopy(receipt);bad['signature_bytes']=base64.b64encode(bytes(64)).decode()
    rejected(lab,'a1','respond',('permission_signature',),request_id=request['request_id'],receipt=bad,witness=None)
    assert_case(lab,'确定性来源拒绝不消耗独立锚',lab.rust('a1','anchor_inspect')==before)
    lab.forwarding_helper('drop','finish',device='a1')
    e=lab.source('a1','respond',request_id=request['request_id'],receipt=receipt,witness=None,expected_exit=1)
    lab.config_restore('a1');assert_case(lab,'Finish丢响应未交付成功',e['code']=='anchor_response')
    lab.resume('a1');assert_case(lab,'完整原日志精确Finish恢复',lab.rust('a1','anchor_inspect')['status']=='ready')
    # A second saved candidate without a recovery journal must remain unresolved.
    request,receipt,_,_=lab.fetch_source('a1','bob',False)
    lab.source('a1','respond',request_id=request['request_id'],receipt=receipt,witness=None,failpoint='after_save',expected_exit=85)
    for _ in range(2):
        e=lab.blocked('a1','anchor_resume');assert_case(lab,'缺日志重启/重试保持锚未决',e['code']=='anchor_unresolved')
    e=lab.source('a1','configure',roots=lab.roots,expected_exit=1);assert_case(lab,'固定根重试不清未决',e['code']=='anchor_paused')

def i09_capacity(lab):
    lab.register('a1');lab.register('b1');verify_public(lab,'a1','b1');lab.fetch_source('a1','alice',False);lab.fetch_source('b1','bob',False)
    for i in range(33):
        request,receipt,_,_=lab.fetch_source('a1','bob',False,ident='capacity-'+str(i))
        witness=lab.source('b1','export_head',**{k:request[k] for k in ('account_id','requester','request_id','challenge')})['proof']
        result=lab.source('a1','respond',request_id=request['request_id'],receipt=receipt,witness=witness)
    assert_case(lab,'自然累积33份对照达到32条上限后持久暂停',result['status']=='identity_source_capacity_exhausted')
    lab.restart();inspected=lab.source('a1','inspect');assert_case(lab,'满额原件不淘汰且重启暂停',inspected['status']=='evidence_capacity_exhausted' and len(inspected['accounts']['bob']['heads'])==32)
    lab.source('a1','configure',roots=lab.roots)
    rejected(lab,'a1','respond',('identity_source_capacity_exhausted',),request_id=request['request_id'],receipt=receipt,witness=None)

EXTRA_CASES=[('I09_anchor',i09_anchor),('I09_capacity',i09_capacity)]

def i09_existing_pause(lab):
    lab.register('a1');lab.register('b1');lab.fetch_source('a1','alice',False)
    fixture=lab.probe_binary.with_name('openmls-recovery-capacity-fixture')
    context={'service':lab.service,'account':'alice','device':'a1'}
    p=subprocess.run([str(fixture)],input=json.dumps({'directory':str(lab.directory/'a1'),'context':context,'mode':'pause'}),capture_output=True,text=True,timeout=10)
    check(p.returncode==0,'显式已有容量暂停夹具失败: '+p.stdout[:300])
    before=state(lab)
    for kind,options in [('configure',{'roots':lab.roots}),('request',{'account_id':'bob','request_id':'cannot-clear-pause'})]:
        e=lab.source('a1',kind,expected_exit=1,**options)
        assert_case(lab,'新增来源入口保留已有Q02容量暂停: '+kind,e['code']=='consistency_paused' and state(lab)==before)
    lab.restart();e=lab.source('a1','configure',roots=lab.roots,expected_exit=1)
    assert_case(lab,'重启后新配置仍不能清已有暂停',e['code']=='consistency_paused' and state(lab)==before)
    lab.case_evidence['pause_boundary']='显式probe合成既有暂停；自然恢复证据耗尽的形成仍见原容量矩阵，本场景只验新增入口守卫'
EXTRA_CASES.append(('I09_existing_pause',i09_existing_pause))


def issuer_challenge_substitution(lab,original):
    from http.server import HTTPServer,BaseHTTPRequestHandler
    raw=decode(original['registration'])
    class Poison(BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
            data=json.dumps({'ok':True,'result':{'challenge_bytes':base64.b64encode(json.dumps(self.server.statement,separators=(',',':')).encode()).decode()}}).encode()
            self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    server=HTTPServer(('127.0.0.1',0),Poison);server.timeout=2
    old=lab.issuer_settings['relay_url'];lab.issuer_settings['relay_url']='http://127.0.0.1:'+str(server.server_port);lab.write_private(lab.issuer_config,lab.issuer_settings)
    try:
        for field,value,expected,code in [('account_id','bob',403,'identity_source_binding'),('signature_key',lab.public['b1']['signature_key'],403,'identity_source_binding'),('issued_at_ms','1000',409,'identity_source_expired')]:
            server.statement=copy.deepcopy(raw);server.statement[field]=value
            if field=='issued_at_ms':server.statement['expires_at_ms']='301000'
            thread=threading.Thread(target=server.handle_request);thread.start()
            try:
                e=lab.issuer('/challenge','alice',{'device_id':'a1','signature_key':lab.public['a1']['signature_key'],'registration_id':raw['registration_id'],'purpose':'first_device'},expected=expected)
                assert_case(lab,'业务签发器拒绝Relay替换/过期挑战: '+field,e['code']==code)
            finally:thread.join(timeout=3);check(not thread.is_alive(),'挑战攻击测试线程未退出')
    finally:
        server.server_close();lab.issuer_settings['relay_url']=old;lab.write_private(lab.issuer_config,lab.issuer_settings)
