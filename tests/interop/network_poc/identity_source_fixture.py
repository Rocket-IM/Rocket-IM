"""独立业务签发/Relay/Rust进程；启动库无设备、注册、公钥或信任事实。"""
import base64
import hashlib
import http.client
import json
import secrets
import selectors
import socket
import sqlite3
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse
from .key_package_fixture import KeyPackageLab
from .first_trust_fixture import DEVICES
from .first_trust_session import verify_public
from .fixture import ROOT,identity,check,CONVERSATION

class IdentitySourceLab(KeyPackageLab):
    def initialize(self):
        self.issuer_process=None;self.receipt_active=True;self.registrations={}
        for d in (*DEVICES,'d1','b2','a3'):
            self.tokens.setdefault(d,secrets.token_urlsafe(32));self.public[d]=self.rust(d,'init')
        self.relay_receipt_key=self.relay_key('init')['signature_key']
        self.business_key_file=self.directory/'business.key';self.backend_token=secrets.token_urlsafe(32);self.status_token=secrets.token_urlsafe(32)
        business=self.helper_call(self.receipt_signer,{'operation':'init','key_path':str(self.business_key_file)})['signature_key']
        self.roots={'service_id':self.service,'issuer':'experiment-business','audience':'rocket-im','business_key':business,'receipt_key':self.relay_receipt_key}
        self.business_tokens={a:secrets.token_urlsafe(32) for a in ('alice','bob','charlie','david')}
        with socket.socket() as reserve:reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
        self.identity_config=self.directory/'identity-config.json'
        self.write_private(self.identity_config,{'roots':self.roots,'backend_token_hash':hashlib.sha256(self.backend_token.encode()).hexdigest(),'issuer_url':f'http://127.0.0.1:{port}','status_token':self.status_token})
        self.issuer_config=self.directory/'issuer-config.json'
        self.issuer_settings={'roots':self.roots,'backend_token':self.backend_token,'status_token':self.status_token,'relay_url':'pending',
              'sessions':[{'token_hash':hashlib.sha256(t.encode()).hexdigest(),'subject':'business-'+a,'account_id':a,'active':True} for a,t in self.business_tokens.items()]}
        self.fixture={'service_id':self.service,'controller_token':self.controller_token,'devices':[],
                      'conversation':{'conversation_id':CONVERSATION,'members':[],'authorization_version':'1','crypto_state_ref':'0'*64}}
        self.fixture_path=self.directory/'fixture.json';self.write_private(self.fixture_path,self.fixture)
        self.relay_args=('--identity-config',str(self.identity_config))
        # Keep a fixed Relay port so issuer config and persisted root config survive restarts.
        with socket.socket() as reserve:reserve.bind(('127.0.0.1',0));relay_port=reserve.getsockname()[1]
        self.relay_args+=('--port',str(relay_port))
        self.relay_entrypoint=ROOT/'poc/network-relay/server.py'
        self.start();self.issuer_settings['relay_url']=self.url.geturl();self.write_private(self.issuer_config,self.issuer_settings)
        self.issuer_log=(self.directory/'issuer.stderr').open('w')
        self.issuer_process=subprocess.Popen([sys.executable,str(ROOT/'poc/network-relay/identity_issuer.py'),'--config',str(self.issuer_config),'--database',str(self.directory/'issuer.sqlite'),'--signer',str(self.receipt_signer),'--key',str(self.business_key_file),'--port',str(port)],stdout=subprocess.PIPE,stderr=self.issuer_log,text=True)
        self.process_count+=1
        with selectors.DefaultSelector() as selector:
            selector.register(self.issuer_process.stdout,selectors.EVENT_READ);check(bool(selector.select(10)),'签发器启动超时');line=self.issuer_process.stdout.readline()
        check(bool(line),'签发器启动失败');self.issuer_url=urlparse(json.loads(line)['url'])
        check(not self.rows_source('device_public_keys') and not self.rows_source('devices'),'启动含预置身份')
        self.case_evidence['initial_database']={name:self.rows_source(name) for name in ('devices','device_public_keys','device_registrations','identity_source_entries')}
        for d in self.public:self.source(d,'configure',roots=self.roots)
    @staticmethod
    def write_private(path,value):path.write_text(json.dumps(value));path.chmod(0o600)
    def helper_call(self,binary,data,expected=0):
        p=subprocess.run([str(binary)],input=json.dumps(data),text=True,capture_output=True,timeout=10);self.process_count+=1
        check(p.returncode==expected,f'公共helper返回错误: {p.stdout[:300]}');value=json.loads(p.stdout)
        return value['result'] if expected==0 else value['error']
    def source(self,d,kind,**fields):
        options={key:fields.pop(key) for key in ('expected_exit','failpoint') if key in fields}
        return self.rust(d,'identity_source',command={'kind':kind,**fields},**options)
    def issuer(self,path,account,body,*,expected=200,token=None):
        c=http.client.HTTPConnection(self.issuer_url.hostname,self.issuer_url.port,timeout=12)
        try:
            self.http_count+=1;c.request('POST',path,json.dumps(body),{'Content-Type':'application/json','Authorization':'Bearer '+(token or self.business_tokens[account])});r=c.getresponse();v=json.loads(r.read());check(r.status in ((expected,) if isinstance(expected,int) else expected),f'签发器 {path} {r.status}: {v}');return v['result'] if v['ok'] else v['error']
        finally:c.close()
    def challenge(self,d,purpose=None,ident=None):
        a=identity(d)['account_id'];purpose=purpose or ('add_device' if any(identity(x)['account_id']==a for x in self.registrations) else 'first_device')
        return self.issuer('/challenge',a,{'device_id':d,'signature_key':self.public[d]['signature_key'],'registration_id':ident or 'source-'+d,'purpose':purpose})
    def sign_doc(self,doc,business=False):
        key=self.business_key_file if business else self.receipt_key
        pub=self.roots['business_key'] if business else self.relay_receipt_key
        return self.helper_call(self.receipt_signer,{'operation':'sign','key_path':str(key),'statement':doc,'expected_signature_key':pub})['receipt']
    def prepare_registration(self,d,purpose=None):
        c=self.challenge(d,purpose);registration=self.prove_registration(d,{'challenge_bytes':c['challenge_bytes']});approval=None
        permit=decode(c['permit'])['body'];a=identity(d)['account_id']
        if permit['purpose']=='add_device':
            old=next(x for x in self.registrations if identity(x)['account_id']==a);fetched=self.fetch_source(old,a,witness=False)
            head=decode(fetched[1])['body']['snapshots'][-1]
            body={'service_id':self.service,'approval_id':'approve-'+d,'actor':self.member(old),'target':self.member(d),'permit_sha256':record_digest(c['permit']),'previous_version':head['version'],'previous_sha256':digest(head),'expires_at_ms':permit['expires_at_ms']}
            approval=self.source(old,'approve',approval=body)['proof']
        return {'permit':c['permit'],'registration':registration,'approval':approval,'access_token':self.tokens[d]}
    def register(self,d):
        req=self.prepare_registration(d);result=self.issuer('/complete',identity(d)['account_id'],req);self.registrations[d]=req
        self.case_evidence.setdefault('registrations',{})[d]={'permit':req['permit'],'registration':req['registration'],'approval':req['approval'],'result':result}
        return result
    def register_all(self):
        for d in self.public:
            if d not in self.registrations:self.register(d)
    def fetch_source(self,d,account,witness=True,ident=None):
        request=self.source(d,'request',account_id=account,request_id=ident or 'head-'+account+'-'+secrets.token_hex(4))
        receipt=self.http(d,'identity_source',{'kind':'directory',**request})['receipt'];proof=None
        if witness:
            peer=next(x for x in self.registrations if identity(x)['account_id']==account and x!=d)
            verify_public(self,d,peer);self.fetch_source(peer,account,witness=False)
            proof=self.source(peer,'export_head',**{k:request[k] for k in ('account_id','requester','request_id','challenge')})['proof']
        result=self.source(d,'respond',request_id=request['request_id'],receipt=receipt,witness=proof)
        return request,receipt,proof,result
    def group(self,**_):
        # Actual MLS create/Add/Welcome, without fixture or direct database group/bootstrap records.
        for d in ('a1','b1'):
            if d not in self.registrations:self.register(d)
            self.fetch_source(d,identity(d)['account_id'],witness=False)
        verify_public(self,'a1','b1');verify_public(self,'b1','a1');self.fetch_source('a1','bob');self.fetch_source('b1','alice')
        created=self.rust('a1','create',peers=[{'account':'bob','device':'b1','signature_key':self.public['b1']['signature_key'],'key_package':self.public['b1']['key_package']}])
        pins=[{'account':identity(d)['account_id'],'device':d,'signature_key':self.public[d]['signature_key']} for d in ('a1','b1')]
        self.rust('b1','join',welcome=created['welcome'],pins=pins)
        check(not self.rows_source('permission_checkpoint'),'不允许测试装置注入群权限')
        self.continued()
    def continued(self,ident='source-continue',**_):
        for sender,target in [('a1','b1'),('b1','a1')]:
            payload='q01-source-'+ident+'-'+sender
            packet=self.rust(sender,'send',id=ident+'-'+sender,payload=payload)
            received=self.rust(target,'receive',id=ident+'-'+sender,ciphertext=packet['ciphertext'])
            check(received['payload_sha256']==hashlib.sha256(payload.encode()).hexdigest(),'真实MLS双向通信失败')
        self.case_evidence.setdefault('roundtrips',[]).append({'id':ident,'route':'actual Rust MLS; no fixture group authority'})
    def rows_source(self,table):
        allowed={'devices','device_public_keys','device_registrations','identity_source_entries','identity_source_directories','identity_source_challenges','permission_checkpoint','kp_materials'};check(table in allowed,'未知表')
        with sqlite3.connect(self.directory/'relay.sqlite') as db:return db.execute('SELECT * FROM '+table+' ORDER BY rowid').fetchall()
    def close(self):
        if getattr(self,'issuer_process',None):
            self.issuer_process.terminate();self.issuer_process.wait(timeout=10);self.issuer_process.stdout.close();self.issuer_log.close();self.issuer_process=None
        super().close()

def decode(proof):return json.loads(base64.b64decode(proof['statement_bytes']))
def digest(value):return hashlib.sha256(json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
def record_digest(record):return digest({k:record[k] for k in ('statement_bytes','signature_bytes')})
