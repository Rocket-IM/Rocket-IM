"""真实Go服务和仓库外消费进程；仅输出无正文/凭证的验证摘要。"""
from pathlib import Path
import hashlib
import json
import os
import queue
import secrets
import signal
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from environment import ROOT, GO, PG, port
from urllib.parse import quote
sys.path.insert(0,str(ROOT/'tools/platform_release'))
from node_pack import node_binary, npm_command, COMPILER, sha, all_hashes
import persistent_keychain

def require(condition,label):
    if not condition: raise AssertionError(label)

def wait(check,label,timeout=45):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        value=check()
        if value:return value
        time.sleep(.15)
    raise AssertionError('deadline: '+label)

class Worker:
    def __init__(self,directory,options):
        self.directory=Path(directory);self.options=options;self.seq=0;self.responses=queue.Queue()
        path=self.directory/'open.json';path.write_text(json.dumps(options));path.chmod(0o600)
        env={k:v for k,v in os.environ.items() if not k.startswith(('CARGO','RUST','ROCKET_IM_TEST_'))};env['PATH']=str(self.directory/'path')
        self.stderr=(self.directory/'worker-stderr.log').open('ab')
        self.process=subprocess.Popen([node_binary(),'network-worker.mjs',path],cwd=self.directory,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.stderr,text=True,bufsize=1)
        def read():
            for line in self.process.stdout:
                try:self.responses.put(json.loads(line))
                except Exception:self.responses.put({'invalid_output':True})
            self.responses.put({'exited':True})
        threading.Thread(target=read,daemon=True).start()
        ready=self.responses.get(timeout=20);require(ready.get('ready'),'worker startup');self.pid=ready['runtime']['pid']
    def call(self,op,expected=None,**fields):
        self.seq+=1;self.process.stdin.write(json.dumps({'id':str(self.seq),'op':op,**fields})+'\n');self.process.stdin.flush()
        reply=self.responses.get(timeout=35);require(reply.get('id')==str(self.seq),'worker response association')
        if expected is not None:require(not reply.get('ok') and reply.get('code')==expected,'expected error '+expected+' got '+str(reply.get('code')));return reply
        require(reply.get('ok'),'worker command '+op+' failed: '+str(reply.get('code')));return reply.get('result')
    def close(self,kill=False):
        if kill:
            try:os.kill(self.pid,signal.SIGKILL)
            except ProcessLookupError:pass
        if self.process.poll() is None:
            try:self.call('close')
            except Exception:self.process.kill()
        self.process.wait(timeout=10);self.stderr.close()

class Lab:
    def __init__(self,release,environment,run):
        self.release=Path(release);self.env=json.loads(Path(environment).read_text());self.run=Path(run);self.run.mkdir(parents=True)
        self.root=Path(self.env['directory'])/('consumers-'+self.run.name);self.root.mkdir(mode=0o700)
        self.ssl=ssl.create_default_context(cafile=str(Path(self.env['directory'])/'ca.pem'))
        self.workers=[];self.service=None;self.proxy=None;self.logs=[];self.keychains=[];self.texts=[];self.tokens=[secrets.token_hex(32),secrets.token_hex(32)]
        self.report={'status':'RUNNING','cases':[],'distribution':'NOT_APPROVED','stage0':'NOT_COMPLETE','windows':'NOT_TESTED','source_before':self.sources()}
        self.save()
    def sources(self):
        names=subprocess.check_output(['git','ls-files','-co','--exclude-standard','-z'],cwd=ROOT).decode().split('\0')
        return {n:sha(ROOT/n) for n in sorted(set(names)) if n and (ROOT/n).is_file() and n.startswith(('src/backend/','tests/interop/network_alpha/','api/http/alpha.','api/realtime/alpha.'))}
    def save(self):self.report['source_after']=self.sources();(self.run/'network-report.json').write_text(json.dumps(self.report,indent=2,ensure_ascii=False))
    def command(self,args,cwd,label,env=None):
        log=self.run/(label+'.log')
        with log.open('wb') as f:p=subprocess.run([str(a) for a in args],cwd=cwd,env=env,stdout=f,stderr=subprocess.STDOUT,timeout=120)
        require(p.returncode==0,label);return log
    def build(self):
        env={**os.environ,'GOPATH':str(ROOT/'dist/toolchains/gopath'),'GOCACHE':str(ROOT/'dist/toolchains/go-cache')}
        self.command([GO,'build','-trimpath','-o',self.run/'im-service','./cmd/im-service'],ROOT/'src/backend','go-build',env)
        self.command([GO,'build','-trimpath','-o',self.run/'fault-proxy',ROOT/'tests/interop/network_alpha/fault_proxy.go'],ROOT/'src/backend','proxy-build',env)
        env['ROCKET_IM_TEST_DATABASE_URL']=self.env['database_url']
        self.command([GO,'test','-race','-count=1','./...'],ROOT/'src/backend','go-race',env)
        self.command([GO,'vet','./...'],ROOT/'src/backend','go-vet',env)
        report=json.loads((self.release/'report.json').read_text());require(report['status']=='PASS_SCOPED','Release regression result')
        archive=Path(report['archive']);self.report.update(archive=str(archive),archive_sha256=sha(archive),service_sha256=sha(self.run/'im-service'),package_report=str(self.release/'report.json'))
        for i,account in enumerate(('alice','bob')):
            consumer=self.root/account;consumer.mkdir();(consumer/'path').mkdir();(consumer/'path/node').symlink_to(node_binary())
            (consumer/'package.json').write_text(json.dumps({'name':'network-alpha-'+account,'private':True,'type':'module'}))
            for name in ('network-worker.mjs','types.ts','tsconfig.json'):(consumer/name).write_bytes((self.release/'source/tests/consumers/node-persistent'/name).read_bytes())
            self.command(npm_command()+['install','--offline','--ignore-scripts','--no-audit','--no-fund',archive],consumer,'install-'+account)
            self.command([node_binary(),COMPILER,'-p',consumer/'tsconfig.json'],consumer,'types-'+account)
            require(all_hashes(consumer/'node_modules/@rocket-im/desktop-dev')==report['package_files'],'installed package bytes')
            keychain=self.root/('lab-'+account+'.keychain-db');password=secrets.token_hex(32)
            require(persistent_keychain.run({'op':'create','keychain':str(keychain),'password':password})['status']==0,'dedicated keychain')
            self.keychains.append(keychain)
            options={'path':str(consumer/'encrypted.db'),'scope':{'service':'alpha-network-test','account':account,'device':account+'-1'},'keychain':str(keychain),'create':True}
            worker=Worker(consumer,options);worker.call('initialize');worker.options['create']=False;self.workers.append(worker)
        openssl='/opt/homebrew/opt/openssl@3/bin/openssl'
        self.command([openssl,'req','-x509','-newkey','rsa:2048','-nodes','-keyout','/dev/null','-out',self.root/'untrusted-ca.pem','-days','2','-subj','/CN=Untrusted Alpha Test CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign'],self.root,'untrusted-ca')
        self.command([openssl,'x509','-in',self.root/'untrusted-ca.pem','-outform','DER','-out',self.root/'untrusted-ca.der'],self.root,'untrusted-ca-der')
        self.wrong_ca_certificate=(self.root/'untrusted-ca.der').read_bytes().hex()
        self.materials=[w.call('material') for w in self.workers]
        # 测试控制器独立读取双方公开身份后显式固定；不把Bearer登录当作信任来源。
        envdir=Path(self.env['directory']);backend_port=port();self.front_port=port();self.backend_port=backend_port
        schema='network_'+str(time.time_ns())
        self.command([PG/'psql','-h',envdir/'socket','-U','alpha','-d','alpha','-v','ON_ERROR_STOP=1','-c','CREATE SCHEMA '+schema],self.root,'create-test-schema')
        self.schema=schema
        config={'listen':f'127.0.0.1:{backend_port}','database_url':self.env['database_url']+'&search_path='+schema,'tls_cert':str(envdir/'server.pem'),'tls_key':str(envdir/'server.key'),'service':'alpha-network-test','conversation':'chat','devices':[]}
        for token,material in zip(self.tokens,self.materials):
            identity=material['identity'];config['devices'].append({'account':identity['scope']['account'],'device':identity['scope']['device'],'identity_key':identity['identity_key'],'token_sha256':hashlib.sha256(token.encode()).hexdigest()})
        self.config=self.root/'service.json';self.config.write_text(json.dumps(config));self.config.chmod(0o600)
        self.control=self.root/'fault.json';self.observations=self.root/'observations.json';self.control.write_text('{}')
        proxy={'Listen':f'127.0.0.1:{self.front_port}','Upstream':f'wss://127.0.0.1:{backend_port}/v1/ws','Cert':str(envdir/'server.pem'),'Key':str(envdir/'server.key'),'CA':str(envdir/'ca.pem'),'Control':str(self.control),'Observations':str(self.observations)}
        proxy_config=self.root/'proxy.json';proxy_config.write_text(json.dumps(proxy))
        shutil.copy2(self.run/'im-service',self.root/'im-service')
        self.report['service_runtime_path']=str(self.root/'im-service')
        self.start_service()
        self.proxy=self.launch('fault-proxy',proxy_config,'proxy')
        def proxy_ready():
            require(self.proxy.poll() is None,'proxy startup')
            try:
                with socket.create_connection(('127.0.0.1',self.front_port),timeout=.2):return True
            except OSError:return False
        wait(proxy_ready,'proxy listener',10)
        self.connect_options=[{'url':f'wss://127.0.0.1:{self.front_port}/v1/ws','token':token,'ca_certificate':self.env['ca_certificate'],'conversation':'chat','peer':self.materials[1-i]['identity'],'creator':i==0} for i,token in enumerate(self.tokens)]
    def launch(self,binary,config,label):
        log=self.run/(label+'-'+str(len(self.logs))+'.log');f=log.open('wb');self.logs.append(log)
        p=subprocess.Popen([(self.root if binary=='im-service' else self.run)/binary,'-config',config],cwd=self.root,stdout=f,stderr=subprocess.STDOUT);f.close();return p
    def start_service(self):
        self.service=self.launch('im-service',self.config,'service')
        def ready():
            if self.service.poll() is not None:raise AssertionError('service startup')
            try:
                with urllib.request.urlopen(f'https://127.0.0.1:{self.backend_port}/healthz',context=self.ssl,timeout=1) as r:return r.status==204
            except Exception:return False
        wait(ready,'service health',10)
    def restart_service(self):
        self.service.kill();self.service.wait(timeout=10);self.start_service()
    def restart_worker(self,index,kill=False):
        old=self.workers[index];old.close(kill);self.workers[index]=Worker(old.directory,old.options);return self.workers[index]
    def connect(self,index):return self.workers[index].call('connect',options=self.connect_options[index])
    def fault(self,mode,index=0):self.control.write_text(json.dumps({'mode':mode,'token_hash':hashlib.sha256(self.tokens[index].encode()).hexdigest(),'consumed':False}))
    def send(self,index,id):
        text='E2EE_ALPHA_TEST_PRIVATE_'+secrets.token_hex(16);self.texts.append(text)
        return text,self.workers[index].call('send',requestId='req-'+id,messageId=id,text=text)
    def status(self,index,id,target):
        s=self.workers[index].call('network');return next((x for x in s['sending'] if x['message_id']==id and x['status']==target),False)
    def history(self,index):
        items=[];query={'direction':'forward','page_size':3}
        while True:
            page=self.workers[index].call('history',query=query);items+=page['items']
            if page['done']:return items
            query['cursor']=page['next_cursor']
    def rpc(self,index,op,body):
        request=urllib.request.Request(f'https://127.0.0.1:{self.backend_port}/v1/rpc',data=json.dumps({'id':'test','op':op,'body':body}).encode(),headers={'Authorization':'Bearer '+self.tokens[index],'Content-Type':'application/json'})
        with urllib.request.urlopen(request,context=self.ssl,timeout=5) as response:return json.load(response)
    def case(self,name,operation):
        started=time.monotonic()
        try:operation();self.report['cases'].append({'name':name,'status':'PASS','seconds':round(time.monotonic()-started,2)})
        except Exception as e:self.report['cases'].append({'name':name,'status':'FAIL','error':str(e)});raise
        finally:self.save()
    def close(self):
        for worker in self.workers:
            try:worker.close()
            except Exception:pass
        for p in (self.proxy,self.service):
            if p and p.poll() is None:p.terminate();p.wait(timeout=10)
        for keychain in self.keychains:persistent_keychain.run({'op':'lock','keychain':str(keychain)})
