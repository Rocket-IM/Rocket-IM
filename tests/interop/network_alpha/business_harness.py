"""公开业务SDK与示例后台的仓库外消费；正常流程不写IM表或搬运密文。"""
from pathlib import Path
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from harness import Lab, Worker, require, wait, ROOT, GO, PG, port, node_binary, npm_command, COMPILER, all_hashes, sha, persistent_keychain
from business_go import pack


class GoConsumer:
    def __init__(self, lab, token=None, endpoint=None, service=None, timeout=5000, attempts=2):
        self.lab = lab
        config = lab.root/('go-options-'+secrets.token_hex(6)+'.json')
        config.write_text(json.dumps({'Endpoint':endpoint or lab.endpoint, 'Service':service or 'business-test', 'Token':token or lab.business_token, 'CA':str(Path(lab.env['directory'])/'ca.pem'), 'TimeoutMS':timeout,'Attempts':attempts}))
        config.chmod(0o600)
        env = {k:v for k,v in os.environ.items() if not k.startswith(('CARGO','RUST'))}
        env['PATH'] = '/usr/bin:/bin'
        self.process = subprocess.Popen([lab.root/'consumer-exec',config],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env,cwd=lab.root)
    def call(self, op, body, code=None, deadline=0):
        self.process.stdin.write(json.dumps({'op':op,'body':body,'deadline_ms':deadline})+'\n');self.process.stdin.flush()
        reply = json.loads(self.process.stdout.readline())
        if code is None: require(reply['ok'],'Go consumer '+op+': '+reply.get('code',''))
        else: require(not reply['ok'] and reply['code']==code,'Go consumer expected '+code+' got '+reply.get('code',''))
        return reply['result']
    def close(self):
        self.process.stdin.close(); self.process.wait(timeout=10)
        require(self.process.returncode==0 and not self.process.stderr.read(),'Go consumer clean exit')


class BusinessLab(Lab):
    def sources(self):
        names=subprocess.check_output(['git','ls-files','-co','--exclude-standard','-z'],cwd=ROOT).decode().split('\0')
        prefixes=('src/backend/','src/server-sdk/go/','examples/business-backend/','tests/consumers/go-business/','tests/interop/network_alpha/','api/http/','tools/platform_release/business_go.py')
        return {n:sha(ROOT/n) for n in sorted(set(names)) if n and (ROOT/n).is_file() and n.startswith(prefixes)}
    def build(self):
        self.business_process=None;self.consumers=[]
        # 仅本轮新建测试项；密码只留装置内存，供真实锁定/解锁回归，不写报告。
        self.keychain_passwords=[]
        self.business_token='rimb_'+secrets.token_hex(32);self.other_token='rimb_'+secrets.token_hex(32);self.expired_token='rimb_'+secrets.token_hex(32)
        self.signing_key=secrets.token_hex(32);self.sessions=[secrets.token_hex(32),secrets.token_hex(32)]
        self.go_env={**os.environ,'GOPATH':str(ROOT/'dist/toolchains/gopath'),'GOCACHE':str(ROOT/'dist/toolchains/go-cache'),'GOTOOLCHAIN':'local'}
        self.command([GO,'build','-trimpath','-o',self.root/'im-service','./cmd/im-service'],ROOT/'src/backend','go-build',self.go_env)
        self.report['service_sha256']=sha(self.root/'im-service')
        package=getattr(self,'frozen_go_package',None) or pack(self.run/'go-release');self.report['go_package']=package
        # 真实版本化模块下载到隔离缓存；二进制与缓存全部在仓库外。
        independent={**self.go_env,'GOPROXY':Path(package['proxy']).as_uri(),'GOSUMDB':'off','GOMODCACHE':str(self.root/'module-cache'),'GOPATH':str(self.root/'gopath')}
        for source,name in [('tests/consumers/go-business','go-consumer'),('examples/business-backend','business-backend')]:
            target=self.root/name;shutil.copytree(ROOT/source,target)
            self.command([GO,'build','-mod=mod','-trimpath','-o',self.root/(name+'-binary'),'.'],target,name+'-build',independent)
            metadata=subprocess.check_output([str(GO),'list','-m','-json','all'],cwd=target,env=independent,text=True)
            require('"Replace"' not in metadata and str(ROOT/'src') not in metadata,'independent module consumption')
            (self.run/(name+'-modules.jsonl')).write_text(metadata)
            shutil.copy2(target/'go.sum',self.run/(name+'-go.sum'))
        # 避免可执行文件与消费源码目录重名。
        shutil.copy2(self.root/'go-consumer-binary',self.root/'consumer-exec')
        envdir=Path(self.env['directory']);self.backend_port=port();self.front_port=self.backend_port
        self.endpoint=f'https://127.0.0.1:{self.backend_port}'
        self.schema='business_'+str(time.time_ns())
        self.command([PG/'psql','-h',envdir/'socket','-U','alpha','-d','alpha','-v','ON_ERROR_STOP=1','-c','CREATE SCHEMA '+self.schema],self.root,'create-schema')
        now=datetime.now(timezone.utc)
        def principal(name,token,expired=False):
            return {'id':name,'token_sha256':hashlib.sha256(token.encode()).hexdigest(),'not_before':(now-timedelta(hours=2)).isoformat(),'expires_at':(now+timedelta(hours=-1 if expired else 2)).isoformat()}
        config={'listen':f'127.0.0.1:{self.backend_port}','database_url':self.env['database_url']+'&search_path='+self.schema,'tls_cert':str(envdir/'server.pem'),'tls_key':str(envdir/'server.key'),'service':'business-test','conversation':'chat','devices':[],'business':{'credential_key_env':'ROCKET_IM_TEST_ISSUER_KEY','principals':[principal('shop',self.business_token),principal('other',self.other_token),principal('expired',self.expired_token,True)]}}
        self.config=self.root/'service.json';self.config.write_text(json.dumps(config));self.config.chmod(0o600)
        self.start_service()
        self.business_port=port();self.business_endpoint=f'https://127.0.0.1:{self.business_port}'
        self.business_config=self.root/'business.json';self.business_config.write_text(json.dumps({'listen':f'127.0.0.1:{self.business_port}','tls_cert':str(envdir/'server.pem'),'tls_key':str(envdir/'server.key'),'service_url':self.endpoint,'service':'business-test','ca_file':str(envdir/'ca.pem'),'business_token_env':'ROCKET_IM_TEST_BUSINESS_TOKEN','sessions':[{'external_user':'buyer-'+str(i),'device':'device-'+str(i),'token_sha256':hashlib.sha256(token.encode()).hexdigest()} for i,token in enumerate(self.sessions)]}));self.business_config.chmod(0o600)
        self.start_business()
        report=json.loads((self.release/'report.json').read_text());archive=Path(report['archive'])
        require(report['status']=='PASS_SCOPED' and sha(archive)==report['archive_sha256'],'frozen actual Node package')
        self.report.update(archive=str(archive),archive_sha256=sha(archive),package_report=str(self.release/'report.json'))
        self.users=[self.business(i,'user',{'device':'device-'+str(i),'request_id':'user-'+str(i)}) for i in range(2)]
        for i,user in enumerate(self.users):
            consumer=self.root/('node-'+str(i));consumer.mkdir();(consumer/'path').mkdir();(consumer/'path/node').symlink_to(node_binary())
            (consumer/'package.json').write_text(json.dumps({'name':'business-node-'+str(i),'private':True,'type':'module'}))
            for name in ('network-worker.mjs','types.ts','tsconfig.json'):shutil.copy2(self.release/'source/tests/consumers/node-persistent'/name,consumer/name)
            self.command(npm_command()+['install','--offline','--ignore-scripts','--no-audit','--no-fund',archive],consumer,'node-install-'+str(i))
            self.command([node_binary(),COMPILER,'-p',consumer/'tsconfig.json'],consumer,'node-types-'+str(i))
            require(all_hashes(consumer/'node_modules/@rocket-im/desktop-dev')==report['package_files'],'installed actual package bytes')
            keychain=self.root/('lab-node-'+str(i)+'.keychain-db');password=secrets.token_hex(32)
            require(persistent_keychain.run({'op':'create','keychain':str(keychain),'password':password})['status']==0,'dedicated keychain');self.keychains.append(keychain)
            self.keychain_passwords.append(password)
            options={'path':str(consumer/'encrypted.db'),'scope':user['scope'],'keychain':str(keychain),'create':True}
            worker=Worker(consumer,options);worker.call('initialize');worker.options['create']=False;self.workers.append(worker)
        self.materials=[w.call('material') for w in self.workers]
        self.bindings=[self.business(i,'device',{'device':'device-'+str(i),'request_id':'bind-'+str(i),'identity_key':self.materials[i]['identity']['identity_key']}) for i in range(2)]
        self.credentials=[self.business(i,'credential',{'device':'device-'+str(i),'request_id':'credential-'+str(i),'ttl_seconds':3600}) for i in range(2)]
        self.tokens=[c['token'] for c in self.credentials]
        # 独立核验渠道：控制器直接取两个独立SDK的公开材料，绝不把Service目录当成信任根。
        self.connect_options=[{'url':f'wss://127.0.0.1:{self.backend_port}/v1/ws','token':self.tokens[i],'ca_certificate':self.env['ca_certificate'],'conversation':self.bindings[i]['conversation'],'peer':self.materials[1-i]['identity'],'creator':self.bindings[i]['creator']} for i in range(2)]
        self.report['normal_path']='business login context -> actual Go SDK -> public API -> restricted credential -> independent peer verification -> direct Go WSS'
    def launch(self,binary,config,label):
        log=self.run/(label+'-'+str(len(self.logs))+'.log');self.logs.append(log)
        env=dict(os.environ)
        if binary=='im-service':env['ROCKET_IM_TEST_ISSUER_KEY']=self.signing_key
        else:env['ROCKET_IM_TEST_BUSINESS_TOKEN']=self.business_token
        with log.open('wb') as f:return subprocess.Popen([self.root/binary,'-config',config],cwd=self.root,stdout=f,stderr=subprocess.STDOUT,env=env)
    def start_business(self):
        self.business_process=self.launch('business-backend-binary',self.business_config,'business')
        def ready():
            require(self.business_process.poll() is None,'business startup')
            try:
                with urllib.request.urlopen(self.business_endpoint+'/healthz',context=self.ssl,timeout=1) as r:return r.status==204
            except Exception:return False
        wait(ready,'business health',10)
    def business(self,index,op,body,status=200):
        req=urllib.request.Request(self.business_endpoint+'/im/'+op,data=json.dumps(body).encode(),headers={'Authorization':'Bearer '+self.sessions[index],'Content-Type':'application/json'})
        try:
            with urllib.request.urlopen(req,context=self.ssl,timeout=15) as r:require(r.status==status,'business status');return json.load(r)
        except urllib.error.HTTPError as e:
            require(e.code==status,'business expected status '+str(status)+' got '+str(e.code));return json.load(e)
    def consumer(self,**kwargs):
        c=GoConsumer(self,**kwargs);self.consumers.append(c);return c
    def close(self):
        for c in getattr(self,'consumers',[]):c.close()
        p=getattr(self,'business_process',None)
        if p and p.poll() is None:p.terminate();p.wait(timeout=10)
        super().close()
