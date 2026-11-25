"""自动续期验收：复用实际Go模块后台、正常SDK包及原传输故障装置。"""
from pathlib import Path
import hashlib
import json
import shutil
import socket
import subprocess
import time
from business_harness import BusinessLab
from harness import ROOT, GO, PG, require, wait, port


class RenewalLab(BusinessLab):
    def build(self, proxy=False):
        frozen=ROOT/'dist/platform-release/persistent/runs/e4634800-392f-46ce-a369-0513e64cade2/business-reviewed/go-release/report.json'
        self.frozen_go_package=json.loads(frozen.read_text())
        require(hashlib.sha256(Path(self.frozen_go_package['archive']).read_bytes()).hexdigest()==self.frozen_go_package['archive_sha256'],'frozen Go artifact bytes')
        for name,digest in self.frozen_go_package['source_sha256'].items():
            require(hashlib.sha256((ROOT/'src/server-sdk/go'/name).read_bytes()).hexdigest()==digest,'unchanged frozen Go SDK source')
        super().build()
        self.proxy_enabled = proxy
        for worker in self.workers:
            shutil.copy2(self.release/'source/tests/consumers/node-persistent/renewal-provider.mjs', worker.directory/'renewal-provider.mjs')
        self.auto_options = [{k:v for k,v in options.items() if k != 'token'} for options in self.connect_options]
        if proxy:
            self.command([GO,'build','-trimpath','-o',self.root/'fault-proxy',ROOT/'tests/interop/network_alpha/fault_proxy.go'],ROOT/'src/backend','proxy-build',self.go_env)
            self.front_port=port(); self.control=self.root/'fault.json'; self.observations=self.root/'observations.json'
            self.control.write_text('{}'); self.observations.write_text('[]')
            envdir=Path(self.env['directory'])
            config={'Listen':f'127.0.0.1:{self.front_port}','Upstream':f'wss://127.0.0.1:{self.backend_port}/v1/ws',
                'Cert':str(envdir/'server.pem'),'Key':str(envdir/'server.key'),'CA':str(envdir/'ca.pem'),
                'Control':str(self.control),'Observations':str(self.observations)}
            path=self.root/'proxy.json';path.write_text(json.dumps(config))
            self.proxy=self.launch('fault-proxy',path,'proxy')
            def ready():
                require(self.proxy.poll() is None,'proxy startup')
                try:
                    with socket.create_connection(('127.0.0.1',self.front_port),timeout=.2):return True
                except OSError:return False
            wait(ready,'proxy listener',10)
            for options in self.auto_options: options['url']=f'wss://127.0.0.1:{self.front_port}/v1/ws'
        self.report['normal_path']='SDK Rust authentication request -> host async business login callback -> independent Go backend using versioned Go SDK -> Go Service -> Rust verified session and durable queue'
        self.report['transport_proxy']=proxy
        for i in range(2): self.setup(i)

    def setup(self,index,endpoint=None,ttl=2):
        self.workers[index].call('authSetup',config={'endpoint':endpoint or self.business_endpoint,
            'session':self.sessions[index],'device':'device-'+str(index),'ttl':ttl,
            'ca':str(Path(self.env['directory'])/'ca.pem'),
            'other':{'session':self.sessions[1-index],'device':'device-'+str(1-index)}})

    def auto(self,index,timeout=1000,attempts=3,concurrent=False):
        return self.workers[index].call('concurrentConnect' if concurrent else 'autoConnect',
            options={**self.auto_options[index],'authentication':{'timeout_ms':timeout,'max_attempts':attempts}})

    def online(self,index):
        return wait(lambda: self.workers[index].call('network')['connection']=='online','automatic online '+str(index))

    def stats(self,index): return self.workers[index].call('authStats')

    def reauto(self,index,**kwargs):
        self.workers[index].call('disconnect');self.auto(index,**kwargs);self.online(index)

    def fact(self,message):
        require(message.replace('-','').isalnum(),'test fact ID')
        sql=f"BEGIN READ ONLY; SELECT row_to_json(m) FROM {self.schema}.alpha_messages m WHERE message_id='{message}'; COMMIT;"
        out=subprocess.check_output([PG/'psql','-h',Path(self.env['directory'])/'socket','-U','alpha','-d','alpha','-Aqt','-v','ON_ERROR_STOP=1','-c',sql],text=True)
        rows=[json.loads(line) for line in out.splitlines() if line.startswith('{')]
        require(len(rows)<=1,'one Service acceptance');return rows[0] if rows else None

    def proof(self,message,original):
        fact=self.fact(message); require(fact is not None,'Service durable acceptance')
        envelope=original['value']['envelope']
        require(fact['request_id']=='req-'+message and fact['envelope']==envelope,'original request/message/ciphertext accepted')
        require(fact['delivered'],'Service device processed fact')
        local=self.workers[0].call('request',requestId='req-'+message)
        require(local['status']=='complete' and local['outcome']['value']==original['value'],'original durable ciphertext unchanged')
        require(len([m for m in self.history(1) if m['message']['message_id']==message])==1,'single recipient history')
        evidence={k:fact[k] for k in ('request_id','message_id','accepted','envelope_hash','delivered')}
        evidence['ciphertext_sha256']=hashlib.sha256(bytes.fromhex(envelope['ciphertext'])).hexdigest()
        self.report.setdefault('exact_queue_proofs',[]).append(evidence)

    def snapshot_secrets(self):
        dump=subprocess.check_output([PG/'pg_dump','-h',Path(self.env['directory'])/'socket','-U','alpha','-d','alpha','--schema='+self.schema,'--data-only'],timeout=30)
        require(b'rimd_' not in dump and b'rimb_' not in dump,'no raw credentials in Service tables')
        logs=b''.join(p.read_bytes() for p in self.run.rglob('*.log'))+b''.join((w.directory/'worker-stderr.log').read_bytes() for w in self.workers)
        protected=b''.join(Path(w.options['path']).read_bytes() for w in self.workers)
        require(b'rimd_' not in logs+protected and b'rimb_' not in logs+protected,'no access token prefixes in logs or client persistence')
        samples=self.texts+self.tokens+self.sessions+[self.business_token,self.signing_key]
        for sample in samples: require(sample.encode() not in dump+logs+protected,'secret absent on normal persistence and log surfaces')
        # 将无秘密的实际Service转储临时提供给消费者扫描其仅在内存中的动态令牌；扫描后删除。
        scan=self.root/'scan-service-and-logs';scan.write_bytes(dump+logs);scan.chmod(0o600)
        try:
            paths=[str(scan)]+[w.options['path'] for w in self.workers]
            checks=[w.call('authScan',paths=paths) for w in self.workers]
        finally:scan.unlink()
        self.report['secret_scan']={'static_samples':len(samples),'dynamic':checks,'matches':0}
