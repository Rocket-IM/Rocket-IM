"""真实冻结Service、独立SDK与新隔离数据库的停服恢复；不打开客户端数据库。"""
from pathlib import Path
from urllib.parse import urlparse,urlunparse,parse_qs,urlencode,quote
import hashlib
import json
import os
import secrets
import shutil
import subprocess
from backup_harness import BackupLab,BackupFault
from harness import ROOT,PG,require,wait,sha,all_hashes

TABLES=('schema_version','alpha_conversation','alpha_devices','business_configuration','business_users','device_identities','device_credentials','business_requests','alpha_messages','alpha_mailbox','alpha_recovery','service_maintenance')

def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

class ServiceBackupLab(BackupLab):
    def __init__(self,release,environment,run):
        self.service_release=Path(release);self.cli_number=0;self.launched=[];self.exports=[];self.targets=[]
        super().__init__(self.service_release/'client',environment,run)
    def command(self,args,cwd,label,env=None):
        if label=='go-build':
            report=json.loads((self.service_release/'report.json').read_text())
            require(report['status']=='PASS_SCOPED' and sha(self.service_release/'im-service')==report['service_sha256'],'real frozen Service artifact')
            require(all_hashes(self.service_release/'source')==report['source_files'],'frozen Service sources')
            shutil.copy2(self.service_release/'im-service',self.root/'im-service')
            self.report['service_artifact']={'release':str(self.service_release),'sha256':report['service_sha256'],'version':report['service_version']}
            log=self.run/'service-artifact-copy.log';log.write_text('Verified frozen executable copied to independent runtime.\n');return log
        return super().command(args,cwd,label,env)
    def setup(self,index,endpoint=None,ttl=None):return super().setup(index,endpoint,ttl if ttl is not None else getattr(self,'credential_ttl',300))
    def build(self,proxy=True):
        super().build(proxy=proxy)
        version=json.loads((self.release/'package/package.json').read_text())['version']
        service=json.loads((self.service_release/'report.json').read_text())['service_version']
        self.report['public_runtime']=f'independent signed {version} npm installs + public versioned Go SDK backend + frozen Service {service} executable'
    def start_service(self):
        config=json.loads(self.config.read_text())
        if 'recovery_state' not in config:
            folder=self.root/'maintenance';folder.mkdir(mode=0o700)
            config['recovery_state']=str(folder/'head.json');self.config.write_text(json.dumps(config));self.config.chmod(0o600)
            self.maintenance('enroll')
        self.head=Path(config['recovery_state']);self.update_target(config)
        super().start_service()
    def update_target(self,config):
        url=urlparse(config['database_url']);self.database=url.path.lstrip('/');self.schema=parse_qs(url.query).get('search_path',['public'])[0]
    def launch(self,binary,config,label):
        p=super().launch(binary,config,label);self.launched.append(p.pid);return p
    def maintenance(self,operation,backup=None,config=None,expected=None,timeout=130):
        self.cli_number+=1;log=self.run/('maintenance-'+str(self.cli_number)+'.log')
        args=[self.root/'im-service','-config',config or self.config,'-operation',operation]
        if backup is not None:args+=['-backup',backup]
        env={**os.environ,'ROCKET_IM_TEST_ISSUER_KEY':self.signing_key,'PATH':'/usr/bin:/bin'}
        p=subprocess.run([str(a) for a in args],cwd=self.root,env=env,capture_output=True,text=True,timeout=timeout)
        log.write_text(p.stdout+p.stderr)
        code=p.stderr.strip().split()[-1] if p.stderr.strip() else None
        if expected:
            require(p.returncode!=0 and code==expected,'maintenance '+operation+' expected '+expected+' got '+str(code))
            result={'code':code}
        else:
            require(p.returncode==0,'maintenance '+operation+' failed '+str(code));result=json.loads(p.stdout)
        self.report.setdefault('maintenance_operations',[]).append({'operation':operation,'result':result,'log':str(log),'config':str(config or self.config)})
        return result
    def stop_service(self):
        if self.service and self.service.poll() is None:
            self.service.terminate();require(self.service.wait(timeout=12)==0,'graceful service exit with complete seal')
            require(json.loads(self.head.read_text())['phase']=='sealed','external clean-stop checkpoint')
    def restart_service(self):self.stop_service();self.start_service()
    def quiesce(self):self.offline();self.stop_service()
    def export_service(self,label):
        folder=self.root/'service-backups';folder.mkdir(mode=0o700,exist_ok=True)
        path=folder/(label+'.rimservice');receipt=self.maintenance('backup',path);self.exports.append(path)
        self.report.setdefault('service_backups',[]).append({'path':str(path),'sha256':sha(path),'receipt':receipt})
        return path
    def new_target(self,label='restore'):
        name='restore_'+secrets.token_hex(6)
        self.command([PG/'createdb','-h',Path(self.env['directory'])/'socket','-U','alpha',name],self.root,'createdb-'+name)
        config=json.loads(self.config.read_text());url=urlparse(config['database_url']);query=parse_qs(url.query);query.pop('search_path',None)
        # pgx按URI字节解码host，不把查询中的+当空格；与原环境的%20路径保持一致。
        config['database_url']=urlunparse(url._replace(path='/'+name,query=urlencode(query,doseq=True,quote_via=quote)))
        path=self.root/(label+'-'+name+'.json');path.write_text(json.dumps(config));path.chmod(0o600)
        self.targets.append({'database':name,'config':str(path)});return path
    def import_service(self,backup,target=None):
        target=target or self.new_target();receipt=self.maintenance('restore',backup,config=target)
        self.config=target;self.update_target(json.loads(target.read_text()));return receipt
    def sql(self,query,database=None):
        return subprocess.check_output([PG/'psql','-h',Path(self.env['directory'])/'socket','-U','alpha','-d',database or self.database,'-Aqt','-v','ON_ERROR_STOP=1','-c',query],text=True,timeout=30)
    def database_snapshot(self):
        statements=['BEGIN READ ONLY']+[f"SELECT json_build_object('table','{name}','rows',COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]')) FROM {self.schema}.{name} t" for name in TABLES]+['COMMIT']
        rows=[json.loads(line) for line in self.sql(';'.join(statements)).splitlines() if line.startswith('{')]
        require(len(rows)==len(TABLES),'all Service tables included')
        return {row['table']:row['rows'] for row in rows}
    def fact(self,message):
        require(message.replace('-','').isalnum(),'controlled fact ID')
        rows=[json.loads(line) for line in self.sql(f"BEGIN READ ONLY; SELECT to_jsonb(t) FROM {self.schema}.alpha_messages t WHERE message_id='{message}'; COMMIT;").splitlines() if line.startswith('{')]
        require(len(rows)<=1,'unique request fact');return rows[0] if rows else None
    def cycle(self,label,reconnect=True,reopen=True):
        self.quiesce();before=self.database_snapshot();states=[self.snapshot(i) for i in range(2)]
        first=[w.call('history',query={'direction':'forward','page_size':1}) for w in self.workers]
        old=self.config;backup=self.export_service(label);target=self.new_target(label)
        receipt=self.import_service(backup,target)
        require(self.maintenance('restore',backup)==receipt,'idempotent repeated current restore')
        require(self.database_snapshot()==before,'exact entire Service database after restore')
        self.maintenance('serve',config=old,expected='maintenance_target_mismatch')
        for i in range(2):
            if reopen:self.workers[i].close();self.restore(i)
            after=self.snapshot(i)
            require(after['state']==states[i]['state'] and after['history']==states[i]['history'],'SDK original identity state and history')
            for key in ('downloaded','processed','reported','sending','unavailable_history'):
                require(after['network'][key]==states[i]['network'][key],'SDK durable '+key)
            require(self.pages(i,first[i])==states[i]['history'],'stable local pagination across Service restore')
        self.report.setdefault('restored_checkpoints',[]).append({'label':label,'digest':receipt['digest'],'tables':{key:{'count':len(value),'sha256':digest(value)} for key,value in before.items()},'sdk_cursors':[{k:state['network'][k] for k in ('downloaded','processed','reported')} for state in states],'target':self.database})
        self.start_service()
        if reconnect:
            for i in range(2):self.auto(i);self.online(i)
        return backup
    def snapshot_secrets(self):
        dump=subprocess.check_output([PG/'pg_dump','-h',Path(self.env['directory'])/'socket','-U','alpha','-d',self.database,'--schema='+self.schema,'--data-only'],timeout=30)
        logs=b''.join(p.read_bytes() for p in self.run.rglob('*.log'))+b''.join((w.directory/'worker-stderr.log').read_bytes() for w in self.workers)
        exports=b''.join(p.read_bytes() for p in self.exports)
        protected=b''.join(Path(w.options['path']).read_bytes() for w in self.workers)
        samples=self.texts+self.tokens+self.sessions+getattr(self,'extra_secrets',[])+[self.business_token,self.other_token,self.expired_token,self.signing_key]
        surfaces=dump+logs+exports+protected+self.head.read_bytes()
        require(b'rimd_' not in surfaces and b'rimb_' not in surfaces,'no token originals in backup DB journal logs clients')
        for value in samples:require(value.encode() not in surfaces,'no actual secret sample on persisted surfaces')
        scan=self.root/'service-scan.bin';scan.write_bytes(dump+logs+exports+self.head.read_bytes());scan.chmod(0o600)
        try:dynamic=[w.call('authScan',paths=[str(scan),w.options['path']]) for w in self.workers]
        finally:scan.unlink()
        self.report.setdefault('secret_scans',[]).append({'static_samples':len(samples),'dynamic':dynamic,'matches':0,'backup_files':len(self.exports)})
    def audit(self,index):
        # 此既有扫描器抽样整个快照（包括公钥/公开密文），其零命中断言只适用于
        # 端侧加密容器及普通日志。Service的真实正文/凭证/签发秘密另由snapshot_secrets扫描。
        paths=self.backups+list(self.run.glob('*.log'))
        fault=BackupFault(self,index,'audit_only',extra={'ROCKET_IM_TEST_AUDIT_PATHS':json.dumps([str(p) for p in paths])})
        try:result=fault.call({'op':'audit_protection'},timeout=180)
        finally:fault.close()
        result['scope']='client encrypted files/keychain/backups and ordinary logs; broad samples include public values'
        self.report.setdefault('private_state_audits',[]).append(result);self.save()
        require(result['sample_count']>20 and all(r['matches']==0 for r in result['files']),'actual broad client samples absent from encrypted client surfaces and logs')
        self.restore(index);return result
    def close(self):
        super().close()
        for pid in self.launched:
            try:os.kill(pid,0)
            except ProcessLookupError:continue
            raise AssertionError('Service/business/proxy process remains')
        self.report['service_processes_reaped']=self.launched;self.report['restore_targets']=self.targets;self.save()
