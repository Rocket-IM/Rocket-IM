#!/usr/bin/env python3
"""真实旧Alpha二进制建库/收发，再用新Service迁移并经公开SDK认领；不手改业务表。"""
import argparse
from datetime import datetime,timedelta,timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import traceback
import urllib.error
import urllib.request
from harness import Lab,ROOT,GO,PG,require,wait,sha
from business_harness import GoConsumer


class MigrationLab(Lab):
    def __init__(self,*args,baseline,consumer,old_service=None,old_version=1):
        self.baseline=Path(baseline);self.consumer_binary=Path(consumer);self.first=True;self.consumers=[];self.old_service=Path(old_service) if old_service else None;self.old_version=old_version
        self.business_token='rimb_'+secrets.token_hex(32);self.signing_key=secrets.token_hex(32)
        super().__init__(*args)
    def build(self):
        env={**os.environ,'GOPATH':str(ROOT/'dist/toolchains/gopath'),'GOCACHE':str(ROOT/'dist/toolchains/go-cache')}
        if self.old_service:shutil.copy2(self.old_service,self.run/'old-service')
        else:self.command([GO,'build','-trimpath','-o',self.run/'old-service','./cmd/im-service'],self.baseline/'src/backend','old-build',env)
        super().build()
        self.report['old_service_sha256']=sha(self.run/'old-service')
        if not self.old_service:self.report['old_source']={str(p.relative_to(self.baseline)):sha(p) for p in (self.baseline/'src/backend').rglob('*') if p.is_file()}
        self.report['migration_client_scope']='Actual prior Release preserves original protected client data; this does not test cross-signing client upgrade.'
        self.proxy.terminate();self.proxy.wait(timeout=10);self.proxy=None
        self.front_port=self.backend_port;self.endpoint=f'https://127.0.0.1:{self.backend_port}'
        for options in self.connect_options:options['url']=f'wss://127.0.0.1:{self.backend_port}/v1/ws'
        shutil.copy2(self.consumer_binary,self.root/'consumer-exec')
    def start_service(self):
        if self.first:shutil.copy2(self.run/'old-service',self.root/'im-service');self.first=False
        super().start_service()
    def launch(self,binary,config,label):
        if binary!='im-service':return super().launch(binary,config,label)
        log=self.run/(label+'-'+str(len(self.logs))+'.log');self.logs.append(log)
        with log.open('wb') as f:return subprocess.Popen([self.root/'im-service','-config',config],cwd=self.root,stdout=f,stderr=subprocess.STDOUT,env={**os.environ,'ROCKET_IM_TEST_ISSUER_KEY':self.signing_key})
    def sql(self,query):
        return subprocess.check_output([str(PG/'psql'),'-h',str(Path(self.env['directory'])/'socket'),'-U','alpha','-d','alpha','-At','-v','ON_ERROR_STOP=1','-c','SET search_path TO '+self.schema+';'+query],text=True).removeprefix('SET\n').strip()
    def snapshot(self):
        rows={table:json.loads(self.sql('SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),\'[]\'::jsonb) FROM '+table+' t')) for table in ('alpha_conversation','alpha_devices','alpha_messages','alpha_mailbox')}
        for table,column in [('alpha_conversation','crypto_context'),('alpha_messages','context_retired'),('alpha_mailbox','disposition')]:
            for row in rows[table]:row.pop(column,None)
        return rows
    def close(self):
        for c in self.consumers:c.close()
        super().close()


def run(lab):
    original={}
    def old_messages():
        require(lab.sql('SELECT version FROM schema_version')==str(lab.old_version),'old binary owns expected schema')
        lab.connect(0);lab.connect(1)
        wait(lambda:all(w.call('network')['connection']=='online' for w in lab.workers),'old Alpha group')
        for i,id in [(0,'old-first'),(1,'old-reply')]:
            original[id]=lab.send(i,id)
            wait(lambda:lab.status(i,id,'delivered'),'old accepted and delivered')
        lab.workers[1].call('disconnect')
        for n in range(6):lab.send(0,'old-offline-'+str(n))
        wait(lambda:all(lab.status(0,'old-offline-'+str(n),'accepted') for n in range(6)),'old offline persisted')
        lab.workers[0].call('disconnect')
    lab.case('actual_schema'+str(lab.old_version)+'_binary_bidirectional_and_offline_messages',old_messages)
    def migrate():
        before=lab.snapshot();lab.service.terminate();lab.service.wait(timeout=10)
        shutil.copy2(lab.run/'im-service',lab.root/'im-service')
        config=json.loads(lab.config.read_text());bad={**config,'conversation':'wrong-binding'}
        badpath=lab.root/'bad-upgrade.json';badpath.write_text(json.dumps(bad))
        with (lab.run/'rejected-upgrade.log').open('wb') as f:failed=subprocess.run([lab.root/'im-service','-config',badpath],stdout=f,stderr=subprocess.STDOUT,timeout=10)
        require(failed.returncode!=0 and lab.sql('SELECT version FROM schema_version')==str(lab.old_version) and lab.snapshot()==before,'failed upgrade leaves original rows and version')
        now=datetime.now(timezone.utc)
        config['business']={'credential_key_env':'ROCKET_IM_TEST_ISSUER_KEY','principals':[{'id':'shop','token_sha256':hashlib.sha256(lab.business_token.encode()).hexdigest(),'not_before':(now-timedelta(hours=1)).isoformat(),'expires_at':(now+timedelta(hours=2)).isoformat(),'legacy_users':{'legacy-alice':'alice','legacy-bob':'bob'}}]}
        lab.config.write_text(json.dumps(config));lab.start_service()
        require(lab.sql('SELECT version FROM schema_version')=='4' and lab.snapshot()==before,'schema4 preserves exact old messages and mailboxes')
        require(lab.sql('SELECT COUNT(*) FROM alpha_recovery')=='0','migration does not invent recovery consent')
        require(lab.sql("SELECT crypto_context FROM alpha_conversation")=='initial','old initial context explicit')
        require(lab.sql('SELECT COUNT(*) FROM alpha_messages WHERE context_retired')=='0','old messages not silently retired')
        require(lab.sql("SELECT COUNT(*) FROM alpha_mailbox m JOIN alpha_devices d USING(device_index) WHERE (m.sequence<=d.processed AND m.disposition IS DISTINCT FROM 'received') OR (m.sequence>d.processed AND m.disposition IS NOT NULL)")=='0','old contiguous receipt facts retained')
        lab.report['migration_preserved_counts']={table:len(rows) for table,rows in before.items()}
        client=GoConsumer(lab,service='alpha-network-test');lab.consumers.append(client)
        lab.new_credentials=[]
        for i,name in enumerate(('alice','bob')):
            user=client.call('users',{'request_id':'map-'+name,'external_user':'legacy-'+name});require(user['account']==name,'explicit old mapping')
            body={'request_id':'bind-'+name,'external_user':'legacy-'+name,'account':name,'device':name+'-1','identity_key':lab.materials[i]['identity']['identity_key']}
            client.call('devices',{**body,'identity_key':'ff'*32},code='device_conflict')
            bound=client.call('devices',body);require(bound['identity']==lab.materials[i]['identity'],'old public identity unchanged')
            req={k:v for k,v in body.items() if k!='identity_key'};req.update(request_id='issue-'+name,ttl_seconds=3600)
            credential=client.call('credentials',req);lab.new_credentials.append((req,credential))
            try:lab.rpc(i,'session',{});raise AssertionError('legacy fixed token still authorized')
            except urllib.error.HTTPError as e:require(e.code==401,'old token explicitly stopped')
            lab.tokens[i]=credential['token'];lab.connect_options[i]['token']=credential['token']
        lab.restart_service()
        for request,credential in lab.new_credentials:require(client.call('credentials',request)==credential,'upgraded issuance ledger survives restart')
        for i in range(2):lab.restart_worker(i);lab.connect(i)
        wait(lambda:all(lab.status(0,'old-offline-'+str(n),'delivered') for n in range(6)),'upgraded offline backlog delivered')
        text,result=original['old-first'];again=lab.workers[0].call('send',requestId='req-old-first',messageId='old-first',text=text)
        require(again['cached'] and again['value']==result['value'],'old encrypted outbox exact retry')
        req={'request_id':'req-old-first','envelope':result['value']['envelope']}
        require(lab.rpc(0,'send',req)['result']['sequence']=='1','old server acceptance idempotency')
        lab.send(1,'after-upgrade');wait(lambda:lab.status(1,'after-upgrade','delivered'),'post upgrade e2ee')
        require(all(w.call('state')['identity']==lab.materials[i]['identity'] for i,w in enumerate(lab.workers)),'original encrypted identities retained')
    lab.case('failed_upgrade_rollback_then_public_identity_adoption_and_live_resume',migrate)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--release',required=True);p.add_argument('--environment',required=True);p.add_argument('--run',required=True);p.add_argument('--baseline',required=True);p.add_argument('--consumer',required=True);p.add_argument('--old-service');p.add_argument('--old-version',type=int,default=1);a=p.parse_args()
    lab=MigrationLab(a.release,a.environment,a.run,baseline=a.baseline,consumer=a.consumer,old_service=a.old_service,old_version=a.old_version)
    try:lab.build();run(lab);require(lab.sources()==lab.report['source_before'],'source changed');lab.report['status']='PASS_SCOPED'
    except Exception as e:lab.report.update(status='FAIL',error=str(e),trace=traceback.format_exc())
    finally:lab.close();lab.save()
    print(json.dumps({'status':lab.report['status'],'error':lab.report.get('error'),'report':str(lab.run/'network-report.json')}))
    raise SystemExit(0 if lab.report['status']=='PASS_SCOPED' else 1)
