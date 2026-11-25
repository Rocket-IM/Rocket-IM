"""备份验收只通过真实安装包操作；故障程序独立签名，宿主不解密或执行SQL。"""
from pathlib import Path
import hashlib
import json
import os
import queue
import shutil
import subprocess
import threading
from recovery_harness import RecoveryLab
from commit_faults import FaultRuntime
from harness import Worker, require, node_binary, sha, persistent_keychain, wait


class BackupFault(FaultRuntime):
    def __init__(self, lab, index, phase, mode='open', extra=None):
        self.queue=queue.Queue();self.sequence=0;self.events=[]
        worker=lab.workers[index];self.options=worker.options;worker.close()
        env={k:v for k,v in os.environ.items() if not k.startswith('ROCKET_IM_TEST_')}
        env['ROCKET_IM_TEST_EXIT_PHASE']=phase;env.update(extra or {})
        scope=self.options['scope']
        args=[lab.release/'fault-runtime',self.options['path'],scope['service'],scope['account'],scope['device'],mode,self.options['keychain']]
        log=lab.run/('backup-fault-'+str(len(lab.report.setdefault('fault_processes',[])))+'.log')
        self.log=log.open('wb')
        self.process=subprocess.Popen(args,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.log,text=True,bufsize=1)
        lab.report['fault_processes'].append({'pid':self.process.pid,'phase':phase,'mode':mode,'log':str(log)})
        def read():
            for line in self.process.stdout:self.queue.put(json.loads(line))
            self.queue.put(None)
        threading.Thread(target=read,daemon=True).start()
        ready=self.queue.get(timeout=20);require(ready and ready.get('ready') and ready.get('test_hooks'),'backup fault handshake')
    def interrupt(self,operation):
        self.sequence+=1
        self.process.stdin.write(json.dumps({'id':str(self.sequence),'operation':operation})+'\n');self.process.stdin.flush()
        self.exited()


class BackupLab(RecoveryLab):
    def build(self,proxy=True):
        super().build(proxy=proxy)
        self.backups=[];self.native_pids=[]
        for worker in self.workers:
            shutil.copy2(self.release/'source/tests/consumers/node-persistent/backup-probe.mjs',worker.directory/'backup-probe.mjs')
        self.track()
    def track(self):
        self.native_pids.extend(w.pid for w in self.workers if w.pid not in self.native_pids)
    def restore(self,index):
        worker=super().restore(index);self.track();return worker
    def offline(self):
        for w in self.workers:w.call('disconnect')
    def aligned(self):
        for i in range(2):wait(lambda:(s:=self.workers[i].call('network'))['downloaded']==s['processed']==s['reported'],'backup contiguous cursors')
    def snapshot(self,index):
        w=self.workers[index]
        return {'state':w.call('state'),'history':self.history(index),'network':w.call('network')}
    def export(self,index,label):
        path=self.root/(label+'.rimbackup')
        info=self.workers[index].call('backup',path=str(path))
        self.backups.append(path)
        self.report.setdefault('backups',[]).append({'path':str(path),'sha256':sha(path),'info':info})
        return path,info
    def probe(self,index,backup,expected=None,options=None,mode='restore',directory=None):
        w=self.workers[index];directory=Path(directory or w.directory)
        env={k:v for k,v in os.environ.items() if not k.startswith(('ROCKET_IM_TEST_','RUST','CARGO'))};env['PATH']=str(w.directory/'path')
        p=subprocess.run([node_binary(),'backup-probe.mjs'],cwd=directory,env=env,
            input=json.dumps({'options':options or w.options,'backup':str(backup),'mode':mode}),text=True,capture_output=True,timeout=30)
        require(p.returncode==0 and not p.stderr,'normal backup probe clean exit')
        result=json.loads(p.stdout)
        if expected:require(result=={'ok':False,'code':expected},'backup expected '+expected+' got '+str(result.get('code')))
        else:require(result.get('ok'),'backup probe failed '+str(result.get('code')))
        self.report.setdefault('probes',[]).append({'index':index,'mode':mode,'backup':str(backup),'result':result})
        return result.get('result')
    def roundtrip(self,index,path,expected=None,missing=False):
        before=self.snapshot(index);w=self.workers[index];w.close()
        if missing:
            original=Path(w.options['path']);held=original.with_suffix('.loss-fixture-original')
            require(not held.exists(),'fresh missing-file fixture');original.rename(held)
        receipt=self.probe(index,path,expected)
        self.restore(index)
        require(self.snapshot(index)==before,'exact original state history queue and cursors after import')
        return receipt
    def pages(self,index,first):
        page=first;items=list(page['items'])
        while not page['done']:
            page=self.workers[index].call('history',query={'direction':'forward','page_size':1,'cursor':page['next_cursor']})
            require(page['upper_bound']==first['upper_bound'],'stable pagination upper');items+=page['items']
        return items
    def audit(self,index):
        paths=[p for p in self.root.rglob('*') if p.is_file() and p.stat().st_size<=64*1024*1024 and (p.suffix=='.rimbackup' or '.pending' in p.name or p.name.endswith('.log') or p.name.endswith('.loss-fixture-original'))]
        paths.extend(self.run.glob('*.log'))
        fault=BackupFault(self,index,'audit_only',extra={'ROCKET_IM_TEST_AUDIT_PATHS':json.dumps([str(p) for p in paths])})
        try:result=fault.call({'op':'audit_protection'},timeout=180)
        finally:fault.close()
        require(result['sample_count']>20 and all(row['matches']==0 for row in result['files']),'actual crypto secrets absent from backups journals keychains logs')
        self.report.setdefault('private_state_audits',[]).append(result);self.restore(index)
        return result
    def close(self):
        super().close()
        locks=[{'path':str(k),**persistent_keychain.run({'op':'status','keychain':str(k)})} for k in self.keychains]
        require(all(x['status']==0 and not x['unlocked'] for x in locks),'only this lab known keychains locked')
        pids=getattr(self,'native_pids',[])+[x['pid'] for x in self.report.get('fault_processes',[])]
        for pid in pids:
            try:os.kill(pid,0)
            except ProcessLookupError:pass
            else:raise AssertionError('backup process remains '+str(pid))
        self.report['cleanup']={'keychains':locks,'pids_reaped':sorted(set(pids))}
        self.save()
