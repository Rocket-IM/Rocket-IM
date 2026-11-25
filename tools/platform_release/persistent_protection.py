"""真实系统密钥库、正常安装包与独立故障程序联合验收；不将测试控制打入 npm 包。"""
import json
import os
from pathlib import Path
import secrets
import selectors
import sqlite3
import subprocess
import time
import sys
import fcntl
from persistent_faults import Runtime
from node_pack import write_json

def run(normal, fault, consumer, directory, independent, package=None, negative_script=None):
    directory.mkdir(parents=True)
    data = consumer/'protected-data'; data.mkdir()
    passwords = {}; observations = []; audit_reports = []; locks = {}; diagnostics = []
    def launch(*args,**kwargs):
        path=directory/f'native-stderr-{len(diagnostics):03d}.log';diagnostics.append(path)
        return Runtime(*args,**kwargs,stderr_path=path)
    fixture_script=Path(__file__).with_name('persistent_keychain.py')
    def system(request):
        completed=subprocess.run([sys.executable,str(fixture_script)],input=json.dumps(request),text=True,capture_output=True,timeout=15)
        assert completed.returncode==0, 'keychain fixture failed'
        return json.loads(completed.stdout)
    def ctl(request):
        result = system(request)
        observations.append({'op':request['op'],'keychain':request['keychain'],'database':request.get('database'),**result})
        assert result['status'] == 0, observations[-1]
        return result
    trust_env={'ROCKET_IM_TEST_TRUSTED_APPLICATIONS':json.dumps([str(normal)])}
    def audit_result(value):
        assert value['sample_count'] > 20, value
        assert all(row['matches']==0 for row in value['files']), value
        audit_reports.append(value)
    def fixture(request):
        op=request['op']; path=request['keychain']
        if op=='hold_access':
            lock=Path(request['database']).with_suffix('.db.access').open('rb')
            fcntl.flock(lock,fcntl.LOCK_EX);locks[request['database']]=lock
            return {'status':0}
        if op=='release_access': locks.pop(request['database']).close();return {'status':0}
        if op=='create':
            passwords[path]=secrets.token_hex(32)
            return ctl({**request,'password':passwords[path]})
        if op=='unlock': return ctl({**request,'password':passwords[path]})
        if op in ('lock','status','remove'): return ctl(request)
        if op=='replace_random':
            fields={'key':secrets.token_hex(32)}
            if request.get('wrongScope'): fields['record_scope']={**request['scope'],'account':'wrong'}
            return ctl({**request,**fields,'op':'replace','binaries':[str(normal),str(fault)]})
        if op=='deny': return ctl(request)
        if op=='provision':
            d=launch(fault,request['database'],request['scope']['account'],create=True,keychain=path,extra_env=trust_env)
            d.close();return {'status':0}
        if op=='plaintext':
            with sqlite3.connect(request['database']) as db: db.execute('CREATE TABLE old_plaintext(value TEXT)'); db.execute("INSERT INTO old_plaintext VALUES ('test-only legacy plaintext')")
            return {'status':0}
        if op=='normal_rejects_test_command':
            d=launch(normal,request['database'],request['scope']['account'],keychain=path)
            try: d.call({'op':'audit_protection'},error='invalid_request')
            finally: d.close()
            return {'status':0}
        if op=='orphan':
            env={**os.environ,**trust_env,'ROCKET_IM_TEST_EXIT_PHASE':'after_protection_create'}
            args=[str(fault),request['database'],'test',request['scope']['account'],'one','create',path]
            process=subprocess.run(args,input='',capture_output=True,text=True,env=env,timeout=15)
            assert process.returncode==86 and not process.stdout and not process.stderr
            return {'status':0}
        account=request['scope']['account']; audit=directory/(account+'-transaction-audit.json')
        if op in ('fault','logout_fault'):
            phase=request['phase']; env={'ROCKET_IM_TEST_AUDIT':str(audit)}
            d=launch(fault,request['database'],account,keychain=path,
                fault=None if phase=='refuse_commit' else phase,refuse=phase=='refuse_commit',extra_env=env)
            try:
                if op=='logout_fault': d.call({'op':'logout'},exited=True)
                elif phase=='refuse_commit': d.execute('target',request['action'],error='commit_unknown')
                else: d.execute('target',request['action'],exited=True)
            finally: d.close()
            if audit.exists(): audit_result(json.loads(audit.read_text()))
            return {'status':0}
        if op=='audit':
            d=launch(fault,request['database'],account,keychain=path)
            try: audit_result(d.call({'op':'audit_protection'}))
            finally: d.close()
            return {'status':0}
        if op in ('late_lock','late_capacity'):
            barrier=directory/op; env={'ROCKET_IM_TEST_BARRIER_PHASE':'capacity_after_read' if op=='late_capacity' else 'after_commit','ROCKET_IM_TEST_BARRIER':str(barrier)}
            d=launch(fault,request['database'],account,keychain=path,extra_env=env)
            try:
                request_json={'id':'1','operation':{'op':'execute','request_id':'late-send','action':{'kind':'send','message_id':'late-message','text':'late protected result'}}}
                if op=='late_capacity': request_json={'id':'1','operation':{'op':'capacity'}}
                d.process.stdin.write((json.dumps(request_json)+'\n').encode());d.process.stdin.flush()
                deadline=time.monotonic()+15
                while not Path(str(barrier)+'.ready').exists():
                    assert time.monotonic()<deadline and d.process.poll() is None
                    time.sleep(.01)
                ctl({**request,'op':'lock'})
                Path(str(barrier)+'.release').write_text('release')
                reply=d.read(); assert not reply['ok'] and reply['error']['code']=='keychain_locked' and reply['result'] is None and not reply['events'], reply
                observations.append({'op':'late_lock_result','result':reply})
            finally: d.close()
            return {'status':0}
        raise ValueError(op)
    result=None; cleanup=[]
    process=subprocess.Popen(independent+['protected-cases.mjs',str(data)],cwd=consumer,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
    selector=selectors.DefaultSelector();selector.register(process.stdout,selectors.EVENT_READ)
    try:
        deadline=time.monotonic()+240
        while process.poll() is None:
            assert time.monotonic()<deadline, 'consumer deadline'
            if not selector.select(1): continue
            line=process.stdout.readline()
            if not line: break
            message=json.loads(line)
            if 'fixture' in message:
                try: answer=fixture(message['fixture'])
                except Exception as error: answer={'status':-1,'error':str(error)}
                process.stdin.write(json.dumps(answer)+'\n');process.stdin.flush()
            if 'progress' in message: write_json(directory/'progress.json',message['progress'])
            if 'result' in message: result=message['result'];break
        process.wait(timeout=10)
        stderr=process.stderr.read();(directory/'consumer-stderr.log').write_text(stderr)
        assert result is not None, f'consumer produced no result: {stderr}'
        write_json(directory/'consumer.json',result)
        assert result['status']=='PASS_SCOPED' and process.returncode==0, result
        sanitized=[]
        for account in ['wrongkey','tamper']:
            negative=subprocess.run([normal,data/(account+'.db'),'test',account,'one','open',data/'lab-consumer.keychain-db'],input='',text=True,capture_output=True,timeout=15)
            reply=json.loads(negative.stdout)
            assert reply=={'ready':False,'error':{'code':'protected_store_invalid','paused':True}}, reply
            path=directory/(account+'-stderr.log');path.write_text(negative.stderr);diagnostics.append(path);sanitized.append(reply)
        assert all(path.read_bytes()==b'' for path in diagnostics), 'native diagnostic output is not empty'
        for pid in result['native_processes']:
            try: os.kill(pid,0)
            except ProcessLookupError: pass
            else: raise AssertionError(f'native process remains {pid}')
        example_keychain=str(data/'lab-example.keychain-db');passwords[example_keychain]=secrets.token_hex(32)
        ctl({'op':'create','keychain':example_keychain,'password':passwords[example_keychain]})
        env={**os.environ,'ROCKET_EXAMPLE_KEYCHAIN':example_keychain,'ROCKET_EXAMPLE_DATA':str(data/'example')}
        example=subprocess.run(independent+['example.mjs'],cwd=consumer,env=env,text=True,capture_output=True,timeout=60)
        (directory/'example-stderr.log').write_text(example.stderr)
        assert example.returncode==0, example.stderr
        example_report=json.loads(example.stdout);write_json(directory/'example.json',example_report)
        negatives=None
        if negative_script is not None:
            negative=subprocess.run(independent+[str(negative_script),str(package),str(fault),str(directory/'artifact-negatives'),example_keychain],cwd=consumer,text=True,capture_output=True,timeout=90)
            (directory/'artifact-negative-stderr.log').write_text(negative.stderr)
            assert negative.returncode==0, negative.stderr
            negatives=json.loads(negative.stdout);write_json(directory/'artifact-negatives.json',negatives)
        return {'status':'PASS_SCOPED','consumer':result,'example':example_report,'artifact_negatives':negatives,'audits':audit_reports,'observations':observations,
            'diagnostics':{'empty_stderr_files':[str(p) for p in diagnostics],'sanitized_open_failures':sanitized}}
    finally:
        if process.poll() is None: process.kill();process.wait(timeout=5)
        selector.close();process.stdin.close();process.stdout.close();process.stderr.close()
        for lock in locks.values(): lock.close()
        for path in passwords:
            locked=system({'op':'lock','keychain':path}); state=system({'op':'status','keychain':path})
            cleanup.append({'keychain':path,'lock':locked,'state':state})
        write_json(directory/'observations.json',observations)
        write_json(directory/'audits.json',audit_reports)
        write_json(directory/'keychain-cleanup.json',cleanup)
        assert all(row['lock']['status']==0 and row['state']['status']==0 and not row['state']['unlocked'] for row in cleanup), cleanup
