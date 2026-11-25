"""用冻结的 dev.1 正常/故障产物创建真实旧库，验证显式升级与不可恢复边界。"""
import hashlib
import json
import os
import sqlite3
import subprocess
from pathlib import Path
from persistent_faults import Runtime
from persistent_recovery_faults import setup,crash
ROOT=Path(__file__).resolve().parents[2]
OLD=ROOT/'dist/platform-release/persistent/runs/f21b7d84-43c0-4c56-9741-2d5422395c1f'
OLD_BINARY=OLD/'package/bin/darwin-arm64/rocket-im-desktop-runtime'
OLD_FAULT=OLD/'fault-runtime'

def raw(path):
    c=sqlite3.connect(f'file:{path}?mode=ro',uri=True)
    try:
        c.execute('BEGIN'); row=c.execute('SELECT data,crypto,digest FROM sdk_state').fetchone();c.commit()
        d=json.loads(row[0]);return {'data_sha256':hashlib.sha256(row[0]).hexdigest(),'crypto_sha256':hashlib.sha256(row[1]).hexdigest(),'digest':row[2],'identity':d['state']['identity']}
    finally:c.close()

def prepare(normal,fault,directory):
    directory.mkdir(parents=True)
    assert hashlib.sha256(OLD_BINARY.read_bytes()).hexdigest()=='5f1fb4720cf66c4e63f4f411f434b4904d254c4a619b7502b6f1d2da9b97b67e'
    archive=OLD/'rocket-im-desktop-dev-0.2.0-dev.1.tgz'
    assert hashlib.sha256(archive.read_bytes()).hexdigest()=='452612c250e4f2ff99dbd04033c51ce903a5634b0ec686239dfdbe508aa08622'
    jobs=[]
    for operation in ('create','join','send','receive'):
        for account in ('alice','bob'):
            name=f'legacy-{account}-{operation}'
            job=setup(OLD_BINARY,directory/name,account,operation)
            job.update(name=name,phase='legacy-after-crypto',category='legacy',original_audit=raw(job['target']['path']))
            crash(OLD_FAULT,job,'after_crypto')
            job['fault_audit']=raw(job['target']['path']);job['legacy_peer']=raw(job['peer']['path'])
            for role in ('target','peer'):job[role]['upgrade']=True
            jobs.append(job)
    for stage in ('healthy','before_migration_commit','after_migration_commit'):
        name=f'legacy-{stage}';job=setup(OLD_BINARY,directory/name,'alice','send')
        r=Runtime(OLD_BINARY,job['target']['path'],'alice')
        try:r.execute('target',job['action'])
        finally:r.close()
        job.update(name=name,phase=stage,category='legacy',original_audit=raw(job['target']['path']),fault_audit=raw(job['target']['path']),legacy_peer=raw(job['peer']['path']))
        if stage!='healthy':
            env={k:v for k,v in os.environ.items() if not k.startswith('ROCKET_IM_TEST_')};env['ROCKET_IM_TEST_EXIT_PHASE']=stage
            result=subprocess.run([str(fault),job['target']['path'],'test','alice','one','upgrade'],input=b'',capture_output=True,env=env,timeout=15)
            assert result.returncode==86 and result.stdout==b'',(result.returncode,result.stdout)
        for role in ('target','peer'):job[role]['upgrade']=True
        jobs.append(job)
    negatives=[]
    for name in ('legacy-init','legacy-wrong-scope','legacy-damaged'):
        job=setup(OLD_BINARY,directory/name,'alice','initialize' if name=='legacy-init' else 'create')
        if name=='legacy-init':crash(OLD_FAULT,job,'after_crypto')
        if name=='legacy-damaged':
            c=sqlite3.connect(job['target']['path']);c.execute('BEGIN IMMEDIATE');c.execute("UPDATE sdk_state SET digest=?",('0'*64,));c.commit();c.close()
        negatives.append({'name':name,**job,'sha256':hashlib.sha256(Path(job['target']['path']).read_bytes()).hexdigest()})
    for name in ('corrupt-candidate','corrupt-digest'):
        job=setup(normal,directory/name,'alice','send');crash(fault,job,'after_candidate')
        c=sqlite3.connect(job['target']['path']);c.execute('BEGIN IMMEDIATE')
        data,crypto,meta=c.execute('SELECT data,crypto,recovery FROM sdk_state').fetchone()
        if name=='corrupt-candidate':
            m=json.loads(meta);m['journal']['candidate']['data']['state']['scope']['account']='wrong'
            meta=json.dumps(m,separators=(',',':')).encode();digest=hashlib.sha256(data+crypto+meta).hexdigest()
        else:digest='0'*64
        c.execute('UPDATE sdk_state SET recovery=?,digest=?',(meta,digest));c.commit();c.close()
        negatives.append({'name':name,**job,'sha256':hashlib.sha256(Path(job['target']['path']).read_bytes()).hexdigest()})
    (directory/'jobs.json').write_text(json.dumps(jobs,ensure_ascii=False,indent=2))
    (directory/'negatives.json').write_text(json.dumps(negatives,ensure_ascii=False,indent=2))
    return directory/'jobs.json',directory/'negatives.json'

def verify(jobs_file):
    results=[]
    for job in json.loads(jobs_file.read_text()):
        for role,expected in [('target',job['fault_audit']),('peer',job['legacy_peer'])]:
            path=job[role]['path'];c=sqlite3.connect(f'file:{path}?mode=ro',uri=True)
            c.execute('BEGIN');meta=json.loads(c.execute('SELECT recovery FROM sdk_state').fetchone()[0]);c.commit();c.close()
            legacy=meta['legacy'];assert hashlib.sha256(bytes(legacy['data'])).hexdigest()==expected['data_sha256'];assert hashlib.sha256(bytes(legacy['crypto'])).hexdigest()==expected['crypto_sha256'];assert legacy['digest']==expected['digest']
            before=hashlib.sha256(Path(path).read_bytes()).hexdigest()
            result=subprocess.run([str(OLD_BINARY),path,'test',job[role]['account'],'one','open'],input=b'',capture_output=True,timeout=15)
            reply=json.loads(result.stdout);assert reply['ready'] is False and reply['error']['code']=='store_format_unsupported',reply
            assert hashlib.sha256(Path(path).read_bytes()).hexdigest()==before
        results.append({'name':job['name'],'status':'PASS','legacy_raw_rows_preserved':True,'old_runtime_refuses_v2':True})
    return results
