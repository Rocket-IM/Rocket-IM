#!/usr/bin/env python3
"""旧秘密裸AEAD最小POC：锁定发行原件、冻结Release、独立进程重载与正负对照。"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import uuid
from verify_first_trust import sources, digest, write
from verify_expired_join import environment, locked_library

ROOT=Path(__file__).resolve().parents[1]
BINARY='openmls-expired-join-probe'

def verify(report):
    if report['status']!='PASS_SCOPED' or report['direct_aead'] is not True:raise RuntimeError('缺直接密码执行证据')
    expected={'remove_member','revoke_device','replace_same_identity'}
    if {s['name'] for s in report['scenarios']}!=expected:raise RuntimeError('变化范围不完整')
    for s in report['scenarios']:
        if (s['target_count'],s['old_sender_aead_rejections'],s['old_body_aead_rejections'])!=(12,36,28):raise RuntimeError('未执行完整具名密码调用')
        if len(s['rows'])!=28 or len(s['not_retained'])!=8:raise RuntimeError('缺失旧代次未单列')
        for row in s['rows']:
            allowed={'stage','epoch','sender','generation','view','material','old_on_old','new_on_new','old_on_new','sender_data_oracle','ciphertext_sha256','old_control_ciphertext_sha256','payload_sha256','legal_mls_receivers','gate_used'}
            if set(row)!=allowed:raise RuntimeError('公开报告字段变化，需复核秘密边界')
            if row['old_on_old']!='PASS' or row['new_on_new']!='PASS' or row['old_on_new']!='AeadDecryptionError' or row['gate_used'] or not row['legal_mls_receivers']:raise RuntimeError('正对照/直接拒绝/合法接收不完整')
        if {r['material'] for r in s['rows']}!={'secret_tree','ratchet_head','retained_key_nonce'}:raise RuntimeError('旧材料类型缺失')
        for row in s['not_retained']:
            if row['result']!='NO_RETAINED_GENERATION_NOT_COUNTED':raise RuntimeError('不可用材料误计通过')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,default=ROOT/'dist/network-relay/old-secrets')
    p.add_argument('--binary',type=Path,help='仅复用来源完全匹配的本轮冻结Release')
    args=p.parse_args();run=args.output.resolve()/'runs'/str(uuid.uuid4());run.mkdir(parents=True,mode=0o700)
    source=sources();source[str(Path(__file__).relative_to(ROOT))]=digest(Path(__file__))
    rust={k:v for k,v in source.items() if k.startswith('poc/openmls-probe/') or k=='poc/rust-toolchain.toml'}
    report={'status':'RUNNING','started_at':datetime.now(timezone.utc).isoformat(),'source':source,'phases':[],
            'full_E17':'NOT_COMPLETE','full_T13_T15_T16_T21':'NOT_COMPLETE','full_stage0':'NOT_COMPLETE',
            'historical_restricted_case':'NOT_EXECUTED_ACCESS_RESTRICTED (unchanged historical record)',
            'limits':['synthetic local MLS actors and encrypted provider snapshots only; not four SDKs or Go Service',
                      'direct SenderData and body AEAD from old message tree/ratchet/cached key material; body attacker given correct sender metadata',
                      'full old provider/bundle retained, but no exhaustive HPKE/update-path/Welcome derivation or compromised-signing-key forgery claim',
                      'no physical erasure, arbitrary PCS, all-account/cross-group revocation or independent cryptographic audit']}
    path=run/'report.json';write(path,report);print(path,flush=True)
    for name in source:
        dest=run/'source'/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/name,dest)
    try:
        report['locked_openmls']=locked_library()
        if args.binary:
            binary=args.binary.resolve();provenance=json.loads((binary.parent/'provenance.json').read_text())
            if provenance['source']!=rust or provenance['binaries'][BINARY]!=digest(binary):raise RuntimeError('冻结程序与完整Rust来源不匹配')
        else:
            cargo,env=environment(ROOT/'dist/crypto-probes/target/openmls')
            manifest=run/'source/poc/openmls-probe/Cargo.toml'
            command=[str(cargo),'+1.98.1','build','--manifest-path',str(manifest),'--locked','--offline','--release','--features','expired-join-probe','--bin',BINARY]
            with (run/'build.log').open('w') as f:result=subprocess.run(command,env=env,stdout=f,stderr=subprocess.STDOUT)
            report['build']={'command':command,'exit_code':result.returncode};write(path,report)
            if result.returncode:raise RuntimeError('Release构建失败，见build.log')
            bindir=run/'bin';bindir.mkdir();binary=bindir/BINARY
            shutil.copy2(ROOT/'dist/crypto-probes/target/openmls/release'/BINARY,binary)
            provenance={'profile':'release','features':['expired-join-probe'],'source':rust,'binaries':{BINARY:digest(binary)},'additional_inputs':{'api/realtime/trusted-startup-vectors.json':source['api/realtime/trusted-startup-vectors.json']}}
            write(bindir/'provenance.json',provenance)
        report['binary']=str(binary);report['binary_sha256']=digest(binary);report['provenance']=provenance
        work=run/'work';work.mkdir(mode=0o700);previous=None;pids=[]
        for name,phase in [('init','old-secrets-init'),('reload','old-secrets-attack'),('repeat_reload','old-secrets-attack')]:
            process=subprocess.run([str(binary),phase,str(work)],capture_output=True,text=True,timeout=60)
            (run/(name+'.stdout.json')).write_text(process.stdout);(run/(name+'.stderr.log')).write_text(process.stderr)
            row={'name':name,'phase':phase,'exit_code':process.returncode};report['phases'].append(row);write(path,report)
            if process.returncode:raise RuntimeError(name+' failed: '+process.stderr.strip())
            value=json.loads(process.stdout);verify(value);row['result']=value;pids.append(value['pid'])
            if previous and (previous['scenarios']!=value['scenarios'] or previous['snapshot_sha256']!=value['snapshot_sha256']):raise RuntimeError('重载改变原件或密码结果')
            previous=value;write(path,report);print('PASS_SCOPED '+name,flush=True)
        if len(set(pids))!=3:raise RuntimeError('没有三个独立进程')
        report['status']='PASS_SCOPED';report['summary']={'scenarios':3,'unique_new_ciphertexts':36,'unique_old_sender_aead_rejections':108,'unique_old_body_aead_rejections':84,'unavailable_old_generations_not_counted':24,'new_body_positive_controls':36,'old_body_positive_controls':84,'body_tamper_controls':36,'aad_tamper_controls':36,'sender_data_tamper_controls':36,'independent_processes':3,'reloaded_results_are_repeats_not_additional_unique_attacks':True}
    except Exception as error:
        report.update(status='FAIL',error=str(error));print('FAIL '+str(error),flush=True)
    report['source_drift']=[k for k,v in source.items() if not (ROOT/k).is_file() or digest(ROOT/k)!=v]
    if report['source_drift']:report['status']='FAIL_SOURCE_DRIFT'
    if 'binary' in report:
        report['binary_sha256_after']=digest(Path(report['binary']))
        if report['binary_sha256_after']!=report['binary_sha256']:report['status']='FAIL_BINARY_DRIFT'
    report['finished_at']=datetime.now(timezone.utc).isoformat();write(path,report)
    print(json.dumps({'status':report['status'],'report':str(path)}));return 0 if report['status']=='PASS_SCOPED' else 1
if __name__=='__main__':raise SystemExit(main())
