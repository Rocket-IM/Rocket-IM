#!/usr/bin/env python3
"""可信启动B01—B10；冻结源码/发行来源，保留全部失败与逐进程公开证据。"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sys
import traceback
import uuid
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tests/interop'))
from network_poc.trusted_startup_fixture import StartupLab
from network_poc.trusted_startup_cases import CASES
from verify_first_trust import sources, provenance, write, digest

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('binary','permission-verifier','receipt-signer','anchor-helper','startup-helper','probe-binary'):
        p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--case',action='append',choices=[n for n,_ in CASES])
    p.add_argument('--development',action='store_true')
    p.add_argument('--output',type=Path,default=ROOT/'dist/network-relay/trusted-startup')
    a=p.parse_args();run=a.output.resolve()/'runs'/str(uuid.uuid4());run.mkdir(parents=True,mode=0o700)
    artifacts={n:getattr(a,n).resolve() for n in ('binary','permission_verifier','receipt_signer','anchor_helper','startup_helper','probe_binary')}
    before=sources();before[str(Path(__file__).relative_to(ROOT))]=digest(Path(__file__))
    if not a.development:
        for artifact in artifacts.values():
            record=json.loads((artifact.parent/'provenance.json').read_text())
            for name,value in record.get('additional_inputs',{}).items():
                if before.get(name)!=value:raise RuntimeError('编译期向量来源漂移: '+name)
    report={'status':'RUNNING','started_at':datetime.now(timezone.utc).isoformat(),'source':before,
            'provenance':({k:{'development_only':True,'sha256':digest(v)} for k,v in artifacts.items()} if a.development else provenance(artifacts,before)),'cases':[], 'full_Q01':'NOT_COMPLETE',
            'full_Q02':'NOT_COMPLETE','full_stage0':'NOT_COMPLETE',
            'limits':['same-user synthetic_local signing and authority domains; no production independence',
                      'launcher pins executable/environment/config transport outside device backups',
                      'rotation is approved new identity/storage/anchor scope; no old history or permissions inherited',
                      'explicit probe pause tests composition, not natural pause formation',
                      'controlled process exits, not physical power loss or erasure']}
    for name in before:
        dest=run/'source'/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/name,dest)
    write(run/'report.json',report);print(run/'report.json',flush=True)
    for name,func in CASES:
        if a.case and name not in a.case:continue
        lab=StartupLab(artifacts['binary'],run/'work'/name,artifacts['permission_verifier'],artifacts['receipt_signer'],artifacts['anchor_helper'],startup_helper=artifacts['startup_helper'])
        lab.probe_binary=artifacts['probe_binary'];row={'id':name,'status':'RUNNING'};report['cases'].append(row)
        try:lab.initialize();func(lab);row['status']='PASS_SCOPED'
        except Exception as e:row.update(status='FAIL',error=str(e));(run/(name+'-failure.log')).write_text(traceback.format_exc())
        finally:
            lab.close();row.update(evidence=lab.case_evidence,process_count=lab.process_count,http_count=lab.http_count);write(run/'report.json',report)
        print(name+' '+row['status'],flush=True)
    report['status']='PASS_SCOPED' if all(r['status']=='PASS_SCOPED' for r in report['cases']) and report['cases'] else 'FAIL'
    if a.development and report['status']=='PASS_SCOPED':report['status']='DEV_PASS_SCOPED'
    after=sources();after[str(Path(__file__).relative_to(ROOT))]=digest(Path(__file__))
    report['source_drift']=[k for k in set(before)|set(after) if before.get(k)!=after.get(k)]
    if report['source_drift']:report['status']='FAIL'
    report['finished_at']=datetime.now(timezone.utc).isoformat();write(run/'report.json',report)
    print(json.dumps({'status':report['status'],'report':str(run/'report.json')}))
    return 0 if report['status'].endswith('PASS_SCOPED') else 1
if __name__=='__main__':raise SystemExit(main())
