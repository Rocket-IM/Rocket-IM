#!/usr/bin/env python3
"""Q01 I01—I10独立身份来源验收；每次运行保留源码、结果和全部失败。"""
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import shutil
import sys
import traceback
import uuid
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tests/interop'))
from network_poc.identity_source_fixture import IdentitySourceLab
from network_poc.identity_source_cases import CASES,EXTRA_CASES
CASES=CASES+EXTRA_CASES
from network_poc.fixture import check
from network_poc.first_trust_evidence import digest
from verify_first_trust import sources,provenance,write

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('binary','permission-verifier','receipt-signer'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--anchor-helper',type=Path);p.add_argument('--probe-binary',type=Path);p.add_argument('--case',action='append',choices=[n for n,_ in CASES]);p.add_argument('--development',action='store_true');p.add_argument('--output',type=Path,default=ROOT/'dist/network-relay/q01-identity-source')
    a=p.parse_args();run=a.output.resolve()/'runs'/str(uuid.uuid4());run.mkdir(parents=True,mode=0o700)
    artifacts={n:getattr(a,n).resolve() for n in ('binary','permission_verifier','receipt_signer','anchor_helper','probe_binary') if getattr(a,n)}
    before=sources();before[str(Path(__file__).relative_to(ROOT))]=digest(Path(__file__).read_bytes())
    report={'status':'RUNNING','started_at':datetime.now(timezone.utc).isoformat(),'cases':[],'source':before,'limits':['独立本机实验业务认证与签发器；不是真实身份供应方','控制器提供的逐设备独立核验是外部假设','Service目录签名和对照不证明全局新鲜','原加密快照/SQLite Relay，非正式SDK/Go Service','不完成Q01/Q02或阶段0'],'full_Q01':'NOT_COMPLETE','full_stage0':'NOT_COMPLETE'}
    try:
        report['provenance']=provenance(artifacts,before,a.development)
        for n in before:
            dest=run/'source'/n;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/n,dest)
        for name,func in CASES:
            if a.case and name not in a.case:continue
            if name=='I09_anchor' and not a.anchor_helper:continue
            if name=='I09_existing_pause' and not a.probe_binary:continue
            work=run/'work'/name;work.mkdir(parents=True,mode=0o700)
            lab=IdentitySourceLab(artifacts['binary'],work,artifacts['permission_verifier'],artifacts['receipt_signer'],artifacts.get('anchor_helper'))
            lab.probe_binary=artifacts.get('probe_binary')
            row={'id':name,'status':'RUNNING'};report['cases'].append(row);write(run/'report.json',report)
            try:lab.initialize();func(lab);row['status']='PASS_SCOPED'
            except Exception as e:row.update(status='FAIL',error=str(e));(run/(name+'-failure.log')).write_text(traceback.format_exc())
            finally:
                lab.close();row['evidence']=lab.case_evidence;row['process_count']=lab.process_count;row['http_count']=lab.http_count;write(run/'report.json',report)
            print(row['status']+' '+name,flush=True)
        report['status']=('DEV_PASS_SCOPED' if a.development else 'PASS_SCOPED') if all(x['status']=='PASS_SCOPED' for x in report['cases']) else 'FAIL'
    except Exception as e:report.update(status='FAIL',error=str(e));(run/'failure.log').write_text(traceback.format_exc())
    after=sources();after[str(Path(__file__).relative_to(ROOT))]=digest(Path(__file__).read_bytes());report['source_drift']=[k for k in set(before)|set(after) if before.get(k)!=after.get(k)]
    if report['source_drift']:report['status']='FAIL'
    report['finished_at']=datetime.now(timezone.utc).isoformat();write(run/'report.json',report);print(json.dumps({'status':report['status'],'report':str(run/'report.json')}));return 0 if report['status'].endswith('PASS_SCOPED') else 1
if __name__=='__main__':raise SystemExit(main())
