#!/usr/bin/env python3
"""Q2-01—Q2-12 最小联合验收；所有重跑/失败、源码和合成状态独立保存。"""
import argparse
import hashlib
from datetime import datetime, timezone
from functools import partial
import json
from pathlib import Path
import shutil
import sys
import traceback
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests/interop'))
from network_poc.fixture import NetworkLab, check
from network_poc.anchor_fixture import AnchorLab
from network_poc.rebuild_fixture import RebuildLab
from network_poc.join_recovery_fixture import RecoveryLab
from network_poc.identity_source_fixture import IdentitySourceLab
from network_poc import (exchange_cases as e, exchange_boundaries as eb,
    exchange_faults as ef, consistency_cases as c, consistency_boundaries as cb,
    anchor_cases as a, anchor_faults as af, rebuild_cases as b,
    rebuild_faults as bf, recovery_capacity_cases as v,
    recovery_consistency_cases as rc, identity_source_cases as i,
    q02_isolated_cases as q)
from verify_first_trust import sources, provenance, write, digest

# 每一行重建独立装置，复用的是可审查操作，不继承历史运行结果。
CASES = []
def add(group, kind, name, operation):
    CASES.append((group, kind, name, operation))
add('Q2-01','network','offline_match',e.matching_and_retry)
add('Q2-01','identity','real_registration_add_welcome',i.i01)
add('Q2-01','recovery','offline_anchor_bidirectional',q.offline_anchor_bidirectional)
for name, operation in [('signed_context',e.tampering_and_context),('trust',eb.trust_required),
                        ('revoked_source',eb.known_revoked_source),('possession',e.source_possession)]:
    add('Q2-02','network',name,operation)
add('Q2-02','identity','roots_and_subject',i.i02)
for name, operation in [('insufficient',eb.insufficient_comparison),('predecessor',eb.missing_predecessor),
                        ('cancel_unreachable',eb.cancellation_and_unreachable)]:
    add('Q2-03','network',name,operation)
add('Q2-03','anchor','unavailable',a.unavailable)
add('Q2-04','identity','fresh_challenge_stale_views',i.i07)
add('Q2-04','network','isolated_actual_branches',q.isolated_fork_window)
for name, operation in [('holder_fork',e.actual_holder_fork),('checkpoint_conflict',c.head_equivocation),
                        ('atomic_import',ef.atomic_import_fork)]:
    add('Q2-05','network',name,operation)
for name, operation in [('rollback_resume',c.rollback_and_resume),('floor_sync',c.head_floor_and_sync),
                        ('conflicting_recovery',cb.conflict_during_recovery)]:
    add('Q2-06','network',name,operation)
add('Q2-06','recovery','closed_floor',rc.closed_floor)
add('Q2-06','recovery','bad_commit',rc.bad_commit_stays_paused)
for name, operation in [('complete_rollback',a.complete_rollback),('clone_race',a.clone_race),
                        ('scope',a.wrong_scope),('key',a.wrong_key),('missing',a.missing_state),
                        ('signed_replay',a.signed_replay)]:
    add('Q2-07','anchor',name,operation)
for point, code in [('before_save',83),('before_rename',84),('after_save',85),
                    ('after_reserve',86),('after_journal',87),('after_finish',88)]:
    add('Q2-08','anchor','client_'+point,partial(af.client_crash,point=point,code=code))
for action in ('reserve','finish'):
    add('Q2-08','anchor','lost_'+action,partial(af.dropped_response,action=action))
    for point in ('before_save','before_rename','after_save'):
        add('Q2-08','anchor',action+'_'+point,partial(af.authority_crash,point=point,action=action))
for mode in ('tamper','rollback','missing'):
    add('Q2-08','anchor','journal_'+mode,partial(af.journal_tamper,mode=mode))
add('Q2-09','anchor','double_rollback',a.common_controller_rollback)
add('Q2-10','network','natural_import_capacity',q.capacity_import)
for mode in ('imports','heads'):
    for anchored in (False,True):
        add('Q2-10','recovery',mode+('_anchor' if anchored else '_snapshot'),
            partial(q.verified_full_capacity,mode=mode,anchored=anchored))
for name, operation in v.CASES.items():
    add('Q2-10','recovery',name,operation)
add('Q2-10','identity','source_capacity',i.i09_capacity)
for name, operation in [('normal',b.normal),('race',b.successor_race),('repeat',b.exact_link_retry),
                        ('history',b.history_boundary),('missing_trust',b.missing_trust),
                        ('source_anchor',bf.source_without_anchor)]:
    add('Q2-11','rebuild',name,operation)
add('Q2-11','rebuild','old_capacity',q.paused_old_rebuild)
add('Q2-11','rebuild','successor_verification_scope',q.successor_verification_scope)
for kind in ('checking','fork','permission','access_removed'):
    add('Q2-11','rebuild','old_'+kind,partial(q.paused_old_rebuild,kind=kind))
    add('Q2-11','rebuild','source_'+kind,partial(b.source_pause,kind=kind))
for kind in ('checking','fork','permission'):
    add('Q2-12','anchor_permission','preserved_'+kind,partial(a.preserved_pause,kind=kind))
add('Q2-12','network','cached_guards',cb.cached_crypto_guards)
add('Q2-12','network','permission_pause',cb.original_permission_pause)
add('Q2-12','identity','compatibility',i.i10)
add('Q2-12','identity','existing_pause',i.i09_existing_pause)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary','permission-verifier','receipt-signer','anchor-helper','probe-binary','old-binary'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--output',type=Path,default=ROOT/'dist/network-relay/q02-isolated')
    parser.add_argument('--case',action='append',help='Q2-01或Q2-01.offline_match，重复可选多个')
    args=parser.parse_args()
    selected=[row for row in CASES if not args.case or row[0] in args.case or row[0]+'.'+row[2] in args.case]
    check(bool(selected),'没有所选用例')
    if args.case:
        check(all(any(key in (r[0],r[0]+'.'+r[2]) for r in CASES) for key in args.case),'存在未知用例')
    artifacts={name:getattr(args,name).resolve() for name in
               ('binary','permission_verifier','receipt_signer','anchor_helper','probe_binary','old_binary')}
    artifacts['capacity_fixture']=artifacts['probe_binary'].with_name('openmls-recovery-capacity-fixture')
    compatibility=ROOT/'dist/reviews/2026-10-15-recovery-capacity/release/normal/bin'
    for executable in ('openmls-state-lab','openmls-permission-verify'):
        artifacts['old_identity_'+executable]=compatibility/executable
    run=args.output.resolve()/'runs'/str(uuid.uuid4());run.mkdir(parents=True,mode=0o700)
    before=sources();before[str(Path(__file__).relative_to(ROOT))]=digest(Path(__file__))
    report={'status':'RUNNING','started_at':datetime.now(timezone.utc).isoformat(),'cases':[],
            'source_sha256_before':before,'artifact_provenance':provenance(artifacts,before),
            'artifacts':{k:str(p) for k,p in artifacts.items()},
            'historical_relay_source':{str(p.relative_to(ROOT)):digest(p) for p in
                (ROOT/'dist/network-relay/q01-identity-source/baseline/source/poc/network-relay').glob('*.py')},
            'full_Q02':'NOT_COMPLETE','full_stage0':'NOT_COMPLETE',
            'limits':['synthetic_local人/渠道/锚故障域','部分装置预置信任检查点；独立身份正例另从空库登记',
                      '原生加密快照与本机SQLite Relay，非四端SDK/Go Service',
                      '受控退出非真实断电；容量合成装置明确标识','不执行原始旧秘密攻击或生产根失陷恢复']}
    for relative in before:
        path=run/'source-snapshot'/relative;path.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/relative,path)
    write(run/'report.json',report);print(run/'report.json',flush=True)
    for group,kind,name,operation in selected:
        work=run/'work'/(group+'.'+name);work.mkdir(parents=True,mode=0o700)
        factory={'network':NetworkLab,'anchor':AnchorLab,'anchor_permission':AnchorLab,
                 'rebuild':RebuildLab,'recovery':RecoveryLab,'identity':IdentitySourceLab}[kind]
        params=[artifacts[n] for n in ('binary',)] + [work]+[artifacts[n] for n in ('permission_verifier','receipt_signer')]
        if kind!='network':params.append(None if kind=='recovery' else artifacts['anchor_helper'])
        lab=factory(*params);lab.probe_binary=artifacts['probe_binary'];lab.old_binary=artifacts['old_binary']
        row={'id':group+'.'+name,'group':group,'status':'RUNNING','fixture':kind};report['cases'].append(row)
        original_rust=lab.rust
        trace=work/'public-operation-trace.jsonl'
        def traced(device, operation, **fields):
            try:
                value=original_rust(device,operation,**fields)
                entry={'device':device,'operation':operation,
                       'expected_exit':fields.get('expected_exit',0),
                       'result_sha256':hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()}
                if operation.startswith('consistency_') or operation=='anchor_inspect':entry['public_result']=value
            except Exception as error:
                entry={'device':device,'operation':operation,'failure':str(error)}
                with trace.open('a') as out:out.write(json.dumps(entry,ensure_ascii=False)+'\n')
                raise
            with trace.open('a') as out:out.write(json.dumps(entry,ensure_ascii=False)+'\n')
            return value
        lab.rust=traced
        write(run/'report.json',report)
        try:
            if kind in ('network','anchor_permission'):
                lab.initialize(permissions=True, **({'device_candidates':True} if name=='cached_guards' else {}))
            else:lab.initialize()
            if kind=='recovery':lab.helper=artifacts['anchor_helper']
            operation(lab);row['status']='PASS_SCOPED'
        except Exception as error:
            row.update(status='FAIL',error=str(error));(run/(group+'.'+name+'-failure.log')).write_text(traceback.format_exc())
        finally:
            lab.close();row['evidence']=getattr(lab,'case_evidence',{}) or getattr(lab,'evidence',{})
            row['fixture_evidence']=getattr(lab,'evidence',{})
            row['process_count']=lab.process_count;row['http_count']=lab.http_count
            row['direct_anchor_process_count']=getattr(lab,'helper_process_count',0)
            write(run/'report.json',report)
        print(row['status']+' '+row['id']+(': '+row['error'] if 'error' in row else ''),flush=True)
    after=sources();after[str(Path(__file__).relative_to(ROOT))]=digest(Path(__file__))
    report['source_drift']=[k for k in set(before)|set(after) if before.get(k)!=after.get(k)]
    report['artifact_drift']=[k for k,p in artifacts.items() if digest(p)!=json.loads((p.parent/'provenance.json').read_text())['binaries'][p.name]]
    report['status']='PASS_SCOPED' if all(r['status']=='PASS_SCOPED' for r in report['cases']) and not report['source_drift'] and not report['artifact_drift'] else 'FAIL'
    report['groups']={group:{'status':'PASS_SCOPED' if len(rows)==sum(1 for r in CASES if r[0]==group)
            and all(r['status']=='PASS_SCOPED' for r in rows) else 'FAIL_OR_PARTIAL',
            'executed':len(rows),'required':sum(1 for r in CASES if r[0]==group)}
            for group in sorted({r[0] for r in CASES})
            for rows in [[r for r in report['cases'] if r['group']==group]]}
    report['finished_at']=datetime.now(timezone.utc).isoformat();write(run/'report.json',report)
    print(report['status']+' '+str(run/'report.json'),flush=True)
    return 0 if report['status']=='PASS_SCOPED' else 1
if __name__=='__main__':raise SystemExit(main())
