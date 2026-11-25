#!/usr/bin/env python3
"""Service实际产物冻结、dev.9合成签名副本与独立本机消费，不覆盖历史发行输入。"""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import traceback
import uuid
from node_pack import all_hashes, sha, write_json
from persistent_signing_packages import LabIdentity, sign, manifest, pack, RELATIVE
from persistent_release import ROOT, OUTPUT

BASE = OUTPUT/'runs/af92988c-5c7b-4aa9-8365-5123954eb792/release-05'
BASE_SHA = 'b331c53440c0089b11b2b8bb7b7720f91fb9e0d822c6f6dfbdfec2cc27c5ba80'

def build(destination, existing_client=None, verified_client=None):
    destination=Path(destination).resolve(); destination.mkdir()
    report={'status':'RUNNING','kind':'service_release_and_verified_resigned_client_copy','stage0':'NOT_COMPLETE','distribution':'NOT_APPROVED','windows':'NOT_TESTED'}
    signer=None
    try:
        before=all_hashes(BASE/'package'); old=json.loads((BASE/'report.json').read_text())
        assert sha(Path(old['archive']))==old['archive_sha256']==BASE_SHA and before==old['package_files']
        assert all(sha(BASE/'source'/name)==digest for name,digest in old['source_before'].items())
        report['original_client']={'report':str(BASE/'report.json'),'archive_sha256':BASE_SHA,'source_files':old['source_before'],'package_files':before}
        client=destination/'client'
        if existing_client or verified_client:
            assert not (existing_client and verified_client)
            prior=Path(existing_client or verified_client).resolve(); original=json.loads((prior/'report.json').read_text())
            assert original['status']=='PASS_SCOPED'
            assert all_hashes(prior/'package')==original['package_files'] and sha(Path(original['archive']))==original['archive_sha256']
            assert all(sha(prior/'source'/name)==digest for name,digest in original['source_before'].items())
            if verified_client:
                assert original['source_before']==original['source_after']==original['frozen_source_after']
                assert json.loads((prior/'package/package.json').read_text())['version']=='0.2.0-dev.13'
                assert all(sha(ROOT/name)==digest for name,digest in original['source_before'].items())
                assert json.loads((prior/'package/artifact.json').read_text())['sourceSha256']==original['source_before']
                report['new_client_verified']=True
            else:
                assert original['source_before']==old['source_before']
            shutil.copytree(prior,client);archive=client/Path(original['archive']).relative_to(prior)
            assert sha(archive)==original['archive_sha256'] and all_hashes(client/'package')==original['package_files']
            original['archive']=str(archive);write_json(client/'report.json',original)
            subprocess.run(['/usr/bin/codesign','--verify','--strict',client/'package'/RELATIVE],check=True,capture_output=True)
            report['reused_verified_client']={'path':str(prior),'archive_sha256':sha(archive),'binary_sha256':sha(client/'package'/RELATIVE)}
        else:
            temporary=Path('/private/tmp')/('Rocket IM Service Signing '+uuid.uuid4().hex[:12])
            signer=LabIdentity(temporary,'service-backup-client')
            report['signer']={'keychain':str(signer.path),'certificate_sha1':signer.fingerprint}
            client=destination/'client';client.mkdir()
            shutil.copytree(BASE/'package',client/'package');shutil.copytree(BASE/'source',client/'source')
            signing=sign(client/'package'/RELATIVE,signer);manifest(client/'package');archive=pack(client/'package',client/'archive')
            shutil.copy2(BASE/'fault-runtime',client/'fault-runtime');fault=sign(client/'fault-runtime',signer)
            assert b'ROCKET_IM_TEST_' not in (client/'package'/RELATIVE).read_bytes()
            write_json(client/'report.json',{'status':'PASS_SCOPED','kind':'verified_resigned_copy_not_rebuild','archive':str(archive),'archive_sha256':sha(archive),'package_files':all_hashes(client/'package'),'source_before':old['source_before'],'signing':signing,'fault_signing':fault,'fault_binary_sha256':sha(client/'fault-runtime')})
        source=destination/'source';shutil.copytree(ROOT/'src/backend',source/'src/backend',ignore=shutil.ignore_patterns('.DS_Store'))
        for name in ['deploy','api/http','api/realtime','tests/interop/network_alpha','src/server-sdk/go','examples/business-backend','tests/consumers/go-business']:
            shutil.copytree(ROOT/name,source/name,ignore=shutil.ignore_patterns('__pycache__','.DS_Store'))
        for name in ['tools/platform_release/service_backup.py','tools/platform_release/service_capacity.py','docs/服务备份恢复.md']:
            target=source/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/name,target)
        inputs=all_hashes(source)
        env={**os.environ,'GOPATH':str(ROOT/'dist/toolchains/gopath'),'GOCACHE':str(ROOT/'dist/toolchains/go-cache'),'GOTOOLCHAIN':'local'}
        binary=destination/'im-service'
        with (destination/'service-build.log').open('wb') as out:
            subprocess.run([ROOT/'dist/toolchains/go/bin/go','build','-trimpath','-o',binary,'./cmd/im-service'],cwd=source/'src/backend',env=env,stdout=out,stderr=subprocess.STDOUT,check=True,timeout=120)
        assert subprocess.check_output([binary,'-version'],text=True).strip()=='0.1.0-alpha.8'
        assert b'ROCKET_IM_TEST_' not in binary.read_bytes()
        assert inputs==all_hashes(source) and all_hashes(BASE/'package')==before and sha(Path(old['archive']))==BASE_SHA
        report.update(status='PASS_SCOPED',source_files=inputs,service_version='0.1.0-alpha.8',service_sha256=sha(binary),client=str(client),client_archive_sha256=sha(archive),historical_preserved=True)
    except Exception as error:
        report.update(status='FAIL',error=str(error),trace=traceback.format_exc())
    finally:
        if signer:signer.close();report['signing_keychain_locked']=True
        write_json(destination/'report.json',report)
    print(json.dumps({'status':report['status'],'report':str(destination/'report.json'),'error':report.get('error')}),flush=True)
    return 0 if report['status']=='PASS_SCOPED' else 1

def verify(task,release,label,suite):
    task=Path(task).resolve();release=Path(release).resolve();run=task/label
    sys.path.insert(0,str(ROOT/'tests/interop/network_alpha'))
    from environment import prepare,stop
    from service_backup_harness import ServiceBackupLab
    from service_backup_cases import core,unknown
    from service_backup_negatives import negatives,interruptions
    from service_reconciliation_harness import ServiceReconciliationLab
    from service_reconciliation_cases import reconcile_core,reconcile_unknown,reconcile_negatives,reconcile_interruptions
    from service_reconciliation_upgrade import run as reconcile_upgrade,successor as reconcile_successor
    import renewal_cases,renewal_lifecycle
    root=Path('/private/tmp')/('Rocket IM Service Backup '+uuid.uuid4().hex[:12]);lab=None
    try:
        prepare(root)
        lab_type=ServiceReconciliationLab if suite.startswith('reconcile-') else ServiceBackupLab
        lab=lab_type(release,root/'environment.json',run)
        if suite=='reconcile-upgrade':lab.evidence_enabled=False
        if suite in ('renewal','reconcile-renewal'):lab.credential_ttl=2
        lab.build(proxy=True)
        if suite=='core':core(lab)
        elif suite=='unknown':unknown(lab)
        elif suite=='negatives':negatives(lab)
        elif suite=='interruptions':interruptions(lab)
        elif suite=='reconcile-core':reconcile_core(lab)
        elif suite=='reconcile-unknown':reconcile_unknown(lab)
        elif suite=='reconcile-negatives':reconcile_negatives(lab)
        elif suite=='reconcile-interruptions':reconcile_interruptions(lab)
        elif suite=='reconcile-upgrade':reconcile_upgrade(lab)
        elif suite=='reconcile-successor':reconcile_successor(lab)
        elif suite in ('renewal','reconcile-renewal'):
            lab.initial();lab.case('restore_before_renewal',lambda:lab.cycle('renewal-base'))
            lab.offline()
            for i in range(2):lab.setup(i,ttl=2)
            renewal_cases.run(lab,orderly_stop=True)
        elif suite in ('lifecycle','reconcile-lifecycle'):
            lab.initial();lab.case('restore_before_lifecycle',lambda:lab.cycle('lifecycle-base'))
            renewal_lifecycle.run(lab)
        else:raise ValueError('unknown suite')
        lab.report['status']='PASS_SCOPED'
    except Exception as error:
        if lab:lab.report.update(status='FAIL',error=str(error),trace=traceback.format_exc())
        else:run.mkdir(parents=True,exist_ok=True);write_json(run/'failure.json',{'status':'FAIL','error':str(error),'trace':traceback.format_exc()})
    finally:
        if lab:
            try:lab.close()
            except Exception as error:lab.report.update(status='FAIL',cleanup_error=str(error));lab.save()
        try:stop(root)
        except Exception as error:
            if lab:lab.report.update(status='FAIL',postgres_cleanup_error=str(error));lab.save()
        if lab:
            live=(root/'postgres/postmaster.pid').exists()
            lab.report['postgres_stopped']=not live
            if live:lab.report['status']='FAIL'
            lab.save()
    status=lab.report['status'] if lab else 'FAIL'
    print(json.dumps({'status':status,'run':str(run),'environment':str(root),'error':lab.report.get('error') if lab else None}),flush=True)
    return 0 if status=='PASS_SCOPED' else 1

if __name__=='__main__':
    if sys.argv[1]=='build':sys.exit(build(*sys.argv[2:]))
    if sys.argv[1]=='build-new-client':sys.exit(build(sys.argv[2],verified_client=sys.argv[3]))
    if sys.argv[1]=='verify':sys.exit(verify(*sys.argv[2:]))
    raise SystemExit('build <new-release> | verify <task> <release> <label> core|unknown|negatives|interruptions|renewal|lifecycle')
