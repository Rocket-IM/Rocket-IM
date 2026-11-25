#!/usr/bin/env python3
"""同机联网备份：真实新编译Release、独立消费和隔离系统状态；不提交或分发。"""
from pathlib import Path
import json
import os
import shutil
import socket
import sys
import traceback
import uuid
import persistent_release as release
from node_pack import all_hashes,sha,write_json
from persistent_signing_packages import LabIdentity,sign,manifest,pack,RELATIVE


def build(destination):
    destination=Path(destination).resolve();signer=None;result={'status':'RUNNING'}
    temporary=Path('/private/tmp')/('Rocket IM Backup Signing '+str(uuid.uuid4()))
    try:
        signer=LabIdentity(temporary,'backup-recognized')
        result.update(keychain=str(signer.path),certificate_sha1=signer.fingerprint)
        require(release.main(destination,signer=lambda binary:sign(binary,signer))==0,'new Release verification')
        old=release.OUTPUT/'runs/54571f34-0522-4475-9e76-4ee668e55237/release-04'
        baseline=json.loads((old/'report.json').read_text())
        require(sha(Path(baseline['archive']))==baseline['archive_sha256']=='e17d2c670a01eedc39fc41977da66cfbe06f8b31e9b2b5b132ec4ea7d9de5d66','historical actual dev8 archive')
        require(all_hashes(old/'package')==baseline['package_files'],'historical package preserved')
        target=destination/'old-copy';shutil.copytree(old/'package',target/'package')
        signing=sign(target/'package'/RELATIVE,signer);manifest(target/'package');archive=pack(target/'package',target/'archive')
        write_json(target/'report.json',{'status':'PASS_SCOPED','kind':'verified_resigned_copy_not_rebuild','baseline':str(old),'original_archive_sha256':baseline['archive_sha256'],
            'archive':str(archive),'archive_sha256':sha(archive),'package_files':all_hashes(target/'package'),'signing':signing})
        require(all_hashes(old/'package')==baseline['package_files'] and sha(Path(baseline['archive']))==baseline['archive_sha256'],'original dev8 unchanged')
        result['status']='PASS_SCOPED'
    except Exception as e:result.update(status='FAIL',error=str(e),trace=traceback.format_exc())
    finally:
        if signer is not None:signer.close();result['signing_keychain_locked']=True
        destination.mkdir(parents=True,exist_ok=True)
        write_json(destination/'backup-signing.json',result)
    print(json.dumps({'status':result['status'],'signing_report':str(destination/'backup-signing.json'),'error':result.get('error')}),flush=True)
    return 0 if result['status']=='PASS_SCOPED' else 1


def require(condition,label):
    if not condition:raise AssertionError(label)


def verify(task,release_path,label,suites):
    sys.path.insert(0,str(release.ROOT/'tests/interop/network_alpha'))
    import environment
    from backup_harness import BackupLab
    import backup_cases,backup_faults,backup_negatives,renewal_cases,renewal_lifecycle
    task=Path(task).resolve();release_path=Path(release_path).resolve();run=task/label;run.mkdir()
    # macOS Unix socket路径上限103字节；短随机后缀保持隔离，完整归属写入报告。
    temporary=Path('/private/tmp')/('Rocket IM Network Backup '+uuid.uuid4().hex[:12])
    report={'status':'RUNNING','temporary':str(temporary),'release':str(release_path),'suites':{},'stage0':'NOT_COMPLETE','windows':'NOT_TESTED','production':'NOT_APPROVED'}
    source={str(p.relative_to(release.ROOT)):sha(p) for p in (release.ROOT/'tests/interop/network_alpha').glob('*') if p.is_file()}
    for name in source:
        dest=run/'inputs'/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(release.ROOT/name,dest)
    write_json(run/'source.json',source);env=None;ports=[]
    try:
        env=environment.prepare(temporary)
        operations={'ordinary':backup_cases.run,'unknown':backup_cases.unknown,'faults':backup_faults.run,'negatives':backup_negatives.run,
            'renewal':renewal_cases.run,'lifecycle':renewal_lifecycle.run}
        for suite in suites:
            lab=BackupLab(release_path,temporary/'environment.json',run/suite)
            try:
                lab.build(proxy=True);ports.extend([lab.backend_port,lab.business_port,lab.front_port])
                # 生命周期/续期用例从已启用进度保护的真实库起步。
                if suite in ('renewal','lifecycle'):
                    if suite=='lifecycle':lab.initial();lab.offline()
                    for i in range(2):lab.export(i,'before-'+suite+'-'+str(i))
                    if suite=='lifecycle':
                        for i in range(2):lab.auto(i);lab.online(i)
                operations[suite](lab)
                lab.report['status']='PASS_SCOPED'
            except Exception as e:
                lab.report.update(status='FAIL',error=str(e),trace=traceback.format_exc());raise
            finally:
                lab.close();lab.save();report['suites'][suite]={'status':lab.report['status'],'cases':len(lab.report['cases']),'report':str(lab.run/'network-report.json')}
                write_json(run/'report.json',report)
        require({n:sha(release.ROOT/n) for n in source}==source,'test inputs changed during suite')
        original=json.loads((release_path/'report.json').read_text())
        require(sha(Path(original['archive']))==original['archive_sha256'],'Release archive unchanged')
        require({n:sha(release_path/'source'/n) for n in original['source_before']}==original['source_before'],'frozen Release source unchanged')
        report['status']='PASS_SCOPED'
    except Exception as e:report.update(status='FAIL',error=str(e),trace=traceback.format_exc())
    finally:
        if env is not None or (temporary/'postgres/postmaster.pid').exists():
            environment.stop(temporary);report['postgres_stopped']=True
        for port in sorted(set(ports)):
            with socket.socket() as sock:require(sock.connect_ex(('127.0.0.1',port))!=0,'listener remains')
        report['listeners_closed']=sorted(set(ports));write_json(run/'report.json',report)
    print(json.dumps({'status':report['status'],'report':str(run/'report.json'),'error':report.get('error')}),flush=True)
    return 0 if report['status']=='PASS_SCOPED' else 1

if __name__=='__main__':
    if sys.argv[1]=='build':sys.exit(build(sys.argv[2]))
    if sys.argv[1]=='verify':sys.exit(verify(sys.argv[2],sys.argv[3],sys.argv[4],sys.argv[5:]))
    raise SystemExit('build RELEASE_DIRECTORY | verify TASK_DIRECTORY RELEASE_DIRECTORY RUN_LABEL SUITE...')
