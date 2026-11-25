"""实际dev.11/alpha.6原库、原备份升级与旧产物拒载；只用本轮同签名专用环境。"""
from pathlib import Path
import json
import os
import subprocess
from capacity_cases import start
from diagnostics_cases import secret_samples
from harness import Worker, require, sha, node_binary, wait
from rejection_upgrade import install, acls
from reserve_cases import enable, capture

OLD_SERVICE=Path(__file__).resolve().parents[3]/'dist/platform-release/persistent/runs/eb56aef4-6ce2-4a69-b429-cedf3b950dda/release-05/im-service'
OLD_SHA='43417b658fae52af79a8154b22f3bfb721b095e3af338da21b6570b9eabea808'


def run(lab,new,full=False):
    old=lab.release
    if full:
        from rejection_cases import prepare_full, terminal, verify_originals
        accepted,rejected=prepare_full(lab)
        lab.auto(1);lab.online(1)
        wait(lambda:all(terminal(lab,id) for id in rejected),'actual dev11 v5 original rejection',45)
        lab.drain(accepted,'old-v5-full');lab.aligned();lab.offline()
        lab.case('actual_dev11_v5_rejected_originals',lambda:verify_originals(lab,rejected))
    else:
        lab.case('actual_dev11_alpha6_originals',lambda:start(lab));lab.fill(6,'reserve-upgrade');lab.aligned();lab.offline()
    backup,_=lab.export(0,'old-dev11-guarded')
    before=[lab.snapshot(i) for i in range(2)];access=acls(lab)
    config=json.loads(lab.config.read_text());require(all('capacity_read' not in p for p in config['business']['principals']),'old omitempty permissions unchanged')
    lab.stop_service();service=lab.database_snapshot();service_backup=lab.export_service('old-alpha6')
    lab.install_new_service();lab.import_service(service_backup);require(service==lab.database_snapshot(),'old entire service backup exactly restored')
    lab.start_service()
    for i in range(2):
        prior=lab.workers[i];prior.close();checksum=sha(Path(prior.options['path']))
        directory=install(lab,new,'reserve-upgrade-'+str(i));lab.workers[i]=Worker(directory,prior.options);lab.setup(i);lab.instrument(lab.workers[i],i);lab.track()
        require(sha(Path(prior.options['path']))==checksum,'new open does not implicitly migrate old database')
        require(lab.snapshot(i)==before[i],'old identities history requests and cursors retained')
    lab.release=new
    lab.case('actual_old_client_backup_read',lambda:lab.roundtrip(0,backup))
    lab.case('old_acl_preserved',lambda:require(acls(lab)==access,'same dedicated keychain ACL'))
    lab.case('explicit_upgrade_'+('v4_v5' if full else 'v3_v4')+'_and_schema5',lambda:enable(lab))
    lab.case('pre_reserve_backup_cannot_remove_policy',lambda:lab.roundtrip(0,backup,expected='backup_stale'))
    lab.consumer().call('capacity',{},code='forbidden')
    def old_gate():
        for i in range(2):
            w=lab.workers[i];w.close();checksum=sha(Path(w.options['path']));directory=install(lab,old,'old-dev11-gate-'+str(i))
            options=directory/'probe.json';options.write_text(json.dumps(w.options));options.chmod(0o600)
            env={k:v for k,v in os.environ.items() if not k.startswith(('CARGO','RUST','ROCKET_IM_TEST_'))};env['PATH']=str(directory/'path')
            p=subprocess.run([node_binary(),'upgrade-probe.mjs',options],cwd=directory,env=env,capture_output=True,text=True,timeout=30)
            require(p.returncode==0 and not p.stderr and json.loads(p.stdout)=={'ok':False,'code':'store_format_unsupported'},'actual dev11 explicitly rejects v6')
            require(sha(Path(w.options['path']))==checksum,'old rejected open does not write');lab.restore(i)
        lab.stop_service();before=lab.database_snapshot();head=sha(lab.head)
        env={**os.environ,'ROCKET_IM_TEST_ISSUER_KEY':lab.signing_key,'PATH':'/usr/bin:/bin'}
        require(sha(OLD_SERVICE)==OLD_SHA,'original alpha6 unchanged')
        p=subprocess.run([OLD_SERVICE,'-config',lab.config],env=env,capture_output=True,text=True,timeout=30)
        (lab.run/'old-alpha6-gate.log').write_text(p.stdout+p.stderr)
        require(p.returncode!=0 and p.stderr.strip().split()[-1]=='schema_version_unsupported','actual alpha6 rejects schema6')
        require(before==lab.database_snapshot() and sha(lab.head)==head,'old Service refusal preserves original and external progress');lab.start_service()
        require(acls(lab)==access,'upgrade/rejection does not change ACL')
    lab.case('actual_old_packages_refuse_reserved_formats',old_gate)
    for i in range(2):
        path,info=lab.export(i,'upgraded-v6-'+str(i));require(info['format']==2,'new format2')
        def old_backup_gate(i=i,path=path):
            w=lab.workers[i];w.close();checksum=sha(Path(w.options['path']))
            lab.probe(i,path,expected='backup_format_unsupported',directory=lab.root/('old-dev11-gate-'+str(i)))
            require(sha(Path(w.options['path']))==checksum,'old backup refusal retains reserved database')
            lab.restore(i)
        lab.case('actual_old_package_refuses_format2_backup_'+str(i),old_backup_gate)
        lab.case('upgraded_v6_backup_restore_'+str(i),lambda i=i,path=path:lab.roundtrip(i,path))
    lab.case('upgraded_schema6_backup_restore',lambda:lab.controlled_restore('upgraded-service',reconnect=False))
    lab.case('upgraded_reserve_observation',lambda:capture(lab,'upgrade-final'))
    lab.case('upgrade_secret_samples',lambda:secret_samples(lab))
    lab.report['reserve_upgrade']={'client':'actual dev.11 '+('v4/v5' if full else 'v3/v4')+' → dev.12 v6','service':'actual alpha.6 schema5 → alpha.7 schema6','old_backup_read':True,'old_artifact_refused':True,'config_digest_unchanged':True,'old_originals_preserved':True}
