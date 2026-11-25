"""实际dev.13/alpha.8未决首轮升级；旧完整备份与新链格式拒载。"""
from pathlib import Path
import json
import os
import subprocess
from capacity_cases import start
from diagnostics_cases import secret_samples
from harness import Worker, require, wait, sha, node_binary
from rejection_upgrade import install, acls
from workset_harness import enable, source, originals, service_state, transport
from workset_repeat import enable_repeat, settle, histories

OLD_SERVICE = Path(__file__).resolve().parents[3]/'dist/platform-release/persistent/runs/ad1ef4d1-0715-47c7-aad7-e6632d9b568a/release-05/im-service'
OLD_SHA = '7b9984fe688e0a42303d6f160388ba821338cf74625370a23f7c21a582ae57f8'


def run(lab, new):
    old = lab.release
    lab.case('actual_dev13_alpha8_first_round',lambda:enable(lab))
    start(lab);lab.aligned();lab.offline()
    pending=[]
    for i in range(2):
        source(lab,i,'repeat-upgrade-first-'+str(i));pending.append(lab.workers[i].call('prepareWorkset'))
        transport(lab,i,'prepare','hold_workset_ack','prepared','prepared')
    # 制备第二端原件会自动推进第一端；冻结升级前实际持久观察，最后一端仍未决。
    pending=[w.call('workset') for w in lab.workers]
    require(pending[1]['phase']=='prepared' and service_state(lab,1)['phase']=='prepared','actual unresolved old promise before upgrade')
    lab.report['old_worksets_before_upgrade']=pending
    backup,info=lab.export(1,'actual-dev13-prepared')
    require(info['format']==3,'actual predecessor backup3 includes unresolved first promise')
    before=[lab.snapshot(i) for i in range(2)];access=acls(lab)
    lab.stop_service();service=lab.database_snapshot();head=sha(lab.head)
    service_backup=lab.export_service('actual-alpha8-prepared')
    lab.install_new_service();lab.import_service(service_backup)
    require(lab.database_snapshot()==service,'old complete Service backup preserved by new executable')
    lab.start_service()
    for i in range(2):
        prior=lab.workers[i];prior.close();checksum=sha(Path(prior.options['path']))
        directory=install(lab,new,'repeat-upgrade-'+str(i))
        lab.workers[i]=Worker(directory,prior.options);lab.setup(i);lab.instrument(lab.workers[i],i);lab.track()
        require(sha(Path(prior.options['path']))==checksum,'normal open does not migrate v7')
        require(lab.snapshot(i)==before[i],'old originals crypto and cursors kept')
        require(lab.workers[i].call('workset')==pending[i],'old actual persisted promise kept')
        expected='workset_not_settled' if pending[i]['phase']!='settled' else 'workset_empty'
        lab.workers[i].call('prepareNextWorkset',previous=pending[i]['workset']['id'],expected=expected)
    lab.release=new
    lab.case('actual_backup3_read_without_upgrade',lambda:lab.roundtrip(1,backup))
    require(acls(lab)==access,'same signer original ACL unchanged')
    lab.case('explicit_schema8_preserves_unresolved_predecessors',lambda:enable_repeat(lab))
    for i in range(2):lab.auto(i)
    wait(lambda:all(w.call('workset')['phase']=='settled' for w in lab.workers),'both upgraded original promises settle')
    lab.aligned();lab.offline()
    first=[w.call('workset') for w in lab.workers];second=[]
    require(all(first[i]['workset']==pending[i]['workset'] for i in range(2)),'settlement keeps exact old manifests')
    for i in range(2):
        source(lab,i,'repeat-upgrade-second-'+str(i))
        lab.workers[i].call('prepareNextWorkset',previous=first[i]['workset']['id'])
        second.append(settle(lab,i));histories(lab,i,[first[i]])
    lab.case('old_backup_cannot_erase_repeated_chain',lambda:lab.roundtrip(1,backup,expected='backup_stale'))
    lab.consumer().call('worksets',{},code='forbidden')
    def old_gate():
        for i in range(2):
            w=lab.workers[i];w.close();checksum=sha(Path(w.options['path']))
            directory=install(lab,old,'dev13-repeat-gate-'+str(i))
            path=directory/'probe.json';path.write_text(json.dumps(w.options));path.chmod(0o600)
            env={k:v for k,v in os.environ.items() if not k.startswith(('CARGO','RUST','ROCKET_IM_TEST_'))};env['PATH']=str(directory/'path')
            p=subprocess.run([node_binary(),'upgrade-probe.mjs',path],cwd=directory,env=env,capture_output=True,text=True,timeout=30)
            require(p.returncode==0 and not p.stderr and json.loads(p.stdout)=={'ok':False,'code':'store_format_unsupported'},'actual dev13 rejects v8')
            require(sha(Path(w.options['path']))==checksum,'old refusal preserves v8 bytes');lab.restore(i)
        lab.stop_service();before=lab.database_snapshot();progress=sha(lab.head)
        env={**os.environ,'ROCKET_IM_TEST_ISSUER_KEY':lab.signing_key,'PATH':'/usr/bin:/bin'}
        require(sha(OLD_SERVICE)==OLD_SHA,'actual alpha8 artifact unchanged')
        p=subprocess.run([OLD_SERVICE,'-config',lab.config],env=env,capture_output=True,text=True,timeout=30)
        (lab.run/'old-alpha8-gate.log').write_text(p.stdout+p.stderr)
        require(p.returncode!=0 and p.stderr.strip().split()[-1]=='schema_version_unsupported','actual alpha8 rejects schema8')
        latest=lab.export_service('alpha9-repeat-for-old-gate');target=lab.new_target('alpha8-refuses-alpha9-backup')
        p=subprocess.run([OLD_SERVICE,'-config',target,'-operation','restore','-backup',latest],env=env,capture_output=True,text=True,timeout=30)
        (lab.run/'old-alpha8-backup-gate.log').write_text(p.stdout+p.stderr)
        require(p.returncode!=0 and p.stderr.strip().split()[-1]=='service_backup_version_unsupported','actual alpha8 refuses alpha9 complete backup')
        require(before==lab.database_snapshot() and progress==sha(lab.head),'old Service and backup rejection preserve originals and external evidence')
        lab.start_service()
    lab.case('actual_old_programs_refuse_new_chain_formats',old_gate)
    for i in range(2):
        state=lab.workers[i].call('workset');originals(lab,i,state)
        path,info=lab.export(i,'repeat-v8-'+str(i));require(info['format']==4,'actual v8 backup4')
        def gate(i=i,path=path):
            w=lab.workers[i];w.close();checksum=sha(Path(w.options['path']))
            lab.probe(i,path,expected='backup_format_unsupported',directory=lab.root/('dev13-repeat-gate-'+str(i)))
            require(sha(Path(w.options['path']))==checksum,'old backup4 refusal preserves data');lab.restore(i)
        lab.case('old_format4_refusal_'+str(i),gate)
        lab.case('new_complete_format4_restore_'+str(i),lambda i=i,path=path:lab.roundtrip(i,path))
    lab.case('new_schema8_complete_backup_restore',lambda:lab.controlled_restore('repeat-upgraded',reconnect=False))
    require(acls(lab)==access,'upgrades and restores preserve original ACL')
    for i in range(2):
        require(service_state(lab,i)==lab.workers[i].call('workset')==second[i],'same latest terminal after all restores')
        histories(lab,i,[first[i]])
    lab.case('upgrade_repeat_secret_samples',lambda:secret_samples(lab))
    lab.report['repeat_upgrade']={'client':'actual dev13 v7 -> dev14 explicit v8','service':'actual alpha8 schema7 -> alpha9 explicit schema8','old_pending_preserved':True,'old_backups_read':True,'old_programs_refuse_new':True,'config_permissions_unchanged':True}
