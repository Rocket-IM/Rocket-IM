"""损坏归档与绑定拒绝；只损坏加密备份测试副本，不开库或导出秘密。"""
from pathlib import Path
import json
import secrets
import shutil
from backup_harness import BackupFault
from harness import require,sha,persistent_keychain,node_binary,npm_command,all_hashes

def run(lab):
    lab.case('negative_initial_history',lab.initial);lab.offline()
    paths=[lab.export(i,'negative-'+str(i))[0] for i in range(2)]
    def malformed():
        for label,data in [('truncated',paths[0].read_bytes()[:5000]),('corrupted',None),('empty',b''),('appended',paths[0].read_bytes()+bytes(4096))]:
            dest=lab.root/(label+'.rimbackup')
            if data is None:
                data=bytearray(paths[0].read_bytes());data[len(data)//2]^=1
            dest.write_bytes(data);lab.roundtrip(0,dest,expected='backup_invalid')
        huge=lab.root/'oversize.rimbackup'
        with huge.open('wb') as f:f.truncate(64*1024*1024+4096)
        lab.roundtrip(0,huge,expected='backup_invalid')
        link=lab.root/'link.rimbackup';link.symlink_to(paths[0]);lab.roundtrip(0,link,expected='backup_path_invalid')
        lab.roundtrip(0,lab.root/'missing.rimbackup',expected='backup_missing')
        lab.roundtrip(0,Path('relative.rimbackup'),expected='backup_path_invalid')
    lab.case('truncated_corrupt_empty_oversized_symlink_relative_missing_backup_rejection',malformed)
    def version():
        path=lab.root/'wrong-version.rimbackup'
        fault=BackupFault(lab,0,'none',extra={'ROCKET_IM_TEST_BACKUP_VERSION':'3'})
        try:fault.call({'op':'create_backup','path':str(path)})
        finally:fault.close()
        lab.restore(0);lab.roundtrip(0,path,expected='backup_format_unsupported')
    lab.case('authenticated_encrypted_wrong_version_rejected',version)
    def binding():
        w=lab.workers[0];before=lab.snapshot(0);w.close();digest=sha(Path(w.options['path']))
        for field in ('service','account','device'):
            options={**w.options,'scope':{**w.options['scope'],field:'other-'+field}}
            lab.probe(0,paths[0],'keychain_item_missing',options=options)
        lab.probe(0,paths[0],'keychain_item_missing',options={**w.options,'path':str(lab.root/'another.db')})
        lab.probe(0,paths[1],'backup_invalid')
        require(sha(Path(w.options['path']))==digest,'all wrong binding failures do not modify current DB')
        lab.restore(0);require(lab.snapshot(0)==before,'all wrong spaces preserve original identity')
    lab.case('wrong_service_account_device_path_and_other_device_backup_rejected',binding)
    def keychain():
        w=lab.workers[0];keychain=w.options['keychain'];before=lab.snapshot(0)
        require(persistent_keychain.run({'op':'lock','keychain':keychain})['status']==0,'lock only current known keychain')
        try:
            w.call('backup',expected='keychain_locked',path=str(lab.root/'locked.rimbackup'));w.close()
            lab.probe(0,paths[0],'keychain_locked')
        finally:require(persistent_keychain.run({'op':'unlock','keychain':keychain,'password':lab.keychain_passwords[0]})['status']==0,'unlock current known test keychain')
        lab.restore(0);require(lab.snapshot(0)==before,'locked operations preserve state')
        w=lab.workers[0];w.close()
        lab.probe(0,paths[0],'keychain_missing',options={**w.options,'keychain':str(lab.root/'does-not-exist.keychain-db')})
        empty=lab.root/'lab-empty.keychain-db';password=secrets.token_hex(32)
        require(persistent_keychain.run({'op':'create','keychain':str(empty),'password':password})['status']==0,'fresh empty keychain');lab.keychains.append(empty)
        lab.probe(0,paths[0],'keychain_item_missing',options={**w.options,'keychain':str(empty)})
        lab.restore(0)
    lab.case('locked_missing_keychain_and_missing_key_refuse_restore',keychain)
    def old_binary():
        old=lab.release/'old-copy';report=json.loads((old/'report.json').read_text())
        directory=lab.root/'old-package-consumer';directory.mkdir()
        (directory/'package.json').write_text('{"private":true,"type":"module"}')
        shutil.copy2(lab.workers[0].directory/'backup-probe.mjs',directory/'backup-probe.mjs')
        lab.command(npm_command()+['install','--offline','--ignore-scripts','--no-audit','--no-fund',report['archive']],directory,'old-consumer-install')
        require(all_hashes(directory/'node_modules/@rocket-im/desktop-dev')==report['package_files'],'actual re-signed historical dev8 package')
        w=lab.workers[0];w.close();before=sha(Path(w.options['path']))
        lab.probe(0,paths[0],'store_format_unsupported',mode='open',directory=directory)
        require(sha(Path(w.options['path']))==before,'old package refuses v4 without modifying DB');lab.restore(0)
    lab.case('recognized_historical_dev8_refuses_activated_v4',old_binary)
    def existing():
        _,_=lab.send(0,'existing-backup-path')
        before=sha(paths[0]);lab.workers[0].call('backup',expected='backup_exists',path=str(paths[0]));require(sha(paths[0])==before,'existing older backup not overwritten')
    lab.case('export_does_not_overwrite_different_snapshot',existing)
    for i in range(2):lab.auto(i);lab.online(i)
    lab.communicate('after-backup-negatives');lab.aligned();lab.case('negative_secret_surfaces',lab.snapshot_secrets);lab.offline()
    for i in range(2):lab.case('negative_private_state_audit_'+str(i),lambda i=i:lab.audit(i))
    def logout():
        fresh,_=lab.export(0,'before-logout');other=lab.snapshot(1)
        lab.workers[0].call('logoutKeep');lab.probe(0,fresh,'logged_out')
        require(lab.snapshot(1)==other,'local logout does not affect other account')
    lab.case('logout_tombstone_rejects_backup_without_recreating_identity',logout)
