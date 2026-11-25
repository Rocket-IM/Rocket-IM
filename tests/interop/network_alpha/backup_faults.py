"""真实进程在持久边界退出；正常包准确重试，不依赖宿主补库。"""
from pathlib import Path
import json
from backup_harness import BackupFault
from harness import require,wait,persistent_keychain

def run(lab):
    lab.case('fault_initial_history',lab.initial);lab.offline()
    for index,phase in enumerate(('backup_after_activation_reserve','backup_after_activation_commit')):
        def activation(index=index,phase=phase):
            before=lab.snapshot(index);path=lab.root/(phase+'.rimbackup')
            fault=BackupFault(lab,index,phase)
            try:fault.interrupt({'op':'create_backup','path':str(path)})
            finally:fault.close()
            lab.restore(index);require(lab.snapshot(index)==before,'interrupted enable preserves identity and original state')
            lab.workers[index].call('backup',path=str(path));lab.backups.append(path);lab.roundtrip(index,path)
        lab.case(phase,activation)
    for phase in ('backup_after_snapshot_commit','backup_after_snapshot_sync','backup_after_publish','backup_after_export_sync'):
        def export(phase=phase):
            before=lab.snapshot(0);path=lab.root/(phase+'.rimbackup')
            fault=BackupFault(lab,0,phase)
            try:fault.interrupt({'op':'create_backup','path':str(path)})
            finally:fault.close()
            lab.restore(0);require(lab.snapshot(0)==before,'export interruption leaves exact state')
            info=lab.workers[0].call('backup',path=str(path));lab.backups.append(path)
            require(lab.roundtrip(0,path)==info,'retry exposes only complete persisted export')
        lab.case(phase,export)
    path,_=lab.export(0,'import-faults')
    for phase in ('backup_after_import_validate','backup_before_import_commit','backup_after_import_commit','backup_after_import_sync','backup_after_install','backup_after_install_sync'):
        def install(phase=phase):
            before=lab.snapshot(0);fault=BackupFault(lab,0,phase,mode='restore')
            try:fault.interrupt({'op':'restore_backup','path':str(path)})
            finally:fault.close()
            lab.probe(0,path);lab.restore(0)
            require(lab.snapshot(0)==before,'atomic import restart has complete original state')
        lab.case(phase,install)
    for phase in ('backup_after_progress_reserve','backup_after_sql_commit','backup_after_progress_confirm'):
        def progress(phase=phase):
            path,_=lab.export(0,'before-'+phase)
            id=phase.replace('_','-');action={'kind':'send','message_id':id,'text':'PRIVATE_PROGRESS_'+phase};lab.texts.append(action['text'])
            fault=BackupFault(lab,0,phase)
            try:fault.interrupt({'op':'execute','request_id':'req-'+id,'action':action})
            finally:fault.close()
            lab.restore(0)
            status=lab.workers[0].call('request',requestId='req-'+id)['status']
            require(status==('missing' if phase=='backup_after_progress_reserve' else 'pending'),'only exact committed reservation visible')
            lab.roundtrip(0,path,expected=None if status=='missing' else 'backup_stale')
            if status=='missing':outcome=lab.workers[0].call('send',requestId='req-'+id,messageId=id,text=action['text'])
            else:outcome=lab.workers[0].call('recoverRequest',requestId='req-'+id,action=action)
            for i in range(2):lab.auto(i);lab.online(i)
            wait(lambda:lab.status(0,id,'delivered'),'progress fault original exact delivery');lab.proof(id,outcome);lab.aligned();lab.offline()
        lab.case(phase,progress)
    def ambiguous():
        backup,_=lab.export(0,'before-ambiguous')
        action={'kind':'send','message_id':'ambiguous','text':'PRIVATE_AMBIGUOUS'};lab.texts.append(action['text'])
        fault=BackupFault(lab,0,'backup_after_sql_commit')
        try:fault.interrupt({'op':'execute','request_id':'req-ambiguous','action':action})
        finally:fault.close()
        current=Path(lab.workers[0].options['path']);held=current.with_suffix('.pending-fixture-original');current.rename(held)
        try:lab.probe(0,backup,'backup_reconciliation_required');require(not current.exists(),'no fabricated import with unresolved external progress')
        finally:held.rename(current)
        lab.restore(0);lab.workers[0].call('recoverRequest',requestId='req-ambiguous',action=action)
    lab.case('missing_current_database_with_unconfirmed_progress_refuses_guessing',ambiguous)
    def late_lock():
        for mode,phase in [('open','backup_after_export_sync'),('restore','backup_after_install_sync')]:
            if mode=='restore':path,_=lab.export(0,'late-import')
            else:path=lab.root/'late-export.rimbackup'
            barrier=lab.root/phase;keychain=lab.workers[0].options['keychain']
            fault=BackupFault(lab,0,'none',mode=mode,extra={'ROCKET_IM_TEST_BARRIER_PHASE':phase,'ROCKET_IM_TEST_BARRIER':str(barrier)})
            operation={'op':'create_backup' if mode=='open' else 'restore_backup','path':str(path)}
            try:
                fault.sequence+=1;fault.process.stdin.write(json.dumps({'id':str(fault.sequence),'operation':operation})+'\n');fault.process.stdin.flush()
                wait(lambda:Path(str(barrier)+'.ready').exists(),'real persisted boundary ready',10)
                require(persistent_keychain.run({'op':'lock','keychain':keychain})['status']==0,'lock this lab current keychain')
                Path(str(barrier)+'.release').write_text('release')
                reply=fault.next();require(reply and not reply['ok'] and reply['error']['code']=='keychain_locked' and not reply['events'],'no success after late lock')
            finally:
                fault.close()
                require(persistent_keychain.run({'op':'unlock','keychain':keychain,'password':lab.keychain_passwords[0]})['status']==0,'unlock only this running lab known item')
            lab.probe(0,path);lab.restore(0);lab.backups.append(path)
    lab.case('late_keychain_lock_suppresses_export_and_import_success',late_lock)
    for i in range(2):lab.auto(i);lab.online(i)
    lab.communicate('after-backup-faults');lab.aligned();lab.case('fault_secret_surfaces',lab.snapshot_secrets);lab.offline()
    for i in range(2):lab.case('fault_private_state_audit_'+str(i),lambda i=i:lab.audit(i))
