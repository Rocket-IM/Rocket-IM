"""真实维护CLI的错误、事务中断和不可安全重开边界。"""
from pathlib import Path
from urllib.parse import urlparse
import json
import os
import socket
import subprocess
import time
from harness import PG,require,wait

def config_copy(lab,label,change):
    c=json.loads(lab.config.read_text());change(c)
    p=lab.root/(label+'.json');p.write_text(json.dumps(c));p.chmod(0o600);return p

def negatives(lab):
    lab.case('negative_initial_history',lab.initial);lab.quiesce();backup=lab.export_service('negative-base');before=lab.database_snapshot()
    def corruption():
        original=backup.read_bytes();parsed=json.loads(original)
        for label,data,code in [('truncated',original[:len(original)//2],'maintenance_file_invalid'),('empty',b'','maintenance_file_invalid'),('appended',original+b'{}','maintenance_file_invalid')]:
            p=backup.with_name(label+'.rimservice');p.write_bytes(data);p.chmod(0o600)
            lab.maintenance('restore',p,config=lab.new_target(label),expected=code)
        variants=[('version',lambda b:b.update(version='unknown'),'service_backup_version_unsupported'),
            ('service-version',lambda b:b.update(service_version='0.0.0'),'service_backup_version_unsupported'),
            ('checkpoint',lambda b:b.update(checkpoint='0'*64),'service_backup_stale'),
            ('identity',lambda b:b['snapshot']['tables'][5]['rows'][0].update(account='another'),'service_backup_invalid'),
            ('schema',lambda b:b['snapshot']['tables'][0]['rows'][0].update(version=99),'service_backup_invalid'),
            ('ciphertext',lambda b:b['snapshot']['tables'][8]['rows'][0]['envelope'].update(ciphertext='00'),'service_backup_invalid'),
            ('missing-table',lambda b:b['snapshot']['tables'].pop(),'service_backup_invalid')]
        for label,change,code in variants:
            b=json.loads(original);change(b);p=backup.with_name(label+'.rimservice');p.write_text(json.dumps(b));p.chmod(0o600)
            lab.maintenance('restore',p,config=lab.new_target(label),expected=code)
        missing=backup.with_name('missing.rimservice');lab.maintenance('restore',missing,config=lab.new_target('missing'),expected='maintenance_file_unavailable')
        link=backup.with_name('link.rimservice');link.symlink_to(backup)
        lab.maintenance('restore',link,config=lab.new_target('link'),expected='maintenance_file_unavailable')
        lab.maintenance('restore','relative.rimservice',config=lab.new_target('relative'),expected='maintenance_path_invalid')
        public=backup.with_name('public.rimservice');public.write_bytes(original);public.chmod(0o644)
        lab.maintenance('restore',public,config=lab.new_target('public'),expected='maintenance_file_invalid')
        large=backup.with_name('oversize.rimservice')
        with large.open('wb') as f:f.truncate(64*1024*1024+1)
        large.chmod(0o600);lab.maintenance('restore',large,config=lab.new_target('oversize'),expected='maintenance_file_invalid')
        require(lab.database_snapshot()==before,'all invalid backups preserve original complete facts')
    lab.case('corrupt_truncated_missing_oversize_wrong_version_schema_identity_ciphertext',corruption)
    def configuration():
        for field in ('service','conversation'):
            c=config_copy(lab,'wrong-'+field,lambda c,field=field:c.update({field:'foreign'}))
            lab.maintenance('backup',backup.with_name(field+'.out'),config=c,expected='maintenance_configuration_mismatch')
        devices=[]
        for i in range(2):
            identity=lab.materials[i]['identity'];devices.append({'account':identity['scope']['account'],'device':'wrong-device-'+str(i),'identity_key':identity['identity_key'],'token_sha256':str(i+1)*64})
        c=config_copy(lab,'wrong-device-binding',lambda c:c.update(devices=devices));lab.maintenance('serve',config=c,expected='maintenance_configuration_mismatch')
        c=config_copy(lab,'missing-tls-secret',lambda c:c.update(tls_key=str(lab.root/'absent.key')));lab.maintenance('serve',config=c,expected='maintenance_secrets_unavailable')
        c=config_copy(lab,'missing-issuer-secret',lambda c:c['business'].update(credential_key_env='UNSET_SERVICE_TEST_ISSUER'));lab.maintenance('serve',config=c,expected='invalid_business_config')
        c=config_copy(lab,'wrong-principal',lambda c:c['business']['principals'][0].update(id='untrusted'));lab.maintenance('serve',config=c,expected='maintenance_configuration_mismatch')
        c=config_copy(lab,'removed-guard',lambda c:c.pop('recovery_state'));lab.maintenance('serve',config=c,expected='service_maintenance_required')
        missing=lab.head.with_name('absent.json');c=config_copy(lab,'missing-head',lambda c:c.update(recovery_state=str(missing)))
        lab.maintenance('serve',config=c,expected='maintenance_file_unavailable');lab.maintenance('enroll',config=c,expected='service_maintenance_required')
        require(not missing.exists(),'cannot reconstruct trusted state from backed-up database')
        copied=lab.head.with_name('copied.json');copied.write_bytes(lab.head.read_bytes());copied.chmod(0o600)
        c=config_copy(lab,'copied-head',lambda c:c.update(recovery_state=str(copied)));lab.maintenance('serve',config=c,expected='maintenance_configuration_mismatch')
        require(lab.database_snapshot()==before,'config failures leave accepted facts unchanged')
    lab.case('wrong_service_config_device_missing_secret_and_guard_bypass_rejections',configuration)
    def targets():
        lab.maintenance('restore',backup,expected='maintenance_target_not_new')
        target=lab.new_target('populated');db=urlparse(json.loads(target.read_text())['database_url']).path.lstrip('/')
        lab.sql('CREATE TABLE unrelated(value text); INSERT INTO unrelated VALUES(\'retained\')',database=db)
        lab.maintenance('restore',backup,config=target,expected='maintenance_target_not_empty')
        require(lab.sql('SELECT value FROM unrelated',database=db).strip()=='retained','existing target never overwritten')
        lab.maintenance('backup',backup,expected='maintenance_install_failed')
        lab.maintenance('enroll',expected='maintenance_state_exists')
        lab.import_service(backup)
        lab.sql(f'BEGIN; ALTER TABLE {lab.schema}.schema_version DROP CONSTRAINT schema_version_version_check; UPDATE {lab.schema}.schema_version SET version=99; COMMIT;')
        lab.maintenance('serve',expected='schema_version_unsupported')
        # 仍保有可信最新封存原件，可在另一全新目标修复；不原地修改失败库。
        lab.import_service(backup);lab.sql(f'CREATE TABLE {lab.schema}.unexpected(value text)')
        lab.maintenance('serve',expected='maintenance_schema_mismatch');lab.import_service(backup)
        require(lab.database_snapshot()==before,'fresh correct target restores exact trusted facts')
        lab.start_service()
        for i in range(2):lab.auto(i);lab.online(i)
        lab.communicate('negative-survivor');lab.aligned()
    lab.case('populated_target_wrong_live_schema_version_and_preserved_original_recovery',targets)
    lab.case('negative_secret_scan',lab.snapshot_secrets);lab.offline()
    for i in range(2):lab.case('negative_private_state_scan_'+str(i),lambda i=i:lab.audit(i))

def locker(lab,database,statement):
    log=(lab.run/('sql-lock-'+str(time.time_ns())+'.log')).open('wb')
    p=subprocess.Popen([PG/'psql','-h',Path(lab.env['directory'])/'socket','-U','alpha','-d',database,'-Aqt','-v','ON_ERROR_STOP=1','-c',statement+'; SELECT pg_sleep(55)'],stdout=log,stderr=subprocess.STDOUT)
    log.close()
    wait(lambda:int(lab.sql("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event='PgSleep'",database=database).strip())>0,'database barrier held',8)
    p.database=database
    p.backend_pid=int(lab.sql("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND wait_event='PgSleep'",database=database).strip())
    return p

def release_locker(lab,p):
    # psql退出不保证服务器立刻检测连接丢失；精确取消本次已记录的测试后台PID。
    lab.sql('SELECT pg_cancel_backend('+str(p.backend_pid)+')',database=p.database)
    p.wait(timeout=5)

def launch_maintenance(lab,operation,config,backup,label):
    log=lab.run/(label+'.log');f=log.open('wb')
    p=subprocess.Popen([lab.root/'im-service','-config',config,'-operation',operation,'-backup',backup],cwd=lab.root,env={**os.environ,'ROCKET_IM_TEST_ISSUER_KEY':lab.signing_key,'PATH':'/usr/bin:/bin'},stdout=f,stderr=subprocess.STDOUT)
    f.close();return p

def interruptions(lab):
    lab.case('interruption_initial_history',lab.initial)
    def drain():
        lab.aligned();lab.workers[1].call('disconnect')
        lock=locker(lab,lab.database,f'BEGIN; SELECT accepted FROM {lab.schema}.alpha_conversation FOR UPDATE')
        try:
            _,sent=lab.send(0,'shutdown-in-flight')
            wait(lambda:int(lab.sql("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'").strip())>0,'real request waits for business lock',8)
            lab.service.terminate();time.sleep(.1)
            require(json.loads(lab.head.read_text())['phase']=='running','not sealed before in-flight request drains')
        finally:release_locker(lab,lock)
        require(lab.service.wait(timeout=10)==0,'graceful shutdown waits for admitted request')
        require(json.loads(lab.head.read_text())['phase']=='sealed','seal only after drain')
        lab.start_service()
        for i in range(2):lab.reauto(i)
        wait(lambda:lab.status(0,'shutdown-in-flight','delivered'),'in-flight outcome reconciled');lab.proof('shutdown-in-flight',sent)
    lab.case('graceful_stop_drains_in_flight_websocket_database_work',drain)
    lab.quiesce();before=lab.database_snapshot()
    def export_interruption():
        lock=locker(lab,lab.database,f'BEGIN; LOCK TABLE {lab.schema}.alpha_messages IN ACCESS EXCLUSIVE MODE')
        path=lab.root/'interrupted.rimservice';p=launch_maintenance(lab,'backup',lab.config,path,'killed-export')
        try:
            wait(lambda:int(lab.sql("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'").strip())>0,'export snapshot blocked before complete',8)
            p.kill();require(p.wait(timeout=5)<0,'actual export process killed')
        finally:
            if p.poll() is None:p.kill();p.wait(timeout=5)
            release_locker(lab,lock)
        require(not path.exists() and json.loads(lab.head.read_text())['phase']=='sealed','no partial completed backup or changed head')
        require(lab.database_snapshot()==before,'export interruption read only')
    lab.case('actual_export_process_interruption',export_interruption)
    backup=lab.export_service('before-import-interruption')
    def import_interruption():
        target=lab.new_target('interrupted');db=urlparse(json.loads(target.read_text())['database_url']).path.lstrip('/')
        lock=locker(lab,db,'SELECT pg_advisory_lock(1380536369)');p=launch_maintenance(lab,'restore',target,backup,'killed-import')
        try:
            wait(lambda:json.loads(lab.head.read_text())['phase']=='restoring','external target reservation before import',8)
            wait(lambda:int(lab.sql("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'",database=db).strip())>0,'real import transaction blocked',8)
            p.kill();require(p.wait(timeout=5)<0,'actual import process killed')
        finally:
            if p.poll() is None:p.kill();p.wait(timeout=5)
            release_locker(lab,lock)
        require(lab.sql("SELECT to_regclass('schema_version') IS NULL",database=db).strip()=='t','all-or-nothing new target remains empty')
        lab.maintenance('serve',expected='service_reconciliation_required')
        lab.maintenance('restore',backup,config=lab.new_target('wrong-resume'),expected='maintenance_target_mismatch')
        lab.import_service(backup,target);require(lab.database_snapshot()==before,'same exact target resumed transaction')
        lab.start_service()
        for i in range(2):lab.auto(i);lab.online(i)
        lab.communicate('after-import-resume');lab.aligned()
    lab.case('actual_import_kill_only_same_target_can_resume',import_interruption)
    def startup_failure():
        lab.quiesce();target=lab.new_target('startup-failure');config=json.loads(target.read_text())
        folder=lab.root/'startup-only-guard';folder.mkdir(mode=0o700);config['recovery_state']=str(folder/'head.json');target.write_text(json.dumps(config))
        lab.maintenance('enroll',config=target)
        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1',lab.backend_port));occupied.listen()
            lab.maintenance('serve',config=target,expected='listen_failed')
        require(json.loads(Path(config['recovery_state']).read_text())['phase']=='running','startup cannot falsely seal')
        lab.maintenance('serve',config=target,expected='service_reconciliation_required')
        lab.start_service()
        for i in range(2):lab.auto(i);lab.online(i)
    lab.case('startup_failure_keeps_reconciliation_gate',startup_failure)
    def unsealed():
        lab.communicate('before-unclean-exit');lab.aligned();latest=lab.database_snapshot()
        lab.service.kill();require(lab.service.wait(timeout=5)<0,'actual running Service SIGKILL');lab.offline()
        lab.maintenance('serve',expected='service_reconciliation_required')
        lab.maintenance('backup',lab.root/'after-crash.rimservice',expected='service_reconciliation_required')
        lab.maintenance('restore',backup,config=lab.new_target('after-crash'),expected='service_reconciliation_required')
        require(lab.database_snapshot()==latest,'known new facts retained while all reopen paths block')
    lab.case('unclean_service_exit_cannot_silently_reopen_or_restore_old_snapshot',unsealed)
    lab.case('interruption_secret_scan',lab.snapshot_secrets)
    for i in range(2):lab.case('interruption_private_scan_'+str(i),lambda i=i:lab.audit(i))
