"""旧alpha.4真实产物、schema4启用及旧程序拒读，不伪造历史运行证据。"""
import json
import shutil
import subprocess
from pathlib import Path
from harness import ROOT,require,sha

def run(lab):
    old=ROOT/'dist/platform-release/persistent/runs/840dfa06-b78d-40d8-a9ea-9be2da37e33f/release-02/im-service'
    require(sha(old)=='6a8e9b503caae7b7037ea276c6e46ce60b3c5aaeb89bbbfc2df531ef8be0418b','unchanged legacy actual Service')
    new=lab.service_release/'im-service'
    def legacy_history():
        lab.stop_service();shutil.copy2(old,lab.root/'im-service')
        require(subprocess.check_output([lab.root/'im-service','-version'],text=True).strip()=='0.1.0-alpha.4','real legacy executable')
        lab.start_service();lab.initial();lab.aligned();lab.quiesce()
        backup=lab.export_service('real-alpha4')
        require(json.loads(backup.read_text())['service_version']=='0.1.0-alpha.4','legacy archive version')
        lab.legacy_backup=backup
        lab.report['legacy_service']={'path':str(old),'sha256':sha(old),'version':'0.1.0-alpha.4'}
    lab.case('actual_alpha4_schema4_history_and_backup',legacy_history)
    def enable():
        shutil.copy2(new,lab.root/'im-service')
        # 新产物仍能恢复旧正常封存备份；仅此后显式启用schema5。
        before=lab.database_snapshot();lab.import_service(lab.legacy_backup)
        require(lab.database_snapshot()==before,'new binary restores exact alpha4 backup')
        receipt=lab.maintenance('enable-reconciliation')
        require(lab.maintenance('enable-reconciliation')==receipt,'explicit upgrade idempotent')
        after=lab.database_snapshot()
        for table in before:
            if table not in ('schema_version','service_maintenance'):require(after[table]==before[table],'schema4 upgrade preserves '+table)
        lab.maintenance('restore',lab.legacy_backup,config=lab.new_target('old-after-upgrade'),expected='service_backup_version_unsupported')
        shutil.copy2(old,lab.root/'im-service')
        lab.maintenance('serve',expected='maintenance_file_invalid')
        shutil.copy2(new,lab.root/'im-service')
        lab.evidence_enabled=True
        lab.start_service()
        for i in range(2):lab.auto(i);lab.online(i)
        lab.communicate('post-schema4-upgrade');lab.aligned()
        lab.cycle('upgraded-running-crash');lab.communicate('post-upgraded-crash');lab.aligned()
    lab.case('explicit_upgrade_preserves_facts_old_binary_and_backup_refused',enable)
    lab.case('upgraded_service_secret_scan',lab.snapshot_secrets);lab.offline()
    for i in range(2):lab.case('upgraded_client_secret_scan_'+str(i),lambda i=i:lab.audit(i))

def successor(lab):
    import recovery_cases
    original_case=lab.case
    def case(name,operation):
        def checked():
            operation()
            if name in ('real_unknown_execution_and_explicit_peer_authorization','bilateral_install_old_queue_reconciliation_no_cursor_skip'):
                lab.cycle('queue-'+name,reconnect=False)
                for i in range(2):lab.auto(i)
        original_case(name,checked)
    lab.case=case
    try:recovery_cases.run(lab)
    finally:lab.case=original_case
    lab.offline()
    for i in range(2):lab.case('queue_private_state_scan_'+str(i),lambda i=i:lab.audit(i))
