"""Service真实SIGKILL、对账完整性与拒绝；客户端仍使用公开API。"""
import json
import secrets
from commit_faults import FaultRuntime
from service_backup_cases import core,unknown
from service_backup_negatives import config_copy,negatives,locker,release_locker,launch_maintenance
from harness import require,wait

def reconcile_core(lab):
    def empty():
        lab.stop_service();lab.start_service()
        state=json.loads(lab.head.read_text());before=lab.database_snapshot()
        lab.crash('empty-run');lab.maintenance('reconcile')
        require(lab.database_snapshot()==before,'empty run exact state')
        require(json.loads(lab.head.read_text())['evidence']==state['evidence'],'no invented business operation')
        lab.start_service()
    lab.case('empty_run_actual_sigkill_reconcile',empty)
    core(lab)
    def backup_regression():
        for i in range(2):lab.auto(i);lab.online(i)
        lab.controlled_restore('schema5-controlled-backup');lab.communicate('after-schema5-restore');lab.aligned()
    lab.case('schema5_normal_backup_new_target_repeat_retired_target_regression',backup_regression)
    lab.case('post_restore_final_service_secret_scan',lab.snapshot_secrets)

def reconcile_unknown(lab):
    unknown(lab)
    for serial,(phase,index) in enumerate([('network_recovery_after_publish',0),('recovery_after_ready',0),('recovery_after_confirm',1),('recovery_after_finish',0)]):
        def stage(phase=phase,index=index,serial=serial):
            lab.offline();request,action=lab.unknown(0,'reconcile-phase-'+str(serial))
            fault=FaultRuntime(lab,index,phase);lab.auto(1-index)
            try:
                if index==0:
                    fault.call({'op':'network_recovery','command':{'kind':'begin','request_id':request,'action':action}})
                    if phase!='network_recovery_after_publish':
                        r=wait(lambda:lab.phase(1,'approval_required'),'peer explicit approval')
                        lab.approve(1,r['round_id'])
                else:
                    lab.begin(0,request,action)
                    r=wait(lambda:(s if (s:=fault.call({'op':'network_recovery','command':{'kind':'status'}})) and s['phase']=='approval_required' else False),'fault peer explicit approval')
                    fault.call({'op':'network_recovery','command':{'kind':'approve','round_id':r['round_id']}})
                fault.exited()
            finally:fault.close()
            lab.restore(index);lab.offline();prior=lab.save_round_proof()
            lab.cycle('successor-phase-'+str(serial),reconnect=False)
            require(lab.save_round_proof()==prior,'all in-flight successor materials exact after SIGKILL')
            for i in range(2):lab.auto(i)
            if phase=='network_recovery_after_publish':
                r=wait(lambda:lab.phase(1,'approval_required'),'same round still requires approval')
                lab.approve(1,r['round_id'])
            lab.complete();lab.communicate('after-successor-phase-'+str(serial));lab.aligned()
            lab.report.setdefault('successor_crash_stages',[]).append({'client_exit':phase,'service_status_before_sigkill':prior['status'],'material_kinds':sorted(prior['materials']),'status':'PASS'})
        lab.case('actual_service_crash_after_client_'+phase,stage)
    lab.case('successor_all_stages_secret_scan',lab.snapshot_secrets);lab.offline()

def reconcile_negatives(lab):
    lab.case('negative_original_history',lab.initial)
    lab.aligned();lab.offline();older=lab.database_snapshot()
    for i in range(2):lab.auto(i);lab.online(i)
    lab.communicate('newer-independent-progress');lab.aligned()
    lab.offline();lab.crash('negative-evidence');before=lab.database_snapshot()
    original=lab.head.read_bytes()
    def record_cases():
        variants=[('truncated',original[:len(original)//2],'maintenance_file_invalid'),('appended',original+b'{}','maintenance_file_invalid'),('empty',b'','maintenance_file_invalid')]
        for label,raw,code in variants:
            try:
                lab.head.write_bytes(raw);lab.maintenance('reconcile',expected=code)
                require(lab.database_snapshot()==before,'invalid evidence does not alter DB')
            finally:lab.head.write_bytes(original)
        try:
            lab.head.unlink();lab.maintenance('reconcile',expected='maintenance_file_unavailable')
            lab.maintenance('enroll',expected='service_maintenance_required')
        finally:lab.head.write_bytes(original);lab.head.chmod(0o600)
        for label in ('run_id','operation_id','digest','unfinished'):
            st=json.loads(original)
            if label=='digest':st['digest']=secrets.token_hex(32)
            elif label=='unfinished':st['evidence']['pending']={'run_id':st['evidence']['run_id'],'operation_id':secrets.token_hex(32),'digest':secrets.token_hex(32)}
            else:st['evidence'][label]=secrets.token_hex(32)
            try:
                lab.head.write_text(json.dumps(st))
                lab.maintenance('reconcile',expected='service_reconciliation_incomplete' if label=='unfinished' else 'service_reconciliation_mismatch')
            finally:lab.head.write_bytes(original)
        copied=lab.head.with_name('copied.json');copied.write_bytes(original);copied.chmod(0o600)
        c=config_copy(lab,'copied-reconcile',lambda c:c.update(recovery_state=str(copied)))
        lab.maintenance('reconcile',config=c,expected='maintenance_configuration_mismatch')
    lab.case('missing_truncated_corrupt_copied_leading_and_unfinished_external_records',record_cases)
    def target_cases():
        lab.maintenance('reconcile',config=lab.new_target('wrong-reconcile-target'),expected='maintenance_target_mismatch')
        for field in ('service','conversation'):
            c=config_copy(lab,'wrong-reconcile-'+field,lambda c,field=field:c.update({field:'foreign'}))
            lab.maintenance('reconcile',config=c,expected='maintenance_configuration_mismatch')
        c=config_copy(lab,'removed-reconcile-guard',lambda c:c.pop('recovery_state'))
        lab.maintenance('serve',config=c,expected='service_maintenance_required')
        require(lab.database_snapshot()==before,'all binding refusals retain facts')
    lab.case('wrong_service_conversation_target_and_removed_guard',target_cases)
    def database_fork():
        # 仅隔离负例夹具临时改一个公开事实，再原样还原；不是恢复API或生产修复流程。
        for table,column,where in [('alpha_messages','delivered',"message_id='original-0'"),('device_credentials','revoked','true')]:
            saved=lab.sql(f"BEGIN READ ONLY; SELECT to_jsonb(t) FROM {lab.schema}.{table} t WHERE {where}; COMMIT;")
            try:
                lab.sql(f'UPDATE {lab.schema}.{table} SET {column}=NOT {column} WHERE {where}')
                lab.maintenance('reconcile',expected='service_reconciliation_mismatch')
            finally:lab.sql(f'UPDATE {lab.schema}.{table} SET {column}=NOT {column} WHERE {where}')
            require(lab.sql(f"BEGIN READ ONLY; SELECT to_jsonb(t) FROM {lab.schema}.{table} t WHERE {where}; COMMIT;")==saved,'controlled fixture reverted exactly')
        require(lab.database_snapshot()==before,'all original facts retained after refused forks')
    lab.case('accepted_processed_and_revocation_forks_refused',database_fork)
    def rollback():
        require(any(int(lab.snapshot(i)['network']['processed'])>int(older['alpha_devices'][i]['tail']) for i in range(2)),'SDK progress ahead of old DB fixture')
        try:
            lab.install_database_fixture(older)
            lab.maintenance('reconcile',expected='service_reconciliation_mismatch')
            lab.maintenance('serve',expected='service_reconciliation_required')
            require(lab.head.read_bytes()==original,'DB rollback cannot rewrite independent evidence')
        finally:lab.install_database_fixture(before)
        require(lab.database_snapshot()==before,'fixture original preserved for further tests')
    lab.case('actual_old_database_with_leading_sdk_and_external_evidence_refused',rollback)
    lab.maintenance('reconcile');lab.start_service()
    # 复用完整备份/身份/秘密/目标负例，使用schema5产物重新执行。
    for i in range(2):lab.auto(i);lab.online(i)
    # 原始历史已建立，避免重复发送固定ID触发正文冲突。
    initial=lab.initial;lab.initial=lambda:None
    try:negatives(lab)
    finally:lab.initial=initial

def reconcile_interruptions(lab):
    lab.case('interruptions_original_history',lab.initial);lab.offline()
    def held_transaction():
        before=lab.database_snapshot()
        lock=locker(lab,lab.database,f'BEGIN; SELECT accepted FROM {lab.schema}.alpha_conversation FOR UPDATE')
        try:
            _,sent=lab.send(0,'killed-before-reservation');lab.auto(0)
            wait(lambda:int(lab.sql("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'").strip())>0,'actual write waits before candidate',8)
            lab.crash('database-before-candidate')
        finally:release_locker(lab,lock)
        lab.offline();require(lab.database_snapshot()==before,'uncommitted write leaves no acceptance')
        lab.maintenance('reconcile');lab.start_service()
        for i in range(2):lab.auto(i);lab.online(i)
        wait(lambda:lab.status(0,'killed-before-reservation','delivered'),'original ciphertext after killed transaction')
        lab.proof('killed-before-reservation',sent);lab.aligned();lab.offline()
    lab.case('actual_service_kill_before_external_candidate_no_phantom_acceptance',held_transaction)
    def reconcile_kill():
        lab.crash('before-reconcile-lock');before=lab.database_snapshot();head=lab.head.read_bytes()
        lock=locker(lab,lab.database,f'BEGIN; LOCK TABLE {lab.schema}.alpha_messages IN ACCESS EXCLUSIVE MODE')
        p=launch_maintenance(lab,'reconcile',lab.config,lab.root/'unused','killed-reconcile')
        try:
            wait(lambda:int(lab.sql("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'").strip())>0,'reconcile checks blocked',8)
            lab.maintenance('reconcile',expected='service_maintenance_busy')
            lab.maintenance('serve',expected='service_maintenance_busy')
            p.kill();require(p.wait(timeout=5)==-9,'actual reconciliation process SIGKILL')
        finally:
            if p.poll() is None:p.kill();p.wait(timeout=5)
            release_locker(lab,lock)
        require(lab.head.read_bytes()==head and lab.database_snapshot()==before,'interrupted check retains evidence and all facts')
        receipt=lab.maintenance('reconcile');require(lab.maintenance('reconcile')==receipt,'repeat resumes complete reconciliation')
        lab.start_service()
        for i in range(2):lab.auto(i);lab.online(i)
        lab.communicate('after-reconcile-kill');lab.aligned()
    lab.case('actual_reconcile_interruption_exclusive_concurrent_reopen_and_retry',reconcile_kill)
    lab.case('interruption_service_secrets',lab.snapshot_secrets);lab.offline()
    for i in range(2):lab.case('interruption_client_secrets_'+str(i),lambda i=i:lab.audit(i))
