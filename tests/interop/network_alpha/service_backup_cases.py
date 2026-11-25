"""恢复前后逐表、原密文、双游标及公开恢复流程对账。"""
import hashlib
import json
import time
from urllib.parse import urlparse
from backup_harness import BackupFault
from commit_faults import FaultRuntime
from business_cases import body,raw
from harness import require,wait

def core(lab):
    lab.case('initial_bilateral_history',lab.initial)
    def normal():
        lab.aligned();lab.cycle('normal');lab.communicate('restored-normal');lab.aligned()
    lab.case('complete_latest_restore_repeat_original_target_rejection_stable_pagination',normal)
    def queue():
        lab.offline();text,sent=lab.send(0,'offline-service-backup')
        require(lab.fact('offline-service-backup') is None,'offline queue not accepted')
        lab.cycle('offline',reconnect=False)
        require(lab.workers[0].call('send',requestId='req-offline-service-backup',messageId='offline-service-backup',text=text)['value']==sent['value'],'exact durable ciphertext')
        for i in range(2):lab.auto(i);lab.online(i)
        wait(lambda:lab.status(0,'offline-service-backup','delivered'),'queued original delivery');lab.proof('offline-service-backup',sent)
    lab.case('offline_original_queue_after_service_restore',queue)
    def accepted():
        lab.offline();text,sent=lab.send(0,'service-lost-ack')
        fault=FaultRuntime(lab,0,'network_after_accept')
        try:fault.exited()
        finally:fault.close()
        lab.restore(0);original=lab.fact('service-lost-ack')
        require(original is not None and lab.status(0,'service-lost-ack','local_saved'),'real acceptance with no committed local ACK')
        lab.cycle('accepted-unacknowledged');wait(lambda:lab.status(0,'service-lost-ack','delivered'),'original acceptance recovered')
        final=lab.fact('service-lost-ack')
        for key in ('request_id','message_id','accepted','envelope_hash','envelope'):require(final[key]==original[key],'unchanged acceptance '+key)
        req={'request_id':'req-service-lost-ack','envelope':sent['value']['envelope']}
        # UI delivered早于发送端把该回执的processed报告完成；先排空并断开客户端，
        # 才能把整库前后差异归因于下面这个冲突请求。
        lab.aligned();lab.offline()
        prior=lab.rpc(0,'send',req);require(prior['ok'] and lab.rpc(0,'send',req)==prior,'exact old request replay')
        before=lab.database_snapshot();bad={**req,'envelope':{**req['envelope'],'ciphertext':'00'}}
        require(not lab.rpc(0,'send',bad)['ok'],'changed password input refused')
        require(lab.database_snapshot()==before,'conflict creates no accept or device event')
        lab.proof('service-lost-ack',sent)
        for i in range(2):lab.auto(i);lab.online(i)
    lab.case('service_accepted_ack_lost_exact_retry_and_conflict',accepted)
    def processed():
        lab.offline();_,sent=lab.send(0,'processed-lost-confirmation');lab.auto(0);lab.online(0)
        wait(lambda:lab.status(0,'processed-lost-confirmation','accepted'),'pending receiver')
        # 使用原始设备令牌固定故障代理目标，不依赖续期的随机新令牌。
        lab.fault('drop_processed_ack',index=1);lab.connect(1)
        wait(lambda:json.loads(lab.control.read_text()).get('consumed'),'actual processed response dropped')
        lab.workers[1].call('disconnect');original=lab.fact('processed-lost-confirmation')
        require(original['delivered'],'Service committed processed confirmation before lost reply')
        lab.control.write_text('{}');lab.cycle('processed-ack-lost')
        wait(lambda:lab.status(0,'processed-lost-confirmation','delivered'),'processed confirmation retry')
        require(lab.fact('processed-lost-confirmation')==original,'processed and delivery fact not duplicated')
        lab.proof('processed-lost-confirmation',sent);lab.aligned()
    lab.case('client_processed_lost_confirmation_and_duplicate_events',processed)
    def stale():
        lab.quiesce();old=lab.export_service('before-peer-progress')
        olddata=lab.database_snapshot();lab.start_service()
        for i in range(2):lab.auto(i);lab.online(i)
        lab.communicate('new-peer-facts');lab.aligned();current=[w.call('network') for w in lab.workers]
        require(any(int(current[i]['processed'])>int(olddata['alpha_devices'][i]['tail']) for i in range(2)),'SDK cursor ahead of old snapshot')
        lab.maintenance('restore',old,config=lab.new_target('live-old'),expected='service_maintenance_busy')
        lab.quiesce();latest=lab.database_snapshot();target=lab.new_target('stale')
        lab.maintenance('restore',old,config=target,expected='service_backup_stale')
        require(lab.database_snapshot()==latest,'refusal retains newer peer and Service facts')
        database=urlparse(json.loads(target.read_text())['database_url']).path.lstrip('/')
        require(lab.sql("SELECT to_regclass('public.schema_version') IS NULL",database=database).strip()=='t','stale backup installs no target')
        lab.start_service()
        for i in range(2):lab.auto(i);lab.online(i)
    lab.case('known_post_backup_facts_and_leading_sdk_cursors_block_old_backup',stale)
    def candidate():
        lab.offline();action={'kind':'send','message_id':'service-candidate','text':'PRIVATE_SERVICE_COMPLETE_CANDIDATE'};lab.texts.append(action['text'])
        fault=BackupFault(lab,0,'after_candidate')
        try:fault.interrupt({'op':'execute','request_id':'req-service-candidate','action':action})
        finally:fault.close()
        lab.restore(0);audit=lab.audit(0);require(audit['candidate_outcome_hash'] is not None,'real durable full candidate')
        lab.cycle('full-candidate',reconnect=False)
        result=lab.workers[0].call('recoverRequest',requestId='req-service-candidate',action=action)
        digest=hashlib.sha256(json.dumps({'status':'complete','outcome':result},sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
        require(digest==audit['candidate_outcome_hash'],'exact candidate installed without crypto reexecution')
        for i in range(2):lab.auto(i);lab.online(i)
        wait(lambda:lab.status(0,'service-candidate','delivered'),'candidate delivered');lab.proof('service-candidate',result)
    lab.case('pending_complete_candidate_preserved_and_exactly_installed',candidate)
    def credentials():
        c=lab.consumer();valid_request={**body(lab,0,'restore-valid'),'ttl_seconds':300};valid=c.call('credentials',valid_request)
        short_request={**body(lab,0,'restore-expired'),'ttl_seconds':1};short=c.call('credentials',short_request)
        revoke_request={**body(lab,0,'restore-revoke-issued'),'ttl_seconds':300};revoked=c.call('credentials',revoke_request)
        rev={**body(lab,0,'restore-revoke'),'credential_id':revoked['credential_id']};conclusion=c.call('revocations',rev)
        lab.extra_secrets=[valid['token'],short['token'],revoked['token']]
        lab.cycle('credential-facts');time.sleep(1.1)
        require(c.call('credentials',valid_request)==valid,'same original valid credential id and token')
        require(c.call('revocations',rev)==conclusion,'revocation durable result')
        c.call('credentials',revoke_request,code='credential_revoked');c.call('credentials',short_request,code='credential_expired')
        request={'id':'credential','op':'session','body':{}}
        for token in (short['token'],revoked['token']):raw(lab,'/v1/rpc',token,request,401)
        raw(lab,'/v1/rpc',valid['token'],request,200)
        c.call('credentials',{**body(lab,1,'wrong-restored-device'),'device':'device-0','ttl_seconds':60},code='device_conflict')
        lab.communicate('after-credential-restore');lab.aligned()
    lab.case('valid_expired_revoked_credentials_bindings_and_idempotence',credentials)
    def client_backup():
        lab.offline();path,_=lab.export(0,'client-backup-retained');lab.roundtrip(0,path)
        for i in range(2):lab.auto(i);lab.online(i)
        lab.communicate('client-backup-retained');lab.aligned()
    lab.case('existing_public_client_backup_capability_retained',client_backup)
    lab.case('actual_service_backup_and_dynamic_secret_scan',lab.snapshot_secrets);lab.offline()
    for i in range(2):lab.case('actual_client_private_state_scan_'+str(i),lambda i=i:lab.audit(i))

def unknown(lab):
    lab.case('unknown_original_bilateral_history',lab.initial);lab.offline();request,action=lab.unknown(0,'service-unknown')
    def gate():
        lab.cycle('unknown-execution',reconnect=False)
        lab.workers[0].call('recoverRequest',expected='successor_required',requestId=request,action=action)
        lab.workers[0].call('send',expected='operation_pending',requestId='blocked',messageId='blocked',text='blocked')
        require(lab.fact('service-unknown') is None,'Service does not manufacture unknown crypto acceptance')
    lab.case('unknown_execution_gate_survives_restore',gate)
    def ongoing():
        lab.auto(0);fault=FaultRuntime(lab,1,'network_recovery_after_publish')
        try:
            round=lab.begin(0,request,action)
            ready=wait(lambda:(r if (r:=fault.call({'op':'network_recovery','command':{'kind':'status'}})) and r['phase']=='approval_required' else False),'explicit second-device authorization')
            fault.call({'op':'network_recovery','command':{'kind':'approve','round_id':ready['round_id']}});fault.exited()
        finally:fault.close()
        lab.restore(1);lab.offline();prior=lab.save_round_proof()
        require(prior['status']!='complete' and 'approval' in prior['materials'],'both authorization materials persisted before backup')
        lab.cycle('ongoing-authorized-successor',reconnect=False)
        require(lab.save_round_proof()==prior,'exact ongoing round materials and context')
        for i in range(2):lab.auto(i)
        lab.complete();lab.communicate('service-successor');lab.aligned();lab.save_round_proof()
        require(lab.workers[0].call('request',requestId=request)['status']=='retired','unknown request retires without invented success')
        lab.cycle('completed-successor');lab.complete();lab.communicate('restored-successor');lab.aligned()
    lab.case('in_progress_bilateral_authorization_and_successor_resume',ongoing)
    lab.case('unknown_service_secret_surfaces',lab.snapshot_secrets);lab.offline()
    for i in range(2):lab.case('unknown_private_state_scan_'+str(i),lambda i=i:lab.audit(i))
