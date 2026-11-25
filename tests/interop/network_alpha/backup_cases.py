"""真实包恢复原身份/历史/队列；Service接受事实由只读装置逐项对账。"""
import hashlib
import json
from pathlib import Path
from backup_harness import BackupFault
from commit_faults import FaultRuntime
from harness import require,wait,Worker

def run(lab):
    lab.case('backup_initial_bilateral_history',lab.initial)
    evidence={}
    def normal():
        lab.workers[0].call('backup',expected='backup_disconnect_required',path=str(lab.root/'active.rimbackup'))
        lab.aligned();lab.offline()
        for i in range(2):
            before=lab.snapshot(i);path,info=lab.export(i,'normal-'+str(i));evidence[i]=(path,info)
            require(lab.snapshot(i)==before,'guard activation does not change public IM state')
            require(lab.workers[i].call('backup',path=str(path))==info,'exact repeat export')
            lab.probe(i,path,'backup_store_in_use')
            first=lab.workers[i].call('history',query={'direction':'forward','page_size':1})
            require(lab.roundtrip(i,path,missing=i==0)==info,'exact import receipt')
            require(lab.roundtrip(i,path)==info,'repeat latest import')
            require(lab.pages(i,first)==before['history'],'stable history pages survive process and DB replacement')
        for i in range(2):lab.auto(i);lab.online(i)
        lab.communicate('normal-restored');lab.aligned()
    lab.case('same_machine_latest_complete_restore_missing_file_repeat_and_pagination',normal)
    def multiple():
        lab.aligned();lab.offline();path,_=lab.export(0,'shared-instance')
        old=lab.workers[0];before=lab.snapshot(0);other=Worker(old.directory,old.options);lab.native_pids.append(other.pid)
        try:
            old.close();lab.probe(0,path,'backup_store_in_use')
            require(other.call('state')==before['state'],'another live owner retains original state')
        finally:other.close()
        lab.probe(0,path);lab.restore(0);require(lab.snapshot(0)==before,'all owners closed then exact import')
    lab.case('all_live_instances_must_close_before_atomic_import',multiple)
    def stale():
        lab.offline()
        for i in range(2):
            path,_=evidence[i];lab.roundtrip(i,path,expected='backup_stale')
        path,_=lab.export(0,'after-stale');text,sent=lab.send(0,'new-offline-local')
        lab.roundtrip(0,path,expected='backup_stale')
        require(lab.workers[0].call('send',requestId='req-new-offline-local',messageId='new-offline-local',text=text)['value']==sent['value'],'stale refusal keeps new ciphertext')
    lab.case('old_backup_rejected_after_new_local_commits_without_state_loss',stale)
    def backlog():
        _,sent=lab.send(0,'offline-backup');path,info=lab.export(0,'offline-backup')
        require(lab.fact('offline-backup') is None,'backed up queue not yet accepted')
        lab.auto(1);lab.online(1);_,peer=lab.send(1,'peer-after-backup')
        wait(lambda:lab.status(1,'peer-after-backup','accepted'),'new peer fact after target backup')
        peer_fact=lab.fact('peer-after-backup')
        require(lab.roundtrip(0,path)==info,'latest target accepts independent peer progress')
        lab.auto(0);lab.online(0)
        wait(lambda:lab.status(0,'offline-backup','delivered'),'original queued ciphertext delivered')
        wait(lambda:lab.status(1,'peer-after-backup','delivered'),'new peer event downloaded from old cursor')
        lab.proof('offline-backup',sent)
        require(lab.fact('peer-after-backup')['envelope']==peer_fact['envelope']==peer['value']['envelope'],'peer original acceptance envelope')
        lab.aligned()
    lab.case('offline_backlog_and_new_service_peer_facts_resume_exactly',backlog)
    def accepted():
        lab.offline();text,sent=lab.send(0,'backup-lost-ack')
        fault=FaultRuntime(lab,0,'network_after_accept')
        try:fault.exited()
        finally:fault.close()
        lab.restore(0);require(lab.status(0,'backup-lost-ack','local_saved'),'no false local acceptance')
        original=lab.fact('backup-lost-ack');require(original is not None,'real Service already accepted')
        path,_=lab.export(0,'lost-ack');lab.roundtrip(0,path)
        require(lab.workers[0].call('send',requestId='req-backup-lost-ack',messageId='backup-lost-ack',text=text)['value']==sent['value'],'no re-encryption after restore')
        for i in range(2):lab.auto(i);lab.online(i)
        wait(lambda:lab.status(0,'backup-lost-ack','delivered'),'accepted original delivered')
        final=lab.fact('backup-lost-ack')
        keys=('request_id','message_id','accepted','envelope_hash','envelope')
        require(all(final[k]==original[k] for k in keys),'original exact durable acceptance')
        lab.proof('backup-lost-ack',sent);lab.aligned()
    lab.case('backup_of_lost_ack_reuses_original_service_acceptance',accepted)
    def candidate():
        lab.offline();action={'kind':'send','message_id':'backup-candidate','text':'PRIVATE_COMPLETE_BACKUP_CANDIDATE'};lab.texts.append(action['text'])
        fault=BackupFault(lab,0,'after_candidate')
        try:fault.interrupt({'op':'execute','request_id':'req-backup-candidate','action':action})
        finally:fault.close()
        lab.restore(0);audit=lab.audit(0);require(audit['candidate_outcome_hash'] is not None,'real full candidate persisted')
        path,_=lab.export(0,'candidate');lab.roundtrip(0,path)
        outcome=lab.workers[0].call('recoverRequest',requestId='req-backup-candidate',action=action)
        record={'status':'complete','outcome':outcome}
        require(hashlib.sha256(json.dumps(record,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()==audit['candidate_outcome_hash'],'installed exact candidate result')
        lab.workers[0].call('recoverRequest',expected='request_conflict',requestId='req-backup-candidate',action={**action,'text':'changed'})
        for i in range(2):lab.auto(i);lab.online(i)
        wait(lambda:lab.status(0,'backup-candidate','delivered'),'candidate ciphertext delivered once');lab.proof('backup-candidate',outcome)
    lab.case('full_candidate_exact_install_without_reexecuting_crypto',candidate)
    lab.case('backup_static_and_dynamic_secret_scan',lab.snapshot_secrets)
    lab.offline()
    for i in range(2):lab.case('backup_actual_private_state_scan_'+str(i),lambda i=i:lab.audit(i))

def unknown(lab):
    lab.case('unknown_backup_initial_history',lab.initial);lab.offline()
    old,_=lab.export(0,'before-unknown');request,action=lab.unknown(0,'backup-unknown')
    lab.roundtrip(0,old,expected='backup_stale')
    def retained():
        path,_=lab.export(0,'unknown');lab.roundtrip(0,path);lab.roundtrip(0,path)
        lab.workers[0].call('recoverRequest',expected='successor_required',requestId=request,action=action)
        lab.workers[0].call('send',expected='operation_pending',requestId='blocked',messageId='blocked',text='blocked')
        require(lab.fact('backup-unknown') is None,'unknown execution no fabricated acceptance')
    lab.case('unknown_execution_restored_with_original_successor_gate',retained)
    def successor():
        for i in range(2):lab.auto(i)
        round=lab.begin(0,request,action);wait(lambda:lab.phase(1,'approval_required'),'explicit approval after backup restore')
        require(lab.workers[0].call('state')['context']=='initial','no implicit context change')
        lab.approve(1,round['round_id']);lab.complete();lab.communicate('backup-successor');lab.aligned();lab.save_round_proof()
        lab.offline()
        for i in range(2):
            path,_=lab.export(i,'after-successor-'+str(i));lab.roundtrip(i,path)
        for i in range(2):lab.auto(i);lab.online(i)
        lab.communicate('backup-successor-reopened')
    lab.case('explicit_network_recovery_then_successor_backup_bilateral_continuity',successor)
    lab.case('unknown_backup_secret_surfaces',lab.snapshot_secrets);lab.offline()
    for i in range(2):lab.case('unknown_actual_private_state_scan_'+str(i),lambda i=i:lab.audit(i))
