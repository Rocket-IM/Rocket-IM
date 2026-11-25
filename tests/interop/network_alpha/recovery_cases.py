"""真实双未知执行、双方授权、原身份/历史、旧接受事实及连续游标。"""
import hashlib
import json
import time
from harness import require,wait
from commit_faults import FaultRuntime

def run(lab):
    lab.case('successor_original_bilateral_history',lab.initial)
    evidence={}
    def queue_unknown():
        for w in lab.workers:w.call('disconnect')
        _,evidence['accepted']=lab.send(0,'accepted-unknown')
        fault=FaultRuntime(lab,0,'network_after_accept')
        try:fault.exited()
        finally:fault.close()
        lab.restore(0);require(lab.status(0,'accepted-unknown','local_saved'),'ack not locally committed')
        require(lab.fact('accepted-unknown') is not None,'Service already accepted original')
        _,evidence['not_accepted']=lab.send(0,'never-accepted')
        evidence['request'],evidence['action']=lab.unknown(0,'unknown-execution')
        fault=FaultRuntime(lab,1,'after_crypto')
        try:fault.exited()
        finally:fault.close()
        lab.restore(1)
        require(lab.workers[1].call('state')['pending_request'] is not None,'real receive execution unknown')
        evidence['receive_pending']=lab.workers[1].call('state')['pending_request']
        for i in range(2):lab.auto(i)
        r=lab.begin(0,evidence['request'],evidence['action']);evidence['round_id']=r['round_id']
        wait(lambda:lab.phase(1,'approval_required'),'actual signed offer exposed')
        time.sleep(2.2)
        require(all(w.call('state')['context']=='initial' for w in lab.workers),'no implicit peer consent from auth or delivery')
        lab.workers[0].call('networkRecovery',expected='recovery_role_mismatch',command={'kind':'approve','round_id':r['round_id']})
        lab.workers[1].call('networkRecovery',expected='recovery_missing',command={'kind':'approve','round_id':'wrong'})
        require([w.call('state')['identity'] for w in lab.workers]==lab.original_identities,'authorization failures preserve identity')
    lab.case('real_unknown_execution_and_explicit_peer_authorization',queue_unknown)
    def recover():
        lab.approve(1,evidence['round_id']);context=lab.complete()
        wait(lambda:lab.status(0,'accepted-unknown','context_retired'),'accepted ciphertext retired without false delivered')
        wait(lambda:lab.status(0,'never-accepted','not_accepted'),'unaccepted ciphertext terminal')
        require(lab.fact('never-accepted') is None,'never accepted remains absent at Service')
        fact=lab.fact('accepted-unknown');require(not fact['delivered'] and fact['context_retired'],'Service explicit unavailable accepted fact')
        require(fact['envelope']==evidence['accepted']['value']['envelope'],'original accepted ciphertext bytes')
        for key,name in [('accepted','accepted-unknown'),('not_accepted','never-accepted')]:
            record=lab.workers[0].call('request',requestId='req-'+name)
            require(record['status']=='complete' and record['outcome']['value']==evidence[key]['value'],'exact old local original '+name)
        for i,request in [(0,evidence['request']),(1,evidence['receive_pending'])]:
            require(lab.workers[i].call('request',requestId=request)=={'status':'retired','context':context},'unknown request retired without fabricated success')
        state=lab.workers[1].call('network');rows=state['unavailable_history'];require(len(rows)==1,'one retained undecryptable history')
        row=lab.workers[1].call('networkUnavailable',sequence=rows[0]['sequence'])
        require(row['envelope']==fact['envelope'] and row['acceptance']['envelope_hash']==fact['envelope_hash'],'public retained original ciphertext history')
        for i in range(2):
            wait(lambda:(s:=lab.workers[i].call('network'))['downloaded']==s['processed']==s['reported'],'contiguous dual cursors '+str(i))
        lab.report['old_queue']={'accepted':{k:fact[k] for k in ('request_id','message_id','accepted','envelope_hash','delivered','context_retired')},
            'not_accepted':'never-accepted','unknown_requests':[evidence['request'],evidence['receive_pending']],
            'context':context,'retained_ciphertext_sha256':hashlib.sha256(bytes.fromhex(row['envelope']['ciphertext'])).hexdigest()}
        lab.communicate('after-successor');lab.save_round_proof()
    lab.case('bilateral_install_old_queue_reconciliation_no_cursor_skip',recover)
    def duplicates():
        before=[w.call('state') for w in lab.workers];r=lab.save_round_proof()
        for key,packet in r['materials'].items():
            index=0 if key in ('offer','ready','installed_target') else 1
            body={'id':r['reservation']['id'],'kind':key,'packet':packet}
            reply=lab.rpc(index,'recovery_publish',body);require(reply['ok'] and reply['result']==r,'duplicate material same durable result')
            wrong=lab.rpc(1-index,'recovery_publish',body);require(not wrong['ok'],'wrong authenticated role rejected')
            changed={**body,'packet':packet[:-2]+('00' if packet[-2:]!='00' else '01')}
            require(not lab.rpc(index,'recovery_publish',changed)['ok'],'tampered packet rejected')
        require([w.call('state') for w in lab.workers]==before,'duplicates and invalid packets do not create context')
        for i in range(2):
            lab.restart_worker(i,kill=True);lab.setup(i);lab.auto(i)
        lab.restart_service();lab.complete();lab.communicate('restarted-successor')
    lab.case('materials_exact_replay_wrong_role_tamper_and_real_restart',duplicates)
    lab.case('successor_secret_surfaces',lab.snapshot_secrets)
