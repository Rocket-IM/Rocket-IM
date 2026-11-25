"""旧包真实原库、旧故障窗口、混合版本与新版授权恢复连续性。"""
import hashlib
import time
from harness import require, wait
from commit_faults import FaultRuntime
from upgrade_gates import run as gates, old_reader, locked_upgrade


def ordinary(lab):
    lab.case('dev7_real_original_bilateral_network',lab.initial)
    lab.case('signature_acl_and_assembly_independent_gates',lambda:gates(lab))
    def pending():
        lab.aligned();history=[lab.history(i) for i in range(2)]
        pages=[w.call('history',query={'direction':'forward','page_size':1}) for w in lab.workers]
        for w in lab.workers:w.call('disconnect')
        oldstate=[w.call('state') for w in lab.workers]
        oldnetwork=[w.call('network') for w in lab.workers]
        messages=[lab.send(0,'offline-upgrade-'+str(i)) for i in range(7)]
        fault=FaultRuntime(lab,0,'network_after_accept')
        try:fault.exited()
        finally:fault.close()
        lab.restore(0)
        accepted=lab.fact('offline-upgrade-0');require(accepted is not None,'old real accepted with unknown ACK')
        require(lab.status(0,'offline-upgrade-0','local_saved'),'old local ACK absent')
        identities=[s['identity'] for s in oldstate]
        lab.switch(0);require(lab.workers[0].call('state')['identity']==identities[0],'first upgraded identity')
        lab.auto(0);lab.auto(1)
        wait(lambda:all(lab.status(0,'offline-upgrade-'+str(i),'delivered') for i in range(7)),'mixed dev8 sender dev7 receiver')
        _,reverse=lab.send(1,'mixed-reverse');wait(lambda:lab.status(1,'mixed-reverse','delivered'),'mixed dev7 sender dev8 receiver')
        for i,(_,sent) in enumerate(messages):lab.proof('offline-upgrade-'+str(i),sent)
        after=lab.fact('offline-upgrade-0')
        require(all(after[k]==accepted[k] for k in ('request_id','message_id','accepted','envelope','envelope_hash')),'original service acceptance exact')
        for w in lab.workers:w.call('disconnect')
        lab.switch(1)
        require([w.call('state')['identity'] for w in lab.workers]==identities,'both original identities')
        for i in range(2):require(lab.stable_pages(i,pages[i])==history[i],'old stable snapshot spans upgrade and new traffic')
        for i in range(2):
            now=lab.workers[i].call('network')
            require(all(int(now[k])>=int(oldnetwork[i][k]) for k in ('downloaded','processed','reported')),'cursors never reset')
        # 未写新版恢复字段的 v3 库仍兼容旧版；版本号本身不是防回滚。
        for i in range(2):lab.probe(i,'old')
        lab.report['ordinary_upgrade']={'old_snapshot_upper':[p['upper_bound'] for p in pages],
            'accepted_request':accepted['request_id'],'accepted_sequence':accepted['accepted'],
            'envelope_sha256':accepted['envelope_hash'],'mixed_versions':'bidirectional_PASS',
            'compatible_old_reader':'PASS_NOT_ANTI_ROLLBACK'}
        for i in range(2):lab.auto(i)
        lab.communicate('both-upgraded');lab.aligned();lab.record('ordinary-upgraded')
    lab.case('offline_backlog_lost_ack_mixed_version_snapshot_and_identity',pending)
    lab.case('upgraded_original_keychain_lock_cancel_unlock_identity_continuity',lambda:locked_upgrade(lab))
    for phase in ('network_after_download','after_reserve','after_candidate','before_commit','after_commit','refuse_commit'):
        def window(phase=phase):
            for w in lab.workers:w.call('disconnect')
            lab.both('old');lab.auto(0);lab.online(0)
            before=lab.workers[1].call('state');oldhistory=lab.history(1)
            name='upgrade-'+phase.replace('_','-');text,sent=lab.send(0,name)
            wait(lambda:lab.status(0,name,'accepted'),'old message accepted before failure')
            fault=FaultRuntime(lab,1,phase,refuse=phase=='refuse_commit')
            try:
                if phase=='refuse_commit':
                    state=wait(lambda:(s if (s:=fault.call({'op':'network_state'}))['connection']=='blocked' else False),'actual SQLite refused commit')
                    require(state['error']['code']=='commit_unknown','old failure explicit');fault.close()
                else:fault.exited()
            finally:fault.close()
            lab.switch(1)
            reopened=lab.workers[1].call('state')
            require(reopened['identity']==before['identity'],'old fault identity survives upgrade')
            require(lab.history(1)[:len(oldhistory)]==oldhistory,'old history prefix unchanged')
            require(reopened['received_count']==str(int(before['received_count'])+(phase=='after_commit')),'only committed candidate visible')
            lab.switch(0);lab.auto(0);lab.auto(1)
            wait(lambda:lab.status(0,name,'delivered'),'upgraded complete candidate continuation')
            rows=[r for r in lab.history(1) if r['message']['message_id']==name]
            require(len(rows)==1 and rows[0]['message']['text']==text,'exact candidate received once')
            lab.proof(name,sent);lab.aligned();lab.record(phase)
        lab.case('old_to_new_real_fault_'+phase,window)
    lab.case('upgrade_normal_secret_surfaces',lab.snapshot_secrets)


def unknown(lab):
    lab.case('dev7_unknown_original_network',lab.initial)
    evidence={}
    def create_unknown():
        for w in lab.workers:w.call('disconnect')
        evidence['pages']=[w.call('history',query={'direction':'forward','page_size':1}) for w in lab.workers]
        _,evidence['accepted']=lab.send(0,'upgrade-accepted-unknown')
        fault=FaultRuntime(lab,0,'network_after_accept')
        try:fault.exited()
        finally:fault.close()
        lab.restore(0)
        _,evidence['not_accepted']=lab.send(0,'upgrade-never-accepted')
        evidence['request'],evidence['action']=lab.unknown(0,'upgrade-unknown-execution')
        fault=FaultRuntime(lab,1,'after_crypto')
        try:fault.exited()
        finally:fault.close()
        lab.restore(1);evidence['receive_request']=lab.workers[1].call('state')['pending_request']
        require(evidence['receive_request'] is not None,'old real receive unknown')
        lab.switch(0)
        lab.workers[0].call('recoverRequest',expected='successor_required',requestId=evidence['request'],action=evidence['action'])
        lab.auto(0);lab.auto(1)
        r=lab.begin(0,evidence['request'],evidence['action']);evidence['round_id']=r['round_id']
        wait(lambda:lab.phase(0,'offered'),'new signed offer published')
        time.sleep(2.2)
        require(all(w.call('state')['context']=='initial' for w in lab.workers),'mixed versions cannot implicitly recover')
        require(lab.workers[1].call('state')['pending_request']==evidence['receive_request'],'old unknown execution unchanged')
        require(not lab.recovery(0)['phase']=='complete','waiting for upgraded peer explicit consent')
        old_reader(lab,0)
        lab.switch(1);lab.auto(0);lab.auto(1)
        wait(lambda:lab.phase(1,'approval_required'),'upgraded peer receives original offer')
        old_reader(lab,1);lab.auto(1)
        require(lab.workers[0].call('state')['context']=='initial','upgrade itself is not consent')
    lab.case('old_unknown_to_new_required_bilateral_upgrade_and_explicit_consent',create_unknown)
    def recover():
        lab.approve(1,evidence['round_id']);context=lab.complete()
        wait(lambda:lab.status(0,'upgrade-accepted-unknown','context_retired'),'old accepted retained without false delivery')
        wait(lambda:lab.status(0,'upgrade-never-accepted','not_accepted'),'old unaccepted exact terminal')
        fact=lab.fact('upgrade-accepted-unknown')
        require(fact['envelope']==evidence['accepted']['value']['envelope'] and fact['context_retired'] and not fact['delivered'],'old accepted ciphertext and explicit unavailable')
        require(lab.fact('upgrade-never-accepted') is None,'unaccepted never inserted')
        for key,name in [('accepted','upgrade-accepted-unknown'),('not_accepted','upgrade-never-accepted')]:
            require(lab.workers[0].call('request',requestId='req-'+name)['outcome']['value']==evidence[key]['value'],'old durable originals exact')
        for i,request in [(0,evidence['request']),(1,evidence['receive_request'])]:
            require(lab.workers[i].call('request',requestId=request)=={'status':'retired','context':context},'unknown requests retired without fabricated success')
            require(lab.stable_pages(i,evidence['pages'][i])==lab.original_history[i],'old snapshot continues after recovery')
        state=lab.workers[1].call('network');require(len(state['unavailable_history'])==1,'one undecryptable old original')
        row=lab.workers[1].call('networkUnavailable',sequence=state['unavailable_history'][0]['sequence'])
        require(row['envelope']==fact['envelope'] and row['acceptance']['envelope_hash']==fact['envelope_hash'],'retained ciphertext public query')
        lab.report['old_unknown_upgrade']={'round_id':evidence['round_id'],'context':context,'original_request':fact['request_id'],
            'original_acceptance':fact['accepted'],'envelope_sha256':fact['envelope_hash'],
            'ciphertext_sha256':hashlib.sha256(bytes.fromhex(row['envelope']['ciphertext'])).hexdigest()}
        lab.aligned();lab.communicate('upgrade-after-successor');lab.save_round_proof();lab.record('recovered')
        for i in range(2):
            old_reader(lab,i);lab.switch(i)
        for i in range(2):lab.auto(i)
        lab.complete();lab.communicate('reinstalled-successor')
        require(lab.inspect_acls()==lab.acls,'original public ACL unchanged after recovery and relocation')
    lab.case('old_originals_reconcile_dual_cursors_and_incompatible_reader_refusal',recover)
    lab.case('unknown_upgrade_secret_surfaces',lab.snapshot_secrets)
