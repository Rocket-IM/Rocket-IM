"""公开授权竞争、拒绝、材料故障、真实事务拒绝与凭证到期共同验收。"""
import copy,hashlib,json,secrets,subprocess,time
from harness import require,wait,PG

def run(lab):
    lab.case('boundaries_original_history',lab.initial)
    def rejection():
        lab.workers[0].call('disconnect');request,action=lab.unknown(0,'rejected-request');lab.auto(0)
        lab.begin(0,request,action);r=wait(lambda:lab.phase(1,'approval_required'),'offer awaiting explicit decision')
        before=[w.call('state') for w in lab.workers]
        lab.workers[1].call('networkRecovery',command={'kind':'reject','round_id':r['round_id']})
        for i in range(2):wait(lambda:lab.phase(i,'closed'),'signed rejection sealed '+str(i))
        require([w.call('state') for w in lab.workers]==before,'rejection does not replace crypto state or history')
        lab.workers[1].call('networkRecovery',expected='recovery_decision_conflict',command={'kind':'approve','round_id':r['round_id']})
        lab.begin(0,request,action);next_round=wait(lambda:lab.phase(1,'approval_required'),'fresh round after rejected one')
        require(next_round['round_id']!=r['round_id'],'separate signed round after rejection')
        lab.approve(1,next_round['round_id']);lab.complete();lab.communicate('after-rejection');lab.save_round_proof()
    lab.case('explicit_rejection_late_approval_and_new_round',rejection)
    def race():
        for w in lab.workers:w.call('disconnect')
        pending=[lab.unknown(i,'concurrent-'+str(i)) for i in range(2)]
        for i in range(2):lab.begin(i,*pending[i])
        for i in range(2):lab.auto(i)
        def winner():
            q=lab.rpc(0,'recovery_query',{'id':None})['result'];return q if q and q['status']=='offered' else False
        q=wait(winner,'one durable winning offer');target=next(i for i in range(2) if lab.original_identities[i]==q['reservation']['target']);peer=1-target
        r=wait(lambda:lab.phase(peer,'approval_required'),'loser needs distinct explicit approval')
        for i in range(2):lab.workers[i].call('send',expected='recovery_active' if i==target else 'operation_pending',requestId='forbidden-race-'+str(i),messageId='forbidden-race-'+str(i),text='unused')
        require(all(w.call('state')['pending_request']==pending[i][0] for i,w in enumerate(lab.workers)),'both original pending retained before consent')
        lab.approve(peer,r['round_id']);lab.complete()
        require(all(w.call('request',requestId=pending[i][0])['status']=='retired' for i,w in enumerate(lab.workers)),'both unknown original requests retired')
        lab.communicate('after-race');lab.save_round_proof()
    lab.case('simultaneous_begin_single_slot_bounded_explicit_loser_consent',race)
    def material_fault(mode,material,label):
        lab.workers[0].call('disconnect');request,action=lab.unknown(0,label);lab.auto(0)
        lab.control.write_text(json.dumps({'mode':mode,'material':material,'consumed':False}))
        lab.begin(0,request,action)
        r=wait(lambda:lab.phase(1,'approval_required'),'normal signed offer '+mode)
        lab.approve(1,r['round_id'])
        wait(lambda:json.loads(lab.control.read_text()).get('consumed'),'real transport fault '+mode)
        lab.restart_service();lab.complete();lab.communicate(label+'-after');lab.save_round_proof()
    for mode,material in [('duplicate_recovery','offer'),('drop_recovery_ack','approval'),('delay_recovery_ack','ready')]:
        lab.case('normal_package_'+mode,lambda mode=mode,material=material:material_fault(mode,material,mode.replace('_','-')))
    def tamper(field):
        before=[w.call('state') for w in lab.workers]
        record=lab.rpc(0,'recovery_query',{'id':None})['result']
        lab.control.write_text(json.dumps({'mode':'tamper_recovery','field':field,'consumed':False}))
        def blocked():
            return [i for i in range(2) if lab.workers[i].call('network')['connection']=='blocked']
        indexes=wait(blocked,'Rust rejects tampered signed reservation binding')
        for i in indexes:require(lab.workers[i].call('network')['error']['code']=='network_recovery_invalid','explicit binding error')
        require([w.call('state') for w in lab.workers]==before,'tampered relay response changes no valid crypto state')
        require(lab.rpc(0,'recovery_query',{'id':None})['result']==record,'invalid relay response cannot rewrite Service material')
        for i in indexes:lab.reauto(i)
        wait(lambda:all(w.call('network')['connection']=='online' for w in lab.workers),'valid relay resume')
    for field in ('service','account','device','identity_key','conversation','old_context','previous','request','request_hash','id','deadline','version'):
        lab.case('client_rejects_changed_'+field+'_without_state_mutation',lambda field=field:tamper(field))
    def service_bindings():
        record=lab.rpc(0,'recovery_query',{'id':None})['result'];original=[w.call('state') for w in lab.workers]
        q=copy.deepcopy(record['reservation']);q.update(id=secrets.token_hex(32),target=lab.original_identities[0],peer=lab.original_identities[1],old_context=record['context'],previous=record['context'],deadline=str(int(time.time()*1000)+60000))
        for field in ('service','account','device','identity_key','conversation','old_context','previous','deadline','request_hash'):
            bad=copy.deepcopy(q)
            if field in ('service','account','device'):bad['target']['scope'][field]='other'
            elif field=='identity_key':bad['target'][field]='ff'*32
            elif field in ('previous','old_context'):bad[field]='ff'*32
            elif field=='deadline':bad[field]='1'
            else:bad[field]='other'
            result=lab.rpc(0,'recovery_reserve',bad)
            require(not result['ok'],'Service rejects invalid reservation '+field)
        require(not lab.rpc(1,'recovery_reserve',q)['ok'],'authenticated wrong role cannot reserve for target')
        require(lab.rpc(0,'recovery_query',{'id':None})['result']==record,'invalid bindings allocate no second context')
        require([w.call('state') for w in lab.workers]==original,'invalid HTTP inputs cannot change identities or history')
    lab.case('service_rejects_wrong_scope_identity_context_deadline_and_role',service_bindings)
    def expired_intent():
        lab.workers[0].call('disconnect');request,action=lab.unknown(0,'expired-before-reserve');before=lab.workers[0].call('state');lab.auto(0)
        record=lab.rpc(0,'recovery_query',{'id':None})['result']
        lab.control.write_text(json.dumps({'mode':'expire_recovery_reservation','consumed':False}))
        lab.begin(0,request,action)
        wait(lambda:json.loads(lab.control.read_text()).get('consumed'),'actual Service deadline rejection')
        def expired():
            state=lab.workers[0].call('network');return state if (state.get('error') or {}).get('code')=='recovery_deadline' else False
        wait(expired,'unreserved attempt explicitly ended')
        require(lab.workers[0].call('state')==before,'expiry preserves original unknown request and history')
        require(lab.rpc(0,'recovery_query',{'id':None})['result']==record,'expired reservation never persisted')
        lab.workers[0].call('disconnect');lab.auto(0)
        # 原未知请求仍受门禁约束，此时不能先等待正常online。
        lab.begin(0,request,action);r=wait(lambda:lab.phase(1,'approval_required'),'new explicit authorization after deadline')
        lab.approve(1,r['round_id']);lab.complete();lab.communicate('after-expired-attempt')
    lab.case('expired_unreserved_intent_requires_new_begin_preserving_unknown',expired_intent)
    def transaction():
        def sql(command):
            subprocess.run([PG/'psql','-h',lab.env['directory']+'/socket','-U','alpha','-d','alpha','-v','ON_ERROR_STOP=1','-c',f'BEGIN; SET LOCAL search_path={lab.schema}; '+command+' COMMIT;'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,check=True)
        lab.workers[0].call('disconnect');request,action=lab.unknown(0,'transaction-refusal');lab.auto(0)
        sql("CREATE FUNCTION reject_recovery() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic commit refusal'; END$$; CREATE TRIGGER fail_recovery BEFORE UPDATE ON alpha_recovery FOR EACH ROW EXECUTE FUNCTION reject_recovery();")
        try:
            lab.begin(0,request,action);wait(lambda:lab.phase(0,'offered'),'persisted local offer despite Service refusal')
            packet=lab.workers[0].call('recovery',command={'kind':'status'})['packet']
            wait(lambda:lab.workers[0].call('network')['connection']=='offline','Service write failure explicit')
            q=lab.rpc(0,'recovery_query',{'id':None})['result'];require(q['materials']=={},'failed transaction published no material')
        finally:sql('DROP TRIGGER fail_recovery ON alpha_recovery; DROP FUNCTION reject_recovery();')
        lab.restart_service();r=wait(lambda:lab.phase(1,'approval_required'),'same candidate transferred after restart')
        lab.approve(1,r['round_id']);lab.complete();q=lab.save_round_proof()
        require(q['materials']['offer']==packet,'persistent offer exact after real transaction refusal')
        lab.communicate('after-transaction')
    lab.case('real_service_transaction_failure_exact_local_candidate_reuse',transaction)
    def renewal():
        for i in range(2):
            issued=lab.stats(i)['issued'];require(len(issued)>=3,'real automatic credentials throughout recovery')
            require(any(c['reason']=='expired' for c in lab.stats(i)['calls']),'Rust owned expiry renewal')
            probe=lab.workers[i].call('authExpired',endpoint=lab.endpoint);require(probe['count']>0 and all(c==401 for c in probe['codes']),'old credential actual HTTP expiry')
        observations=json.loads(lab.observations.read_text());duplicates={}
        for x in observations:
            if x['operation']=='recovery_publish':duplicates.setdefault(x['request'],[]).append(x['body_hash'])
        repeats={k:v for k,v in duplicates.items() if len(v)>1}
        require(repeats and all(len(set(v))==1 for v in repeats.values()),'repeated actual wire materials byte-identical')
        lab.report['material_retransmissions']=repeats
    lab.case('actual_expiry_and_wire_material_reuse',renewal)
    lab.case('boundary_secret_surfaces',lab.snapshot_secrets)
