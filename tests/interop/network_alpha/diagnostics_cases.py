"""实际dev.11/alpha.6诊断、授权隔离与真实MLS候选/后继恢复。"""
from pathlib import Path
import json
import secrets
import time
from backup_harness import BackupFault
from capacity_cases import start
from harness import require, wait, sha
from service_backup_harness import digest


def budget(value, name):
    return next(b for b in value['budgets'] if b['category'] == name)


def operation(value, name):
    return next(o for o in value['operations'] if o['operation'] == name)


def observe(lab, label, global_scope=True):
    # 调用者先停联网；查询本身不改变连接、账本、游标或数据版本。
    before = lab.database_snapshot()
    files = [sha(Path(w.options['path'])) for w in lab.workers]
    states = [lab.snapshot(i) for i in range(2)]
    local = []
    service = []
    for i, worker in enumerate(lab.workers):
        worker.call('events')
        value = worker.call('capacity')
        again = worker.call('capacity')
        require(value['observation_id'] != again['observation_id'], 'fresh observation identity')
        require({k:v for k,v in value.items() if k != 'observation_id'} == {k:v for k,v in again.items() if k != 'observation_id'}, 'same durable logical snapshot')
        require(value['scope'] == worker.options['scope'] and value['revision'] == states[i]['state']['revision'], 'local owner and revision')
        require(worker.call('events') == [], 'diagnosis publishes no change events')
        require(value['reserve'] == {'state':'not_enabled','protected_remaining':None,'ordinary_available':None,'resources':[],'work':[]}, 'no invented reservation')
        require(value['physical'] == value['remote'] == {'state':'unavailable','reserved':False}, 'no remote or disk promise')
        require(all(o['state'] != 'bounded_ready' for o in value['operations']), 'observation cannot grant execution')
        local.append(value)
        remote = lab.diagnostic(lab.tokens[i])
        require(remote['scope']['account'] == worker.options['scope']['account'] and remote['scope']['device'] == worker.options['scope']['device'], 'authenticated own device')
        require([b['category'] for b in remote['budgets']] == ['accepted'] and remote['scope']['principal'] is None, 'no global subject budgets leaked')
        require(int(budget(remote,'accepted')['used']) == len(before['alpha_messages']), 'real accepted count')
        service.append(remote)
    global_value = lab.consumer().call('capacity',{}) if global_scope else None
    if global_value:
        require(int(budget(global_value,'business_requests')['used']) == len(before['business_requests']), 'all-subject usage from public Go SDK')
        require(int(budget(global_value,'recovery_rounds')['used']) == len(before['alpha_recovery']), 'all actual rounds')
        require(budget(global_value,'export_row_bytes')['enforcement'] == 'not_applied', 'schema5 keeps existing reconciliation export path')
        require(budget(global_value,'reconciliation_row_bytes')['enforcement'] == 'hard_limit', 'enabled evidence budget is enforced')
        require(budget(global_value,'export_file_bytes')['state'] == 'measured', 'complete current encoded backup size')
    require(before == lab.database_snapshot(), 'all twelve Service tables unchanged')
    require(states == [lab.snapshot(i) for i in range(2)], 'state history cursors unchanged')
    require(files == [sha(Path(w.options['path'])) for w in lab.workers], 'encrypted client originals unchanged')
    row = {'label':label,'local':local,'device_service':service,'global_service':global_value,
           'before_after':{'service_sha256':digest(before),'client_files':files,'unchanged':True}}
    lab.report.setdefault('diagnostics',[]).append(row)
    lab.save()
    return local


def secret_samples(lab):
    lab.snapshot_secrets()
    # 诊断报告也作为公开输出单独扫描；令牌样本只留测试进程内存。
    raw = json.dumps({'diagnostics':lab.report.get('diagnostics',[]),'reserve':lab.report.get('reserve_observations',[])}).encode()
    samples = lab.texts+lab.tokens+lab.sessions+getattr(lab,'extra_secrets',[])+[lab.business_token,lab.other_token,lab.expired_token,lab.signing_key]
    require(all(sample.encode() not in raw for sample in samples), 'diagnostic output has no real secret sample')
    lab.report.setdefault('diagnostic_secret_scans',[]).append({'static_samples':len(samples),'matches':0})


def permissions(lab):
    before = lab.database_snapshot()
    lab.consumer(token=lab.other_token).call('capacity',{},code='forbidden')
    lab.consumer(token=lab.expired_token).call('capacity',{},code='unauthorized')
    lab.diagnostic(lab.tokens[0],business=True,status=401,code='unauthorized')
    lab.diagnostic(lab.business_token,status=401,code='unauthorized')
    lab.diagnostic('rimd_'+'0'*64,status=401,code='unauthorized')
    lab.diagnostic(lab.tokens[0],suffix='?account=another',status=400,code='invalid_request')
    lab.diagnostic(lab.business_token,business=True,body=b'{}',status=400,code='invalid_request')
    require(before == lab.database_snapshot(), 'rejected capacity does not consume requests')
    consumer = lab.consumer()
    credential = consumer.call('credentials',{'request_id':'diagnostic-revoke-credential','external_user':'buyer-0','account':lab.users[0]['scope']['account'],'device':'device-0','ttl_seconds':300})
    lab.extra_secrets = [credential['token']]
    lab.diagnostic(credential['token'])
    consumer.call('revocations',{'request_id':'diagnostic-revoke','external_user':'buyer-0','account':credential['account'],'device':'device-0','credential_id':credential['credential_id']})
    lab.diagnostic(credential['token'],status=409,code='credential_revoked')
    expired = consumer.call('credentials',{'request_id':'diagnostic-expire','external_user':'buyer-0','account':credential['account'],'device':'device-0','ttl_seconds':1})
    lab.extra_secrets.append(expired['token'])
    time.sleep(1.1)
    lab.diagnostic(expired['token'],status=409,code='credential_expired')


def candidate(lab):
    request = 'diagnostic-candidate'
    text = 'DIAGNOSTIC_PRIVATE_'+secrets.token_hex(32)
    lab.texts.append(text)
    action = {'kind':'send','message_id':request,'text':text}
    fault = BackupFault(lab,0,'after_candidate')
    try: fault.interrupt({'op':'execute','request_id':request,'action':action})
    finally: fault.close()
    lab.restore(0)
    observed = observe(lab,'real-complete-candidate')
    require(observed[0]['recovery']['pending'] == 'complete_candidate', 'actual complete candidate')
    require(int(next(c['bytes'] for c in observed[0]['components'] if c['category']=='candidate_bytes')) > 0, 'whole encoded candidate counted')
    require(operation(observed[0],'install_candidate')['state']=='not_reserved', 'candidate installation still checked at execution')
    lab.workers[0].call('recoverRequest',requestId=request,action=action)
    for i in range(2): lab.auto(i); lab.online(i)
    wait(lambda: lab.status(0,request,'delivered'), 'installed original candidate sent exactly once')
    lab.aligned();lab.offline()
    require(len([h for h in lab.history(1) if h['message']['message_id']==request]) == 1, 'one real decrypted candidate')
    observe(lab,'after-candidate-install')


def successor(lab):
    request, action = lab.unknown(0,'diagnostic-unknown')
    observed = observe(lab,'real-executing-unknown')
    require(observed[0]['recovery']['pending']=='executing_unknown', 'actual crypto interruption remains unknown')
    require(operation(observed[0],'recover_pending')['state']=='blocked', 'no invented candidate recovery')
    require(operation(observed[0],'retry_request')['state']=='requires_input', 'other exact old requests remain queryable')
    lab.workers[0].call('recoverRequest',requestId='init',action={'kind':'initialize'})
    for i in range(2):lab.auto(i)
    round_id = lab.begin(0,request,action)['round_id']
    wait(lambda:lab.phase(1,'approval_required'),'real peer must authorize')
    lab.offline()
    pending = observe(lab,'local-authorization-before-peer')
    require(pending[0]['recovery']['locally_authorized'] and not pending[1]['recovery']['locally_authorized'], 'local intent is not bilateral authorization')
    lab.approve(1,round_id)
    for i in range(2):lab.auto(i)
    lab.complete()
    lab.communicate('diagnostic-successor')
    lab.aligned();lab.offline()
    final = observe(lab,'after-bilateral-recovery')
    require(all(int(budget(v,'transitions')['used'])==1 for v in final),'real retained transition counted')
    secret_samples(lab)


def run(lab):
    lab.case('initialized_unbound_read_only_capacity',lambda:observe(lab,'initialized-unbound'))
    lab.case('capacity_public_scope_and_expiry',lambda:permissions(lab))
    lab.case('real_e2ee_warmup',lambda:start(lab))
    lab.fill(8,'diagnostic-load');lab.offline()
    lab.case('real_e2ee_capacity_unchanged',lambda:observe(lab,'eight-e2ee'))
    lab.case('live_credential_and_diagnostic_samples',lambda:secret_samples(lab))
    lab.case('real_complete_candidate_capacity',lambda:candidate(lab))
    lab.case('real_unknown_and_authorized_recovery_capacity',lambda:successor(lab))
    lab.case('capacity_after_service_restore',lambda:lab.controlled_restore('diagnostic-service',reconnect=False))
    lab.case('restored_capacity_unchanged',lambda:observe(lab,'restored-service'))
    for i in range(2):
        path,_ = lab.export(i,'diagnostic-client-'+str(i))
        lab.case('client_backup_capacity_'+str(i),lambda i=i,path=path:lab.roundtrip(i,path))
    lab.case('restored_client_capacity',lambda:observe(lab,'restored-clients'))
    lab.case('capacity_secret_samples',lambda:secret_samples(lab))
    for i in range(2):lab.case('capacity_private_state_audit_'+str(i),lambda i=i:lab.audit(i))


def full(lab):
    from rejection_cases import prepare_full, terminal, verify_originals
    accepted,rejected = prepare_full(lab)
    lab.auto(1);lab.online(1)
    wait(lambda:all(terminal(lab,id) for id in rejected),'real v5 rejected original committed')
    lab.drain(accepted,'diagnostic-full');lab.aligned();lab.offline()
    def check():
        values = observe(lab,'real-256-and-v5-rejection')
        require(all(budget(v,'ordinary_messages')['used']=='256' for v in values),'real normal slots full')
        require(all(operation(v,'new_send')['state']=='blocked' for v in values),'known full message limit')
        require(all(operation(v,'retry_request')['state']=='requires_input' for v in values),'full ledger keeps precise original lookup')
    lab.case('real_full_v5_capacity_read_only',check)
    lab.case('full_capacity_all_original_retries',lambda:verify_originals(lab,rejected))
    lab.case('full_capacity_live_secret_samples',lambda:secret_samples(lab))
    path,_ = lab.export(1,'diagnostic-v5-full')
    lab.case('full_v5_backup_restore',lambda:lab.roundtrip(1,path))
    lab.case('full_v5_restored_capacity',lambda:observe(lab,'restored-full-v5'))
