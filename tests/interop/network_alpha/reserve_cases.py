"""known-v1真实Release联合验收；控制装置只使用公开SDK与原故障程序。"""
from pathlib import Path
import secrets
from backup_harness import BackupFault
from commit_faults import FaultRuntime
from capacity_cases import start
from diagnostics_cases import secret_samples
from harness import require, wait, sha, persistent_keychain


def work(value, kind):
    return int(next(w['count'] for w in value['reserve']['work'] if w['kind']==kind))

def capture(lab,label):
    local=[w.call('capacity') for w in lab.workers]
    remote=[lab.diagnostic(t) for t in lab.tokens]
    global_value=lab.consumer().call('capacity',{}) if lab.operator else None
    for v in local:
        require(v['reserve']['state']=='bounded_ready','persisted local policy')
        require(v['physical']==v['remote']=={'state':'unavailable','reserved':False},'no physical/remote guarantee')
        for resource in v['reserve']['resources']:
            budget=next(b for b in v['budgets'] if b['category']==resource['category'])
            require(int(resource['protected_remaining'])+int(resource['ordinary_available'])==int(budget['hard_remaining']),'U+R exact remaining')
    for v in remote:require(v['reserve']['resources']==[], 'device cannot infer global business usage')
    lab.report.setdefault('reserve_observations',[]).append({'label':label,'local':local,'device_service':remote,'global_service':global_value});lab.save()
    return local,global_value

def enable(lab):
    lab.offline()
    before=[lab.snapshot(i) for i in range(2)]
    lab.workers[0].call('reserveCancel',expected='cancelled')
    require(lab.workers[0].call('capacity')['reserve']['state']=='not_enabled','cancel before dispatch changes nothing')
    fault=BackupFault(lab,0,'after_commit')
    try:fault.interrupt({'op':'reserve_capacity'})
    finally:fault.close()
    lab.restore(0)
    for i,w in enumerate(lab.workers):
        first=w.call('reserveCapacity');checksum=sha(Path(w.options['path']))
        again=w.call('reserveCapacity')
        require(first['reserve']==again['reserve'] and sha(Path(w.options['path']))==checksum,'idempotent enable has no second write')
        require(lab.snapshot(i)==before[i],'enable preserves identity original requests history and cursors')
    lab.stop_service();before=lab.database_snapshot()
    lab.maintenance('enable-capacity-reserve');again=lab.maintenance('enable-capacity-reserve')
    after=lab.database_snapshot()
    require(after['schema_version']==[{'version':6}],'explicit schema6')
    for name in before:
        if name not in ('schema_version','service_maintenance'):require(before[name]==after[name],'original table retained '+name)
    lab.start_service();capture(lab,'enabled')

def sending(lab):
    lab.offline();text,result=lab.send(0,'reserve-ack')
    value=lab.workers[0].call('capacity');require(work(value,'send_settlement')==1,'known original send protected')
    keychain=lab.workers[0].options['keychain'];checksum=sha(Path(lab.workers[0].options['path']))
    try:
        require(persistent_keychain.run({'op':'lock','keychain':keychain})['status']==0,'lock only this lab keychain')
        lab.workers[0].call('capacity',expected='keychain_locked')
        lab.workers[0].call('reserveCapacity',expected='keychain_locked')
    finally:
        require(persistent_keychain.run({'op':'unlock','keychain':keychain,'password':lab.keychain_passwords[0]})['status']==0,'unlock only this lab known keychain')
    require(lab.workers[0].call('capacity')['reserve']==value['reserve'] and sha(Path(lab.workers[0].options['path']))==checksum,'lock keeps known original reservation unchanged')
    original=result['value']['envelope']
    fault=FaultRuntime(lab,0,'network_after_accept')
    try:fault.exited()
    finally:fault.close()
    lab.restore(0)
    require(work(lab.workers[0].call('capacity'),'send_settlement')==1,'unknown ACK not released')
    repeated=lab.workers[0].call('send',requestId='req-reserve-ack',messageId='reserve-ack',text=text)
    require(repeated['value']['envelope']==original,'same ciphertext exact retry')
    lab.workers[0].call('send',expected='request_conflict',requestId='req-reserve-ack',messageId='reserve-ack',text=text+'changed')
    lab.auto(0);wait(lambda:lab.status(0,'reserve-ack','accepted'),'actual original ACK')
    lab.workers[0].call('disconnect');lab.auto(1)
    wait(lambda:len([m for m in lab.history(1) if m['message']['message_id']=='reserve-ack'])==1,'real E2EE known message')
    wait(lambda:lab.fact('reserve-ack')['delivered'],'actual peer processed')
    lab.workers[1].call('disconnect')
    fault=FaultRuntime(lab,0,'network_after_download')
    try:fault.exited()
    finally:fault.close()
    lab.restore(0)
    values,global_value=capture(lab,'downloaded-known-control')
    require(work(values[0],'known_control')==1 and work(values[0],'known_report')==1,'only downloaded control and report')
    if global_value:require(work(global_value,'known_control_report')==1,'Service protects same known control report locally')
    lab.auto(0);wait(lambda:lab.status(0,'reserve-ack','delivered'),'control committed')
    lab.aligned();lab.offline();values,global_value=capture(lab,'settled-control')
    require(work(values[0],'known_control')==work(values[0],'known_report')==0,'R converted to durable U')

def candidate(lab):
    lab.offline();request='reserve-candidate';text='RESERVE_PRIVATE_'+secrets.token_hex(24);lab.texts.append(text)
    action={'kind':'send','message_id':request,'text':text}
    fault=BackupFault(lab,0,'after_candidate')
    try:fault.interrupt({'op':'execute','request_id':request,'action':action})
    finally:fault.close()
    lab.restore(0);values,_=capture(lab,'complete-candidate');require(work(values[0],'candidate_install')==1,'real complete candidate is covered')
    lab.workers[0].call('recoverRequest',requestId=request,action=action)
    for i in range(2):lab.auto(i)
    wait(lambda:lab.status(0,request,'delivered'),'exact candidate delivered');lab.aligned();lab.offline()
    require(len([m for m in lab.history(1) if m['message']['message_id']==request])==1,'one decrypted original')

def recovery(lab):
    lab.offline();request,action=lab.unknown(0,'reserve-unknown')
    require(work(lab.workers[0].call('capacity'),'candidate_install')==0,'unknown execution not covered')
    for i in range(2):lab.auto(i)
    round_id=lab.begin(0,request,action)['round_id'];wait(lambda:lab.phase(1,'approval_required'),'original explicit peer authorization')
    lab.offline();lab.approve(1,round_id)
    fault=FaultRuntime(lab,0,'network_recovery_after_known_commit',connect=False)
    try:
        fault.call({'op':'connect','options':lab.connect_options[0]});lab.auto(1);fault.exited()
    finally:fault.close()
    lab.restore(0);lab.workers[1].call('disconnect')
    values,_=capture(lab,'target-ready-known-commit');require(work(values[0],'target_install')==1,'known authorized target candidate install covered')
    for i in range(2):lab.auto(i)
    lab.complete();lab.communicate('reserve-successor');lab.aligned();lab.offline()
    values,_=capture(lab,'successor-installed');require(work(values[0],'target_install')==0,'same local install settled')
    require(values[0]['budgets'][7]['used']=='1','old archive retained')


def activation(lab,index,phase):
    before=lab.snapshot(index);path=lab.root/(phase+'.rimbackup')
    fault=BackupFault(lab,index,phase)
    try:fault.interrupt({'op':'create_backup','path':str(path)})
    finally:fault.close()
    lab.restore(index)
    require(lab.snapshot(index)==before,'interrupted guard activation preserves complete original state')
    value=lab.workers[index].call('capacity')
    require(value['reserve']['state']=='bounded_ready','activation reopen retains v6 policy')
    require(next(r['protected_remaining'] for r in value['reserve']['resources'] if r['category']=='meta_bytes')=='0','first guard reservation converted to committed Meta')
    info=lab.workers[index].call('backup',path=str(path));lab.backups.append(path)
    require(info['format']==2,'new reserve backup format after activation interruption')
    lab.roundtrip(index,path)

def run(lab):
    lab.case('explicit_enable_unknown_result_and_idempotence',lambda:enable(lab))
    lab.case('real_e2ee_admitted_under_original_limits',lambda:start(lab))
    lab.aligned();lab.offline()
    lab.case('known_send_ack_control_and_report',lambda:sending(lab))
    lab.case('real_complete_candidate_install',lambda:candidate(lab))
    lab.case('authorized_known_target_install_unknown_gate',lambda:recovery(lab))
    for i,phase in enumerate(('backup_after_activation_reserve','backup_after_activation_commit')):
        lab.case('v6_'+phase,lambda i=i,phase=phase:activation(lab,i,phase))
    for i in range(2):
        path,info=lab.export(i,'reserve-client-'+str(i));require(info['format']==2,'explicit reserve backup format')
        lab.case('v6_backup_restore_'+str(i),lambda i=i,path=path:lab.roundtrip(i,path))
    lab.case('schema6_service_backup_restore',lambda:lab.controlled_restore('reserve-service',reconnect=False))
    lab.case('restored_reservations',lambda:capture(lab,'restored'))
    lab.case('reserve_secret_samples',lambda:secret_samples(lab))
    for i in range(2):lab.case('reserve_private_state_'+str(i),lambda i=i:lab.audit(i))


def full(lab):
    from rejection_cases import prepare_full, finish
    lab.case('full_explicit_enable',lambda:enable(lab))
    accepted,rejected=prepare_full(lab)
    values,_=capture(lab,'full-known-original-before-rejection')
    require(work(values[1],'send_settlement')>=1,'pending original remains protected until known rejection')
    finish(lab,accepted,rejected)
    values,_=capture(lab,'full-restored-256-and-rejected-original')
    for value in values:
        require(next(b['used'] for b in value['budgets'] if b['category']=='ordinary_messages')=='256','unchanged ordinary message slots')
        require(work(value,'send_settlement')==0,'all actual original outcomes settled')
    lab.case('full_reserve_secret_samples',lambda:secret_samples(lab))
