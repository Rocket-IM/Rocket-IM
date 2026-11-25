"""大正文端侧先达预算的独立补证；不冒充256条服务端接受测试。"""
from service_backup_harness import digest
from capacity_cases import start
from harness import require


def large_local_budget(lab):
    start(lab);lab.offline();lab.payload_bytes=32768
    service=lab.database_snapshot();created=[];last_state=None
    for serial in range(1,256):
        id='large-local-'+str(serial)
        last_state=lab.workers[0].call('state')
        try:
            lab.send(0,id);created.append(id)
        except AssertionError as error:
            require(str(error)=='worker command send failed: storage_limit','explicit first large local budget refusal')
            require(lab.workers[0].call('state')==last_state,'capacity failure has no password-state revision')
            require(lab.workers[0].call('request',requestId='req-'+id)['status']=='missing','capacity failure reserves no request')
            break
    else:
        raise AssertionError('large payload should meet byte budget before message quota')
    require(lab.database_snapshot()==service,'offline records cannot manufacture Service acceptance')
    before=lab.snapshot(0)
    for id in (created[0],created[-1]):
        _,text,sent=lab.originals[id]
        require(lab.workers[0].call('send',requestId='req-'+id,messageId=id,text=text)['value']==sent['value'],
                'precise retry bypasses new-operation byte budget without new encryption')
    require(lab.snapshot(0)==before,'large precise retries preserve original state')
    lab.controlled_restore('large-local-budget',reconnect=False)
    lab.cycle('large-local-budget',reconnect=False)
    require(lab.snapshot(0)==before,'large local queue and original ciphertexts survive both Service recoveries')
    lab.report['large_local_limit']={'payload_bytes':32768,'new_local_messages':len(created),
        'total_local_history':len(before['history']),'service_accepted':len(service['alpha_messages']),
        'error':'storage_limit','rejected_request_state':'missing','history_sha256':digest(before['history']),
        'state_sha256':digest(before['state']),'queue':'retained offline; not accepted or delivered',
        'scope':'normal actual SDK public API; 16MiB data / 32MiB meta preparation budget; no quota adjustment'}
    for sample in lab.samples:
        if sample['message_id'].startswith('large-local-'):
            sample['phase']='large_local_budget'
            sample['outcome']='local_budget_rejected' if sample['outcome']=='command_failed' else 'local_saved_offline'
    lab.save_samples();lab.snapshot_secrets()
    for i in range(2):lab.audit(i)
