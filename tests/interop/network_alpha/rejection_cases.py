"""永久拒绝的真实Release验收；所有接受均由独立SDK发送，不向PG插入主场景数据。"""
import hashlib
import json
from capacity_cases import start
from harness import require, wait

REJECTION = {'source': 'service_send', 'code': 'message_limit'}

def prepare_full(lab, rejected=1, remaining=2):
    start(lab);lab.fill(256-remaining,'rejection_preload');lab.offline()
    accepted_ids=['final-'+str(i) for i in range(remaining)]
    rejected_ids=['rejected-'+str(i) for i in range(rejected)]
    for id in accepted_ids:lab.send(0,id)
    for id in rejected_ids:lab.send(1,id)
    lab.auto(0);lab.online(0)
    wait(lambda:all(lab.fact(id) for id in accepted_ids),'original Service reaches exactly 256 accepts',45)
    require(len(lab.database_snapshot()['alpha_messages'])==256,'fixed Service capacity')
    return accepted_ids,rejected_ids

def terminal(lab,id):
    rows=[s for s in lab.workers[1].call('network')['sending'] if s['message_id']==id]
    return len(rows)==1 and rows[0]['status']=='rejected' and rows[0]['acceptance'] is None and rows[0]['rejection']==REJECTION

def verify_originals(lab,rejected_ids):
    lab.aligned();lab.offline();before=lab.database_snapshot()
    for index in range(2):
        history=lab.history(index);expected=256+(len(rejected_ids) if index==1 else 0)
        require(len(history)==expected,'complete public history including rejection originals')
        require([int(m['local_position']) for m in history]==list(range(1,expected+1)),'append positions remain continuous')
        for item in history:
            id=item['message']['message_id'];sender,text,sent=lab.originals[id]
            require(item['message']['text']==text,'every original history text retained')
            if id in rejected_ids:
                require(index==1 and item['rejection']==REJECTION,'explicit public terminal history')
            else:require('rejection' not in item,'accepted message is not rejected')
        rows=[m for m in before['alpha_messages'] if m['sender']==index]
        for m in rows:
            req={'request_id':m['request_id'],'envelope':m['envelope']}
            ack=lab.rpc(index,'send',req)
            require(ack['ok'] and ack['result']['sequence']==str(m['accepted']),'all exact accepted retries retain fact')
        first=lab.workers[index].call('history',query={'direction':'forward','page_size':1})
        require(lab.pages(index,first)==history,'history full pagination after compaction')
    for id in rejected_ids:
        _,text,sent=lab.originals[id];worker=lab.workers[1]
        require(terminal(lab,id) and lab.fact(id) is None,'rejection never becomes acceptance')
        request=worker.call('request',requestId='req-'+id)
        require(request['status']=='complete' and request['outcome']['value']==sent['value'],'original local request result retained')
        scope=worker.options['scope']
        require(worker.call('message',account=scope['account'],device=scope['device'],messageId=id)['text']==text,'direct message query retains rejected original')
        require(worker.call('send',requestId='req-'+id,messageId=id,text=text)['value']==sent['value'],'exact local retry reuses original ciphertext')
        worker.call('send',expected='request_conflict',requestId='req-'+id,messageId=id,text='changed')
        worker.call('send',expected='message_conflict',requestId='new-'+id,messageId=id,text=text)
        for _ in range(3):
            reply=lab.rpc(1,'send',{'request_id':'req-'+id,'envelope':sent['value']['envelope']})
            require(not reply['ok'] and reply['error']['code']=='message_limit','exact rejected Service request remains refused')
    for w in lab.workers:
        w.call('send',expected='message_limit',requestId='new-full',messageId='new-full',text='new')
        require(w.call('request',requestId='new-full')['status']=='missing','full new request has no crypto reservation')
    require(before==lab.database_snapshot(),'reads and precise retries preserve all Service tables')
    require(all(e['disposition']=='received' for e in before['alpha_mailbox']),'no fabricated retired disposition')
    for sample in lab.samples:
        if sample['message_id'] in rejected_ids:
            sample.update(phase='permanent_rejection',outcome='service_rejected_terminal')
    lab.report.setdefault('rejection_proofs',[]).append({
        'accepted':256,'rejected':len(rejected_ids),'public_history':[256,256+len(rejected_ids)],
        'originals':[{'id':id,'envelope_sha256':hashlib.sha256(json.dumps(lab.originals[id][2]['value']['envelope'],sort_keys=True).encode()).hexdigest()} for id in rejected_ids],
        'cursors':[{k:w.call('network')[k] for k in ('downloaded','processed','reported')} for w in lab.workers],
        'all_exact_accepted_retries':256,'normal_message_limit':256,'request_limit':1024,
    });lab.save()

def finish(lab,accepted_ids,rejected_ids):
    lab.auto(1);lab.online(1)
    wait(lambda:all(terminal(lab,id) for id in rejected_ids),'all permanent rejections committed',45)
    lab.drain(accepted_ids,'accepted_after_rejection');lab.aligned()
    lab.case('all_originals_terminal_and_contiguous_tail',lambda:verify_originals(lab,rejected_ids))
    for i in range(2):
        def client_restore(i=i):
            path,_=lab.export(i,'terminal-client-'+str(i));lab.roundtrip(i,path,missing=True)
        lab.case('terminal_client_backup_restore_'+str(i),client_restore)
    lab.case('terminal_normal_service_backup_new_empty_target',lambda:lab.controlled_restore('terminal-full',reconnect=False))
    lab.case('terminal_actual_service_sigkill_reconcile',lambda:lab.cycle('terminal-full',reconnect=False))
    for i in range(2):lab.auto(i);lab.online(i)
    lab.case('restored_terminal_originals_and_contiguous_tail',lambda:verify_originals(lab,rejected_ids))
    lab.case('terminal_final_full_facts',lambda:lab.checkpoint('terminal_final'))
    lab.case('terminal_service_secret_samples',lab.snapshot_secrets)
    for i in range(2):lab.case('terminal_client_broad_samples_'+str(i),lambda i=i:lab.audit(i))
    audits=lab.report['private_state_audits'][-2:]
    require([a['budgets']['normal_messages'] for a in audits]==[256,256],'actual Rust normal-message slots remain bounded')
    require([a['budgets']['rejected_sends'] for a in audits]==[0,len(rejected_ids)],'actual rejected originals belong to request ledger')
    for a in audits:
        b=a['budgets'];require(b['requests']<=1024 and b['data_bytes']<=16*1024*1024 and b['crypto_bytes']<=4*1024*1024 and b['metadata_bytes']<=32*1024*1024,'actual Rust byte/request budgets unchanged')

def run(lab,multiple=False):
    accepted,rejected=prepare_full(lab,rejected=4 if multiple else 1,remaining=4 if multiple else 2)
    if multiple:
        lab.control.write_text(json.dumps({'mode':'delay_send_rejection','consumed':False}))
    finish(lab,accepted,rejected)
    if multiple:
        require(json.loads(lab.control.read_text()).get('consumed'),'real rejection response delayed past deadline')
        rows=[o for o in json.loads(lab.observations.read_text()) if o['request']=='req-'+rejected[0]]
        require(len(rows)>=2 and len({o['body_hash'] for o in rows})==1,'late response retries exact original before terminal')
        lab.report['late_rejection_response']={'attempts':len(rows),'body_sha256':rows[0]['body_hash'],'terminal_persisted_after_confirmed_response':True}
