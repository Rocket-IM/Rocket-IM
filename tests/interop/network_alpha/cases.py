"""公开实际包的联网验收；测试控制器仅开关进程/故障，正常链路不传输密文。"""
import hashlib
import json
from pathlib import Path
import subprocess
import time
from harness import Lab, require, wait, PG, ROOT, node_binary, Worker
import os

def run(lab):
    def auth():
        wrong={**lab.connect_options[0],'token':'0'*64};lab.workers[0].call('connect',expected='unauthorized',options=wrong)
        peer=lab.connect_options[0]['peer'];wrong={**lab.connect_options[0],'peer':{**peer,'identity_key':'00'*32}}
        lab.workers[0].call('connect',expected='identity_mismatch',options=wrong)
        wrong={**lab.connect_options[0],'ca_certificate':'00'*32};lab.workers[0].call('connect',expected='invalid_certificate',options=wrong)
        wrong={**lab.connect_options[0],'ca_certificate':lab.wrong_ca_certificate}
        lab.workers[0].call('connect',expected='tls_verification_failed',options=wrong)
        wrong={**lab.connect_options[0],'url':lab.connect_options[0]['url'].replace('wss://','ws://')}
        lab.workers[0].call('connect',expected='tls_required',options=wrong)
        require(lab.workers[0].call('network')['connection']=='offline','rejected connect preserves offline')
        lab.connect(0);lab.connect(1)
        wait(lambda:all(w.call('network')['connection']=='online' for w in lab.workers),'SDK automatic group formation')
        for i,w in enumerate(lab.workers):require(w.call('state')['peer']==lab.materials[1-i]['identity'],'independently pinned peer')
    lab.case('auth_tls_and_independent_identity_then_automatic_group',auth)

    original={}
    def bidirectional():
        for i,id in [(0,'first'),(1,'reply')]:
            text,result=lab.send(i,id);original[id]=(text,result)
            wait(lambda:lab.status(i,id,'delivered'),'bidirectional delivery')
            found=[x['message'] for x in lab.history(1-i) if x['message']['message_id']==id]
            require(len(found)==1 and found[0]['text']==text,'exact decrypted text')
        events=lab.workers[0].call('events')
        require(any(e['kind']=='local_commit' for e in events),'local commit event')
        require(any(e['kind']=='network_state' and any(s['status']=='accepted' for s in e['state']['sending']) for e in events),'accepted subscription')
        require(any(e['kind']=='network_state' and any(s['status']=='delivered' for s in e['state']['sending']) for e in events),'delivered subscription')
        text,result=original['first'];repeat=lab.workers[0].call('send',requestId='req-first',messageId='first',text=text)
        require(repeat['cached'] and repeat['value']==result['value'],'SDK original ciphertext retry')
        lab.workers[0].call('send',expected='request_conflict',requestId='req-first',messageId='first',text=text+'changed')
        request={'request_id':'req-first','envelope':result['value']['envelope']}
        a=lab.rpc(0,'send',request);b=lab.rpc(0,'send',request);require(a['ok'] and a==b,'Service exact acceptance retry')
        changed={**request,'envelope':{**request['envelope'],'ciphertext':'00'}}
        require(lab.rpc(0,'send',changed)['error']['code']=='idempotency_conflict','Service conflict')
        for field in ('service','conversation','sender_account','sender_device'):
            bad={**request,'envelope':{**request['envelope'],field:'intruder'}}
            require(lab.rpc(0,'send',bad)['error']['code']=='scope_mismatch','scope permission '+field)
        require(lab.rpc(1,'send',request)['error']['code']=='scope_mismatch','wrong device')
        bad={**request,'plaintext':'must-not-be-accepted'}
        require(lab.rpc(0,'send',bad)['error']['code']=='invalid_request','unknown plaintext field')
    lab.case('bidirectional_history_events_exact_retry_and_scope_denial',bidirectional)

    def offline():
        b=lab.workers[1];before=b.call('state')['received_count'];b.call('disconnect')
        sent=[]
        for i in range(7):
            id='offline-'+str(i);text,result=lab.send(0,id);sent.append((id,text))
        wait(lambda:all(lab.status(0,id,'accepted') for id,_ in sent),'offline accepted')
        require(b.call('state')['received_count']==before,'offline no false delivery')
        lab.restart_service();lab.restart_worker(1,kill=True);lab.connect(1)
        wait(lambda:all(lab.status(0,id,'delivered') for id,_ in sent),'offline multi-page complete')
        items=lab.history(1);actual=[(x['message']['message_id'],x['message']['text']) for x in items if x['message']['message_id'].startswith('offline-')]
        require(actual==sent,'offline page order and no gaps')
        state=lab.workers[1].call('network');require(int(state['processed'])<=int(state['downloaded']),'cursor relation')
        wait(lambda:lab.workers[1].call('network')['reported']==lab.workers[1].call('network')['processed'],'receipt retry caught up')
    lab.case('offline_multiple_pages_service_crash_and_sdk_restart',offline)

    def lost_acks():
        for mode,id in [('drop_send_ack','lost-ack'),('delay_send_ack','timeout-ack')]:
            lab.fault(mode,0);text,result=lab.send(0,id)
            wait(lambda:lab.status(0,id,'delivered'),mode,60)
            require(json.loads(lab.control.read_text())['consumed'],'fault consumed')
            observed=[x for x in json.loads(lab.observations.read_text()) if x['request']=='req-'+id]
            require(len(observed)>=2 and len({x['body_hash'] for x in observed})==1,'exact request bytes retried after '+mode)
            require(len([x for x in lab.history(1) if x['message']['message_id']==id])==1,'single display '+mode)
            retry=lab.workers[0].call('send',requestId='req-'+id,messageId=id,text=text);require(retry['value']==result['value'],'no re-encryption')
        lab.fault('drop_processed_ack',1);lab.send(0,'receipt-ack')
        wait(lambda:lab.status(0,'receipt-ack','delivered'),'delivery receipt ACK loss')
        wait(lambda:lab.workers[1].call('network')['reported']==lab.workers[1].call('network')['processed'],'receipt exact retry')
        require(json.loads(lab.control.read_text())['consumed'],'receipt fault consumed')
    lab.case('dropped_accept_timeout_and_receipt_ack_exact_retries',lost_acks)

    def local_restart():
        lab.workers[0].call('disconnect');text,result=lab.send(0,'local-restart')
        require(lab.status(0,'local-restart','local_saved'),'only locally saved while disconnected')
        identity=lab.workers[0].call('state')['identity'];lab.restart_worker(0,kill=True)
        require(lab.workers[0].call('state')['identity']==identity,'identity continuity')
        retry=lab.workers[0].call('send',requestId='req-local-restart',messageId='local-restart',text=text)
        require(retry['cached'] and retry['value']==result['value'],'restart retained exact ciphertext')
        lab.connect(0);wait(lambda:lab.status(0,'local-restart','delivered'),'automatic durable queue restart')
        lab.workers[0].call('cancel',expected='cancelled');require(lab.workers[0].call('request',requestId='cancelled')['status']=='missing','pre-cancel no durable write')
        old=[x['message'] for x in lab.history(0)];lab.restart_worker(0);require([x['message'] for x in lab.history(0)]==old,'history persists close')
        lab.connect(0)
    lab.case('persisted_outbox_process_restart_identity_history_and_cancel',local_restart)

    def connected_boundaries():
        old=lab.workers[0];old.close()
        target=old.directory/'client-boundaries.mjs';target.write_bytes((ROOT/'tests/interop/network_alpha/client_boundaries.mjs').read_bytes())
        env={k:v for k,v in os.environ.items() if not k.startswith(('CARGO','RUST','ROCKET_IM_TEST_'))};env['PATH']=str(old.directory/'path')
        result=subprocess.run([node_binary(),target],cwd=old.directory,env=env,input=json.dumps({'open':old.options,'connect':lab.connect_options[0]}),capture_output=True,text=True,timeout=45)
        require(result.returncode==0 and not result.stderr,'connected cancel/timeout/close')
        outcome=json.loads(result.stdout);require(outcome['status']=='PASS','client boundary result');lab.report['connected_boundaries']=outcome
        lab.workers[0]=Worker(old.directory,old.options);lab.connect(0)
        require(lab.workers[1].call('state')['identity']==lab.materials[1]['identity'],'other account unaffected')
    lab.case('connected_cancel_timeout_close_and_history_cursor_restart',connected_boundaries)

    from commit_faults import run as commit_faults
    commit_faults(lab)

    def private_storage():
        envdir=Path(lab.env['directory'])
        # 只在内存检查正常Service持久化与SDK加密文件；不把敏感样本写入报告。
        dump=subprocess.check_output([PG/'pg_dump','-h',envdir/'socket','-U','alpha','-d','alpha','--schema='+lab.schema,'--data-only'],timeout=30)
        logs=b''.join(p.read_bytes() for p in lab.run.rglob('*.log'))+b''.join((w.directory/'worker-stderr.log').read_bytes() for w in lab.workers)
        protected=b''.join((w.directory/'encrypted.db').read_bytes() for w in lab.workers)
        for text in lab.texts:
            require(text.encode() not in dump and text.encode() not in logs and text.encode() not in protected,'plaintext absent in service/log/encrypted DB')
        for token in lab.tokens:
            require(token.encode() not in dump and token.encode() not in logs and token.encode() not in protected,'credential absent in persistent/log surfaces')
        lab.report['secret_scan']={'message_samples':len(lab.texts),'credential_samples':len(lab.tokens),'matches':0}

    def tamper():
        b=lab.workers[1];before=b.call('state')['received_count'];lab.fault('tamper_message',1);lab.send(0,'tampered')
        state=wait(lambda:(s if (s:=b.call('network'))['connection']=='blocked' else False),'MLS rejects altered ciphertext',45)
        require(state['error'] is not None,'explicit decrypt failure')
        require(b.call('state')['received_count']==before,'tampered payload not committed')
        require(int(state['downloaded'])>int(state['processed']),'failure retains raw item without processed advance')
        require(not lab.status(0,'tampered','delivered'),'no false delivery')
        lab.report['tamper_error']=state['error']['code']
    lab.case('tampered_ciphertext_with_recomputed_transport_hash_rejected_by_mls',tamper)

    lab.case('service_and_test_logs_and_encrypted_storage_no_plaintext_or_credentials',private_storage)
