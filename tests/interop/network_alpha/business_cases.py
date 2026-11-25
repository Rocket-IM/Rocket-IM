"""本轮身份/API/真实双设备的验收；失败明确留在报告中。"""
from concurrent.futures import ThreadPoolExecutor
import json
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from harness import require, wait, PG
from business_faults import FaultProxy


def body(lab,index,request):
    return {'request_id':request,'external_user':'buyer-'+str(index),'account':lab.users[index]['user']['account'],'device':'device-'+str(index)}

def raw(lab,path,token,payload,status):
    headers={'Content-Type':'application/json'}
    if token is not None:headers['Authorization']='Bearer '+token
    req=urllib.request.Request(lab.endpoint+path,data=json.dumps(payload).encode(),headers=headers)
    try:
        with urllib.request.urlopen(req,context=lab.ssl,timeout=5) as r:require(r.status==status,'HTTP status');return json.load(r)
    except urllib.error.HTTPError as e:
        require(e.code==status,'expected HTTP '+str(status)+' got '+str(e.code));return e.read()


def run(lab):
    c=lab.consumer()
    def authorization():
        request={'service':'business-test','request_id':'denied','external_user':'buyer-0'}
        for token in (None,'rimb_'+'0'*64,lab.expired_token,lab.tokens[0]):raw(lab,'/v1/business/users',token,request,401)
        rpc={'id':'session','op':'session','body':{}}
        for token in (None,lab.business_token,'rimd_'+'0'*32+'_'+'0'*64):raw(lab,'/v1/rpc',token,rpc,401)
        other=lab.consumer(token=lab.other_token)
        own=other.call('users',{'request_id':'own-map','external_user':'buyer-0'})
        require(own['account']!=lab.users[0]['user']['account'],'business namespaces distinct')
        other.call('credentials',{**body(lab,0,'other-claim'),'ttl_seconds':60},code='forbidden')
        c.call('credentials',{**body(lab,0,'account-spoof'),'account':lab.users[1]['user']['account'],'ttl_seconds':60},code='forbidden')
        c.call('credentials',{**body(lab,0,'device-spoof'),'device':'device-1','ttl_seconds':60},code='device_conflict')
        c.call('devices',{**body(lab,0,'key-spoof'),'identity_key':'ff'*32},code='device_conflict')
        foreign=lab.consumer(service='another-service');foreign.call('users',{'request_id':'foreign','external_user':'buyer-0'},code='scope_mismatch')
        lab.business(0,'credential',{'request_id':'impersonate','device':'device-1','ttl_seconds':60},403)
        lab.business(0,'credential',{'request_id':'impersonate','device':'device-0','external_user':'buyer-1','ttl_seconds':60},400)
        raw(lab,'/v1/business/devices',lab.business_token,{'service':'business-test',**body(lab,0,'private-input'),'identity_key':lab.materials[0]['identity']['identity_key'],'private_key':'synthetic-private-key-must-not-persist'},400)
        # 设备凭证只映射到自己的会话身份，不能将对端凭证冒充本地身份。
        lab.workers[0].call('connect',expected='identity_mismatch',options={**lab.connect_options[0],'token':lab.tokens[1]})
        lab.workers[0].call('connect',expected='unauthorized',options={**lab.connect_options[0],'token':lab.business_token})
        peer=lab.connect_options[0]['peer']
        lab.workers[0].call('connect',expected='identity_mismatch',options={**lab.connect_options[0],'peer':{**peer,'identity_key':'00'*32}})
        require(lab.workers[0].call('network')['connection']=='offline','trust failure no connection')
    lab.case('business_device_scope_purpose_and_independent_trust_rejections',authorization)

    def retries():
        request={**body(lab,0,'concurrent-credential'),'ttl_seconds':60}
        consumers=[lab.consumer() for _ in range(8)]
        with ThreadPoolExecutor(max_workers=8) as pool:results=list(pool.map(lambda cc:cc.call('credentials',request),consumers))
        require(all(x==results[0] for x in results),'concurrent identical credential')
        for op,request in [('users',{'request_id':'parallel-map','external_user':'buyer-0'}),('devices',{**body(lab,0,'parallel-bind'),'identity_key':lab.materials[0]['identity']['identity_key']})]:
            with ThreadPoolExecutor(max_workers=8) as pool:values=list(pool.map(lambda cc:cc.call(op,request),consumers))
            require(all(x==values[0] for x in values),'concurrent '+op+' has one identity')
        request={**body(lab,0,'concurrent-credential'),'ttl_seconds':60}
        c.call('credentials',{**request,'ttl_seconds':61},code='idempotency_conflict')
        c.call('users',{'request_id':request['request_id'],'external_user':'buyer-0'},code='idempotency_conflict')
        for mode in ('drop','delay'):
            proxy=FaultProxy(lab,mode)
            try:
                client=lab.consumer(endpoint=proxy.endpoint,timeout=100,attempts=3)
                req={**body(lab,0,'lost-'+mode),'ttl_seconds':60}
                result=client.call('credentials',req)
                require(proxy.count>=2 and len(set(proxy.hashes))==1,'exact SDK retry '+mode)
                require(c.call('credentials',req)==result,'committed credential replay '+mode)
            finally:proxy.close()
        for op,request in [('users',{'request_id':'lost-map','external_user':'buyer-0'}),('devices',{**body(lab,0,'lost-bind'),'identity_key':lab.materials[0]['identity']['identity_key']})]:
            proxy=FaultProxy(lab,'drop')
            try:
                client=lab.consumer(endpoint=proxy.endpoint)
                result=client.call(op,request)
                require(proxy.count==2 and len(set(proxy.hashes))==1 and c.call(op,request)==result,'lost response '+op+' preserves identity')
            finally:proxy.close()
        proxy=FaultProxy(lab,'timeout')
        try:
            client=lab.consumer(endpoint=proxy.endpoint,attempts=1)
            request={**body(lab,0,'timeout-after-commit'),'ttl_seconds':60}
            client.call('credentials',request,code='deadline_exceeded',deadline=100)
            require(proxy.count==1,'timeout reached Service')
            first=c.call('credentials',request);require(c.call('credentials',request)==first,'timeout did not duplicate')
        finally:proxy.close()
        c.call('users',{'request_id':'pre-cancel','external_user':'buyer-0'},code='deadline_exceeded',deadline=-1)
        lab.restart_service()
        require(c.call('credentials',{**body(lab,0,'concurrent-credential'),'ttl_seconds':60})==results[0],'restart retained exact credential')
        for i in range(2):
            require(lab.business(i,'credential',{'device':'device-'+str(i),'request_id':'credential-'+str(i),'ttl_seconds':3600})==lab.credentials[i],'normal business credential survives restart')
    lab.case('independent_go_concurrent_loss_timeout_restart_exact_replay',retries)

    sent={}
    def messaging():
        lab.connect(0);lab.connect(1)
        wait(lambda:all(w.call('network')['connection']=='online' for w in lab.workers),'direct automatic group')
        for i,id in [(0,'business-first'),(1,'business-reply')]:
            text,result=lab.send(i,id);sent[id]=(text,result)
            wait(lambda:lab.status(i,id,'delivered'),'direct bidirectional delivery')
            actual=[x['message']['text'] for x in lab.history(1-i) if x['message']['message_id']==id]
            require(actual==[text],'decrypted history')
        text,result=sent['business-first'];again=lab.workers[0].call('send',requestId='req-business-first',messageId='business-first',text=text)
        require(again['cached'] and again['value']==result['value'],'original ciphertext preserved')
        req={'request_id':'req-business-first','envelope':result['value']['envelope']}
        ack=lab.rpc(0,'send',req);require(ack['ok'] and lab.rpc(0,'send',req)==ack,'exact server acceptance')
        require(lab.rpc(1,'send',req)['error']['code']=='scope_mismatch','cross device send rejected')
        for field in ('service','sender_account','sender_device'):
            invalid={**req,'envelope':{**req['envelope'],field:'foreign'}}
            require(lab.rpc(0,'send',invalid)['error']['code']=='scope_mismatch','send scope '+field)
        events=lab.workers[0].call('events')
        for status in ('accepted','delivered'):require(any(e['kind']=='network_state' and any(s['status']==status for s in e['state']['sending']) for e in events),'subscription '+status)
        lab.workers[1].call('disconnect');batch=[]
        for n in range(6):
            id='business-offline-'+str(n);text,_=lab.send(0,id);batch.append((id,text))
        wait(lambda:all(lab.status(0,id,'accepted') for id,_ in batch),'offline accepted')
        lab.restart_service();lab.restart_worker(1,kill=True);lab.connect(1)
        wait(lambda:all(lab.status(0,id,'delivered') for id,_ in batch),'offline multi-page delivered')
        actual=[(x['message']['message_id'],x['message']['text']) for x in lab.history(1) if x['message']['message_id'].startswith('business-offline-')]
        require(actual==batch,'no skipped or repeated offline messages')
        for i in range(2):require(lab.workers[i].call('state')['identity']==lab.materials[i]['identity'],'persistent identity')
        require(lab.rpc(0,'send',req)==ack,'restart retains original acceptance')
    lab.case('actual_node_packages_direct_e2ee_history_events_offline_reconnect',messaging)

    def expiry_and_revocation():
        short=c.call('credentials',{**body(lab,0,'short-credential'),'ttl_seconds':1})
        lab.workers[0].call('disconnect');lab.workers[0].call('connect',options={**lab.connect_options[0],'token':short['token']})
        time.sleep(1.1)
        raw(lab,'/v1/rpc',short['token'],{'id':'expired','op':'session','body':{}},401)
        wait(lambda:lab.workers[0].call('network')['connection']!='online','expired live WSS stops')
        c.call('credentials',{**body(lab,0,'short-credential'),'ttl_seconds':1},code='credential_expired')
        lab.workers[0].call('disconnect');lab.connect(0)
        rev={**body(lab,0,'revoke-main'),'credential_id':lab.credentials[0]['credential_id']}
        c.call('revocations',{**rev,'external_user':'buyer-1','account':lab.users[1]['user']['account'],'device':'device-1'},code='forbidden')
        out=c.call('revocations',rev);require(out['revoked'] and c.call('revocations',rev)==out,'revoke replay')
        raw(lab,'/v1/rpc',lab.tokens[0],{'id':'revoked','op':'session','body':{}},401)
        wait(lambda:lab.workers[0].call('network')['connection']!='online','revoked live WSS stops')
        lab.restart_service();raw(lab,'/v1/rpc',lab.tokens[0],{'id':'revoked','op':'session','body':{}},401)
        lab.business(0,'credential',{'device':'device-0','request_id':'credential-0','ttl_seconds':3600},409)
        renewed=lab.business(0,'credential',{'device':'device-0','request_id':'renewed','ttl_seconds':3600})
        require(renewed['credential_id']!=lab.credentials[0]['credential_id'],'explicit new issuance')
        lab.secret_tokens=[short['token'],lab.tokens[0],renewed['token']]
        lab.workers[0].call('disconnect');lab.tokens[0]=renewed['token'];lab.connect_options[0]['token']=renewed['token'];lab.connect(0)
        lab.send(0,'after-renewal');wait(lambda:lab.status(0,'after-renewal','delivered'),'explicit replacement reconnects')
    lab.case('real_expiry_live_socket_revocation_and_explicit_new_credential',expiry_and_revocation)

    def secrets():
        envdir=Path(lab.env['directory'])
        dump=subprocess.check_output([PG/'pg_dump','-h',envdir/'socket','-U','alpha','-d','alpha','--schema='+lab.schema,'--data-only'],timeout=30)
        logs=b''.join(p.read_bytes() for p in lab.run.rglob('*.log'))+b''.join((w.directory/'worker-stderr.log').read_bytes() for w in lab.workers)
        protected=b''.join((w.directory/'encrypted.db').read_bytes() for w in lab.workers)
        require(b'rimd_' not in dump and b'rimb_' not in dump and b'synthetic-private-key-must-not-persist' not in dump+logs,'no raw credential or rejected private field persisted')
        samples=lab.texts+lab.tokens+lab.secret_tokens+[lab.business_token,lab.other_token,lab.signing_key]+lab.sessions
        for text in samples:require(text.encode() not in dump+logs+protected,'secret absent from storage/logs')
        lab.report['secret_scan']={'samples':len(samples),'matches':0,'private_keys':'never requested or exported by business APIs; encrypted client storage retained'}
    lab.case('service_business_logs_storage_no_tokens_private_key_exports_or_text',secrets)
