"""真实短期令牌、暂时失败、严格错误、原队列与关停；不由宿主换token或投递密文。"""
from pathlib import Path
from types import SimpleNamespace
import json
import time
from business_faults import FaultProxy
from harness import require, wait


def run(lab, *, orderly_stop=False):
    a,b=lab.workers
    def initial():
        results=lab.auto(0,concurrent=True)
        require(sum(v['ok'] for v in results)==1 and all(v['ok'] or v['code']=='already_connected' for v in results),'concurrent connect single owner')
        lab.auto(1);lab.online(0);lab.online(1)
        for index in range(2):
            stats=lab.stats(index);require(stats['peak']==1,'one callback per instance')
            require(stats['calls'][0]['reason']=='initial','initial authentication reason')
        _,sent=lab.send(0,'renewal-first');wait(lambda:lab.status(0,'renewal-first','delivered'),'initial automatic credential message')
        lab.proof('renewal-first',sent)
    lab.case('automatic_initial_credentials_concurrent_connect_real_backend',initial)

    def expiry():
        before=[len(lab.stats(i)['issued']) for i in range(2)]
        wait(lambda:all(len(lab.stats(i)['issued'])>=before[i]+3 for i in range(2)),'three real consecutive expirations',25)
        for i in range(2):
            stats=lab.stats(i); require(any(c['reason']=='expired' for c in stats['calls']),'expiry owned by Rust')
            require(len({c['token_sha256'] for c in stats['issued']})==len(stats['issued']),'new authorization each expiry')
            probe=lab.workers[i].call('authExpired',endpoint=lab.endpoint)
            require(probe['count']>=3 and all(c==401 for c in probe['codes']),'expired old credentials rejected by real Service')
            lab.report.setdefault('expiry_probes',[]).append(probe)
        identity=a.call('state')['identity'];_,sent=lab.send(0,'renewal-after-expiries')
        wait(lambda:lab.status(0,'renewal-after-expiries','delivered'),'delivery after repeated expiry')
        require(a.call('state')['identity']==identity,'no key or trust replacement')
        lab.proof('renewal-after-expiries',sent)
    lab.case('real_consecutive_expiry_new_authorization_old_tokens_rejected',expiry)

    def unavailable():
        a.call('disconnect');a.call('authFault',mode='unavailable',count=2)
        start=len(lab.stats(0)['calls']);lab.auto(0)
        _,sent=lab.send(0,'renewal-unavailable')
        require(lab.status(0,'renewal-unavailable','local_saved'),'no false acceptance during callback backoff')
        wait(lambda:lab.status(0,'renewal-unavailable','delivered'),'temporary failure auto recovery')
        calls=lab.stats(0)['calls'][start:];require([c['attempt'] for c in calls[:3]]==[1,2,3],'bounded retry episode')
        lab.proof('renewal-unavailable',sent)
    lab.case('temporary_provider_failure_bounded_backoff_original_queue',unavailable)

    def http_faults():
        for mode in ('drop','timeout'):
            a.call('disconnect')
            proxy=FaultProxy(SimpleNamespace(endpoint=lab.business_endpoint,ssl=lab.ssl,env=lab.env),mode)
            try:
                lab.setup(0,endpoint=proxy.endpoint,ttl=2);lab.auto(0,timeout=100 if mode=='timeout' else 1000)
                _,sent=lab.send(0,'business-response-'+mode)
                if mode=='timeout':
                    state=wait(lambda:(s if (s:=a.call('network'))['connection']=='blocked' else False),'three timed out callbacks',10)
                    require(state['error']['code']=='credential_timeout','timeout explicit')
                    require(len(lab.stats(0)['calls'])==3 and proxy.count==3,'three real HTTP attempts only')
                    require(lab.status(0,'business-response-'+mode,'local_saved'),'timeout does not acknowledge send')
                    lab.report['timeout_stats']=lab.stats(0)
                    a.call('disconnect');lab.setup(0);lab.auto(0)
                wait(lambda:lab.status(0,'business-response-'+mode,'delivered'),'business response loss recovery')
                if mode=='drop':require(proxy.count>=2,'real dropped HTTP response retried')
                lab.proof('business-response-'+mode,sent)
                a.call('disconnect')
            finally:proxy.close()
            lab.setup(0);lab.auto(0);lab.online(0)
    lab.case('business_http_response_drop_and_real_timeout_recovery',http_faults)

    def wrong_results():
        errors={'expired':'credential_expired_or_invalid','scope_service':'credential_scope_mismatch','scope_account':'credential_scope_mismatch',
            'scope_device':'credential_scope_mismatch','wrong_purpose':'invalid_credential','wrong_token_identity':'identity_mismatch',
            'invalid_token':'unauthorized','login_required':'login_required','forbidden':'credential_forbidden','cancelled':'authentication_cancelled','throw':'credential_provider_failed'}
        for mode,code in errors.items():
            a.call('disconnect');start=len(lab.stats(0)['calls']);identity=b.call('state')['identity']
            a.call('authFault',mode=mode,count=1);lab.auto(0)
            state=wait(lambda:(s if (s:=a.call('network'))['connection']=='blocked' else False),'explicit '+mode)
            require(state['error']['code']==code,'error category '+mode+' got '+str(state['error']))
            time.sleep(.35);require(len(lab.stats(0)['calls'])==start+1,'no blind retry '+mode)
            require(b.call('state')['identity']==identity,'B isolation '+mode)
            require(all(c['scope']==a.options['scope'] for c in lab.stats(0)['calls']),'callback immutable full scope')
        lab.reauto(0)
    lab.case('expiry_scope_purpose_identity_permanent_errors_no_retry',wrong_results)

    def network_outage():
        if orderly_stop:
            # 已登记Service的未封存崩溃必须拒绝；本案测试已封存停服时的续期失败。
            lab.stop_service();lab.report['outage_stop']='graceful_sealed_service_required'
        else:lab.service.kill();lab.service.wait(timeout=10)
        _,sent=lab.send(0,'service-outage-queue')
        for index in range(2):
            state=wait(lambda:(s if (s:=lab.workers[index].call('network'))['connection']=='blocked' else False),'Service outage bounded authentication',20)
            require(state['error']['code']=='credential_unavailable','temporary backend failure explicit')
        require(lab.status(0,'service-outage-queue','local_saved') and lab.fact('service-outage-queue') is None,'no false Service acceptance')
        lab.start_service()
        for index in range(2):lab.reauto(index)
        wait(lambda:lab.status(0,'service-outage-queue','delivered'),'real network outage original queue recovers')
        lab.proof('service-outage-queue',sent)
    lab.case('real_service_outage_expiry_bounded_failure_then_original_queue',network_outage)

    def queue_restart():
        a.call('disconnect');a.call('authFault',mode='hang',count=3);lab.auto(0,timeout=250)
        messages=[{'requestId':'req-restart-'+str(i),'messageId':'restart-'+str(i),'text':'E2EE_RENEWAL_QUEUE_'+str(i)} for i in range(7)]
        lab.texts.extend(m['text'] for m in messages);outcomes=a.call('concurrentSend',messages=messages)
        require(all(lab.status(0,m['messageId'],'local_saved') for m in messages),'concurrent local durable queue during blocked auth')
        identity=a.call('state')['identity'];cursor=a.call('history',query={'direction':'forward','page_size':1})
        lab.restart_service();lab.restart_worker(0,kill=True);lab.setup(0)
        require(lab.workers[0].call('state')['identity']==identity,'original identity survived restart')
        for m,result in zip(messages,outcomes):
            require(lab.workers[0].call('request',requestId=m['requestId'])['outcome']['value']==result['value'],'unchanged queue before reconnect')
        lab.auto(0)
        wait(lambda:all(lab.status(0,m['messageId'],'delivered') for m in messages),'restart original queue delivered',60)
        for m,result in zip(messages,outcomes):lab.proof(m['messageId'],result)
        if not cursor['done']:
            page=lab.workers[0].call('history',query={'direction':'forward','page_size':1,'cursor':cursor['next_cursor']})
            require(page['upper_bound']==cursor['upper_bound'],'history cursor survived credential/SDK restart')
    lab.case('auth_blocked_concurrent_queue_service_sdk_restart_original_identity_history',queue_restart)

    if lab.proxy_enabled:
        def lost_acceptance():
            for mode in ('drop_send_ack','delay_send_ack'):
                lab.workers[1].call('disconnect')
                lab.control.write_text(json.dumps({'mode':mode,'token_hash':'','consumed':False}))
                wait(lambda:0<int(lab.stats(0)['issued'][-1]['expires_at_unix_ms'])-int(time.time()*1000)<500,'real expiration near acceptance',10)
                message='renewal-'+mode.replace('_','-');_,sent=lab.send(0,message)
                first=wait(lambda:lab.fact(message),'Service committed original acceptance')
                # 原接受已提交，回执仍未知；SDK和Service都重启，重新认证不能产生新密文/接受ID。
                lab.restart_worker(0,kill=True);lab.restart_service();lab.setup(0)
                require(lab.status(0,message,'local_saved'),'acceptance unknown remains local_saved after restart')
                lab.auto(0);lab.auto(1)
                wait(lambda:lab.status(0,message,'delivered'),'old acceptance precise retry',60)
                observations=[x for x in json.loads(lab.observations.read_text()) if x['request']=='req-'+message]
                require(len(observations)>=2 and len({x['body_hash'] for x in observations})==1,'actual repeated identical wire request')
                require(len({x['token_hash'] for x in observations})>=2,'same ciphertext retried with new authorization')
                fact=lab.fact(message)
                require(all(first[k]==fact[k] for k in ('request_id','message_id','accepted','envelope','envelope_hash')),'old acceptance precisely retained across restart')
                lab.proof(message,sent)
                lab.report.setdefault('wire_retry_proofs',[]).append({'message':message,'attempts':len(observations),'body_sha256':observations[0]['body_hash'],'authorization_hashes':sorted({x['token_hash'] for x in observations}),'original_acceptance':first['accepted']})
        lab.case('real_acceptance_drop_timeout_original_ciphertext_wire_retry',lost_acceptance)
    lab.case('dynamic_credentials_no_persistence_or_log_leaks',lab.snapshot_secrets)
