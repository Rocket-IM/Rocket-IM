"""真实256条端到端与独立过载队列；已满实例不清库、不扩额。"""
import json
import time
import urllib.request
from harness import require, wait


def start(lab):
    for i in range(2): lab.auto(i)
    for i in range(2): lab.online(i)
    for w in lab.workers:
        wait(lambda w=w: w.call('state')['conversation'] is not None, 'actual E2EE group ready')
    lab.fill(2, 'warmup')
    lab.original_identities = [w.call('state')['identity'] for w in lab.workers]
    lab.original_history = [lab.history(i) for i in range(2)]


def startup(lab):
    lab.auto(0)
    wait(lambda: len(lab.stats(0)['issued']) >= 1, 'real first credential')
    time.sleep(1)
    one = lab.workers[0].call('network')
    require(one['connection'] == 'connecting' and lab.workers[0].call('state')['conversation'] is None,
            'one device cannot finish initial bilateral group')
    lab.auto(1)
    for i in range(2): lab.online(i)
    lab.report['startup_order_proof'] = {'before_peer': one, 'after_peer': [w.call('network') for w in lab.workers],
                                         'credentials_issued': [len(lab.stats(i)['issued']) for i in range(2)]}
    lab.fill(2, 'warmup');lab.offline();lab.snapshot_secrets()


def stable_read_retry(lab, label):
    lab.aligned(); lab.offline()
    before = lab.database_snapshot()
    for i in range(2):
        messages = [m for m in before['alpha_messages'] if m['sender'] == i]
        for m in messages:
            req = {'request_id': m['request_id'], 'envelope': m['envelope']}
            ack = lab.rpc(i, 'send', req)
            require(ack['ok'] and ack['result']['sequence'] == str(m['accepted']), 'exact accepted fact replay')
            original = lab.originals.get(m['message_id'])
            if original:
                require(lab.workers[i].call('request',requestId=m['request_id'])['outcome']['value']==original[2]['value'],
                        'every original SDK request and ciphertext retained')
        first = lab.workers[i].call('history', query={'direction': 'forward', 'page_size': 1})
        history = lab.history(i)
        require(lab.pages(i, first) == history and len(history)==256, 'full stable local history')
        for item in history:
            original = lab.originals[item['message']['message_id']]
            require(item['message']['text']==original[1], 'every decrypted original text retained')
        first = lab.rpc(i, 'poll', {'after': '0', 'limit': 4})['result']
        page = first; events = list(page['events'])
        while page['next'] != page['upper']:
            page = lab.rpc(i, 'poll', {'after': page['next'], 'upper': first['upper'], 'limit': 4})['result']
            require(page['upper'] == first['upper'], 'stable Service page upper')
            events += page['events']
        require(len(events) == int(first['upper']), 'all original device events accessible')
    m = before['alpha_messages'][0]
    bad = {'request_id': m['request_id'], 'envelope': {**m['envelope'], 'ciphertext': '00'}}
    require(lab.rpc(m['sender'], 'send', bad)['error']['code'] == 'idempotency_conflict', 'changed input rejected at full quota')
    require(lab.database_snapshot() == before, 'read/retry/conflict leave all twelve tables unchanged')
    with urllib.request.urlopen(lab.endpoint+'/healthz', context=lab.ssl, timeout=3) as response:
        require(response.status == 204, 'health at full quota')
    lab.report.setdefault('full_reads', []).append({'label': label, 'messages': len(before['alpha_messages']), 'exact_retries': len(before['alpha_messages'])})


def baseline(lab):
    lab.case('empty_state_resources', lambda: lab.checkpoint('empty'))
    lab.case('two_real_warmup_messages', lambda: start(lab))
    for target, phase in [(32,'low'), (128,'middle')]:
        lab.case('fill_'+phase, lambda target=target,phase=phase: lab.fill(target, phase))
    for i in range(2):
        stats=lab.stats(i)
        require(sum(c['reason']=='expired' for c in stats['calls'])>=3 and stats['peak']==1,
                'multiple actual expiries and one credential callback owner throughout load')
    lab.case('partial_normal_backup_new_target', lambda: lab.controlled_restore('partial-128'))
    def offline_queue():
        lab.offline(); ids = []
        for i in range(2):
            id = 'offline-'+str(i); lab.send(i,id); ids.append(id)
            require(lab.fact(id) is None and lab.status(i,id,'local_saved'), 'offline not accepted')
        for i in range(2): lab.auto(i); lab.online(i)
        lab.drain(ids, 'offline_queue')
    lab.case('offline_bilateral_original_queue', offline_queue)
    lab.case('fill_high', lambda: lab.fill(240, 'high'))
    lab.case('near_full_sigkill_reconcile', lambda: lab.cycle('near-full-240'))
    lab.case('near_full_normal_backup_restore', lambda: lab.controlled_restore('near-full-240'))
    lab.case('fill_near_full', lambda: lab.fill(256, 'near_full'))
    def local_limit():
        lab.aligned(); lab.offline(); before = lab.database_snapshot()
        for i,w in enumerate(lab.workers):
            original = lab.snapshot(i)
            w.call('send', expected='message_limit', requestId='local-overflow', messageId='local-overflow', text='PRIVATE_LOCAL_REJECT')
            require(w.call('request', requestId='local-overflow')['status'] == 'missing', 'no local reservation or crypto change')
            require(lab.snapshot(i) == original, 'local capacity rejection preserves state')
        require(lab.database_snapshot() == before, 'local rejection no Service changes')
    lab.case('both_sdk_message_limits_before_crypto', local_limit)
    lab.case('full_history_and_all_exact_retries', lambda: stable_read_retry(lab,'before-restore'))
    lab.case('full_normal_backup_restore_new_empty_target', lambda: lab.controlled_restore('full-256'))
    lab.case('full_sigkill_reconcile_and_reopen', lambda: lab.cycle('full-256'))
    lab.case('full_restored_history_and_all_exact_retries', lambda: stable_read_retry(lab,'after-restore'))
    lab.case('final_full_facts', lambda: lab.checkpoint('full_final'))
    lab.case('full_service_real_secret_samples', lab.snapshot_secrets)
    for i in range(2): lab.case('full_client_broad_samples_'+str(i), lambda i=i: lab.audit(i))


def overflow(lab):
    start(lab); lab.fill(254, 'overflow_preload'); lab.offline()
    # 三条都在各自本地额度内创建；先让A的两条实际接受，再让B提交第257条。
    ids = ['last-255','last-256']
    for id in ids: lab.send(0,id)
    text, sent = lab.send(1,'over-257')
    lab.auto(0); lab.online(0)
    wait(lambda: all(lab.fact(id) is not None for id in ids), '256 real Service acceptances')
    lab.auto(1)
    state = wait(lambda: (n if (n:=lab.workers[1].call('network'))['connection']=='blocked' else False), 'explicit new request rejection')
    require(state['error']['code']=='message_limit', 'Service full response propagated')
    require(lab.fact('over-257') is None and lab.status(1,'over-257','local_saved'), 'unaccepted ciphertext retained')
    lab.offline(); before = lab.database_snapshot(); local = lab.snapshot(1)
    req = {'request_id':'req-over-257','envelope':sent['value']['envelope']}
    for _ in range(3):
        require(lab.rpc(1,'send',req)['error']['code']=='message_limit','same actual rejected ciphertext stays rejected')
    require(lab.database_snapshot()==before,'257th creates no acceptance or mailbox event')
    require(lab.workers[1].call('send',requestId='req-over-257',messageId='over-257',text=text)['value']==sent['value'],'exact local rejection retry no crypto reexecution')
    require(lab.snapshot(1)==local,'rejection does not advance local cursors')
    lab.report['overflow']={'accepted':256,'new_request':'over-257','service_rejections':4,
        'result':'message_limit','local_record':'complete/local_saved retained',
        'limitation':'Unaccepted local send blocks subsequent sync; two accepted messages remain unread by B. No eviction or fabricated processing.'}
    for s in lab.samples:
        if s['message_id']=='over-257':s.update(phase='overflow',outcome='service_rejected_retained')
        elif s['message_id'] in ids:s.update(phase='overflow',outcome='accepted_receiver_offline')
    lab.checkpoint('full_with_rejected_local_queue')
    lab.case('overflow_exact_backup_restore',lambda:lab.controlled_restore('overflow-256',reconnect=False))
    lab.case('overflow_exact_sigkill_reconcile',lambda:lab.cycle('overflow-256',reconnect=False))
    require(lab.snapshot(1)==local,'original rejected queue and cursor after both recoveries')
    require(lab.database_snapshot()['alpha_messages']==before['alpha_messages'],'all original accepts after both recoveries')
    lab.case('overflow_service_real_secret_samples',lab.snapshot_secrets)
    for i in range(2):lab.case('overflow_client_broad_samples_'+str(i),lambda i=i:lab.audit(i))
