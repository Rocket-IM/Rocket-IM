"""真实E2EE固定原件的共同确认、失联、持久中断与终态验收。"""
from pathlib import Path
import json
from capacity_cases import start
from diagnostics_cases import secret_samples
from harness import require, wait, sha
from workset_harness import (enable, source, observe, service_state, boundaries, boundary,
                            transport, originals, locked, manifest_id, refused)


def conflicts(lab, index):
    state = lab.workers[index].call('workset'); w = state['workset']
    before = lab.database_snapshot()
    for field, value in [('sdk_instance', 'f'*64), ('context', 'e'*64), ('last', str(int(w['last'])+1)),
                         ('originals_hash', 'd'*64)]:
        changed = {**w, field: value}; changed['id'] = manifest_id(changed)
        reply = lab.rpc(index, 'capacity_workset_prepare', changed)
        require(not reply['ok'] and reply['error']['code'] == 'workset_conflict', 'different owner context or original conflicts')
    reply = lab.rpc(1-index, 'capacity_workset_prepare', w)
    require(not reply['ok'] and reply['error']['code'] in ('scope_mismatch', 'workset_conflict'), 'other device cannot claim owner')
    reply = lab.rpc(index, 'capacity_workset_settle', w)
    require(not reply['ok'] and reply['error']['code'] == 'workset_not_confirmed', 'out-of-order settlement is not success')
    require(before == lab.database_snapshot(), 'all rejected inputs preserve every row')
    for _ in range(2):
        require(lab.rpc(index, 'capacity_workset_prepare', w)['result'] == service_state(lab, index), 'exact same input uses existing row')
    require(before == lab.database_snapshot(), 'precise retries do not consume business request ledger')
    lab.consumer(token=lab.other_token).call('worksets', {}, code='forbidden')
    lab.consumer(token=lab.expired_token).call('worksets', {}, code='unauthorized')


def prepare(lab, index):
    source(lab, index, 'common-source-'+str(index))
    w = lab.workers[index]
    w.call('worksetCancel', expected='cancelled')
    require(w.call('workset') is None, 'cancel before dispatch creates no promise')
    # 先取得同一原库的格式2快照；后续不能借恢复撤销工作集。
    backup, info = lab.export(index, 'before-workset-'+str(index))
    require(info['format'] == 2, 'actual pre-workset backup2')
    refused(lab, index, 'prepare', None)
    boundaries(lab, index, 'prepare', None, 'prepared')
    state = observe(lab, index, 'local-prepared-'+str(index), 'prepared', None)
    originals(lab, index, state)
    path = Path(lab.workers[index].options['path']); checksum = sha(path)
    require(lab.workers[index].call('prepareWorkset') == state and sha(path) == checksum, 'repeat preparation returns same durable record without write')
    lab.roundtrip(index, backup, expected='backup_stale')
    locked(lab, index)


def handshake(lab, index, predecessor=None):
    for operation, before, after, remote_before, remote_after in (
        ('prepare', 'prepared', 'confirmed', 'settled' if predecessor else None, 'prepared'),
        ('confirm', 'confirmed', 'active', 'prepared', 'confirmed'),
        ('settle', 'active', 'settled', 'confirmed', 'settled')):
        transport(lab, index, operation, 'hold_workset_request', before, remote_before)
        transport(lab, index, operation, 'hold_workset_ack', before, remote_after, hits=2)
        if predecessor:
            from workset_repeat import replay_reply
            replay_reply(lab, index, predecessor, operation)
        # 远端已持久，但SDK不知道；真实Service异常退出后必须先通过原外部进度对账。
        lab.cycle('common-'+str(index)+'-'+operation, reconnect=False)
        observe(lab, index, 'reconciled-'+str(index)+'-'+operation, before, remote_after)
        if operation == 'prepare':
            conflicts(lab, index)
            if index == 0:
                lab.control.write_text(json.dumps({'mode': 'tamper_workset_ack', 'field': 'capacity_workset_prepare'}))
                lab.auto(index)
                wait(lambda: (lab.workers[index].call('network').get('error') or {}).get('code') == 'workset_reply_invalid', 'changed receipt explicitly blocks')
                lab.workers[index].call('disconnect');lab.control.write_text('{}')
                observe(lab, index, 'invalid-receipt-preserved', before, remote_after)
        # 已验证回复、写事务之前退出仍不发布下一阶段。
        refused(lab, index, operation+'-transition', before)
        boundary(lab, index, operation+'-reply', 'workset_after_'+operation+'_reply', before)
        boundaries(lab, index, operation+'-transition', before, after)
        state = observe(lab, index, 'durable-'+str(index)+'-'+after, after, remote_after)
        originals(lab, index, state)
        backup, info = lab.export(index, 'common-'+str(index)+'-'+after)
        require(info['format'] == (4 if predecessor else 3), 'actual complete versioned backup')
        lab.roundtrip(index, backup)
        require(lab.workers[index].call('workset') == state, 'exact workset through complete client restore')
        if after == 'active':
            reply = lab.rpc(index, 'capacity_workset_settle', state['workset'])
            require(not reply['ok'] and reply['error']['code'] == 'workset_not_complete', 'confirmation alone cannot settle unfinished originals')
    lab.aligned();lab.offline()
    state = lab.workers[index].call('workset')
    for op in ('prepare', 'confirm', 'settle'):
        require(lab.rpc(index, 'capacity_workset_'+op, state['workset'])['result'] == state, 'late exact packet cannot regress terminal state')
    require(lab.workers[index].call('prepareWorkset') == state, 'settled record remains one immutable set')


def run(lab):
    lab.case('explicit_schema7_and_local_known_policy', lambda: enable(lab))
    lab.case('real_e2ee_initial_originals', lambda: start(lab));lab.aligned();lab.offline()
    for i in range(2):
        lab.case('workset_local_prepare_boundaries_'+str(i), lambda i=i: prepare(lab, i))
        lab.case('workset_full_confirm_settle_boundaries_'+str(i), lambda i=i: handshake(lab, i))
    before = [w.call('workset') for w in lab.workers]
    lab.case('both_worksets_full_service_backup_restore', lambda: lab.controlled_restore('common-settled', reconnect=False))
    require([service_state(lab, i) for i in range(2)] == before, 'full Service backup retains both terminal records')
    lab.case('post_restore_common_originals', lambda: [originals(lab, i, before[i]) for i in range(2)])
    lab.case('common_secret_samples', lambda: secret_samples(lab))
    raw = json.dumps(lab.report['workset_observations']).encode()
    require(all(v.encode() not in raw for v in lab.texts+lab.tokens+lab.sessions+[lab.signing_key,lab.business_token]), 'workset evidence includes no actual secret sample')
    for i in range(2):
        lab.case('common_private_state_'+str(i), lambda i=i: lab.audit(i))
    lab.report['common_scope'] = {'version': 'control-workset-v1', 'participants': 'one authenticated Service and one SDK instance per immutable device workset',
        'cross_database_atomic': False, 'future_messages_promised': False, 'expiry_release': False,
        'real_e2ee': True, 'sqlite_fault_boundaries': len(lab.report['workset_sqlite_boundaries'])}


def full(lab):
    from rejection_cases import finish
    enable(lab);start(lab);lab.aligned();lab.offline()
    for i in range(2):
        source(lab, i, 'common-full-'+str(i))
        lab.workers[i].call('prepareWorkset');lab.auto(i)
        wait(lambda: (lab.workers[i].call('workset') or {}).get('phase') == 'settled', 'normal complete confirmation chain')
        lab.aligned();lab.offline()
    preserved = [w.call('workset') for w in lab.workers]
    for i in range(2):lab.auto(i)
    lab.fill(254, 'common-full-preload');lab.offline()
    accepted = ['common-final-0', 'common-final-1']; rejected = ['common-rejected']
    for id in accepted:lab.send(0, id)
    lab.send(1, rejected[0]);lab.auto(0)
    wait(lambda: all(lab.fact(id) for id in accepted), 'actual schema7 accepts256', 45)
    finish(lab, accepted, rejected)
    require([w.call('workset') for w in lab.workers] == preserved, 'full load and rejected original never replace settled records')
    for i in range(2):originals(lab, i, preserved[i])
    lab.case('full_common_secret_samples', lambda: secret_samples(lab))
