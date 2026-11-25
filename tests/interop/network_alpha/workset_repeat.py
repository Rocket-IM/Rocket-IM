"""真实Release两轮/三轮不同E2EE原件、旧终态和新轮持久边界；不写被测数据库。"""
from pathlib import Path
import json
from backup_harness import BackupFault
from capacity_cases import start
from diagnostics_cases import secret_samples
from harness import require, wait, sha
from workset_harness import enable, source, service_state, originals, locked
from workset_cases import handshake


def enable_repeat(lab):
    lab.offline();lab.stop_service()
    lab.maintenance('enable-repeated-workset')
    before = lab.database_snapshot()
    lab.maintenance('enable-repeated-workset')
    require(before == lab.database_snapshot() and before['schema_version'] == [{'version': 8}], 'explicit schema8 exactly idempotent')
    lab.start_service()


def settle(lab, index):
    lab.auto(index)
    wait(lambda: lab.workers[index].call('workset')['phase'] == 'settled', 'actual repeated confirmation and settlement')
    lab.aligned();lab.offline()
    state = lab.workers[index].call('workset')
    require(service_state(lab, index) == state, 'same terminal workset')
    originals(lab, index, state)
    return state


def histories(lab, index, expected):
    row = next(r for r in lab.database_snapshot()['alpha_devices'] if r['device_index'] == index)
    require(row['capacity_workset_history'] == expected, 'all Service predecessor terminals retained exactly')
    for state in expected:originals(lab, index, state)
    lab.report.setdefault('repeated_histories', []).append({'device': index, 'history': expected, 'current': service_state(lab, index)})
    lab.save()


def next_boundary(lab, index, previous, hook, committed):
    before = lab.snapshot(index);old = lab.workers[index].call('workset')
    fault = BackupFault(lab, index, hook)
    try:fault.interrupt({'op': 'prepare_next_capacity_workset', 'previous': previous})
    finally:fault.close()
    lab.restore(index);now = lab.workers[index].call('workset')
    if committed:
        require(now['phase'] == 'prepared' and now['workset']['previous'] == previous, 'only complete next candidate committed')
    else:require(now == old, 'precommit exit retains prior terminal')
    require(lab.snapshot(index) == before, 'next preparation preserves crypto originals history and cursors')
    lab.report.setdefault('repeat_sqlite_boundaries', []).append({'device': index, 'hook': hook, 'committed': committed, 'retained_predecessor': previous})
    lab.save()


def prepare_next(lab, index, previous):
    source(lab, index, 'repeat-second-'+str(index))
    old = lab.workers[index].call('workset');w = lab.workers[index]
    backup, info = lab.export(index, 'repeat-before-second-'+str(index))
    require(info['format'] == 3, 'real v7 backup retains terminal predecessor')
    w.call('nextWorksetCancel', previous=previous, expected='cancelled')
    require(w.call('workset') == old, 'cancel before dispatch cannot allocate successor')
    before = lab.snapshot(index)
    fault = BackupFault(lab, index, 'repeat_commit_failure', extra={'ROCKET_IM_TEST_COMMIT_FAILURE': '1'})
    try:
        fault.sequence += 1
        fault.process.stdin.write(json.dumps({'id': str(fault.sequence), 'operation': {'op': 'prepare_next_capacity_workset', 'previous': previous}})+'\n');fault.process.stdin.flush()
        reply = fault.next()
        require(reply and not reply['ok'] and reply['error']['code'] == 'workset_commit_unknown', 'unknown next commit never reports success')
    finally:fault.close()
    lab.restore(index)
    require(lab.workers[index].call('workset') == old and lab.snapshot(index) == before, 'unknown commit preserves prior and all originals')
    for hook in ('workset_before_write', 'workset_after_write', 'workset_after_progress_reserve'):
        next_boundary(lab, index, previous, hook, False)
    next_boundary(lab, index, previous, 'workset_after_sql_commit' if index == 0 else 'workset_after_progress_confirm', True)
    current = lab.workers[index].call('workset')
    path = Path(lab.workers[index].options['path']);checksum = sha(path)
    values = lab.workers[index].call('nextWorksetConcurrent', previous=previous)
    require(values == [current, current] and sha(path) == checksum, 'same predecessor concurrent retries are read-only')
    lab.workers[index].call('prepareNextWorkset', previous=current['workset']['id'], expected='workset_not_settled')
    require(int(current['workset']['first']) > int(old['workset']['last']) and current['workset']['originals_hash'] != old['workset']['originals_hash'], 'second actual distinct originals beyond prior range')
    lab.roundtrip(index, backup, expected='backup_stale')
    originals(lab, index, current);locked(lab, index)


def replay_reply(lab, index, old, operation):
    current = lab.workers[index].call('workset')
    lab.control.write_text(json.dumps({'mode': 'replay_workset_ack', 'field': 'capacity_workset_'+operation, 'workset_reply': old}))
    lab.auto(index)
    wait(lambda: (lab.workers[index].call('network').get('error') or {}).get('code') == 'workset_reply_invalid', 'actual older valid reply cannot advance successor')
    lab.workers[index].call('disconnect');lab.control.write_text('{}')
    require(lab.workers[index].call('workset') == current, 'old ID reply never changes next phase')
    lab.report.setdefault('repeat_reply_replays', []).append({'device':index,'operation':operation,'old':old,'current':current})
    lab.save()


def third(lab, index, first, second):
    source(lab, index, 'repeat-third-'+str(index))
    previous = second['workset']['id']
    # 调用取消与数据库提交可能竞速；只有读取已持久记录才能判断，不能据取消回收。
    lab.workers[index].call('nextWorksetCancelInFlight', previous=previous, expected='cancelled_unknown')
    lab.workers[index].close();lab.restore(index)
    now = lab.workers[index].call('workset')
    if now == second:
        next_boundary(lab, index, previous, 'workset_after_next_prepared', True)
    else:require(now['workset']['previous'] == previous and now['phase'] == 'prepared', 'cancelled call may have durably prepared')
    current = lab.workers[index].call('prepareNextWorkset', previous=previous)
    require(lab.workers[index].call('prepareNextWorkset', previous=first['workset']['id']) == second, 'old predecessor retry returns exact historical second')
    for op in ('prepare','confirm','settle'):
        for old in (first,second):require(lab.rpc(index, 'capacity_workset_'+op, old['workset'])['result'] == old, 'historical request returns corresponding old terminal')
    replay_reply(lab, index, second, 'prepare')
    require(lab.workers[index].call('workset') == current, 'third round stays prepared after replay')
    result = settle(lab, index);histories(lab, index, [first, second])
    return result


def run(lab):
    enable(lab);start(lab);lab.aligned();lab.offline()
    lab.case('enable_repeat_schema8', lambda: enable_repeat(lab))
    first = []
    for i in range(2):
        source(lab, i, 'repeat-first-'+str(i));lab.workers[i].call('prepareWorkset')
        first.append(settle(lab, i))
    lab.report['repeated_first'] = first
    second = []
    for i in range(2):
        lab.case('repeat_next_prepare_boundaries_'+str(i), lambda i=i: prepare_next(lab, i, first[i]['workset']['id']))
        lab.case('repeat_confirm_settle_boundaries_'+str(i), lambda i=i: handshake(lab, i, first[i]))
        second.append(lab.workers[i].call('workset'));histories(lab, i, [first[i]])
    for i in range(2):lab.case('third_round_replay_cancel_'+str(i), lambda i=i: third(lab, i, first[i], second[i]))
    before = [w.call('workset') for w in lab.workers]
    lab.case('repeated_full_service_backup', lambda: lab.controlled_restore('repeated-terminals', reconnect=False))
    for i in range(2):
        path,info=lab.export(i,'repeated-all-'+str(i));require(info['format']==4,'actual complete v8 backup4')
        lab.case('repeated_full_client_backup_'+str(i),lambda i=i,path=path:lab.roundtrip(i,path))
        require(lab.workers[i].call('workset')==before[i], 'full backup preserves current')
        require(lab.workers[i].call('prepareNextWorkset',previous=first[i]['workset']['id'])==second[i], 'full client restore preserves historical successor')
        histories(lab,i,[first[i],second[i]])
        lab.case('repeated_private_state_'+str(i),lambda i=i:lab.audit(i))
    lab.case('repeated_secret_samples',lambda:secret_samples(lab))
    lab.report['repeat_scope']={'real_e2ee':True,'rounds_per_device':3,'hard_event_bound':512,'unbounded_repeat':False,'cross_database_atomic':False,'old_promises_deleted':False}


def full(lab):
    from rejection_cases import finish
    enable(lab);start(lab);lab.aligned();lab.offline();enable_repeat(lab)
    prior=[None,None];first=[None,None]
    for round_number in range(2):
        for i in range(2):
            source(lab,i,'repeat-full-'+str(round_number)+'-'+str(i))
            if prior[i]:lab.workers[i].call('prepareNextWorkset',previous=prior[i]['workset']['id'])
            else:lab.workers[i].call('prepareWorkset')
            prior[i]=settle(lab,i)
            if round_number==0:first[i]=prior[i]
    for i in range(2):lab.auto(i)
    # start已有2条，四条工作集原件，继续到254后验证256/257原边界。
    lab.fill(254,'repeat-full-preload');lab.offline()
    accepted=['repeat-final-0','repeat-final-1'];rejected=['repeat-rejected']
    for label in accepted:lab.send(0,label)
    lab.send(1,rejected[0]);lab.auto(0)
    wait(lambda:all(lab.fact(label) for label in accepted),'real repeated schema8 accepts256',45)
    finish(lab,accepted,rejected)
    require([w.call('workset') for w in lab.workers]==prior,'256/257 load never replaces terminal chain')
    for i in range(2):originals(lab,i,prior[i]);histories(lab,i,[first[i]])
    lab.case('repeated_full_secret_samples',lambda:secret_samples(lab))
