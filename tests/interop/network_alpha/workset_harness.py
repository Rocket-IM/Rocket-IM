"""共同工作集只通过真实公开包操作；原故障程序触发原SQLite持久边界。"""
from pathlib import Path
import hashlib
import json
from backup_harness import BackupFault
from commit_faults import FaultRuntime
from harness import require, wait, sha
from reserve_cases import capture, work


def service_state(lab, index):
    reply = lab.rpc(index, 'capacity_workset_query', {})
    require(reply['ok'], 'authenticated Service workset query')
    value = reply['result']
    if lab.operator:
        require(lab.consumer().call('worksets', {})[index] == value, 'independent public Go SDK agrees')
    return value


def phase(value):
    return value['phase'] if value else None


def observe(lab, index, label, local_phase, remote_phase):
    local = lab.workers[index].call('workset')
    remote = service_state(lab, index)
    require(phase(local) == local_phase and phase(remote) == remote_phase, 'exact durable phases '+label)
    if local and remote:
        require(local['workset'] == remote['workset'], 'same full owner context originals and ID')
    capacity, global_value = capture(lab, label)
    row = {'label': label, 'device': index, 'local': local, 'service': remote,
           'local_capacity': capacity[index], 'service_capacity': global_value}
    lab.report.setdefault('workset_observations', []).append(row)
    lab.save()
    return local


def enable(lab):
    lab.offline()
    for w in lab.workers:
        w.call('reserveCapacity')
    lab.stop_service()
    lab.maintenance('enable-capacity-reserve')
    lab.maintenance('enable-capacity-workset')
    before = lab.database_snapshot()
    lab.maintenance('enable-capacity-workset')
    require(before == lab.database_snapshot(), 'schema7 enable precisely idempotent')
    require(before['schema_version'] == [{'version': 7}], 'explicit schema7 migration')
    lab.start_service()


def source(lab, index, label):
    lab.offline()
    text, sent = lab.send(index, label)
    lab.auto(index)
    wait(lambda: lab.status(index, label, 'accepted'), 'real original acceptance')
    lab.workers[index].call('disconnect')
    peer = 1-index
    lab.auto(peer)
    wait(lambda: any(m['message']['message_id'] == label and m['message']['text'] == text
                     for m in lab.history(peer)), 'actual peer E2EE decrypt')
    wait(lambda: lab.fact(label)['delivered'], 'peer actually reports original')
    lab.workers[peer].call('disconnect')
    fault = FaultRuntime(lab, index, 'network_after_download')
    lab.report.setdefault('fault_processes', []).append({'pid': fault.process.pid, 'phase': 'network_after_download'})
    try:
        fault.exited()
    finally:
        fault.close()
    lab.restore(index)
    cap = lab.workers[index].call('capacity')
    require(work(cap, 'known_control') == work(cap, 'known_report') == 1, 'fixed downloaded known control')
    require(lab.workers[index].call('request', requestId='req-'+label)['outcome']['value'] == sent['value'], 'original crypto outcome unchanged')
    return text, sent


def boundary(lab, index, stage, hook, expected):
    before = lab.snapshot(index)
    original = lab.workers[index].call('workset')
    fault = BackupFault(lab, index, hook)
    try:
        if stage == 'prepare':
            fault.interrupt({'op': 'prepare_capacity_workset'})
        else:
            fault.call({'op': 'connect', 'options': lab.connect_options[index]})
            fault.exited()
    finally:
        fault.close()
    lab.restore(index)
    now = lab.workers[index].call('workset')
    require(phase(now) == expected, 'only durable phase after '+hook)
    if original and now:
        require(original['workset'] == now['workset'], 'immutable original workset after '+hook)
    require(lab.snapshot(index) == before, 'control handshake does not alter crypto history queue or cursors')
    lab.report.setdefault('workset_sqlite_boundaries', []).append({
        'device': index, 'transition': stage, 'hook': hook, 'phase': expected, 'exit': 86,
        'originals_preserved': True})
    lab.save()


def boundaries(lab, index, stage, before, after):
    for hook in ('workset_before_write', 'workset_after_write', 'workset_after_progress_reserve'):
        boundary(lab, index, stage, hook, before)
    hook = 'workset_after_sql_commit' if index == 0 else 'workset_after_progress_confirm'
    boundary(lab, index, stage, hook, after)


def refused(lab, index, stage, expected):
    before = lab.snapshot(index)
    fault = BackupFault(lab, index, 'workset_commit_failure', extra={'ROCKET_IM_TEST_COMMIT_FAILURE': '1'})
    try:
        if stage == 'prepare':
            fault.sequence += 1
            fault.process.stdin.write(json.dumps({'id': str(fault.sequence), 'operation': {'op': 'prepare_capacity_workset'}})+'\n')
            fault.process.stdin.flush();reply = fault.next()
            require(reply and not reply['ok'] and reply['error']['code'] == 'workset_commit_unknown', 'commit error never returns local prepare success')
        else:
            fault.call({'op': 'connect', 'options': lab.connect_options[index]})
            state = wait(lambda: (s if (s := fault.call({'op': 'network_state'}))['connection'] == 'blocked' else False), 'unknown local commit blocks networking')
            require(state['error']['code'] == 'workset_commit_unknown', 'explicit unknown phase commit result')
    finally:
        fault.close()
    lab.restore(index)
    require(phase(lab.workers[index].call('workset')) == expected and lab.snapshot(index) == before, 'failed commit retains original phase crypto history and cursors')
    lab.report.setdefault('workset_unknown_returns', []).append({'device': index, 'stage': stage,
        'error': 'workset_commit_unknown', 'retained_phase': expected, 'originals_preserved': True})
    lab.save()


def transport(lab, index, operation, mode, local_phase, remote_phase, hits=1):
    lab.control.write_text(json.dumps({'mode': mode, 'field': 'capacity_workset_'+operation}))
    lab.auto(index)
    wait(lambda: json.loads(lab.control.read_text()).get('hits', 0) >= hits, 'actual '+mode+' '+operation, 30)
    lab.workers[index].call('disconnect')
    # 取消原连接后，迟到回复不能写入下一次会话。
    value = observe(lab, index, mode+'-'+operation, local_phase, remote_phase)
    lab.control.write_text('{}')
    return value


def manifest_id(w):
    s = w['owner']['scope']
    fields = ['rocket-im/capacity-workset/1', w['version'], s['service'], s['account'], s['device'],
              w['owner']['identity_key'], w['sdk_instance'], w['conversation'], w['context'],
              w['first'], w['last'], w['originals_hash']]
    return hashlib.sha256(json.dumps(fields, separators=(',', ':')).encode()).hexdigest()


def originals(lab, index, state):
    w = state['workset']
    data = lab.database_snapshot()
    accepted = {m['request_id']: m for m in data['alpha_messages'] if m['sender'] == index}
    events = sorted([r['event'] for r in data['alpha_mailbox'] if r['device_index'] == index
                     and int(w['first']) <= r['sequence'] <= int(w['last'])], key=lambda e: int(e['sequence']))
    fields = []
    for e in events:
        a = e['acceptance']; original = accepted[a['request_id']]
        require(lab.workers[index].call('request', requestId=a['request_id'])['outcome']['value']['envelope'] == original['envelope'], 'each SDK original equals accepted Service ciphertext')
        fields.append([e['sequence'], e['kind'], a['request_id'], a['message_id'], a['sequence'],
                       a['envelope_hash'], original['envelope']['context']])
    digest = hashlib.sha256(json.dumps(['rocket-im/control-originals/1', fields], separators=(',', ':')).encode()).hexdigest()
    require(len(fields) == int(w['last'])-int(w['first'])+1 and digest == w['originals_hash'], 'independent original input digest')
    require(manifest_id(w) == w['id'], 'independent canonical workset ID')


def locked(lab, index):
    from harness import persistent_keychain
    w = lab.workers[index]; before = w.call('workset'); checksum = sha(Path(w.options['path']))
    try:
        require(persistent_keychain.run({'op': 'lock', 'keychain': w.options['keychain']})['status'] == 0, 'lock own current test keychain')
        w.call('workset', expected='keychain_locked')
        w.call('prepareWorkset', expected='keychain_locked')
    finally:
        require(persistent_keychain.run({'op': 'unlock', 'keychain': w.options['keychain'], 'password': lab.keychain_passwords[index]})['status'] == 0, 'unlock only current owned keychain')
    require(w.call('workset') == before and sha(Path(w.options['path'])) == checksum, 'lock preserves workset and quota bytes')
