"""真实旧库、恢复窗口、分页与系统拒绝；消费者只使用已安装 npm 的公开接口。"""
import json
import os
from pathlib import Path
import secrets
import selectors
import subprocess
import time

from node_pack import node_binary, sha, write_json
from persistent_faults import Runtime
from persistent_keychain import run as control
from persistent_signing_packages import consume
from persistent_signing_acl import inspect

def history(consumer, mode, data, keychain, log):
    env = {k: v for k, v in os.environ.items() if not k.startswith('ROCKET_IM_TEST_')}
    env['PATH'] = str(Path(node_binary()).parent)
    p = subprocess.run([node_binary(), 'history-cases.mjs', mode, str(data), str(keychain)],
        cwd=consumer, env=env, capture_output=True, text=True, timeout=90)
    write_json(log, {'returncode': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr})
    assert p.returncode == 0 and not p.stderr, f'history consumer failed: {log}'
    result = json.loads(p.stdout); assert result['status'] == 'PASS'
    return result

def live(consumer, data, keychain, password, directory):
    env = {k: v for k, v in os.environ.items() if not k.startswith('ROCKET_IM_TEST_')}
    env['PATH'] = str(Path(node_binary()).parent)
    p = subprocess.Popen([node_binary(), 'history-live.mjs', str(data), str(keychain)], cwd=consumer,
        env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    selector = selectors.DefaultSelector(); selector.register(p.stdout, selectors.EVENT_READ)
    result = None; system = []
    try:
        deadline = time.monotonic() + 480
        while p.poll() is None:
            assert time.monotonic() < deadline, 'live consumer deadline'
            if not selector.select(1): continue
            line = p.stdout.readline()
            if not line: break
            value = json.loads(line)
            if 'fixture' in value:
                request = value['fixture']; assert request['keychain'] == str(keychain)
                assert request['op'] in ('lock', 'unlock')
                answer = control({**request, **({'password': password} if request['op'] == 'unlock' else {})})
                system.append({'op': request['op'], **answer})
                p.stdin.write(json.dumps(answer) + '\n'); p.stdin.flush()
            if 'result' in value: result = value['result']; break
        p.wait(timeout=10)
        stderr = p.stderr.read(); (directory / 'live-stderr.log').write_text(stderr)
        write_json(directory / 'live.json', {'result': result, 'system': system, 'returncode': p.returncode})
        assert p.returncode == 0 and not stderr and result and result['status'] == 'PASS_SCOPED', f'live consumer: {stderr}'
        return result
    finally:
        if p.poll() is None: p.kill(); p.wait(timeout=5)
        selector.close(); p.stdin.close(); p.stdout.close(); p.stderr.close()

def late_lock(fault, data, keychain, password, directory):
    barrier = directory / 'history-read-barrier'
    runtime = Runtime(fault, data / 'alice.db', 'alice', keychain=keychain,
        extra_env={'ROCKET_IM_TEST_BARRIER_PHASE': 'history_after_read', 'ROCKET_IM_TEST_BARRIER': str(barrier)},
        stderr_path=directory / 'late-history-stderr.log')
    try:
        runtime.process.stdin.write((json.dumps({'id': '1', 'operation': {'op': 'history',
            'query': {'direction': 'forward', 'page_size': 20}}}) + '\n').encode()); runtime.process.stdin.flush()
        deadline = time.monotonic() + 15
        while not Path(str(barrier) + '.ready').exists():
            assert time.monotonic() < deadline and runtime.process.poll() is None
            time.sleep(.01)
        assert control({'op': 'lock', 'keychain': str(keychain)})['status'] == 0
        Path(str(barrier) + '.release').write_text('release')
        reply = runtime.read()
        assert reply['ok'] is False and reply['result'] is None and reply['events'] == [] and reply['error']['code'] == 'keychain_locked', reply
        write_json(directory / 'late-history-result.json', reply)
        return {'status': 'PASS', 'checkpoint': 'after history read transaction commit', 'reply': reply}
    finally:
        runtime.close()
        assert control({'op': 'unlock', 'keychain': str(keychain), 'password': password})['status'] == 0

def run(consumers, old_fault, new_fault, data_root, directory):
    directory.mkdir(); observations = []; keychains = []
    scenarios = [('ordinary', None, 'none')]
    scenarios += [(p, p, 'none') for p in ('after_reserve', 'after_candidate', 'after_commit', 'refuse_commit')]
    scenarios += [('recovery-' + stage, 'after_crypto', stage) for stage in ('none', 'offered', 'prepared', 'ready', 'committed', 'finished')]
    def record(result):
        observations.append(result); write_json(directory / 'progress.json', observations)
        return result
    def invoke(which, mode, data, keychain, stage='none'):
        return record(consume(consumers[which], mode, data, keychain, stage,
            directory / f'{data.name}-{which}-{mode}-{stage}.json'))
    def read(mode, data, keychain, which='new'):
        return record(history(consumers[which], mode, data, keychain, directory / f'{data.name}-{which}-history-{mode}.json'))
    def create(data):
        data.mkdir(parents=True); path = data / 'lab-history.keychain-db'; keychains.append(path)
        password = secrets.token_hex(32)
        assert control({'op': 'create', 'keychain': str(path), 'password': password})['status'] == 0
        return path, password
    try:
        for label, phase, stage in scenarios:
            data = data_root / label; keychain, password = create(data)
            invoke('old', 'setup', data, keychain)
            acl = {a: inspect(keychain, data / (a + '.db'), a) for a in ('alice', 'bob')}
            if phase:
                runtime = Runtime(old_fault, data / 'alice.db', 'alice', keychain=keychain,
                    fault=phase if phase != 'refuse_commit' else None, refuse=phase == 'refuse_commit',
                    stderr_path=directory / (label + '-fault-stderr.log'))
                try:
                    runtime.execute('target', {'kind': 'send', 'message_id': 'target', 'text': 'upgrade pending message'},
                        **({'error': 'commit_unknown'} if phase == 'refuse_commit' else {'exited': True}))
                finally: runtime.close()
                invoke('old', 'prepare', data, keychain, stage)
            before = {a: sha(data / (a + '.db')) for a in acl}
            read('capture', data, keychain)
            assert before == {a: sha(data / (a + '.db')) for a in acl}, 'history changed old database bytes'
            if label == 'ordinary':
                record(late_lock(new_fault, data, keychain, password, directory))
                assert before == {a: sha(data / (a + '.db')) for a in acl}
            assert control({'op': 'lock', 'keychain': str(keychain)})['status'] == 0
            invoke('new', 'deny', data, keychain, 'keychain_locked')
            assert control({'op': 'unlock', 'keychain': str(keychain), 'password': password})['status'] == 0
            invoke('new', 'resume', data, keychain, 'successor' if phase == 'after_crypto' else 'exact')
            read('continued', data, keychain)
            invoke('old', 'verify', data, keychain)
            if label == 'ordinary':
                read('old-append', data, keychain, 'old')
                read('after-old-writes', data, keychain)
            assert acl == {a: inspect(keychain, data / (a + '.db'), a) for a in acl}, 'original ACL changed'
            write_json(directory / (label + '-preservation.json'), {'read_only_database_sha256': before,
                'read_only_bytes_unchanged': True, 'original_acl_unchanged': True, 'acl': acl})
        data = data_root / 'live'; keychain, password = create(data)
        record(live(consumers['new'], data, keychain, password, directory))
        assert all(p.read_bytes() == b'' for p in directory.glob('*stderr.log'))
        return {'status': 'PASS_SCOPED', 'scenarios': len(scenarios), 'observations': observations}
    finally:
        cleanup = []
        for keychain in keychains:
            if keychain.exists():
                cleanup.append({'path': str(keychain), 'lock': control({'op': 'lock', 'keychain': str(keychain)}),
                    'state': control({'op': 'status', 'keychain': str(keychain)})})
        write_json(directory / 'cleanup.json', cleanup)
        assert all(x['lock']['status'] == 0 and x['state']['status'] == 0 and not x['state']['unlocked'] for x in cleanup)
