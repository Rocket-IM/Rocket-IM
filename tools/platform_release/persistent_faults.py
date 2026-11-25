"""独立测试二进制的确定退出/拒绝提交；正常交付包不含这些故障入口。"""
import json
import os
from pathlib import Path
import selectors
import subprocess

class Runtime:
    def __init__(self, binary, path, account, create=False, fault=None, refuse=False, refuse_journal=False, upgrade=False, refuse_recovery=None, keychain=None, extra_env=None, stderr_path=None):
        env = {k:v for k,v in os.environ.items() if not k.startswith("ROCKET_IM_TEST_")}
        if fault:
            env['ROCKET_IM_TEST_EXIT_PHASE'] = fault
        if refuse:
            env['ROCKET_IM_TEST_COMMIT_FAILURE'] = '1'
        if refuse_journal:
            env['ROCKET_IM_TEST_JOURNAL_FAILURE'] = '1'
        if refuse_recovery:
            env['ROCKET_IM_TEST_RECOVERY_FAILURE'] = refuse_recovery
        if extra_env: env.update(extra_env)
        self.stderr_file = Path(stderr_path).open('wb') if stderr_path else None
        self.process = subprocess.Popen([str(binary), str(path), 'test', account, 'one', 'upgrade' if upgrade else 'create' if create else 'open'] + ([str(keychain)] if keychain else []),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr_file or subprocess.DEVNULL, env=env)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.sequence = 0
        ready = self.read()
        if ready.get('ready') is not True:
            self.close()
            raise AssertionError(ready)
    def read(self):
        if not self.selector.select(10):
            raise TimeoutError('runtime response timeout')
        data = self.process.stdout.readline(1024 * 1024 + 1)
        return json.loads(data) if data else None
    def call(self, operation, exited=False, error=None):
        self.sequence += 1
        self.process.stdin.write((json.dumps({'id': str(self.sequence), 'operation': operation}) + '\n').encode())
        self.process.stdin.flush()
        reply = self.read()
        if exited:
            assert reply is None
            assert self.process.wait(timeout=5) == 86
            return None
        assert reply is not None, 'unexpected process exit'
        if error:
            assert not reply['ok'] and reply['error']['code'] == error and reply['events'] == [], reply
            return reply['error']
        assert reply['ok'], reply
        return reply['result']
    def execute(self, request, action, **kw):
        return self.call({'op':'execute','request_id':request,'action':action}, **kw)
    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.selector.close()
        self.process.stdout.close()
        if not self.process.stdin.closed:
            self.process.stdin.close()
        if self.stderr_file and not self.stderr_file.closed:
            self.stderr_file.close()

def run(normal, fault_binary, directory):
    cases = []
    for operation in ('join', 'send', 'receive'):
        for phase in ('after_reserve', 'after_crypto', 'before_commit', 'after_commit', 'refuse_commit'):
            folder = directory / (operation + '-' + phase)
            folder.mkdir(parents=True)
            handles = []
            def start(binary, account, **kwargs):
                obj = Runtime(binary, folder / (account + '.db'), account, **kwargs)
                handles.append(obj)
                return obj
            try:
                a, b = start(normal, 'alice', create=True), start(normal, 'bob', create=True)
                for d in (a,b):
                    d.execute('init', {'kind':'initialize'})
                am = a.call({'op':'joining_material'}); bm = b.call({'op':'joining_material'})
                welcome = a.execute('create', {'kind':'create_group','conversation':'chat','peer':bm['identity'],'key_package':bm['key_package']})['value']['welcome']
                join = {'kind':'join_group','conversation':'chat','peer':am['identity'],'welcome':welcome}
                send = {'kind':'send','message_id':'message','text':'测试提交故障'}
                if operation != 'join':
                    b.execute('join', join)
                if operation == 'receive':
                    envelope = a.execute('send', send)['value']['envelope']
                    action = {'kind':'receive','envelope':envelope}
                else:
                    action = join if operation == 'join' else send
                target, account = (a, 'alice') if operation == 'send' else (b, 'bob')
                before = target.call({'op':'state'})
                target.close()
                faulty = start(fault_binary, account, fault=None if phase == 'refuse_commit' else phase, refuse=phase == 'refuse_commit')
                if phase == 'refuse_commit':
                    faulty.execute('target', action, error='commit_unknown')
                else:
                    faulty.execute('target', action, exited=True)
                faulty.close()
                restored = start(normal, account)
                state = restored.call({'op':'state'})
                result = restored.call({'op':'request','request_id':'target'})
                if phase == 'after_commit':
                    assert result['status'] == 'complete' and state['pending_request'] is None
                    retry = restored.execute('target', action)
                    assert retry['cached'] and retry['value'] == result['outcome']['value']
                    if operation == 'send':
                        got = b.execute('continued', {'kind':'receive','envelope':retry['value']['envelope']})
                        assert got['value']['message']['text'] == send['text']
                    elif operation == 'join':
                        envelope = a.execute('continued', send)['value']['envelope']
                        restored.execute('continued', {'kind':'receive','envelope':envelope})
                    else:
                        assert state['received_count'] == '1'
                    sender, receiver = (restored, b) if operation == 'send' else (restored, a)
                    back = sender.execute('back', {'kind':'send','message_id':'back','text':'恢复通信'})['value']['envelope']
                    receiver.execute('back', {'kind':'receive','envelope':back})
                else:
                    assert result['status'] == 'pending' and state['pending_request'] == 'target'
                    assert state['revision'] == before['revision'] and state['received_count'] == before['received_count']
                    assert state['conversation'] == before['conversation']
                    restored.execute('target', action, error='operation_pending')
                cases.append({'name':operation+'-'+phase,'status':'PASS','request_status':result['status'], 'revision':state['revision']})
            finally:
                for d in reversed(handles):
                    d.close()
    return cases
