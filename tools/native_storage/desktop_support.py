"""独立 Node 消费进程与合成 Rust 对端；控制器不实现密码或客户端存储。"""
import json
import os
import selectors
import subprocess
import time
from crypto_support import CryptoProbe, redact, success
from support import require
from desktop_package import node_binary

SCOPE = {'service': 'local-service', 'account': 'alice', 'device': 'alice-device'}


class Host:
    def __init__(self, consumer, directory, records):
        self.records = records
        self.sequence = 0
        self.buffer = b''
        self.closed = False
        self.children = []
        self.stderr = (directory / 'node-stderr.log').open('ab')
        # 实际消费环境没有 Cargo、Rust 或生成器路径。
        env = os.environ.copy()
        env['PATH'] = str(directory / 'no-build-tools')
        env.pop('CARGO_HOME', None)
        env.pop('RUSTUP_HOME', None)
        self.process = subprocess.Popen([node_binary(), consumer / 'host.mjs'], cwd=consumer, env=env,
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        records.append({'direction': 'node_spawn', 'pid': self.process.pid, 'PATH': env['PATH']})

    def request(self, op, name='a', **values):
        self.sequence += 1
        request = {'id': str(self.sequence), 'op': op, 'name': name, **values}
        self.records.append({'direction': 'node_request', 'payload': redact(request)})
        self.process.stdin.write((json.dumps(request, ensure_ascii=False) + '\n').encode())
        self.process.stdin.flush()
        deadline = time.monotonic() + 15
        while b'\n' not in self.buffer:
            require(time.monotonic() < deadline, 'Node 响应超时')
            if self.selector.select(0.1):
                chunk = os.read(self.process.stdout.fileno(), 65536)
                require(chunk, 'Node 在响应前退出')
                self.buffer += chunk
                require(len(self.buffer) < 2 * 1024 * 1024, 'Node 响应过量')
        line, self.buffer = self.buffer.split(b'\n', 1)
        reply = json.loads(line)
        require(reply['id'] == request['id'], 'Node 关联 ID 错误')
        self.records.append({'direction': 'node_response', 'payload': redact(reply)})
        if op == 'open' and reply['ok']:
            self.children.append(reply['result']['pid'])
            require(reply['result']['databaseThread'] != reply['result']['coordinatorThread'], '数据库线程未隔离')
        return reply

    def ok(self, op, name='a', **values):
        reply = self.request(op, name, **values)
        require(reply['ok'], f'Node 请求失败: {reply}')
        return reply.get('result')

    def fail(self, op, code, name='a', **values):
        reply = self.request(op, name, **values)
        require(not reply['ok'] and reply['error']['code'] == code, f'Node 拒绝不符: {reply}')
        return reply['error']

    def open(self, database, name='a', create=False, scope=None, timeout=10000):
        return self.ok('open', name, options={'path': str(database), 'scope': scope or SCOPE,
                                            'create': create, 'timeoutMs': timeout})

    def close(self):
        if self.closed:
            return
        try:
            self.ok('exit')
            require(self.process.wait(timeout=5) == 0, 'Node 非正常退出')
        finally:
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait(timeout=5)
            self.closed = True
            self.selector.close()
            self.process.stdin.close()
            self.process.stdout.close()
            self.stderr.close()
            leaked = []
            for pid in self.children:
                try: os.kill(pid, 0); leaked.append(pid)
                except ProcessLookupError: pass
            self.records.append({'direction': 'node_exit', 'pid': self.process.pid,
                                 'code': self.process.returncode, 'rust_pids': self.children, 'leaked': leaked})
            require(not leaked, 'Rust 子进程未回收')

    def __enter__(self): return self
    def __exit__(self, exc_type, error, traceback):
        try: self.close()
        except Exception as cleanup_error:
            if error is None: raise
            error.add_note(f'清理同时失败: {cleanup_error}')
            self.records.append({'direction':'cleanup_error','error':str(cleanup_error)})


def peer(binary, directory, records):
    return CryptoProbe(binary, directory / 'unused-peer.db', directory, records, account='bob', device='bob-device',
                       flags=('--memory-peer', '--test-mode'), timeout=180)


def setup(host, other, database):
    host.open(database, create=True)
    identity = host.ok('initialize', requestId='initialize')['value']
    remote = success(other.request('peer_identity'))
    welcome = host.ok('createGroup', requestId='create-group', conversation='test-conversation', peer=remote)['value']['welcome']
    success(other.request('peer_join', conversation='test-conversation', peer=identity, welcome=welcome))
    return identity


def send(host, suffix='one', **values):
    return host.ok('send', requestId=f'send-{suffix}', attemptId=f'attempt-{suffix}', messageId=f'message-{suffix}',
                   text=f'合成中文🙂{suffix}', **values)


def peer_send(other, suffix='one'):
    return success(other.request('peer_send', message_id=f'peer-message-{suffix}', text=f'合成对端🙂{suffix}'))
