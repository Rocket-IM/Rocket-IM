"""真实 npm 消费：持久化、隔离、异步事件、生命周期和 SQLite 锁负例。"""
import os
import signal
import sqlite3
import threading
from crypto_support import success
from desktop_support import Host, SCOPE, peer, setup, send, peer_send
from support import require


def normal(consumer, binary, directory, records):
    database = directory / '桌面 state.db'
    with peer(binary, directory, records) as other:
        with Host(consumer, directory, records) as host:
            identity = setup(host, other, database)
            sent = send(host)
            decoded = success(other.request('peer_receive', envelope=sent['value']))
            require(decoded['text'] == '合成中文🙂one', '真实发送未解密')
            incoming = peer_send(other)
            received = host.ok('receive', requestId='receive-one', sequence='1', envelope=incoming)
            require(received['value']['message']['text'] == '合成对端🙂one', '真实接收不符')
            before = host.ok('state')
            require(before['receivedCount'] == 1 and before['processedCursor'] == '1' and len(before['outbox']) == 1, '原子收发状态不符')
            require(send(host)['cached'], '发送重试未命中')
            duplicate = host.ok('receive', requestId='receive-one', sequence='1', envelope=incoming)
            require(duplicate['cached'] and host.ok('state') == before, '精确接收重试改变状态')
            duplicate = host.ok('receive', requestId='receive-two', sequence='2', envelope=incoming)
            require(duplicate['value']['duplicate'], '异槽重复未去重')
            require(host.ok('state')['receivedCount'] == 1, '重复生成正文')
            next_envelope = peer_send(other, 'two')
            raw = [{'sequence':'1','envelope':incoming}, {'sequence':'2','envelope':incoming}, {'sequence':'3','envelope':next_envelope}]
            download = host.ok('download', records=raw)
            require(download['downloadCursor'] == '3' and download['processedCursor'] == '2', '下载游标与处理游标未分离')
            result = host.ok('process', requestId='process-three', sequence='3')
            require(result['value']['message']['text'] == '合成对端🙂two', '处理结果错误')
            final = host.ok('state')
            require(final['receivedCount'] == 2 and final['processedCursor'] == final['downloadCursor'] == '3', '最终游标不符')
            events = host.ok('events')
            require(len(events) == 6, f'成功/重试/重复事件数量错误 {len(events)}')
            require(all(e['change']['scope'] == SCOPE and int(e['revisionRead']) >= int(e['change'].get('revision','0')) for e in events), '事件回调未读到已提交状态')
            host.ok('close'); host.ok('close')
            host.fail('state', 'closed')
            host.open(database)
            require(host.ok('state') == final, '同 Node 关闭重开状态变化')
        with Host(consumer, directory, records) as restart:
            restart.open(database)
            require(restart.ok('state') == final, '独立 Node/Rust 重启没有恢复')
            restored = send(restart)
            require(restored['cached'] and restored['value'] == sent['value'], '重启没有返回原密文')
            require(restart.ok('received', sequence='3') == result['value'], '已提交正文没有恢复')
            require(restart.ok('events') == [], '恢复读取或缓存重复发事件')
            new = send(restart, 'after-restart')
            require(success(other.request('peer_receive', envelope=new['value']))['text'] == '合成中文🙂after-restart', '重启密码状态不可用')
    return {'identity':identity, 'final':final, 'events':events, 'persistent_peers':1, 'memory_peers':1}


def isolation(consumer, binary, directory, records):
    database = directory / 'a.db'
    with peer(binary, directory, records) as other, Host(consumer, directory, records) as host:
        setup(host, other, database)
        original = send(host)
        final = host.ok('state')
        for key in ('service','account','device'):
            wrong = SCOPE | {key: 'other-' + key}
            host.fail('open', 'crypto_scope_mismatch', name='wrong', options={'path':str(database),'scope':wrong})
        for name, scope in [('account', SCOPE | {'account':'other-account'}), ('service', SCOPE | {'service':'other-service'})]:
            host.open(directory / (name+'.db'), name=name, create=True, scope=scope)
            identity = host.ok('initialize', name=name, requestId='initialize')['value']
            require(identity['account'] == scope['account'] and identity['service'] == scope['service'], '账号隔离失败')
            host.fail('receive', 'crypto_no_group', name=name,
                      requestId='receive-one',sequence='1',envelope=original['value'])
        host.fail('send','crypto_request_conflict',requestId='send-one',attemptId='attempt-one',messageId='message-one',text='不同正文')
        host.fail('download','crypto_scope_mismatch',records=[{'sequence':'1','envelope':original['value'] | {'service':'other-service'}}])
        require(host.ok('state') == final, '跨范围/冲突改变原状态')
        host.ok('close', name='account')
        require(host.ok('state', name='service')['identity']['service'] == 'other-service', '关闭影响其他范围')
    return {'scopes':3, 'wrong_scope_open_rejections':3, 'original':final}


def lifecycle(consumer, binary, directory, records):
    database = directory / 'life.db'
    with peer(binary, directory, records) as other, Host(consumer, directory, records) as host:
        setup(host, other, database)
        before = host.ok('state')
        host.fail('preCancel','cancelled',requestId='not-written')
        require(host.ok('state') == before, '提前取消仍写入')
        queued = host.ok('queue')
        require(queued.count('ok') == 8 and queued[-1] == 'queue_full', '队列未限制为8')
        host.ok('listenerThrow'); host.ok('unsubscribe')
        send(host)
        require(host.ok('listenerErrors') == ['Error: synthetic_listener_error'], '监听异常/取消订阅错误')
        event_count = len(host.ok('events'))
        sent = host.ok('closePending',requestId='close-send',attemptId='close-attempt',messageId='close-message',text='关闭时已接受')
        require(not sent['cached'], '关闭时请求未执行')
        require(len(host.ok('events')) == event_count, '关闭后仍有迟到事件')
        host.open(database)
        require(len(host.ok('state')['outbox']) == 2, '关闭丢弃已接受请求')
    return {'queue':queued, 'late_events':0, 'listener_error_reported':True}


def lock_and_cancel(consumer, binary, directory, records, mode):
    database = directory / 'locked.db'
    with peer(binary, directory, records) as other, Host(consumer, directory, records) as host:
        setup(host, other, database)
        before = host.ok('state'); event_count = len(host.ok('events'))
        host.open(directory / 'other.db', name='other', create=True, scope=SCOPE | {'account':'other'})
        other_before = host.ok('state',name='other')
        with sqlite3.connect(database, isolation_level=None) as lock:
            lock.execute('BEGIN EXCLUSIVE')
            beat = host.ok('heartbeat')
            if mode == 'locked':
                host.fail('send','database_error',requestId='lock-send',attemptId='lock-attempt',messageId='lock-message',text='锁后重试')
                require(host.ok('heartbeat') - beat >= 5, 'SQLite 等待阻塞 Node 主线程')
                host.fail('state','database_error')
            elif mode == 'cancel':
                host.fail('cancel','cancelled_unknown',requestId='lock-send',attemptId='lock-attempt',messageId='lock-message',text='锁后重试')
            elif mode == 'killed':
                child = host.children[0]
                os.kill(child, signal.SIGSTOP)
                killer = threading.Timer(0.025, lambda: os.kill(child, signal.SIGKILL))
                killer.start()
                try: host.fail('state', 'process_exit_unknown')
                finally: killer.join()
            elif mode == 'timeout':
                # SIGSTOP 确保是公开包真实子进程等待超时，未改数据库/测试API。
                host.ok('close')
                lock.execute('ROLLBACK')
                runtime = host.open(database,timeout=100)
                os.kill(runtime['pid'], signal.SIGSTOP)
                host.fail('state','request_timeout_unknown')
                lock.execute('BEGIN EXCLUSIVE')
            lock.execute('ROLLBACK')
        require(host.ok('state',name='other') == other_before, '取消/故障影响另一个账号')
        require(len(host.ok('events')) == event_count, '失败发布成功事件')
        host.ok('close'); host.open(database)
        require(host.ok('state') == before, '锁故障保留了半状态')
        retry = host.ok('send',requestId='lock-send',attemptId='lock-attempt',messageId='lock-message',text='锁后重试')
        require(success(other.request('peer_receive',envelope=retry['value']))['text'] == '锁后重试', '故障恢复不可用')
    return {'mode':mode, 'no_success_on_failure':True, 'normal_retry':True, 'other_scope_unchanged':True}
