"""既有 Rust 故障入口制造持久窗口，真实 npm 包重开核验；故障入口不进入包。"""
from crypto_support import CryptoProbe, failure, inspect, success, unchanged
from desktop_support import Host, peer, setup, peer_send
from support import require


def fault_case(consumer, binary, directory, records, operation, fault):
    database = directory / 'state.db'
    request_id = 'fault-request'
    with peer(binary, directory, records) as other:
        with Host(consumer, directory, records) as host:
            setup(host, other, database)
            envelope = peer_send(other)
            if operation == 'process':
                host.ok('download',records=[{'sequence':'1','envelope':envelope}])
            before = host.ok('state')
        with CryptoProbe(binary,database,directory,records,flags=('--test-mode',)) as probe:
            original = inspect(probe)
            if operation == 'send':
                action = {'op':'send','attempt_id':'fault-attempt','message_id':'fault-message','text':'合成故障恢复'}
                command = {'op':'execute','request':{'request_id':request_id,'action':action,'fault':fault}}
            elif operation == 'process':
                command = {'op':'process','request_id':request_id,'sequence':'1','fault':fault}
            else:
                command = {'op':'download','request':{'records':[{'sequence':'1','envelope':envelope}],'fault':fault}}
            if fault in ('before_commit','after_commit'):
                probe.send(command)
                marker = probe.checkpoint(fault)
                probe.crash()
                fault_evidence = {'checkpoint':marker,'real_sigkill':True}
            else:
                response = probe.request(**command)
                failure(response,'database_error' if fault == 'after_sql' else 'commit_failed')
                require(response['trace'][-1] in ('ROLLBACK','ROLLBACK_AUTOMATIC'), '故障未回滚')
                unchanged(original,inspect(probe),pending=operation != 'download')
                fault_evidence = response
        with Host(consumer,directory,records) as recovered:
            recovered.open(database)
            current = recovered.ok('state')
            require(recovered.ok('events') == [], '恢复发布候选事件')
            if fault == 'after_commit':
                require(not current['pending'], '已提交仍未决')
                if operation == 'send':
                    result = recovered.ok('send',requestId=request_id,attemptId='fault-attempt',messageId='fault-message',text='合成故障恢复')
                    require(result['cached'] and len(current['outbox']) == 1, '丢响应后未恢复原密文')
                    require(success(other.request('peer_receive',envelope=result['value']))['text'] == '合成故障恢复','恢复密文不可解密')
                elif operation == 'process':
                    result = recovered.ok('process',requestId=request_id,sequence='1')
                    require(result['cached'] and current['receivedCount'] == 1 and current['processedCursor'] == '1', '丢响应后接收状态不一致')
                    require(recovered.ok('received',sequence='1')['message']['text'] == '合成对端🙂one','重开未恢复正文')
                else:
                    result = recovered.ok('download',records=[{'sequence':'1','envelope':envelope}])
                    require(result['cached'] and current['downloadCursor'] == '1' and current['processedCursor'] == '0','下载丢响应未恢复')
                require(recovered.ok('events') == [], '取回已提交缓存重复发布事件')
                require(recovered.ok('state') == current, '缓存重试改变已提交状态')
            elif operation == 'download':
                require(current == before, '下载回滚保留半状态')
                recovered.ok('download',records=[{'sequence':'1','envelope':envelope}])
                result = recovered.ok('process',requestId='recovered-process',sequence='1')
                require(result['value']['message']['text'] == '合成对端🙂one', '下载故障后重试失败')
            else:
                require(current == before | {'pending':True}, '失败候选改变已提交业务状态')
                if operation == 'send':
                    recovered.fail('send','crypto_pending',requestId=request_id,attemptId='fault-attempt',messageId='fault-message',text='合成故障恢复')
                else:
                    recovered.fail('process','crypto_pending',requestId=request_id,sequence='1')
                    recovered.fail('received','receive_not_found',sequence='1')
                recovered.fail('initialize','crypto_pending',requestId='fresh-request')
                require(recovered.ok('events') == [] and recovered.ok('state') == current,'暂停重试改变状态/发布事件')
                recovered.ok('close'); recovered.open(database)
                require(recovered.ok('state') == current, '暂停未跨重启保持')
        # 使用原诊断入口核对 provider、密文、计数、游标一起恢复；不是 TS 公共 API。
        with CryptoProbe(binary,database,directory,records) as verify:
            final = inspect(verify)
            if fault != 'after_commit' and operation != 'download':
                unchanged(original,final,pending=True)
            elif operation == 'send':
                require(final['encryptions'] == '1' and final['provider_hash'] != original['provider_hash'], '发送provider未共同提交')
            elif operation in ('process','download'):
                expected = '0' if operation == 'download' and fault == 'after_commit' else '1'
                require(final['decryptions'] == expected, '恢复重复解密')
    return {'operation':operation, 'fault':fault, 'fault_evidence':fault_evidence,
            'recovered_state':current, 'rust_final':final, 'fault_driver':'separate native_crypto; not packaged'}
