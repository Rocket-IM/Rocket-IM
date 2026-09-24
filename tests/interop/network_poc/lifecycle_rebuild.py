"""真实重建后继的删除/到期签页；注册前排队与注册后既存正文分开验证。"""

from copy import deepcopy
from functools import partial
import hashlib

from .deletion_observer import assert_terminal_transition, relay_records
from .fixture import check
from .lifecycle_support import clock, notification
from .rebuild_sync_fixture import page_value, statement


def stream(records, lab, alias):
    own = lab.identities[alias]
    matches = [row for row in records['streams']
               if (row['account'], row['device']) == (own['account_id'], own['device_id'])]
    check(len(matches) == 1, '真实目录中缺少唯一设备流')
    return matches[0]


def target(records, lab, accepted):
    own = lab.identities['successor']
    matches = [row for row in records['events'] if row['type'] == 'message'
               and row['acceptance_id'] == accepted['acceptance_id']
               and (row['account'], row['device']) == (own['account_id'], own['device_id'])]
    check(len(matches) == 1 and matches[0]['seq'] == '1', '后继必须具有精确的原消息槽1')
    return matches[0]


def ordinary_page(lab, current_stream):
    # 使用普通真实设备及它的当前流，后继不能借普通端点跳过独立绑定。
    return lab.http('source_peer', 'pull_events_signed', {'service_id': lab.service,
        'stream_id': current_stream, 'after_seq': '0', 'limit': '100'})


def register(lab):
    before = relay_records(lab)
    old_stream = stream(before, lab, 'successor')['stream_id']
    lab.registration_request()
    response = lab.register_http()
    bound = lab.bind()
    current_stream = statement(response['binding'])['stream_id']
    check(current_stream != old_stream and bound['sync']['download_cursor'] == '0',
          '真实后继登记未更换临时流或继承了旧游标')
    after = relay_records(lab)
    expected = deepcopy(before)
    stream(expected, lab, 'successor')['stream_id'] = current_stream
    check(after == expected, '登记换流改变了已排队原消息、通知、序号或接受事实')
    lab.case_evidence['registration'] = {'temporary_stream_id': old_stream,
        'bound_stream_id': current_stream, 'binding': response['binding'],
        'selected_relay_projection_unchanged_except_stream': True}
    return current_stream


def local(lab, seq='1'):
    return lab.rust('successor', 'wire_slot_inspect', event_seq=seq)


def finished(lab, availability, retained):
    processed = lab.process_page()
    state = lab.rust('successor', 'wire_inspect')
    old = local(lab)
    notice = local(lab, '2')
    check(state['inbox_count'] == retained and state['outbox_count'] == 0
          and len(processed['deliveries']) == retained, '后继通知创建或撤回了消息/送达事实')
    sync = state['sync']
    check(sync['download_cursor'] == sync['processed_cursor'] == '2'
          and sync['slot_count'] == 2 and sync['pending_count'] == 0
          and sync['quarantined_count'] == 0 and sync['source_verified'], '后继通知未正常推进双游标')
    check(old['slot']['availability'] == availability
          and notice['result'] == {'status': 'availability_recorded'}, '后继原槽或通知结果错误')
    check(lab.rust('successor', 'wire_read_pending')['pending_count'] == 0,
          '后继生命周期通知创建隐式阅读意图')
    return {'wire': state, 'message_slot': old, 'notification_slot': notice, 'processed': processed}


def rebuild_lifecycle(lab, *, availability, phase):
    lab.join_http()
    payload = 'synthetic-rebuild-lifecycle-' + availability + '-' + phase
    packet, accepted = lab.publish('lifecycle-target', payload=payload)
    initial = relay_records(lab)
    original = target(initial, lab, accepted)
    peer_stream = stream(initial, lab, 'source_peer')['stream_id']
    first_ordinary = ordinary_page(lab, peer_stream)
    ordinary_original = page_value(first_ordinary)['events'][0]
    check(ordinary_original['event']['envelope'] == packet['envelope'],
          '普通目标页不是原HTTP接受的实际MLS消息')
    first_page = initial_process = old_local = None
    if phase == 'after_registration':
        current_stream = register(lab)
        first_page = lab.next_page('100')
        original_page = page_value(first_page)
        check(original_page['stream_id'] == current_stream
              and [row['event_seq'] for row in original_page['events']] == ['1'],
              '后继初始签页不对应原消息槽')
        check(original_page['events'][0]['event']['envelope'] == packet['envelope'],
              '后继初始页改变原MLS字节')
        lab.download(first_page)
        initial_process = lab.process_page()
        check(len(initial_process['results']) == len(initial_process['deliveries']) == 1
              and initial_process['results'][0]['result']['status'] == 'valid'
              and initial_process['results'][0]['result']['message']['payload_sha256']
              == hashlib.sha256(payload.encode()).hexdigest(), '后继未实际解密原消息')
        old_local = local(lab)
    before_terminal = relay_records(lab)
    if availability == 'deleted':
        lab.control('set_availability', acceptance_id=accepted['acceptance_id'], availability='deleted')
    else:
        clock(lab, int(accepted['expires_at_unix_ms']))
    terminal_ordinary = ordinary_page(lab, peer_stream)
    ordinary_notification = notification(page_value(terminal_ordinary), ordinary_original, accepted, availability)
    after_terminal = relay_records(lab)
    assert_terminal_transition(before_terminal, after_terminal, accepted['acceptance_id'], availability)
    if phase == 'before_registration':
        untouched = lab.rust('successor', 'wire_inspect')
        check(untouched['inbox_count'] == 0 and untouched['sync']['download_cursor'] == '0'
              and untouched['sync']['processed_cursor'] == '0', '未登记后继提前继承消息状态')
        current_stream = register(lab)
    retained = int(phase == 'after_registration')
    expected_cursor = '1' if retained else '0'
    check(lab.rust('successor', 'wire_inspect')['sync']['download_cursor'] == expected_cursor,
          '后继未使用原持久尾游标')
    signed_page = lab.next_page('100')
    value = page_value(signed_page)
    claims = statement(signed_page['receipt'])
    check(claims['after_seq'] == expected_cursor and claims['stream_id'] == current_stream
          and value['stream_id'] == current_stream
          and len(value['events']) == 2 - retained, '后继页并非从原尾游标读取新通知')
    original_slot = {'stream_id': current_stream, 'event_seq': original['seq'],
                     'event_id': original['event_id']}
    successor_notice = notification(value, original_slot, accepted, availability)
    check(successor_notice['event']['target_event_id'] != ordinary_notification['event']['target_event_id']
          and current_stream != peer_stream, '后继通知错误复用了另一设备的原槽或普通流')
    if not retained:
        tombstone = value['events'][0]
        check(tombstone == {**original_slot, 'availability': availability},
              '注册前终态未保留原ID/序号的无正文占位')
    lab.download(signed_page)
    projected = local(lab)
    check(projected['slot']['availability'] == availability, '后继下载提交后未立即应用通知')
    if retained:
        check(projected == {**old_local, 'slot': {**old_local['slot'], 'availability': availability}},
              '后继通知改写原事件或成功结果')
    final = finished(lab, availability, retained)
    if retained:
        check(final['message_slot']['result'] == old_local['result']
              and final['processed']['deliveries'] == initial_process['deliveries'], '旧成功事实被撤回')
    else:
        check(final['message_slot']['result'] == {'status': 'unavailable', 'availability': availability},
              '注册前已不可用的消息仍被解密')
    expected_acceptance = {**accepted, 'availability': availability}
    check(lab.http('source', 'submit_message', {'envelope': packet['envelope']}) == expected_acceptance,
          '原接受包重试复活消息或改写原接受事实')
    before_restart = relay_records(lab)
    snapshot = lab.snapshot('successor').read_bytes()
    original_binding = deepcopy(lab.binding)
    old_pid = lab.process.pid
    lab.restart()
    check(lab.process.pid != old_pid and relay_records(lab) == before_restart
          and lab.snapshot('successor').read_bytes() == snapshot, 'Relay重启改变后继流或本机快照')
    check(lab.register_http()['binding'] == original_binding, '重启重签或更换后继绑定')
    active = lab.request_page('100')['request']
    check(statement(active)['after_seq'] == '2', '空尾请求未使用完成游标')
    duplicate = lab.download(signed_page)
    check(duplicate['duplicate'] and duplicate['sync'] == final['wire']['sync'], '原签页精确重试改写后继游标')
    check(lab.request_page('100')['request'] == active, '原页重试清除了后来活动挑战')
    repeated = finished(lab, availability, retained)
    check(repeated['processed']['results'] == [] and repeated['wire'] == final['wire']
          and repeated['message_slot'] == final['message_slot'], '后继精确重试重新处理或复活原消息')
    empty_page = lab.http_page(active)
    empty = page_value(empty_page)
    check(empty['events'] == [] and empty['next_after_seq'] == empty['watermark'] == '2'
          and not empty['has_more'], '后继空尾页包含重复通知或跳游标')
    lab.download(empty_page)
    empty_result = finished(lab, availability, retained)
    check(empty_result['processed']['results'] == [] and empty_result['wire'] == final['wire'],
          '空尾页修改已完成消息状态')
    check(relay_records(lab) == before_restart and before_restart['counts']['receipts'] == 0,
          '重试、重启或空页新增通知/未报告回执')
    lab.case_evidence.update(availability=availability, phase=phase, accepted=accepted,
        payload_sha256=hashlib.sha256(payload.encode()).hexdigest(), initial_relay=initial,
        before_terminal=before_terminal, after_terminal=after_terminal,
        original_successor_event=original, initial_ordinary_page=first_ordinary,
        terminal_ordinary_page=terminal_ordinary, first_rebuild_page=first_page,
        first_process=initial_process, signed_incremental_page=signed_page,
        after_download=projected, final=final, repeated=repeated, empty_page=empty_page,
        restart={'old_pid': old_pid, 'new_pid': lab.process.pid}, final_relay=before_restart,
        rebuild_scope={'old_group': 'G1', 'new_group': 'G2', 'old_processed_cursor': '1',
            'new_initial_cursor': '0', 'distinct_device': lab.plan['old_scope']['device']
                != lab.plan['successor_scope']['device'],
            'new_stream_binding_verified': True,
            'target_binding': 'cached original message/header' if retained else
                'Service-signed original target; no local original plaintext/header'},
        rebuild_setup=deepcopy(lab.evidence))


CASES = [(f'M11.lifecycle.rebuild.{availability}.{phase}',
          partial(rebuild_lifecycle, availability=availability, phase=phase))
         for availability in ('deleted', 'expired')
         for phase in ('before_registration', 'after_registration')]
