"""真实旧 Relay 的后继历史终态升级；复用原 MLS、锚批准和签名流绑定。"""

from copy import deepcopy
from functools import partial
import hashlib

from .backfill_fixture import backfill, ledger, upgrade
from .deletion_observer import assert_terminal_transition, relay_records
from .fixture import check
from .lifecycle_rebuild import finished, local, ordinary_page, register, stream, target
from .lifecycle_support import clock, notification
from .rebuild_sync_fixture import page_value, statement


def legacy_terminal(before, after, accepted, availability):
    """旧程序只作原位终态投影；验证升级夹具没有预先制造新通知。"""
    expected = deepcopy(before)
    for row in expected['attempts']:
        if row['acceptance_id'] == accepted['acceptance_id']:
            row['availability'] = availability
    for row in expected['events']:
        if row['acceptance_id'] == accepted['acceptance_id'] and row['availability'] == 'available':
            row['availability'] = availability
    check(after == expected, '真实旧程序没有保持仅原位终态投影的升级前基线')
    check(all(row['type'] != 'message_availability' for row in after['events']),
          '升级前旧程序意外生成生命周期通知')


def rebuild_backfill(lab, *, availability, phase):
    lab.join_http()
    payload = 'synthetic-backfill-rebuild-' + availability + '-' + phase
    packet, accepted = lab.publish('backfill-target', payload=payload)
    initial = relay_records(lab)
    original = target(initial, lab, accepted)
    peer_stream = stream(initial, lab, 'source_peer')['stream_id']
    first_ordinary = ordinary_page(lab, peer_stream)
    ordinary_original = page_value(first_ordinary)['events'][0]
    check(ordinary_original['event']['envelope'] == packet['envelope'],
          '普通目标原签页不是实际 HTTP 接受的 MLS 字节')
    first_page = initial_process = old_local = None
    if phase == 'after_registration':
        current_stream = register(lab)
        first_page = lab.next_page('100')
        value = page_value(first_page)
        check(value['stream_id'] == current_stream and value['watermark'] == '1'
              and len(value['events']) == 1
              and value['events'][0]['event']['envelope'] == packet['envelope'],
              '旧后继初始签页未保留原消息槽和 MLS 字节')
        lab.download(first_page)
        initial_process = lab.process_page()
        check(len(initial_process['results']) == len(initial_process['deliveries']) == 1
              and initial_process['results'][0]['result']['status'] == 'valid'
              and initial_process['results'][0]['result']['message']['payload_sha256']
              == hashlib.sha256(payload.encode()).hexdigest(), '旧后继未实际解密原消息')
        old_local = local(lab)
    before_terminal = relay_records(lab)
    if availability == 'deleted':
        lab.control('set_availability', acceptance_id=accepted['acceptance_id'], availability='deleted')
    else:
        clock(lab, int(accepted['expires_at_unix_ms']))
    terminal_ordinary = ordinary_page(lab, peer_stream)
    old_page = page_value(terminal_ordinary)
    check(old_page['watermark'] == '1' and len(old_page['events']) == 1
          and old_page['events'][0]['availability'] == availability
          and 'event' not in old_page['events'][0], '旧程序终态不是无通知的原槽墓碑')
    after_terminal = relay_records(lab)
    legacy_terminal(before_terminal, after_terminal, accepted, availability)
    old_snapshot = lab.snapshot('successor').read_bytes()
    migration = upgrade(lab)
    check(relay_records(lab) == after_terminal and lab.snapshot('successor').read_bytes() == old_snapshot,
          '升级改变原接受事实、原槽、流身份或客户端快照')
    pending = ledger(lab)
    check(pending['schema'] == 'rim-poc-storage-6' and pending['version'] == 'rim-lifecycle-backfill-1'
          and len(pending['rows']) == 3 and all(row['status'] == 'pending' for row in pending['rows']),
          '升级没有冻结三个原消息目标的待回填范围')
    first_backfill = backfill(lab)
    expected_backfill = {'version': 'rim-lifecycle-backfill-1', 'scope_count': '3',
        'pending_count': '0', 'appended_count': '3', 'existing_count': '0', 'skipped_count': '0'}
    check(first_backfill == expected_backfill, '首次回填没有明确完成三个冻结原槽')
    completed_ledger = ledger(lab)
    check(len(completed_ledger['rows']) == 3
          and all(row['status'] == 'appended' and row['notification_event_id']
                  for row in completed_ledger['rows']), '回填没有保存三个通知的持久幂等记录')
    after_backfill = relay_records(lab)
    assert_terminal_transition(before_terminal, after_backfill, accepted['acceptance_id'], availability)
    backfilled_ordinary = ordinary_page(lab, peer_stream)
    ordinary_notice = notification(page_value(backfilled_ordinary), ordinary_original, accepted, availability)
    if phase == 'before_registration':
        untouched = lab.rust('successor', 'wire_inspect')
        check(untouched['inbox_count'] == 0 and untouched['sync']['download_cursor'] == '0'
              and untouched['sync']['processed_cursor'] == '0', '尚未登记后继提前继承旧消息或游标')
        current_stream = register(lab)
        check(ledger(lab) == completed_ledger, '注册替换临时流 ID 改变了原槽回填幂等记录')
    retained = int(phase == 'after_registration')
    expected_cursor = '1' if retained else '0'
    check(lab.rust('successor', 'wire_inspect')['sync']['download_cursor'] == expected_cursor,
          '升级或回填重置后继持久游标')
    signed_page = lab.next_page('100')
    value, claims = page_value(signed_page), statement(signed_page['receipt'])
    check(claims['after_seq'] == expected_cursor and claims['stream_id'] == current_stream
          and value['stream_id'] == current_stream and len(value['events']) == 2 - retained,
          '后继没有从原持久游标取得回填通知')
    original_slot = {'stream_id': current_stream, 'event_seq': original['seq'],
                     'event_id': original['event_id']}
    successor_notice = notification(value, original_slot, accepted, availability)
    check(successor_notice['event']['target_event_id'] != ordinary_notice['event']['target_event_id']
          and current_stream != peer_stream, '后继通知绑定到了普通设备的槽或流')
    if not retained:
        check(value['events'][0] == {**original_slot, 'availability': availability},
              '登记前回填未保留旧槽 ID、序号与无正文墓碑')
    lab.download(signed_page)
    projected = local(lab)
    check(projected['slot']['availability'] == availability, '后继下载后没有立即投影历史终态')
    if retained:
        check(projected == {**old_local, 'slot': {**old_local['slot'], 'availability': availability}},
              '回填改写了后继旧消息内容或原成功结果')
    final = finished(lab, availability, retained)
    if retained:
        check(final['message_slot']['result'] == old_local['result']
              and final['processed']['deliveries'] == initial_process['deliveries'],
              '回填撤回原有效副本或改变送达候选')
    else:
        check(final['message_slot']['result'] == {'status': 'unavailable', 'availability': availability},
              '登记前已经终态的原消息被解密')
    expected_acceptance = {**accepted, 'availability': availability}
    check(lab.http('source', 'submit_message', {'envelope': packet['envelope']}) == expected_acceptance,
          '升级后原包重试改变原接受事实或复活消息')
    before_restart = relay_records(lab)
    duplicate_backfill = backfill(lab)
    check(duplicate_backfill == expected_backfill and ledger(lab) == completed_ledger
          and relay_records(lab) == before_restart, '重复回填追加了第二份通知或改变原事实')
    snapshot, original_binding = lab.snapshot('successor').read_bytes(), deepcopy(lab.binding)
    old_pid = lab.process.pid
    lab.restart()
    check(lab.process.pid != old_pid and relay_records(lab) == before_restart
          and lab.snapshot('successor').read_bytes() == snapshot, '重启改变回填、后继流或客户端快照')
    restarted_backfill = backfill(lab)
    check(restarted_backfill == expected_backfill and ledger(lab) == completed_ledger
          and relay_records(lab) == before_restart, '重启后回填重复追加原槽通知')
    check(lab.register_http()['binding'] == original_binding, '升级重启后后继绑定发生改变')
    active = lab.request_page('100')['request']
    check(statement(active)['after_seq'] == '2', '后继空尾请求未使用完成游标')
    duplicate = lab.download(signed_page)
    check(duplicate['duplicate'] and duplicate['sync'] == final['wire']['sync'], '回填签页重试改变游标')
    check(lab.request_page('100')['request'] == active, '原页重试丢失之后的活动挑战')
    repeated = finished(lab, availability, retained)
    check(repeated['processed']['results'] == [] and repeated['wire'] == final['wire']
          and repeated['message_slot'] == final['message_slot'], '签页重试重新处理或复活原消息')
    empty_page = lab.http_page(active)
    empty = page_value(empty_page)
    check(empty['events'] == [] and empty['next_after_seq'] == empty['watermark'] == '2'
          and not empty['has_more'], '后继空尾包含重复通知或跳过游标')
    lab.download(empty_page)
    empty_result = finished(lab, availability, retained)
    check(empty_result['processed']['results'] == [] and empty_result['wire'] == final['wire'],
          '空尾签页改变已完成消息状态')
    check(relay_records(lab) == before_restart and before_restart['counts']['receipts'] == 0,
          '回填重试、重启或空尾生成了未报告回执')
    lab.case_evidence.update(availability=availability, phase=phase, accepted=accepted,
        payload_sha256=hashlib.sha256(payload.encode()).hexdigest(), initial_relay=initial,
        before_terminal=before_terminal, after_terminal=after_terminal, after_backfill=after_backfill,
        migration=migration, pending_ledger=pending, completed_ledger=completed_ledger,
        backfill_runs=[first_backfill, duplicate_backfill, restarted_backfill],
        original_successor_event=original, initial_ordinary_page=first_ordinary,
        terminal_ordinary_page=terminal_ordinary, backfilled_ordinary_page=backfilled_ordinary,
        first_rebuild_page=first_page, first_process=initial_process,
        signed_incremental_page=signed_page, after_download=projected, final=final,
        repeated=repeated, empty_page=empty_page, final_relay=before_restart,
        restart={'old_pid': old_pid, 'new_pid': lab.process.pid},
        rebuild_scope={'old_group': 'G1', 'new_group': 'G2', 'old_processed_cursor': '1',
            'new_initial_cursor': '0', 'distinct_device': lab.plan['old_scope']['device']
                != lab.plan['successor_scope']['device'], 'new_stream_binding_verified': True,
            'target_binding': 'cached original message/header' if retained else
                'Service-signed original target; no local original plaintext/header'},
        rebuild_setup=deepcopy(lab.evidence))


CASES = [(f'M11.backfill.rebuild.{availability}.{phase}',
          partial(rebuild_backfill, availability=availability, phase=phase))
         for availability in ('deleted', 'expired')
         for phase in ('before_registration', 'after_registration')]
