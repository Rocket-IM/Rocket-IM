"""真实旧 Relay 终态升级后的普通流回填及提交窗口恢复。"""

from copy import deepcopy
from functools import partial
import http.client

from .backfill_fixture import backfill, ledger, upgrade
from .deletion_observer import relay_records
from .fixture import check
from .lifecycle_support import (TARGETS, finished, notification, setup, slot,
                                snapshot, transition, trigger)


VERSION = 'rim-lifecycle-backfill-1'


def _history(lab, availability, phase):
    packet, accepted, pages, old = setup(lab, phase)
    before = relay_records(lab)
    trigger(lab, availability, accepted)
    terminal = relay_records(lab)
    expected = deepcopy(before)
    for row in expected['attempts']:
        if row['acceptance_id'] == accepted['acceptance_id']:
            row['availability'] = availability
    for row in expected['events']:
        if row['acceptance_id'] == accepted['acceptance_id']:
            row['availability'] = availability
    check(terminal == expected, '旧 Relay 终态必须只有投影，不能伪造删除新通知的旧库')
    old_tails = {}
    for device in TARGETS:
        page = lab.pull(device, '1')
        check(page['events'] == [] and page['watermark'] == page['next_after_seq'] == '1',
              '升级前旧尾游标已收到通知')
        check(slot(lab, device) == old[device], '旧 Relay 操作直接修改端侧快照')
        old_tails[device] = page.wrapper
    check(relay_records(lab) == terminal, '旧终态补拉改变原接受事实或水位')
    lab.case_evidence.update(availability=availability, original_relay=before,
        old_terminal_relay=terminal, old_tail_pages=old_tails)
    return packet, accepted, pages, old, before, terminal


def _pending(observed, accepted, availability):
    check(observed['schema'] == 'rim-poc-storage-6' and observed['version'] == VERSION,
          '未明确升级到本轮版本')
    rows = observed['rows']
    check(len(rows) == 3 and {r['device'] for r in rows} == set(TARGETS),
          '升级范围不是三个原消息槽')
    check(all(str(r['target_seq']) == '1' and r['acceptance_id'] == accepted['acceptance_id']
              and r['attempt_id'] == accepted['attempt_id'] and r['availability'] == availability
              and r['status'] == 'pending' and r['notification_event_id'] is None for r in rows),
          '冻结范围没有保存原槽/接受/终态，或提前完成')


def _completed(pending, observed, relay, response):
    check(response == {'version': VERSION, 'scope_count': '3', 'pending_count': '0',
                       'appended_count': '3', 'existing_count': '0', 'skipped_count': '0'},
          '回填汇总没有精确说明三个已完成目标')
    check(observed['schema'] == pending['schema'] and observed['version'] == pending['version'],
          '执行改变升级版本')
    check(len(observed['rows']) == len(pending['rows']), '执行改变冻结扫描范围')
    by_id = {r['event_id']: r for r in relay['events']}
    ids = []
    for before, after in zip(pending['rows'], observed['rows']):
        ident = after['notification_event_id']
        check(after == {**before, 'status': 'appended', 'notification_event_id': ident}
              and ident in by_id, '幂等标记未与通知共同提交')
        event = by_id[ident]
        check(event['account'] == before['account'] and event['device'] == before['device']
              and event['seq'] == '2' and event['type'] == 'message_availability',
              '持久标记没有指向本设备新增通知')
        ids.append(ident)
    check(len(set(ids)) == 3, '多个原槽复用了同一通知标识')


def _consume(lab, device, accepted, availability, phase, original_page, old):
    cursor = lab.rust(device, 'wire_inspect')['sync']['download_cursor']
    check(cursor == ('0' if phase == 'unfetched' else '1'), '端侧原尾游标提前变化')
    page = lab.pull(device, cursor)
    item = notification(page, original_page['events'][0], accepted, availability)
    check(len(page['events']) == (2 if phase == 'unfetched' else 1), '回填未从持久游标增量取得')
    lab.download(device, page)
    projected = slot(lab, device)
    check(projected['slot']['availability'] == availability, '通知下载没有提交原槽终态')
    if phase != 'unfetched':
        check(projected == {**old, 'slot': {**old['slot'], 'availability': availability}},
              '回填改变原事件身份或既有处理结果')
    first = finished(lab, device, availability, phase)
    if phase == 'processed':
        check(first['message_slot']['result'] == old['result'], '回填撤回已取得的有效副本')
    else:
        check(first['message_slot']['result'] == {'status': 'unavailable', 'availability': availability},
              '回填后未处理消息仍被解密')
    lab.download(device, page)
    repeated = finished(lab, device, availability, phase)
    check(repeated['processed']['results'] == [] and first['wire'] == repeated['wire']
          and first['message_slot'] == repeated['message_slot'], '重复下载重处理或复活原消息')
    full = lab.pull(device)
    lab.download(device, full)
    check(finished(lab, device, availability, phase)['processed']['results'] == [],
          '重叠补拉改变已处理事实')
    tail = lab.pull(device, '2')
    check(tail['events'] == [] and tail['watermark'] == tail['next_after_seq'] == '2',
          '回填后尾游标又收到重复通知')
    return {'cursor_before': cursor, 'signed_page': page.wrapper, 'notification': item,
            'after_download': projected, 'first': first, 'repeated': repeated,
            'final_tail': tail.wrapper}


def historical(lab, *, availability, phase):
    packet, accepted, pages, old, before, terminal = _history(lab, availability, phase)
    upgrade(lab)
    pending = ledger(lab)
    _pending(pending, accepted, availability)
    response = backfill(lab)
    completed = ledger(lab)
    changed = relay_records(lab)
    transition(before, changed, accepted, availability)
    _completed(pending, completed, changed, response)
    for device in TARGETS:
        check(slot(lab, device) == old[device], '回填直接修改端侧快照')
    expected = {**accepted, 'availability': availability}
    for operation in ('get_attempt', 'close_attempt'):
        check(lab.attempt(accepted['logical_message_id'], operation=operation) == expected,
              '回填改变原接受事实')
    check(lab.submit(packet) == expected, '回填后旧包重试复活消息')
    check(backfill(lab) == response and ledger(lab) == completed and relay_records(lab) == changed,
          '重复执行改变完成汇总或重复追加')
    old_pid = lab.process.pid
    lab.restart()
    check(lab.process.pid != old_pid and ledger(lab) == completed and relay_records(lab) == changed,
          '重启改变已完成标记或消息记录')
    check(backfill(lab) == response and ledger(lab) == completed and relay_records(lab) == changed,
          '重启后重复执行重新扫描或重复追加')
    targets = {device: _consume(lab, device, accepted, availability, phase, pages[device], old[device])
               for device in TARGETS}
    check(relay_records(lab) == changed and changed['counts']['receipts'] == 0,
          '没有报告操作却新增回执或修改消息记录')
    lab.case_evidence.update(pending_ledger=pending, completed_ledger=completed, summary=response,
        completed_relay=changed, targets=targets, restart={'old_pid': old_pid, 'new_pid': lab.process.pid})


def interrupted(lab, *, availability, hook):
    packet, accepted, pages, old, before, terminal = _history(lab, availability, 'queued')
    upgrade(lab)
    pending = ledger(lab)
    _pending(pending, accepted, availability)
    saved = {d: snapshot(lab, d) for d in TARGETS}
    lab.control('hook', hook=hook)
    process = lab.process
    try:
        backfill(lab)
        raise AssertionError('指定回填窗口没有丢失 HTTP 响应')
    except (http.client.RemoteDisconnected, ConnectionResetError) as error:
        disconnected = type(error).__name__
    expected_exit = {'before_commit_exit': 86, 'after_commit_exit': 87}.get(hook)
    actual_exit = process.poll() if expected_exit is None else process.wait(timeout=10)
    check(actual_exit == expected_exit, 'Relay 真实退出码不符')
    after = relay_records(lab)
    after_ledger = ledger(lab)
    committed = hook != 'before_commit_exit'
    if committed:
        transition(before, after, accepted, availability)
    else:
        check(after == terminal and after_ledger == pending, '提交前退出留下半通知或半完成标记')
    check({d: snapshot(lab, d) for d in TARGETS} == saved
          and all(slot(lab, d) == old[d] for d in TARGETS), 'Relay 中断改变端侧快照')
    old_pid = process.pid
    lab.restart()
    check(lab.process.pid != old_pid and relay_records(lab) == after and ledger(lab) == after_ledger,
          '重启改变中断后的已提交状态')
    response = backfill(lab)
    recovered = relay_records(lab)
    recovered_ledger = ledger(lab)
    transition(before, recovered, accepted, availability)
    _completed(pending, recovered_ledger, recovered, response)
    if committed:
        check(recovered == after and recovered_ledger == after_ledger, '丢响应重试重复追加或重写标记')
    check(backfill(lab) == response and relay_records(lab) == recovered and ledger(lab) == recovered_ledger,
          '恢复后重复回填不幂等')
    final = _consume(lab, 'b1', accepted, availability, 'queued', pages['b1'], old['b1'])
    check(lab.submit(packet) == {**accepted, 'availability': availability}, '中断恢复改变原包接受事实')
    check(relay_records(lab) == recovered and recovered['counts']['receipts'] == 0,
          '恢复消费擅自产生回执或重复通知')
    lab.case_evidence.update(hook=hook, disconnected=disconnected, relay_exit_code=actual_exit,
        relay_pid=old_pid, recovered_pid=lab.process.pid, before_snapshot_sha256=saved,
        pending_ledger=pending, interrupted_ledger=after_ledger, completed_ledger=recovered_ledger,
        after_interruption=after, summary=response, completed_relay=recovered, target=final)


CASES = [(f'M11.backfill.{availability}.{phase}', partial(historical, availability=availability, phase=phase))
         for availability in ('deleted', 'expired') for phase in ('unfetched', 'queued', 'processed')]
CASES += [(f'M11.backfill.{availability}.{hook}', partial(interrupted, availability=availability, hook=hook))
          for availability in ('deleted', 'expired')
          for hook in ('before_commit_exit', 'after_commit_exit', 'drop_after_commit')]
