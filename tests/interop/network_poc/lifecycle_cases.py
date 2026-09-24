"""已处理、排队、未下载设备经真实签页观察删除/到期及重启去重。"""

from functools import partial
import time

from .deletion_observer import relay_records
from .fixture import check
from .lifecycle_support import (TARGETS, clock, finished, notification, setup, slot,
                                transition, trigger)


def incremental(lab, *, availability, phase):
    packet, accepted, pages, old = setup(lab, phase)
    baseline = relay_records(lab)
    trigger(lab, availability, accepted)
    changed = relay_records(lab)
    transition(baseline, changed, accepted, availability)
    lab.case_evidence.update(availability=availability, before_relay=baseline, transition_relay=changed)
    for device in TARGETS:
        check(slot(lab, device) == old[device], '服务端操作直接修改客户端快照')
    expected = {**accepted, 'availability': availability}
    for op in ('get_attempt', 'close_attempt'):
        check(lab.attempt(accepted['logical_message_id'], operation=op) == expected, '原接受事实变化')
    check(lab.submit(packet) == expected, '旧包重试复活消息')
    if availability == 'deleted':
        trigger(lab, availability, accepted)
    else:
        clock(lab, int(accepted['accepted_at_unix_ms']))
    check(relay_records(lab) == changed, '重复操作或时钟回退产生新事件')
    old_pid = lab.process.pid
    lab.restart()
    check(lab.process.pid != old_pid and relay_records(lab) == changed, '重启未保持完整事务')
    evidence = {}
    for device in TARGETS:
        cursor = lab.rust(device, 'wire_inspect')['sync']['download_cursor']
        page = lab.pull(device, cursor)
        item = notification(page, pages[device]['events'][0], accepted, availability)
        check(len(page['events']) == (2 if phase == 'unfetched' else 1), '必须从持久尾游标拉取')
        lab.download(device, page)
        projected = slot(lab, device)
        check(projected['slot']['availability'] == availability, '下载提交后原槽未立即不可用')
        if phase != 'unfetched':
            check(projected == {**old[device], 'slot': {**old[device]['slot'], 'availability': availability}},
                  '投影改变原事件或已处理结果')
        first = finished(lab, device, availability, phase)
        if phase == 'processed':
            check(first['message_slot']['result'] == old[device]['result'], '删除撤回了已有有效处理事实')
        else:
            check(first['message_slot']['result'] == {'status': 'unavailable', 'availability': availability},
                  '未处理旧消息在通知后仍被解密')
        lab.download(device, page)
        repeated = finished(lab, device, availability, phase)
        check(repeated['processed']['results'] == [] and first['wire'] == repeated['wire']
              and first['message_slot'] == repeated['message_slot'], '重复页重处理或复活原消息')
        # 完整重复补拉只作去重补充；首次发现通知已在上方严格从原游标发生。
        full = lab.pull(device)
        lab.download(device, full)
        check(finished(lab, device, availability, phase)['processed']['results'] == [], '重叠补拉重新处理')
        tail = lab.pull(device, '2')
        check(tail['events'] == [] and tail['watermark'] == tail['next_after_seq'] == '2', '尾页存在重复通知')
        evidence[device] = {'cursor_before': cursor, 'signed_incremental_page': page.wrapper,
                            'notification': item, 'after_download': projected, 'final': repeated}
    check(relay_records(lab) == changed and changed['counts']['receipts'] == 0, '未报告却产生回执或重复通知')
    lab.case_evidence.update(targets=evidence, restart={'old_pid': old_pid, 'new_pid': lab.process.pid}, final_relay=changed)


def real_deadline(lab):
    _, accepted, pages, _ = setup(lab, 'processed')
    baseline = relay_records(lab)
    deadline = int(accepted['expires_at_unix_ms'])
    remaining = deadline - int(time.time() * 1000)
    check(remaining > 0, '真实时钟前置已越过期限，不能冒充到期前基线')
    before = lab.pull('b1', '1')
    check(before['events'] == [] and relay_records(lab) == baseline, '真实期限前提前到期')
    time.sleep(max(0, (deadline + 30 - int(time.time() * 1000)) / 1000))
    observed_at = int(time.time() * 1000)
    page = lab.pull('b1', '1')
    notification(page, pages['b1']['events'][0], accepted, 'expired')
    transition(baseline, relay_records(lab), accepted, 'expired')
    lab.download('b1', page)
    final = finished(lab, 'b1', 'expired', 'processed')
    lab.case_evidence.update(availability='expired', observed_at_unix_ms=str(observed_at),
        deadline_unix_ms=str(deadline), before_signed_page=before.wrapper,
        after_signed_page=page.wrapper, final=final, final_relay=relay_records(lab))


CASES = [(f'M11.lifecycle.{availability}.{phase}', partial(incremental, availability=availability, phase=phase))
         for availability in ('deleted', 'expired') for phase in ('unfetched', 'queued', 'processed')]
CASES += [('M11.lifecycle.wall_clock', real_deadline)]
