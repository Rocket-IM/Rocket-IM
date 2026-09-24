"""M11 生命周期真实消息/签页的观察，不实现协议合并或改写客户端状态。"""

from copy import deepcopy
import hashlib

from .deletion_observer import relay_records
from .fixture import check
from .slot_support import publish

TARGETS = ('a2', 'b1', 'c1')


def snapshot(lab, device='b1'):
    return hashlib.sha256((lab.directory / device / 'state.enc').read_bytes()).hexdigest()


def slot(lab, device, seq='1'):
    return lab.rust(device, 'wire_slot_inspect', event_seq=seq)


def clock(lab, value):
    before = relay_records(lab)
    path = lab.clock_path.with_suffix('.tmp')
    path.write_text(str(value) + '\n')
    path.chmod(0o600)
    path.replace(lab.clock_path)
    check(relay_records(lab) == before, '推进测试时钟不应直接修改数据库')
    lab.case_evidence.setdefault('clock_updates', []).append(str(value))


def setup(lab, phase='queued'):
    packet, accepted, payload_hash = publish(lab, 'lifecycle-target')
    pages, before = {}, {}
    for device in TARGETS:
        page = lab.pull(device)
        check(len(page['events']) == 1 and page['watermark'] == '1', '初始页应只有原消息')
        pages[device] = page
        if phase != 'unfetched':
            lab.download(device, page)
            if phase == 'processed':
                result = lab.rust(device, 'wire_process')
                check(len(result['results']) == 1 and len(result['deliveries']) == 1
                      and result['results'][0]['result']['message']['payload_sha256'] == payload_hash,
                      '基线没有实际解密原消息')
        before[device] = slot(lab, device)
    lab.case_evidence.update(phase=phase, accepted=accepted,
        payload_sha256=payload_hash, original_pages={d: p.wrapper for d, p in pages.items()}, before_slots=before)
    return packet, accepted, pages, before


def trigger(lab, availability, accepted):
    if availability == 'deleted':
        return lab.control('set_availability', acceptance_id=accepted['acceptance_id'], availability='deleted')
    clock(lab, int(accepted['expires_at_unix_ms']))
    # 原尾游标的实际签页请求触发到期；后续取页仍从持久游标开始。
    page = lab.pull('b1', '1')
    lab.case_evidence['trigger_page'] = page.wrapper
    return page


def transition(before, after, accepted, availability):
    """核对原投影和精确三目标通知；不把选定字段称为全数据库比较。"""
    expected = deepcopy(before)
    ident = accepted['acceptance_id']
    for record in expected['attempts']:
        if record['acceptance_id'] == ident:
            record['availability'] = availability
    for record in expected['events']:
        if record['acceptance_id'] == ident and record['availability'] == 'available':
            record['availability'] = availability
    old_ids = {r['event_id'] for r in before['events']}
    added = [r for r in after['events'] if r['event_id'] not in old_ids]
    check(len(added) == 3 and {r['device'] for r in added} == set(TARGETS)
          and all(r['type'] == 'message_availability' and r['availability'] == 'available'
                  and r['acceptance_id'] == ident for r in added), '生命周期扇出目标/数量/载荷可用性错误')
    check([r for r in after['events'] if r['event_id'] in old_ids] == expected['events'], '旧槽身份或原载荷摘要变化')
    for field in ('attempts', 'logical_messages', 'receipts'):
        check(after[field] == expected[field], '原接受事实、逻辑链或回执改变: ' + field)
    check(after['streams'] == [{**r, 'watermark': str(int(r['watermark']) + int(r['device'] in TARGETS))}
                              for r in before['streams']], '设备流身份或连续水位变化不符')
    check(after['counts'] == {**before['counts'], 'events': before['counts']['events'] + 3}, '新增通知改变消息/接受计数')


def notification(page, original, accepted, availability):
    events = [s for s in page['events'] if s.get('event', {}).get('type') == 'message_availability']
    check(len(events) == 1, '实际增量页缺少唯一本目标生命周期通知')
    item = events[0]
    expected = {'type': 'message_availability', 'target_event_seq': original['event_seq'],
                'target_event_id': original['event_id'], 'acceptance_id': accepted['acceptance_id'],
                'attempt_id': accepted['attempt_id'], 'availability': availability}
    check(item['event'] == expected and item['stream_id'] == original['stream_id']
          and item['event_seq'] == '2' and item['event_id'] != original['event_id']
          and item['availability'] == 'available', '通知没有精确绑定原槽/接受/终态')
    return item


def finished(lab, device, availability, phase):
    processed = lab.rust(device, 'wire_process')
    current = lab.rust(device, 'wire_inspect')
    original = slot(lab, device)
    check(original['slot']['availability'] == availability, '旧槽没有在下载时投影')
    count = int(phase == 'processed')
    check(current['inbox_count'] == count and len(processed['deliveries']) == count,
          '生命周期通知新建/撤回业务消息或伪造送达')
    check(current['sync']['download_cursor'] == current['sync']['processed_cursor'] == '2'
          and current['sync']['slot_count'] == 2 and current['sync']['pending_count'] == 0
          and current['sync']['quarantined_count'] == 0 and current['sync']['source_verified'],
          '通知没有正确完成两个游标或被误隔离')
    check(slot(lab, device, '2')['result']['status'] == 'availability_recorded', '通知结果类型不明确')
    check(lab.rust(device, 'wire_read_inspect')['pending_count'] == 0, '通知自动创建阅读意图')
    return {'wire': current, 'message_slot': original, 'notification_slot': slot(lab, device, '2'),
            'processed': processed}
