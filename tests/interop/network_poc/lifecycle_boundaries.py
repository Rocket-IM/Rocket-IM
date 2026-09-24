"""来源、旧程序、伪造目标、到期游标及满本地队列边界。"""

import base64
from copy import deepcopy
import json
import subprocess

from .deletion_observer import relay_records
from .fixture import check
from .lifecycle_support import clock, finished, notification, setup, slot, snapshot, trigger
from .stream_fixture import StreamPage


def event_id_read_recovery(lab):
    _, accepted, pages, old = setup(lab, phase='processed')
    ident = pages['b1']['events'][0]['event_id']
    lab.rust('b1', 'wire_read', event_ids=[ident])
    reading = lab.rust('b1', 'wire_read_inspect')
    check(reading['pending_count'] == 1, '回归前置缺少真实消息的已读意图')
    trigger(lab, 'deleted', accepted)
    page = lab.pull('b1', '1')
    bad = deepcopy(page)
    bad['events'][0]['event_id'] = ident
    signed = lab.sign_test_page(bad)
    before = snapshot(lab)

    def observe(operation, **fields):
        # 同时保留修复前的成功下载/随后加载失败，不能只断言某一次错误退出。
        request = {'directory': str(lab.directory / 'b1'), 'service': lab.service,
                   'account': 'bob', 'device': 'b1', 'operation': operation, **fields}
        result = subprocess.run([str(lab.binary)], input=json.dumps(request), text=True,
                                capture_output=True, timeout=30)
        lab.process_count += 1
        return {'exit_code': result.returncode, 'reply': json.loads(result.stdout)}

    downloaded = observe('wire_download_signed', **signed.signed_input())
    after = snapshot(lab)
    reloaded = observe('wire_read_inspect')
    lab.case_evidence.update(original_event_id=ident, before_reading=reading,
        duplicate_id_signed_page=signed.wrapper, actual_signed_page=page.wrapper,
        snapshot_sha256_before=before, snapshot_sha256_after=after,
        duplicate_download=downloaded, following_load=reloaded)
    check(downloaded['exit_code'] == 1
          and downloaded['reply'].get('error', {}).get('code') == 'invalid_envelope'
          and before == after and reloaded['exit_code'] == 0
          and reloaded['reply'].get('result') == reading,
          '跨序号重复事件ID未在保存前拒绝，或破坏后续已读状态加载')
    lab.download('b1', page)
    processed = lab.rust('b1', 'wire_process')
    check(slot(lab, 'b1')['result'] == old['b1']['result']
          and slot(lab, 'b1')['slot']['availability'] == 'deleted'
          and slot(lab, 'b1', '2')['result']['status'] == 'availability_recorded'
          and len(processed['deliveries']) == 1
          and lab.rust('b1', 'wire_read_inspect') == reading,
          '拒绝恶页后的正常通知损坏已有结果或阅读意图')
    lab.restart()
    lab.download('b1', page)
    check(lab.rust('b1', 'wire_process')['results'] == []
          and lab.rust('b1', 'wire_read_inspect') == reading,
          '同槽精确重试或重启破坏原阅读意图')
    lab.case_evidence.update(final_reading=reading, final=lab.rust('b1', 'wire_inspect'),
        final_relay=relay_records(lab))


def rejected_pages(lab):
    _, accepted, pages, old = setup(lab)
    trigger(lab, 'deleted', accepted)
    page = lab.pull('b1', '1')
    records = relay_records(lab)
    before = snapshot(lab)
    failures = []
    variants = [('target_event_seq', '0'), ('target_event_seq', '2'),
                ('target_event_id', 'another-event'), ('acceptance_id', 'another-acceptance'),
                ('attempt_id', 'P2'), ('availability', 'available'), ('availability', 'access_removed')]
    for field, value in variants:
        bad = deepcopy(page)
        bad['events'][0]['event'][field] = value
        # 明确的合成Service错误签页，不把重签负例称为第三方破签。
        signed = lab.sign_test_page(bad)
        error = lab.download('b1', signed, expected_exit=1)
        check(snapshot(lab) == before and slot(lab, 'b1') == old['b1'], '坏目标部分写入或投影')
        failures.append({'field': field, 'value': value, 'code': error['code'], 'snapshot_sha256': before})
    cross = lab.pull('a2', '1')
    cross_error = lab.download('b1', cross, expected_exit=1)
    check(snapshot(lab) == before, '跨设备页改变目标状态')
    wrapper = deepcopy(page.wrapper)
    raw = json.loads(base64.b64decode(wrapper['page_bytes']))
    raw['events'][0]['event']['availability'] = 'expired'
    wrapper['page_bytes'] = base64.b64encode(json.dumps(raw).encode()).decode()
    forged = StreamPage(wrapper)
    forged_error = lab.download('b1', forged, expected_exit=1)
    check(snapshot(lab) == before, '未重签篡改被保存')
    raw_error = lab.rust('b1', 'wire_download', **dict(page), expected_exit=1)
    check(snapshot(lab) == before, '裸事件错误继承既有source_verified状态')
    lab.download('b1', page)
    final = finished(lab, 'b1', 'deleted', 'queued')
    # 新水位已前进时旧原页明确拒绝，拒绝后仍可读取正确尾页。
    current = snapshot(lab)
    old_error = lab.download('b1', pages['b1'], expected_exit=1)
    check(snapshot(lab) == current and relay_records(lab) == records, '迟到旧available页复活消息')
    lab.download('b1', lab.pull('b1', '2'))
    check(lab.rust('b1', 'wire_process')['results'] == [], '旧页拒绝后无法继续合法同步')
    lab.case_evidence.update(negative_targets=failures, cross_device_error=cross_error,
        invalid_signature_error=forged_error, unsigned_error=raw_error, delayed_page_error=old_error,
        actual_signed_page=page.wrapper, final=final, final_relay=records)


def old_program(lab):
    _, accepted, pages, _ = setup(lab)
    trigger(lab, 'deleted', accepted)
    page = lab.pull('b1', '1')
    current_binary = lab.binary
    before = snapshot(lab)
    try:
        lab.binary = lab.old_binary
        error = lab.download('b1', page, expected_exit=1)
    finally:
        lab.binary = current_binary
    check(snapshot(lab) == before, '旧程序未知事件失败后改写状态')
    lab.download('b1', page)
    final = finished(lab, 'b1', 'deleted', 'queued')
    after = snapshot(lab)
    try:
        lab.binary = lab.old_binary
        load_error = lab.rust('b1', 'wire_inspect', expected_exit=1)
    finally:
        lab.binary = current_binary
    check(snapshot(lab) == after, '旧程序读取新快照失败后改写状态')
    lab.case_evidence.update(old_binary=str(lab.old_binary), old_page_error=error,
        old_snapshot_error=load_error, before_snapshot_sha256=before, after_snapshot_sha256=after,
        signed_page=page.wrapper, final=final, final_relay=relay_records(lab))


def deadline_cursor(lab):
    _, accepted, pages, _ = setup(lab)
    before = relay_records(lab)
    expires = int(accepted['expires_at_unix_ms'])
    clock(lab, expires - 1)
    check(lab.pull('b1', '1')['events'] == [] and relay_records(lab) == before, '期限前投影')
    clock(lab, expires)
    error = lab.pull('b1', '2', expected=409)
    check(error['code'] == 'cursor_invalid' and relay_records(lab) == before, '未来游标跳过到期通知或提前写入')
    page = lab.pull('b1', '1')
    notification(page, pages['b1']['events'][0], accepted, 'expired')
    lab.download('b1', page)
    final = finished(lab, 'b1', 'expired', 'queued')
    rows = relay_records(lab)
    clock(lab, expires - 1)
    check(lab.pull('b1', '2')['events'] == [] and relay_records(lab) == rows, '时钟回退复活消息')
    lab.case_evidence.update(future_cursor_error=error, deadline_unix_ms=str(expires),
        signed_page=page.wrapper, final=final, final_relay=rows)


def full_pending(lab):
    _, accepted, _, old = setup(lab)
    trigger(lab, 'deleted', accepted)
    page = lab.pull('b1', '1')
    before = snapshot(lab)
    error = lab.download('b1', page, expected_exit=1)
    check(error['code'] == 'resource_exhausted' and snapshot(lab) == before
          and slot(lab, 'b1') == old['b1'], '满本地队列部分应用通知')
    # 本地尚未保存通知且持有旧密文；现有显式处理会形成有效副本，这是保留的边界。
    processed = lab.rust('b1', 'wire_process')
    check(processed['results'][0]['result']['status'] == 'valid', '旧已下载副本处理边界变化')
    lab.download('b1', page)
    final = finished(lab, 'b1', 'deleted', 'processed')
    lab.case_evidence.update(blocked_error=error, original_snapshot_sha256=before,
        explicit_old_copy_processing=processed, signed_page=page.wrapper, final=final,
        conclusion='OBSERVED_LIMITATION_FULL_PENDING_REQUIRES_EXPLICIT_PROGRESS_AND_CANNOT_REVOKE_OLD_COPY',
        final_relay=relay_records(lab))


CASES = [('M11.lifecycle.rejected_pages', rejected_pages),
         ('M11.lifecycle.event_id_read_recovery', event_id_read_recovery),
         ('M11.lifecycle.old_program', old_program),
         ('M11.lifecycle.deadline_cursor', deadline_cursor),
         ('M11.lifecycle.full_pending', full_pending)]
