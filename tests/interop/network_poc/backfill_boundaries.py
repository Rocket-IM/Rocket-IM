"""升级来源、既有通知、撤权与冻结扫描范围的真实进程边界。"""

from concurrent.futures import ThreadPoolExecutor
from functools import partial

from .backfill_fixture import CURRENT_RELAY, LEGACY_RELAY, backfill, ledger, upgrade
from .deletion_observer import relay_records
from .fixture import check
from .lifecycle_support import finished, setup, snapshot, trigger
from .permission_cases import prepare, submit
from .slot_support import publish


def existing_notices(lab):
    _, accepted, _, _ = setup(lab)
    trigger(lab, 'deleted', accepted)
    original = relay_records(lab)
    check(sum(e['type'] == 'message_availability' for e in original['events']) == 3,
          '增量旧版本没有实际产生原通知')
    upgrade(lab)
    response = backfill(lab)
    saved = ledger(lab)
    check(response['existing_count'] == '3' and response['appended_count'] == '0'
          and response['pending_count'] == '0' and relay_records(lab) == original,
          '已有通知被重复追加')
    lab.stop()
    lab.relay_entrypoint = LEGACY_RELAY
    try:
        lab.start()
        raise RuntimeError('旧程序不应打开新版数据库')
    except AssertionError as error:
        reason = str(error)
        code = lab.process.wait(timeout=10)
    finally:
        lab.stop()
    check(code == 1 and ledger(lab) == saved and relay_records(lab) == original,
          '旧程序没有明确拒绝或改变新版持久事实')
    lab.relay_entrypoint = CURRENT_RELAY
    lab.start()
    check(backfill(lab) == response and ledger(lab) == saved, '重启重新采用已有通知')
    page = lab.pull('b1', '1')
    lab.download('b1', page)
    final = finished(lab, 'b1', 'deleted', 'queued')
    lab.case_evidence.update(response=response, before_relay=original, final_relay=relay_records(lab),
        final_ledger=saved, signed_page=page.wrapper, final=final,
        old_relay_rejection={'exit_code': code, 'fixture_error': reason})


def scope_and_concurrency(lab):
    _, accepted, _, _ = setup(lab)
    trigger(lab, 'deleted', accepted)
    _, later, _ = publish(lab, 'post-upgrade-terminal')
    original = relay_records(lab)
    upgrade(lab)
    trigger(lab, 'deleted', later)
    before = relay_records(lab)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(backfill, lab) for _ in range(2)]
        responses = [future.result() for future in futures]
    rows = ledger(lab)
    after = relay_records(lab)
    check(responses[0] == responses[1] and responses[0]['scope_count'] == '3'
          and responses[0]['appended_count'] == '3'
          and len(rows['rows']) == 3 and all(r['acceptance_id'] == accepted['acceptance_id'] for r in rows['rows']),
          '并发回填重复处理或扫描范围包含升级后的终态')
    old_ids = {e['event_id'] for e in before['events']}
    new = [e for e in after['events'] if e['event_id'] not in old_ids]
    check(len(new) == 3 and all(e['acceptance_id'] == accepted['acceptance_id'] for e in new)
          and after['attempts'] == before['attempts'] and after['receipts'] == before['receipts'],
          '回填影响新终态或原接受事实')
    page = lab.pull('b1', '1')
    check([e['event_seq'] for e in page['events']] == ['2', '3', '4'], '混合通知序号不连续')
    lab.download('b1', page)
    processed = lab.rust('b1', 'wire_process')
    check(not processed['deliveries'] and processed['sync']['processed_cursor'] == '4',
          '混合历史通知产生误报或跳游标')
    lab.restart()
    check(backfill(lab) == responses[0] and ledger(lab) == rows and relay_records(lab) == after,
          '重启后扩大扫描范围或重新追加')
    lab.case_evidence.update(original_relay=original, before_backfill=before, responses=responses,
        final_relay=after, final_ledger=rows, signed_page=page.wrapper, processed=processed)


def authorization(lab, *, revoked):
    _, accepted, _, _ = setup(lab)
    trigger(lab, 'deleted', accepted)
    action = {'kind': 'revoke_device', 'account_id': 'alice', 'device_id': 'a2'} if revoked else {
        'kind': 'remove_member', 'account_id': 'charlie'}
    change = prepare(lab, 'historical-access-removal', action)['change']
    permission = submit(lab, change)
    before = relay_records(lab)
    removed = 'a2' if revoked else 'c1'
    check(next(e for e in before['events'] if e['device'] == removed)['availability'] == 'deleted',
          '缺少先终态后撤权且原槽不带撤权标记的真实历史前置')
    upgrade(lab)
    response = backfill(lab)
    rows, after = ledger(lab), relay_records(lab)
    check(response['appended_count'] == '2' and response['skipped_count'] == '1'
          and next(r for r in rows['rows'] if r['device'] == removed)['status'] == 'skipped',
          '历史撤权仍得到终态通知')
    check(sum(e['type'] == 'message_availability' for e in after['events']) == 2
          and not any(e['type'] == 'message_availability' and e['device'] == removed for e in after['events']),
          '通知泄露给已撤权原目标')
    blocked = lab.pull(removed, '1', expected=403) if revoked else lab.pull(removed, '1')
    check(blocked['code'] == 'device_revoked' if revoked else blocked['events'] == [],
          '原设备访问规则改变')
    page = lab.pull('b1', '1')
    lab.download('b1', page)
    final = finished(lab, 'b1', 'deleted', 'queued')
    lab.restart()
    check(backfill(lab) == response and relay_records(lab) == after and ledger(lab) == rows,
          '重启撤销跳过结果不稳定')
    lab.case_evidence.update(permission_record={'change': change, 'receipt': permission['receipt']},
        removed_device=removed, before_relay=before, response=response, final_relay=after,
        final_ledger=rows, removed_response=blocked, signed_page=page.wrapper, final=final)


def full_pending(lab):
    _, accepted, _, _ = setup(lab)
    trigger(lab, 'deleted', accepted)
    upgrade(lab)
    response = backfill(lab)
    page = lab.pull('b1', '1')
    before = snapshot(lab)
    error = lab.download('b1', page, expected_exit=1)
    check(error['code'] == 'resource_exhausted' and snapshot(lab) == before, '满pending未原子拒绝历史通知')
    old = lab.rust('b1', 'wire_process')
    check(old['results'][0]['result']['status'] == 'valid', '未知终态副本语义改变')
    lab.download('b1', page)
    final = finished(lab, 'b1', 'deleted', 'processed')
    lab.case_evidence.update(response=response, error=error, snapshot_sha256_before=before,
        old_copy_process=old, signed_page=page.wrapper, final=final, final_ledger=ledger(lab),
        final_relay=relay_records(lab))


CASES = [('M11.backfill.existing_notices', existing_notices),
         ('M11.backfill.scope_and_concurrency', scope_and_concurrency),
         ('M11.backfill.remove_after_terminal', partial(authorization, revoked=False)),
         ('M11.backfill.revoke_after_terminal', partial(authorization, revoked=True)),
         ('M11.backfill.full_pending', full_pending)]
