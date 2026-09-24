"""原Relay事务与Rust快照真实进程退出；不以模拟返回值替代提交边界。"""

from functools import partial
import http.client

from .deletion_observer import relay_records
from .fixture import check
from .lifecycle_support import (clock, finished, notification, setup, slot, snapshot,
                                transition, trigger)
from .read_faults import _observed_rust


def relay_loss(lab, *, availability, hook):
    packet, accepted, pages, old = setup(lab)
    before = relay_records(lab)
    saved = snapshot(lab)
    if availability == 'expired':
        clock(lab, int(accepted['expires_at_unix_ms']))
    lab.control('hook', hook=hook)
    process = lab.process
    try:
        if availability == 'deleted':
            lab.control('set_availability', acceptance_id=accepted['acceptance_id'], availability='deleted')
        else:
            lab.pull('b1', '1')
        raise AssertionError('指定窗口没有丢失HTTP响应')
    except (http.client.RemoteDisconnected, ConnectionResetError) as error:
        disconnected = type(error).__name__
    expected_exit = {'before_commit_exit': 86, 'after_commit_exit': 87}.get(hook)
    actual_exit = process.poll() if expected_exit is None else process.wait(timeout=10)
    check(actual_exit == expected_exit, 'Relay真实退出码不符')
    after = relay_records(lab)
    committed = hook != 'before_commit_exit'
    if committed:
        transition(before, after, accepted, availability)
    else:
        check(after == before, '退出前留下半投影或半通知')
    check(snapshot(lab) == saved and slot(lab, 'b1') == old['b1'], 'Relay事务改变客户端')
    old_pid = process.pid
    lab.restart()
    check(lab.process.pid != old_pid and relay_records(lab) == after, '重启改变已提交结果')
    trigger(lab, availability, accepted)
    recovered = relay_records(lab)
    transition(before, recovered, accepted, availability)
    check(not committed or recovered == after, '恢复原操作重复追加通知')
    page = lab.pull('b1', '1')
    notification(page, pages['b1']['events'][0], accepted, availability)
    lab.download('b1', page)
    final = finished(lab, 'b1', availability, 'queued')
    check(lab.submit(packet) == {**accepted, 'availability': availability}, '原包恢复改变接受事实')
    lab.case_evidence.update(availability=availability, hook=hook, disconnected=disconnected,
        relay_exit_code=actual_exit, relay_pid=old_pid, recovered_pid=lab.process.pid,
        before_relay=before, after_interruption=after, final_relay=recovered,
        signed_page=page.wrapper, final=final)


def snapshot_loss(lab, *, point):
    _, accepted, pages, old = setup(lab)
    trigger(lab, 'deleted', accepted)
    page = lab.pull('b1', '1')
    notification(page, pages['b1']['events'][0], accepted, 'deleted')
    before = snapshot(lab)
    rows = relay_records(lab)
    code = {'before_save': 83, 'before_rename': 84, 'after_save': 85}[point]
    _, pid = _observed_rust(lab, 'wire_download_signed', **page.signed_input(), failpoint=point, expected_exit=code)
    projected = slot(lab, 'b1')
    wire = lab.rust('b1', 'wire_inspect')
    if point == 'after_save':
        check(projected == {**old['b1'], 'slot': {**old['b1']['slot'], 'availability': 'deleted'}}
              and wire['sync']['download_cursor'] == '2' and slot(lab, 'b1', '2')['found'],
              '提交后原投影、通知和游标未整体持久化')
    else:
        check(snapshot(lab) == before and projected == old['b1'] and wire['sync']['download_cursor'] == '1'
              and not slot(lab, 'b1', '2')['found'], '提交前留下半通知或原槽投影')
    check(relay_records(lab) == rows, '端侧故障改写服务端')
    lab.download('b1', page)
    final = finished(lab, 'b1', 'deleted', 'queued')
    lab.case_evidence.update(point=point, actual_exit_code=code, pid=pid, state_after_exit=wire,
        target_after_exit=projected, before_snapshot_sha256=before, signed_page=page.wrapper,
        final=final, final_relay=rows)


CASES = [(f'M11.lifecycle.{availability}.{hook}', partial(relay_loss, availability=availability, hook=hook))
         for availability in ('deleted', 'expired')
         for hook in ('before_commit_exit', 'after_commit_exit', 'drop_after_commit')]
CASES += [(f'M11.lifecycle.snapshot.{point}', partial(snapshot_loss, point=point))
          for point in ('before_save', 'before_rename', 'after_save')]
