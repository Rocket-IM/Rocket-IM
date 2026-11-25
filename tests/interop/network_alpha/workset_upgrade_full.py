"""实际旧dev.12满额v5拒绝原件，保留尚未报告的连续控制后显式升级v7。"""
from pathlib import Path
from capacity_cases import start
from commit_faults import FaultRuntime
from diagnostics_cases import secret_samples
from harness import Worker, require, wait, sha
from rejection_cases import terminal, verify_originals
from rejection_upgrade import install, acls
from workset_harness import enable, originals, service_state


def interrupted(lab, phase):
    fault = FaultRuntime(lab, 1, phase)
    lab.report.setdefault('fault_processes', []).append({'pid': fault.process.pid, 'phase': phase})
    try:fault.exited()
    finally:fault.close()
    lab.restore(1)


def run(lab, new):
    old = lab.release
    start(lab);lab.fill(254, 'actual-old-v5-preload');lab.offline()
    lab.send(1, 'old-v5-known');lab.auto(1)
    wait(lambda: lab.status(1, 'old-v5-known', 'accepted'), 'actual255 acceptance');lab.workers[1].call('disconnect')
    lab.auto(0);wait(lambda: lab.fact('old-v5-known')['delivered'], 'known old control exists')
    lab.send(0, 'old-v5-final');wait(lambda: lab.status(0, 'old-v5-final', 'accepted'), 'actual256 acceptance')
    lab.workers[0].call('disconnect');lab.send(1, 'old-v5-rejected')
    lab.case('actual_old_v5_terminal_with_unreported_control', lambda: interrupted(lab, 'network_after_rejection_commit'))
    require(terminal(lab, 'old-v5-rejected'), 'actual old package persisted v5 rejection')
    interrupted(lab, 'network_after_download')
    require(lab.workers[1].call('network')['processed'] == '254', 'fixed old cursor before control255 and message256')
    backup, info = lab.export(1, 'actual-v5-full-original');require(info['format'] == 1, 'old v5 format1 backup')
    before = [lab.snapshot(i) for i in range(2)];access = acls(lab)
    lab.stop_service();lab.maintenance('enable-capacity-reserve')
    service = lab.database_snapshot();service_backup = lab.export_service('actual-alpha7-full')
    lab.install_new_service();lab.import_service(service_backup)
    require(lab.database_snapshot() == service, 'full old Service original rows restored exactly');lab.start_service()
    for i in range(2):
        previous = lab.workers[i];previous.close();checksum = sha(Path(previous.options['path']))
        directory = install(lab, new, 'v5-full-upgrade-'+str(i));lab.workers[i] = Worker(directory, previous.options)
        lab.setup(i);lab.instrument(lab.workers[i], i);lab.track()
        require(sha(Path(previous.options['path'])) == checksum and lab.snapshot(i) == before[i], 'new open preserves actual v3/v5 originals without migration')
    lab.release = new
    lab.case('actual_full_v5_backup_read', lambda: lab.roundtrip(1, backup))
    enable(lab)
    state = lab.workers[1].call('prepareWorkset')
    require(state['workset']['first'] == state['workset']['last'] == '255', 'new common range stops before unknown message256')
    originals(lab, 1, state)
    for i in range(2):lab.auto(i)
    wait(lambda: lab.workers[1].call('workset')['phase'] == 'settled', 'old v5 control correctly settles after upgrade', 45)
    lab.aligned();lab.offline()
    lab.case('all_full_originals_and_rejected_request_retained', lambda: verify_originals(lab, ['old-v5-rejected']))
    lab.case('old_v5_backup_cannot_revoke_common', lambda: lab.roundtrip(1, backup, expected='backup_stale'))
    path, info = lab.export(1, 'actual-v5-upgraded-v7');require(info['format'] == 3, 'full upgraded backup3')
    lab.case('full_upgraded_v7_restore', lambda: lab.roundtrip(1, path))
    lab.case('full_upgraded_schema7_restore', lambda: lab.controlled_restore('actual-v5-common-full', reconnect=False))
    require(service_state(lab, 1) == lab.workers[1].call('workset'), 'terminal common record survives both restores')
    require(acls(lab) == access, 'same dedicated ACL after full upgrade')
    for i in range(2):lab.case('full_upgraded_secret_state_'+str(i), lambda i=i: lab.audit(i))
    lab.case('full_upgraded_secret_samples', lambda: secret_samples(lab))
    lab.report['actual_v5_common_upgrade'] = {'old_release': str(old), 'new_release': str(new),
        'old_v5_rejected_original': True, 'accepted': 256, 'rejected': 1, 'range': ['255', '255'],
        'unknown_message_not_promised': '256', 'final_format': 7, 'backup_format': 3}
