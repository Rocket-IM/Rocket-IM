"""实际dev.12/alpha.7原库和原备份；新显式格式与旧二进制拒载。"""
from pathlib import Path
import json
import os
import subprocess
from capacity_cases import start
from diagnostics_cases import secret_samples
from harness import Worker, require, sha, node_binary, wait
from rejection_upgrade import install, acls
from workset_harness import source, originals, service_state, enable

OLD_SERVICE = Path(__file__).resolve().parents[3]/'dist/platform-release/persistent/runs/a113058b-4419-47df-aacb-21f94837b5b4/release-05/im-service'
OLD_SHA = '1e828e452598e8a0f2d5b89fa46bd4f5c08d2c726e913c5e7f40c914da34cc63'


def run(lab, new, legacy=False):
    old = lab.release
    lab.case('actual_dev12_alpha7_originals', lambda: start(lab));lab.aligned();lab.offline()
    if not legacy:
        for w in lab.workers:w.call('reserveCapacity')
    lab.stop_service();lab.maintenance('enable-capacity-reserve');lab.start_service()
    backup, info = lab.export(0, 'actual-dev12-original')
    require(info['format'] == (1 if legacy else 2), 'actual predecessor backup format')
    before = [lab.snapshot(i) for i in range(2)]; access = acls(lab)
    lab.stop_service();service = lab.database_snapshot();service_backup = lab.export_service('actual-alpha7')
    lab.install_new_service();lab.import_service(service_backup)
    require(lab.database_snapshot() == service, 'old Service complete backup exact with new executable')
    lab.start_service()
    for i in range(2):
        prior = lab.workers[i];prior.close();checksum = sha(Path(prior.options['path']))
        directory = install(lab, new, 'common-upgrade-'+str(i))
        lab.workers[i] = Worker(directory, prior.options);lab.setup(i);lab.instrument(lab.workers[i], i);lab.track()
        require(sha(Path(prior.options['path'])) == checksum, 'new open does not auto upgrade old format')
        require(lab.snapshot(i) == before[i], 'exact previous identity originals history and cursors')
        require(lab.workers[i].call('workset') is None, 'old data never invents common state')
    lab.release = new
    lab.case('actual_old_backup_read', lambda: lab.roundtrip(0, backup))
    require(acls(lab) == access, 'same signer preserves original ACL')
    lab.case('explicit_v6_schema6_to_common', lambda: enable(lab))
    for i in range(2):
        source(lab, i, 'common-upgrade-source-'+str(i))
        lab.workers[i].call('prepareWorkset');lab.auto(i)
        wait(lambda: (lab.workers[i].call('workset') or {}).get('phase') == 'settled', 'new public protocol settles')
        lab.aligned();lab.offline()
    lab.case('old_backup_cannot_remove_common', lambda: lab.roundtrip(0, backup, expected='backup_stale'))
    lab.consumer().call('worksets', {}, code='forbidden')
    def old_gate():
        for i in range(2):
            w = lab.workers[i];w.close();checksum = sha(Path(w.options['path']))
            directory = install(lab, old, 'dev12-common-gate-'+str(i))
            path = directory/'probe.json';path.write_text(json.dumps(w.options));path.chmod(0o600)
            env = {k:v for k,v in os.environ.items() if not k.startswith(('CARGO','RUST','ROCKET_IM_TEST_'))};env['PATH'] = str(directory/'path')
            p = subprocess.run([node_binary(), 'upgrade-probe.mjs', path], cwd=directory, env=env, capture_output=True, text=True, timeout=30)
            require(p.returncode == 0 and not p.stderr and json.loads(p.stdout) == {'ok': False, 'code': 'store_format_unsupported'}, 'actual dev12 rejects v7')
            require(sha(Path(w.options['path'])) == checksum, 'old refusal leaves original bytes');lab.restore(i)
        lab.stop_service();before = lab.database_snapshot();head = sha(lab.head)
        env = {**os.environ, 'ROCKET_IM_TEST_ISSUER_KEY': lab.signing_key, 'PATH': '/usr/bin:/bin'}
        require(sha(OLD_SERVICE) == OLD_SHA, 'old alpha7 artifact unchanged')
        p = subprocess.run([OLD_SERVICE, '-config', lab.config], env=env, capture_output=True, text=True, timeout=30)
        (lab.run/'old-alpha7-gate.log').write_text(p.stdout+p.stderr)
        require(p.returncode != 0 and p.stderr.strip().split()[-1] == 'schema_version_unsupported', 'actual alpha7 refuses schema7')
        latest = lab.export_service('alpha8-workset-for-old-gate')
        target = lab.new_target('alpha7-refuses-alpha8-workset-backup')
        p = subprocess.run([OLD_SERVICE, '-config', target, '-operation', 'restore', '-backup', latest], env=env, capture_output=True, text=True, timeout=30)
        (lab.run/'old-alpha7-backup-gate.log').write_text(p.stdout+p.stderr)
        require(p.returncode != 0 and p.stderr.strip().split()[-1] == 'service_backup_version_unsupported', 'actual alpha7 refuses new complete backup')
        require(before == lab.database_snapshot() and sha(lab.head) == head, 'old Service and backup refusal retain all data and external progress')
        lab.start_service()
    lab.case('actual_old_binaries_refuse_new_formats', old_gate)
    for i in range(2):
        state = lab.workers[i].call('workset');originals(lab, i, state)
        path, info = lab.export(i, 'common-upgraded-v7-'+str(i));require(info['format'] == 3, 'new backup3')
        def gate(i=i, path=path):
            w = lab.workers[i];w.close();checksum = sha(Path(w.options['path']))
            lab.probe(i, path, expected='backup_format_unsupported', directory=lab.root/('dev12-common-gate-'+str(i)))
            require(sha(Path(w.options['path'])) == checksum, 'old format3 refusal preserves data');lab.restore(i)
        lab.case('old_backup3_refusal_'+str(i), gate)
        lab.case('new_complete_backup3_restore_'+str(i), lambda i=i,path=path: lab.roundtrip(i, path))
    lab.case('new_schema7_full_backup_restore', lambda: lab.controlled_restore('common-upgraded', reconnect=False))
    require(acls(lab) == access, 'all upgrades preserve original ACL')
    for i in range(2):
        require(service_state(lab, i) == lab.workers[i].call('workset'), 'same terminal workset after all restores')
    lab.case('upgrade_common_secret_samples', lambda: secret_samples(lab))
    lab.report['workset_upgrade'] = {'client': 'actual dev12 '+('v3/v4' if legacy else 'v6')+' → dev13 explicit v7',
        'service': 'actual alpha7 schema6 → alpha8 explicit schema7', 'old_backups_read': True,
        'old_artifacts_refuse_new': True, 'config_permissions_unchanged': True}
