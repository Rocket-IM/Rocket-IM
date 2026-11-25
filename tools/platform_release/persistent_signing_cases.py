"""旧新正常包消费、未决及材料窗口；系统控制和故障程序仅在外部装置。"""
import json
import os
from pathlib import Path
import secrets
import shutil

from node_pack import sha, write_json
from persistent_faults import Runtime
from persistent_keychain import run as control
from persistent_signing_acl import inspect
from persistent_signing_packages import consume, RELATIVE, NAME, manifest

def run(consumers, packages, old_fault, data_root, directory):
    directory.mkdir(); observations = []; cleanup = []; keychains = []
    scenarios = [('ordinary', None, 'none')]
    scenarios += [(phase, phase, 'none') for phase in ('after_reserve', 'after_candidate', 'after_commit', 'refuse_commit')]
    scenarios += [('recovery-' + stage, 'after_crypto', stage) for stage in ('none', 'offered', 'prepared', 'ready', 'committed', 'finished')]
    def call(which, mode, data, keychain, stage='none', suffix=''):
        label = f'{data.name}-{which}-{mode}-{stage}{suffix}'
        result = consume(consumers[which], mode, data, keychain, stage, directory / (label + '.json'))
        observations.append({'case': label, **result}); write_json(directory / 'progress.json', observations)
        return result
    try:
        for label, phase, stage in scenarios:
            data = data_root / label; data.mkdir(parents=True)
            keychain = data / 'lab-upgrade.keychain-db'; keychains.append(keychain)
            password = secrets.token_hex(32)
            assert control({'op': 'create', 'keychain': str(keychain), 'password': password})['status'] == 0
            call('old', 'setup', data, keychain)
            before = {a: inspect(keychain, data / (a + '.db'), a) for a in ('alice', 'bob')}
            if phase:
                runtime = Runtime(old_fault, data / 'alice.db', 'alice', keychain=keychain,
                    fault=phase if phase != 'refuse_commit' else None, refuse=phase == 'refuse_commit',
                    stderr_path=directory / (label + '-fault-stderr.log'))
                try:
                    runtime.execute('target', {'kind': 'send', 'message_id': 'target', 'text': 'upgrade pending message'},
                        **({'error': 'commit_unknown'} if phase == 'refuse_commit' else {'exited': True}))
                finally:
                    runtime.close()
                assert (directory / (label + '-fault-stderr.log')).read_bytes() == b''
                call('old', 'prepare', data, keychain, stage)
            # 拒绝测试特意重新生成包摘要，证明不是被 SHA/版本检查提前拦截。
            saved = {a: sha(data / (a + '.db')) for a in ('alice', 'bob')}
            if label in ('ordinary', 'recovery-ready'):
                for variant in ('other-signer', 'other-id', 'adhoc'):
                    call(variant, 'deny', data, keychain, 'keychain_auth_failed,keychain_interaction_denied')
                    assert saved == {a: sha(data / (a + '.db')) for a in saved}
                if label == 'ordinary':
                    call('stale-hash', 'deny', data, keychain, 'artifact_hash_mismatch')
                    call('wrong-version', 'deny', data, keychain, 'artifact_version_mismatch')
                    call('tampered', 'deny', data, keychain, 'process_exit_unknown,process_start_failed')
                    # 同一安装路径原子换成错误签名；测试结束恢复正常副本及其摘要。
                    package = packages['old']; live = package / RELATIVE
                    original = live.read_bytes(); artifact = (package / 'artifact.json').read_bytes()
                    try:
                        replacement = live.with_name('replacement')
                        shutil.copy2(packages['other-signer'] / RELATIVE, replacement); os.replace(replacement, live)
                        manifest(package)
                        call('old', 'deny', data, keychain, 'keychain_auth_failed,keychain_interaction_denied', '-same-path')
                    finally:
                        replacement = live.with_name('restore'); replacement.write_bytes(original); replacement.chmod(0o755)
                        os.replace(replacement, live); (package / 'artifact.json').write_bytes(artifact)
                    assert saved == {a: sha(data / (a + '.db')) for a in saved}
            call('new', 'verify', data, keychain)
            # 锁定是真实 OS 状态；解锁后必须继续使用同一旧项。
            assert control({'op': 'lock', 'keychain': str(keychain)})['status'] == 0
            call('new', 'deny', data, keychain, 'keychain_locked')
            assert control({'op': 'unlock', 'keychain': str(keychain), 'password': password})['status'] == 0
            call('new', 'resume', data, keychain, 'successor' if phase == 'after_crypto' else 'exact')
            call('new', 'verify', data, keychain, suffix='-restarted')
            after = {a: inspect(keychain, data / (a + '.db'), a) for a in before}
            assert before == after, 'original public ACL metadata changed'
            write_json(directory / (label + '-acl.json'), {'before': before, 'after': after, 'unchanged': True,
                'boundary': 'public ACL metadata and trusted application paths; not an export of internal DR'})
            for account in ('alice', 'bob'):
                assert (data / (account + '.db')).read_bytes()[:16] != b'SQLite format 3\0'
            # 版本号不是防回滚策略：同 DR 旧程序仍可读取兼容 v3 原库，显式记录。
            if label == 'ordinary':
                call('old', 'verify', data, keychain, suffix='-compatible-old-version')
                call('relocated', 'verify', data, keychain)
        data = data_root / 'adhoc-to-certificate'; data.mkdir()
        keychain = data / 'lab-upgrade.keychain-db'; keychains.append(keychain)
        assert control({'op': 'create', 'keychain': str(keychain), 'password': secrets.token_hex(32)})['status'] == 0
        call('original-adhoc', 'setup', data, keychain)
        before = {a: inspect(keychain, data / (a + '.db'), a) for a in ('alice', 'bob')}
        saved = {a: sha(data / (a + '.db')) for a in before}
        call('old', 'deny', data, keychain, 'keychain_auth_failed,keychain_interaction_denied')
        call('new', 'deny', data, keychain, 'keychain_auth_failed,keychain_interaction_denied')
        assert saved == {a: sha(data / (a + '.db')) for a in saved}
        assert before == {a: inspect(keychain, data / (a + '.db'), a) for a in before}
        call('original-adhoc', 'verify', data, keychain)
        return {'status': 'PASS_SCOPED', 'scenarios': len(scenarios), 'observations': observations}
    finally:
        for keychain in keychains:
            if keychain.exists():
                locked = control({'op': 'lock', 'keychain': str(keychain)})
                state = control({'op': 'status', 'keychain': str(keychain)})
                cleanup.append({'path': str(keychain), 'lock': locked, 'state': state})
        write_json(directory / 'cleanup.json', cleanup)
        assert all(x['lock']['status'] == 0 and x['state']['status'] == 0 and not x['state']['unlocked'] for x in cleanup)
