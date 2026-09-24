"""真实第五程序读取与版本/身份替换；保持创建时的业务秘密 ACL。"""
import json
from pathlib import Path
import shutil
import os
import struct

from protected_support import Fixture
from protected_cases import startup_error
from signing_build import binaries, command, metadata
from support import require, sha, write_json


def check_public_metadata(item):
    require(item['lookup_status'] == item['access_status'] == item['acl_list_status'] == 0
            and item['acls_bounded'] and item['acls'], '无法完整读取现存项公开ACL元数据')
    for acl in item['acls']:
        require(acl['contents_status'] == 0 and acl['authorizations_available'] and
                all(acl[key] for key in ('authorizations_bounded', 'description_bounded', 'applications_bounded')),
                '公开ACL元数据失败或截断')
        require(all(app.get('status') == 0 and app.get('bounded') and app.get('data_hex') is not None
                    for app in acl['applications']), '公开可信应用数据失败或截断')
    read_acls = [acl for acl in item['acls'] if 'ACLAuthorizationDecrypt' in acl['authorizations']]
    require(read_acls and all(acl['applications_present'] and len(acl['applications']) == 4 for acl in read_acls),
            '秘密读取ACL没有固定四个明确应用')


def run_access(groups, probes, directory, commands, records, mode):
    output = Path(directory)
    output.mkdir(mode=0o700)
    fixture = Fixture.__new__(Fixture)
    evidence = {'mode': mode, 'status': 'RUNNING', 'read_probes': {}, 'program_swaps': {}}
    try:
        Fixture.__init__(fixture, binaries(groups['v1']), output, commands)
        fixture.bootstrap()
        fixture.group('signing-access', history=True)
        original = sha(fixture.database)
        for name, path in probes.items():
            result = command([path, fixture.keychain, fixture.locator['item']], records)
            response = json.loads(result['stdout'])
            require(response['pid'] == result['pid'] and response['completed'], '读取探针未实际执行')
            require({item['kind'] for item in response['items']} == {'key', 'trust'}, '探针没有分别读两个秘密项')
            for item in response['items']:
                check_public_metadata(item)
            evidence['read_probes'][name] = response
            if name in ('fifth-id', 'other-signer-same-id') or mode == 'adhoc':
                require(all(item['read_status'] in (-25293, -25308) and not item['got_secret']
                            for item in response['items']), '不同代码身份读取了秘密或未真正到达访问拒绝')
            else:
                # 等DR的不同程序是身份连续性正向对照，不把改名副本当未授权程序。
                evidence['same_dr_reader_permitted'] = all(item['got_secret'] for item in response['items'])
                require(evidence['same_dr_reader_permitted'] and
                        all(item['read_status'] == item['free_status'] == 0 for item in response['items']),
                        '相同签名要求的新内容未获原秘密读取授权')
            require(sha(fixture.database) == original, '只读探针改写数据库')
        # 复制/改名合法程序：代码身份相同，不预设为未授权者。
        copied = output / 'same-identity-copy'
        shutil.copy2(fixture.binary, copied)
        fixture.binary = copied
        with fixture.probe() as probe:
            require(probe.request('inspect')['ok'], '同一合法程序副本不能只读打开')
        evidence['same_bytes_copy_accepted'] = True
        for label in ('other-id', 'other-signer', 'v2'):
            if mode == 'adhoc' and label == 'other-signer':
                evidence['program_swaps'][label] = {'status': 'NOT_TESTED', 'reason': 'ad_hoc_has_no_signer'}
                continue
            fixture.binary = groups[label] / 'native_anchored'
            with fixture.probe(ready=None) as probe:
                started = probe.next_stdout()
                probe.startup, probe.ready = started, started.get('ready') is True
                if started.get('ready'):
                    actual = {'accepted': True, 'pid': probe.process.pid}
                    require(label == 'v2', '不同签名身份/identifier程序访问了原秘密')
                else:
                    actual = {'accepted': False, 'pid': probe.process.pid, 'error': startup_error(started)}
                    probe.finish(1)
                    require(actual['error']['code'] in ('keychain_auth_failed', 'keychain_interaction_denied'),
                            '替换失败没有到达钥匙串访问拒绝')
                    require(label != 'v2' or mode == 'adhoc', '同DR合法升级被钥匙串拒绝')
            evidence['program_swaps'][label] = actual
            require(sha(fixture.database) == original, '打开/拒绝改写原数据库')
        if mode != 'adhoc':
            live = groups['v1'] / 'native_anchored'
            saved = output / 'original-v1-native_anchored'
            shutil.copy2(live, saved)
            replacement = live.with_name('replacement-native_anchored')
            try:
                shutil.copy2(groups['other-signer'] / 'native_anchored', replacement)
                os.replace(replacement, live)
                fixture.binary = live
                with fixture.probe(ready=False) as probe:
                    rejection = startup_error(probe.startup)
                    require(rejection['code'] in ('keychain_auth_failed', 'keychain_interaction_denied'),
                            '同路径不同签名未被钥匙串拒绝')
                    evidence['same_path_other_signer'] = {'pid': probe.process.pid, 'error': rejection,
                                                        'tested_sha256': sha(live)}
            finally:
                shutil.copy2(saved, replacement)
                os.replace(replacement, live)
                require(sha(live) == sha(saved), '没有恢复独立v1副本')
            require(sha(fixture.database) == original, '同路径拒绝改写原库')
        # 故意破坏已签名可执行代码，单独记录系统启动拒绝，不能计成钥匙串读拒绝。
        tampered = output / 'tampered-signed-reader'
        shutil.copy2(probes['fifth-id'], tampered)
        raw = bytearray(tampered.read_bytes())
        require(struct.unpack_from('<I', raw)[0] == 0xFEEDFACF, '探针不是预期Mach-O64')
        position, code_offset = 32, None
        for _ in range(struct.unpack_from('<I', raw, 16)[0]):
            kind, size = struct.unpack_from('<II', raw, position)
            if kind == 0x19:
                for section in range(struct.unpack_from('<I', raw, position + 64)[0]):
                    start = position + 72 + section * 80
                    if raw[start:start + 16].split(b'\0')[0] == b'__text':
                        code_offset = struct.unpack_from('<I', raw, start + 48)[0]
            position += size
        require(code_offset is not None, '找不到签名覆盖的真实代码区')
        raw[code_offset] ^= 1
        tampered.write_bytes(raw)
        static = command(['codesign', '--verify', '--strict', tampered], records, None)
        require(static['returncode'] != 0, '被篡改签名仍通过静态检查')
        launch = command([tampered, fixture.keychain, fixture.locator['item']], records, None)
        evidence['tampered_signature'] = {'sha256': sha(tampered), 'offset': code_offset,
            'static_returncode': static['returncode'], 'launch_pid': launch['pid'],
            'launch_returncode': launch['returncode'], 'probe_result_returned': bool(launch['stdout']),
            'classification': 'signature_validation_or_startup_failure_not_keychain_rejection'}
        require(launch['returncode'] != 0 and not launch['stdout'], '篡改代码仍执行了读取探针')
        final_read = json.loads(command([probes['fifth-id'], fixture.keychain,
                                        fixture.locator['item']], records)['stdout'])
        for item in final_read['items']: check_public_metadata(item)
        def normalized(items):
            return {item['kind']: sorted(json.dumps(acl, sort_keys=True) for acl in item['acls'])
                    for item in items}
        require(normalized(final_read['items']) == normalized(evidence['read_probes']['fifth-id']['items']),
                '访问/替换测试期间原钥匙串ACL发生变化')
        evidence['original_acl_public_metadata_unchanged'] = True
        evidence['acl_observation_boundary'] = 'SecTrustedApplicationCopyData只导出公开路径；不声称导出或比较完整内部DR。装置没有修改业务ACL的调用。'
        evidence.update(status='PASS', database_unchanged=True)
    except Exception as error:
        evidence.update(status='FAIL', error=f'{type(error).__name__}: {error}')
    finally:
        if hasattr(fixture, 'keychain') and fixture.keychain.exists():
            try:
                fixture.ctl('keychain_lock')
                evidence['keychain_locked'] = True
            except Exception as error:
                evidence.update(status='FAIL', cleanup_error=str(error))
        write_json(output / 'access-report.json', evidence)
    return evidence
