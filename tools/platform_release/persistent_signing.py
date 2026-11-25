#!/usr/bin/env python3
"""本机 SDK 签名升级验收：新合成签名身份、旧新 TGZ 和真实系统密钥库。"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import traceback
import uuid

from node_pack import all_hashes, sha, write_json
import persistent_release as release
from persistent_signing_packages import (LabIdentity, IDENTIFIER, RELATIVE, NAME, command,
    requirement, sign, manifest, pack, install)
from persistent_signing_cases import run as cases

BASELINE = release.OUTPUT / 'runs/9936977d-0f25-4083-bb71-7b1ab3c40dfe'

def evidence_hashes(directory):
    # 旧报告包含仅供消费环境的 node 符号链接；证据检查记录链接本身，不跟随读取。
    return {str(p.relative_to(directory)): {'symlink': os.readlink(p)} if p.is_symlink() else sha(p)
        for p in sorted(directory.rglob('*')) if p.is_symlink() or p.is_file()}

def tamper(path):
    raw = bytearray(path.read_bytes()); assert struct.unpack_from('<I', raw)[0] == 0xFEEDFACF
    position = 32; offset = None
    for _ in range(struct.unpack_from('<I', raw, 16)[0]):
        kind, size = struct.unpack_from('<II', raw, position)
        if kind == 0x19:
            for section in range(struct.unpack_from('<I', raw, position + 64)[0]):
                start = position + 72 + section * 80
                if raw[start:start + 16].split(b'\0')[0] == b'__text':
                    offset = struct.unpack_from('<I', raw, start + 48)[0]
        position += size
    assert offset is not None; raw[offset] ^= 1; path.write_bytes(raw)
    return offset

def main():
    run = release.OUTPUT / 'runs' / str(uuid.uuid4()); run.mkdir(parents=True)
    temporary = Path('/private/tmp') / ('Rocket IM SDK 签名升级 ' + run.name); temporary.mkdir(mode=0o700)
    report = {'status': 'RUNNING', 'started_at': datetime.now(timezone.utc).isoformat(),
        'scope': 'macOS arm64 / Node / synthetic self-signed identity / file keychain',
        'source_before': release.sources(), 'baseline': str(BASELINE), 'temporary': str(temporary),
        'signatures': {}, 'packages': {}, 'stage0': 'NOT_COMPLETE', 'windows': 'NOT_TESTED',
        'apple_development': 'NOT_TESTED', 'developer_id': 'NOT_TESTED', 'distribution': 'NOT_APPROVED'}
    identities = []
    def save(): write_json(run / 'signing-report.json', report)
    save(); print(str(run / 'signing-report.json'), flush=True)
    try:
        original = json.loads((BASELINE / 'report.json').read_text())
        baseline_hashes = evidence_hashes(BASELINE)
        assert original['status'] == 'PASS_SCOPED'
        assert sha(Path(original['archive'])) == original['archive_sha256']
        assert sha(BASELINE / 'package' / RELATIVE) == original['binary_sha256']
        assert {p: sha(BASELINE / 'source' / p) for p in original['source_before']} == original['source_before']
        report['baseline_hashes'] = baseline_hashes
        signer = LabIdentity(temporary / 'signer', 'recognized'); identities.append(signer)
        other = LabIdentity(temporary / 'other-signer', 'unrecognized'); identities.append(other)
        report['signers'] = [{'certificate_sha1': x.fingerprint, 'keychain': str(x.path)} for x in identities]
        new_run = run / 'new-release'
        assert release.main(new_run, lambda path: sign(path, signer)) == 0, 'new Release regression failed'
        new_report = json.loads((new_run / 'report.json').read_text())
        report['new_release_report'] = str(new_run / 'report.json')
        frozen_scripts = new_run / 'source/tests/consumers/node-persistent'
        old_stage = run / 'old-package'; shutil.copytree(BASELINE / 'package', old_stage)
        report['signatures']['old'] = sign(old_stage / RELATIVE, signer); manifest(old_stage)
        old_archive = pack(old_stage, run / 'old-archive')
        # 旧版故障程序只施加确定退出；正常旧包自行创建业务项，无额外 ACL 应用。
        old_fault = run / 'old-fault-runtime'; shutil.copy2(BASELINE / 'fault-runtime', old_fault)
        report['signatures']['old-fault'] = sign(old_fault, signer)
        archives = {'old': old_archive, 'new': Path(new_report['archive'])}
        stages = {'old': old_stage, 'new': new_run / 'package'}
        for label in ('other-signer', 'other-id', 'adhoc', 'stale-hash', 'wrong-version', 'tampered'):
            stage = run / ('package-' + label); shutil.copytree(stages['new'], stage)
            binary = stage / RELATIVE
            if label in ('other-signer', 'stale-hash'):
                report['signatures'][label] = sign(binary, other)
            elif label == 'other-id':
                report['signatures'][label] = sign(binary, signer, IDENTIFIER + '.other')
            elif label == 'adhoc':
                command(['/usr/bin/codesign', '--force', '--sign', '-', '--identifier', IDENTIFIER, binary], run, label)
                command(['/usr/bin/codesign', '--verify', '--strict', binary], run, label + '-verify')
            elif label == 'tampered':
                report['tampered_offset'] = tamper(binary)
                assert command(['/usr/bin/codesign', '--verify', '--strict', binary], run, label + '-verify', None).returncode != 0
            if label != 'stale-hash': manifest(stage)
            if label == 'wrong-version':
                p = stage / 'artifact.json'; value = json.loads(p.read_text()); value['version'] = '0.0.0-invalid'; write_json(p, value)
            archives[label] = pack(stage, run / ('archive-' + label)); stages[label] = stage
        archives['original-adhoc'] = Path(original['archive']); stages['original-adhoc'] = BASELINE / 'package'
        consumers = {}; packages = {}
        for label, archive in archives.items():
            consumer = temporary / ('consumer-' + label)
            packages[label] = install(archive, consumer, frozen_scripts, run); consumers[label] = consumer
            report['packages'][label] = {'archive': str(archive), 'sha256': sha(archive), 'installed': str(packages[label]),
                'binary_sha256': sha(packages[label] / RELATIVE), 'version': json.loads((packages[label] / 'package.json').read_text())['version']}
        assert report['packages']['old']['version'] != report['packages']['new']['version']
        assert report['packages']['old']['binary_sha256'] != report['packages']['new']['binary_sha256']
        # 合法安装整体搬迁；原数据路径不变，测试可执行文件路径不是授权依据。
        relocated = temporary / '合法 改名安装'; shutil.copytree(consumers['new'], relocated)
        consumers['relocated'] = relocated; packages['relocated'] = relocated / 'node_modules' / NAME
        for label in ('old', 'new', 'other-signer', 'other-id', 'adhoc'):
            p = command(['/usr/bin/codesign', '--verify', '--strict', '-R', '=' + requirement(signer), packages[label] / RELATIVE], run, 'recognized-requirement-' + label, None)
            assert (p.returncode == 0) == (label in ('old', 'new')), f'{label}: recognized requirement check mismatch'
        for label in ('old', 'new'):
            assert b'ROCKET_IM_TEST_' not in (packages[label] / RELATIVE).read_bytes()
        save()
        report['upgrade'] = cases(consumers, packages, old_fault, temporary / 'data', run / 'matrix')
        report['source_after'] = release.sources(); assert report['source_after'] == report['source_before']
        assert evidence_hashes(BASELINE) == baseline_hashes, 'historical evidence changed'
        for label, archive in archives.items():
            assert sha(archive) == report['packages'][label]['sha256']
            assert all_hashes(packages[label]) == all_hashes(stages[label]), f'installed package changed: {label}'
        report.update(status='PASS_SCOPED', baseline_preserved=True, source_stable=True)
    except Exception as error:
        report.update(status='FAIL', error=f'{type(error).__name__}: {error}', traceback=traceback.format_exc())
    finally:
        report['signing_cleanup'] = []
        for identity in identities:
            try:
                identity.close(); report['signing_cleanup'].append({'path': str(identity.path), 'locked': True})
            except Exception as error:
                report.update(status='FAIL', cleanup_error=str(error))
        report['finished_at'] = datetime.now(timezone.utc).isoformat(); save()
    print(json.dumps({'status': report['status'], 'report': str(run / 'signing-report.json'), 'error': report.get('error')}), flush=True)
    return 0 if report['status'] == 'PASS_SCOPED' else 1

if __name__ == '__main__': sys.exit(main())
