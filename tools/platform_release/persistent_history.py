#!/usr/bin/env python3
"""dev.4 → dev.5 历史查询验收：新合成签名、冻结 Release、独立安装与真实钥匙串。"""
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sys
import traceback
import uuid

from node_pack import all_hashes, sha, write_json
import persistent_release as release
from persistent_signing import evidence_hashes
from persistent_signing_packages import LabIdentity, RELATIVE, sign, manifest, pack, install
from persistent_history_cases import run as cases

BASELINE = release.OUTPUT / 'runs/97492364-d225-4be0-a612-389cfc73434d/new-release'
EXPECTED_ARCHIVE = 'b03afa01ef0fed727f42085708e85bfac122b6d869542d178518e176abf43475'

def main():
    run = release.OUTPUT / 'runs' / str(uuid.uuid4()); run.mkdir(parents=True)
    temporary = Path('/private/tmp') / ('Rocket IM SDK 历史分页 ' + run.name); temporary.mkdir(mode=0o700)
    report = {'status': 'RUNNING', 'started_at': datetime.now(timezone.utc).isoformat(),
        'source_before': release.sources(), 'baseline': str(BASELINE), 'temporary': str(temporary),
        'stage0': 'NOT_COMPLETE', 'windows': 'NOT_TESTED', 'other_platform_runtime': 'NOT_TESTED', 'distribution': 'NOT_APPROVED'}
    signer = None
    def save(): write_json(run / 'history-report.json', report)
    save(); print(run / 'history-report.json', flush=True)
    try:
        original = json.loads((BASELINE / 'report.json').read_text())
        assert original['status'] == 'PASS_SCOPED' and sha(Path(original['archive'])) == EXPECTED_ARCHIVE == original['archive_sha256']
        assert sha(BASELINE / 'package' / RELATIVE) == original['binary_sha256']
        # 全部前项原件，包括签名失败/矩阵及归档，不重签、不改写。
        report['baseline_hashes'] = evidence_hashes(BASELINE.parent)
        signer = LabIdentity(temporary / 'signer', 'history')
        report['signer'] = {'certificate_sha1': signer.fingerprint, 'keychain': str(signer.path)}
        new = run / 'new-release'; save()
        assert release.main(new, lambda p: sign(p, signer)) == 0, 'new release regression failed'
        new_report = json.loads((new / 'report.json').read_text())
        report['new_release_report'] = str(new / 'report.json')
        old_stage = run / 'old-package'; shutil.copytree(BASELINE / 'package', old_stage)
        report['old_signature'] = sign(old_stage / RELATIVE, signer); manifest(old_stage)
        old_archive = pack(old_stage, run / 'old-archive')
        old_fault = run / 'old-fault-runtime'; shutil.copy2(BASELINE / 'fault-runtime', old_fault)
        report['old_fault_signature'] = sign(old_fault, signer)
        archives = {'old': old_archive, 'new': Path(new_report['archive'])}
        stages = {'old': old_stage, 'new': new / 'package'}
        scripts = new / 'source/tests/consumers/node-persistent'
        consumers = {}; packages = {}; report['packages'] = {}
        for label, archive in archives.items():
            consumer = temporary / ('consumer-' + label)
            packages[label] = install(archive, consumer, scripts, run); consumers[label] = consumer
            for name in ('history-cases.mjs', 'history-live.mjs'): shutil.copy2(scripts / name, consumer / name)
            assert b'ROCKET_IM_TEST_' not in (packages[label] / RELATIVE).read_bytes()
            report['packages'][label] = {'archive': str(archive), 'sha256': sha(archive),
                'installed': str(packages[label]), 'version': json.loads((packages[label] / 'package.json').read_text())['version'],
                'binary_sha256': sha(packages[label] / RELATIVE)}
        assert report['packages']['old']['version'] == '0.2.0-dev.4'
        assert report['packages']['new']['version'] == '0.2.0-dev.5'
        save()
        report['history'] = cases(consumers, old_fault, new / 'fault-runtime', temporary / 'data', run / 'matrix')
        report['source_after'] = release.sources(); assert report['source_after'] == report['source_before']
        assert evidence_hashes(BASELINE.parent) == report['baseline_hashes']
        for label, archive in archives.items():
            assert sha(archive) == report['packages'][label]['sha256']
            assert all_hashes(packages[label]) == all_hashes(stages[label])
        report.update(status='PASS_SCOPED', baseline_preserved=True, source_stable=True)
    except Exception as error:
        report.update(status='FAIL', error=f'{type(error).__name__}: {error}', traceback=traceback.format_exc())
    finally:
        if signer is not None:
            try: signer.close(); report['signer_locked'] = True
            except Exception as error: report.update(status='FAIL', cleanup_error=str(error))
        report['finished_at'] = datetime.now(timezone.utc).isoformat(); save()
    print(json.dumps({'status': report['status'], 'report': str(run / 'history-report.json'), 'error': report.get('error')}), flush=True)
    return 0 if report['status'] == 'PASS_SCOPED' else 1

if __name__ == '__main__': sys.exit(main())
