#!/usr/bin/env python3
"""原生签名/真实钥匙串访问与升级恢复实验；每次使用新目录，正式身份必须显式指定。"""
import argparse
import json
import platform
import sys
import uuid
import subprocess
import shutil
from pathlib import Path

from anchor_verify import source_hashes
from protected_support import redact
from protected_verify import CASE_NAMES, run_cases
from rebuild_verify import package_hashes
from signing_access import run_access
from signing_build import BASE, NAMES, binaries, command, prepare
from signing_lifecycle import run_lifecycle
from support import OUTPUT as STORAGE_OUTPUT, sha, utc_now, write_json

OUTPUT = STORAGE_OUTPUT / 'signing'


def instrument_processes(records):
    """记录每个外部进程启动时实际程序摘要；不读取stdin/stdout秘密内容。"""
    original = subprocess.Popen

    class AuditedProcess(original):
        def __init__(self, args, *positional, **options):
            values = [str(value) for value in args]
            executable = Path(shutil.which(values[0]) or values[0]).resolve()
            digest = sha(executable)
            super().__init__(args, *positional, **options)
            records.append((self, {'pid': self.pid, 'executable': str(executable),
                                  'executable_sha256': digest, 'args': values, 'at': utc_now()}))
    subprocess.Popen = AuditedProcess
    return original


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('adhoc', 'self-signed', 'apple'), required=True)
    parser.add_argument('--identity', help='用户明确选择的Apple签名证书SHA-1；仅apple模式')
    args = parser.parse_args()
    if (args.mode == 'apple') != bool(args.identity):
        parser.error('apple模式必须显式指定identity，其他模式不可指定')
    output = OUTPUT / 'runs' / str(uuid.uuid4())
    output.mkdir(parents=True, mode=0o700)
    report = {'run_id': output.name, 'mode': args.mode, 'status': 'RUNNING', 'started_at': utc_now(),
              'host': {'system': platform.system(), 'release': platform.release(), 'machine': platform.machine()},
              'scope': 'isolated file Keychain signing access and byte-changed package lifecycle',
              'assurance': 'synthetic_local', 'formal_acceptance': 'NOT_COMPLETED',
              'identity_requested': args.identity, 'setup': {}, 'sources_before': source_hashes(),
              'packages_before': package_hashes(), 'baseline_binaries_before': {str(p): sha(p) for p in BASE.iterdir()},
              'not_tested': ['Developer ID distribution and notarization', 'screen lock, logout or operating system reboot',
                             'certificate rotation/revocation, compromised signing key and version anti-rollback',
                             'Windows/mobile, official SDK integration or Stage 1',
                             'production independent anchor; synthetic helper anchor.key remains outside client protection']}
    commands, records = [], []
    processes = []
    original_popen = instrument_processes(processes)
    write_json(output / 'report.json', report)
    print(json.dumps({'run_id': output.name, 'mode': args.mode, 'status': 'STARTED'}), flush=True)
    try:
        report['identity_inventory'] = command(['security', 'find-identity', '-v', '-p', 'codesigning'], records)['stdout']
        groups, probes = prepare(output / 'programs', args.mode, records, report['setup'], args.identity)
        report['setup']['status'] = 'PASS'
        write_json(output / 'report.json', report)
        report['access'] = run_access(groups, probes, output / 'access', commands, records, args.mode)
        print(json.dumps({'access_status': report['access']['status']}), flush=True)
        # 同DR升级才满足生命周期测试的前置；不重建ACL来强行继续。
        equivalent = (report['setup']['equal_dr_and_valid_signatures'] and
                      report['access']['status'] == 'PASS' and
                      report['access'].get('same_dr_reader_permitted') is True and
                      report['access'].get('program_swaps', {}).get('v2', {}).get('accepted') is True)
        if args.mode == 'apple':
            equivalent = equivalent and all(check['cli_accepted'] for check in report['setup']['v1_v2_cross_requirement_checks'])
        if equivalent:
            report['lifecycle'] = run_lifecycle(binaries(groups['v1']), binaries(groups['v2']),
                                                output / 'lifecycle', commands)
            from signing_late_recovery import run_late
            report['late_recovery'] = run_late(binaries(groups['v1']), binaries(groups['v2']),
                                               output / 'late-recovery', commands)
        else:
            report['lifecycle'] = {'status': 'NOT_TESTED', 'reason': 'v2_does_not_satisfy_v1_requirement',
                                   'counts': {'planned': 8, 'total': 0, 'passed': 0}}
        # 原41项实际签名副本回归；不调用会覆盖旧target的原main/build。
        regression = output / 'protected-regression'; regression.mkdir(mode=0o700)
        original = {'status': 'RUNNING', 'cases': [], 'signing_mode': args.mode, 'program_version': 'v2'}
        run_cases(binaries(groups['v2']), regression, original, commands, CASE_NAMES)
        original['counts'] = {'total': len(original['cases']),
                              'passed': sum(case['status'] == 'PASS' for case in original['cases'])}
        original['status'] = 'PASS' if original['counts']['passed'] == len(CASE_NAMES) else 'FAIL'
        write_json(regression / 'report.json', original)
        report['protected_regression'] = original
        successful = report['access']['status'] == original['status'] == 'PASS'
        if args.mode == 'adhoc':
            report['status'] = 'PASS_LIMITED' if successful else 'FAIL'
        else:
            report['status'] = 'PASS_EXPERIMENT' if successful and report['lifecycle']['status'] == 'PASS' and report['late_recovery']['status'] == 'PASS' else 'FAIL'
    except Exception as error:
        report.update(status='FAIL', error=f'{type(error).__name__}: {error}')
    finally:
        subprocess.Popen = original_popen
        public_processes = []
        for process, record in processes:
            record['returncode'] = process.poll()
            record['reaped'] = record['returncode'] is not None
            public_processes.append(record)
        write_json(output / 'external-processes.json', public_processes)
        report['external_process_count'] = len(public_processes)
        report['external_processes_reaped'] = all(item['reaped'] for item in public_processes)
        report['tested_programs_unchanged'] = all(
            sha(Path(item['path'])) == item['sha256']
            for group in report['setup'].get('groups', {}).values() for item in group['binaries'].values())
        if not report['external_processes_reaped'] or not report['tested_programs_unchanged']:
            report.update(status='FAIL', process_or_program_error='进程未回收或已测试程序被改写')
        report['sources_after'] = source_hashes()
        report['packages_after'] = package_hashes()
        report['baseline_binaries_after'] = {str(p): sha(p) for p in BASE.iterdir()}
        report['sources_unchanged'] = report['sources_after'] == report['sources_before']
        report['packages_unchanged'] = report['packages_after'] == report['packages_before']
        report['baseline_binaries_unchanged'] = report['baseline_binaries_after'] == report['baseline_binaries_before']
        if not all(report[key] for key in ('sources_unchanged', 'packages_unchanged', 'baseline_binaries_unchanged')):
            report.update(status='FAIL', stability_error='本轮运行期间输入或既有包/程序变化')
        report['finished_at'] = utc_now()
        if args.mode == 'apple':
            selected = report['setup'].get('selected_identity', {})
            report['apple_signed_local_acceptance'] = {
                'status': 'PASS' if report['status'] == 'PASS_EXPERIMENT' else 'FAIL',
                'identity_kind': selected.get('kind'),
                'team_identifier': selected.get('team_identifier'),
                'scope': '本机隔离文件钥匙串的Apple签名访问、代码升级和恢复生命周期',
                'boundary': '不代表发行、公证、生产安全、证书轮换或正式SDK验收'}
        write_json(output / 'public-commands.json', records)
        with (output / 'commands.jsonl').open('w') as target:
            for entry in commands: target.write(json.dumps(redact(entry), ensure_ascii=False) + '\n')
        write_json(output / 'report.json', redact(report))
    print(json.dumps({'run_id': output.name, 'status': report['status'], 'error': report.get('error'),
                      'lifecycle': report.get('lifecycle', {}).get('counts'),
                      'regression': report.get('protected_regression', {}).get('counts')}), flush=True)
    return 1 if report['status'] == 'FAIL' else 0


if __name__ == '__main__':
    sys.exit(main())
