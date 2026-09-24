"""复制已验收程序后签名；不原地改写 protected 产物或自动选择真实身份。"""
from pathlib import Path
import shutil
import subprocess

from signing_keychain import LabIdentity
from support import OUTPUT as STORAGE_OUTPUT, ROOT, require, sha, utc_now

NAMES = ('native_anchored', 'native_crypto', 'native_rebuild', 'native_protection')
BASE = STORAGE_OUTPUT / 'signing/baseline-binaries'
UPGRADE = STORAGE_OUTPUT / 'signing/target/release'
HELPER = BASE / 'openmls-rollback-anchor'


def command(args, records, expected=0):
    """此入口仅接收公开参数，秘密生成/导入由独立内存接口处理。"""
    args = [str(arg) for arg in args]
    record = {'args': args, 'started_at': utc_now()}
    records.append(record)
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    record['pid'] = process.pid
    try:
        stdout, stderr = process.communicate(timeout=40)
        require(len(stdout) + len(stderr) < 4 * 1024 * 1024, '公共签名工具输出超限')
        record.update(stdout=stdout.decode(errors='replace'), stderr=stderr.decode(errors='replace'))
    finally:
        if process.poll() is None:
            import os, signal
            os.killpg(process.pid, signal.SIGKILL)
        record.update(returncode=process.wait(timeout=5), reaped=True, finished_at=utc_now())
    if expected is not None:
        require(record['returncode'] == expected,
                f'{Path(args[0]).name}退出{record["returncode"]}：{record.get("stderr", "")[:800]}')
    return record


def metadata(path, records):
    displayed = command(['codesign', '-d', '-r-', '--verbose=4', path], records)
    text = displayed['stdout'] + displayed['stderr']
    dr = next(line.split('designated => ', 1)[1] for line in text.splitlines()
              if 'designated => ' in line)
    verified = command(['codesign', '--verify', '--strict', '--verbose=2', path], records, None)
    return {'path': str(path), 'sha256': sha(path), 'signature': text, 'requirement': dr,
            'static_valid': verified['returncode'] == 0}


def binaries(directory):
    return (directory / NAMES[0], directory / NAMES[1], HELPER,
            directory / NAMES[2], directory / NAMES[3])


def sign(path, identifier, signer, records):
    args = ['codesign', '--force', '--timestamp=none', '--identifier', identifier]
    if signer is None:
        args += ['--sign', '-']
    elif isinstance(signer, LabIdentity):
        # 仅实验明确固定证书。正式Apple身份沿用codesign生成的发行渠道默认DR。
        from signing_local import sign_local
        started = utc_now()
        result = sign_local(path, identifier, signer.identity,
                            f'designated => identifier "{identifier}" and certificate leaf = H"{signer.fingerprint}"')
        records.append({'operation': 'local_experimental_signing_SPI', 'path': str(path),
                        'identifier': identifier, 'certificate_sha1': signer.fingerprint,
                        'started_at': started, 'finished_at': utc_now(), 'result': result})
        return
    else:
        args += ['--sign', signer]
    command([*args, path], records)


def copy_group(output, label, signer, records, version=1, other_id=False):
    directory = output / label / 'release'
    directory.mkdir(parents=True, mode=0o700)
    unsigned_payloads = {}
    for name in NAMES:
        path = directory / name
        source = UPGRADE / name if version == 2 else BASE / name
        require(source.is_file(), f'缺少版本输入：{source}')
        shutil.copy2(source, path)
        if version == 2:
            # v2含本轮清理后故障检查点，并提高实验最低系统版本load command。
            # 用于代码身份连续性；不是schema迁移或已发布产品升级。
            command(['xcrun', 'vtool', '-set-build-version', 'macos', '12.0', '26.1',
                     '-replace', '-output', path, path], records)
        unsigned_payloads[name] = sha(path)
        identifier = f'org.rocket-im.lab.{"other." if other_id else ""}{name}'
        sign(path, identifier, signer, records)
    return directory, unsigned_payloads


def prepare(output, mode, records, report, identity=None):
    output = Path(output)
    signers = []
    try:
        if mode == 'self-signed':
            first = LabIdentity(output / 'signing-a', 'a'); signers.append(first)
            second = LabIdentity(output / 'signing-b', 'b'); signers.append(second)
        elif mode == 'apple':
            require(identity is not None and len(identity) == 40 and
                    all(c in '0123456789abcdefABCDEF' for c in identity), '必须明确提供合法身份指纹')
            from signing_apple import selected_identity
            report['selected_identity'] = selected_identity(identity, output, records, command)
            first, second = identity, None
            report['alternate_identity_boundary'] = 'ad hoc对照，不代表第二个Apple签名团队；不同Apple身份迁移未测试'
        else:
            first, second = None, None
        report['signers'] = [{'kind': 'isolated_self_signed', 'fingerprint': s.fingerprint,
                              'keychain': str(s.path)} for s in signers]
        groups = {}
        for name, signer, version, other in [('v1', first, 1, False), ('v2', first, 2, False),
                                              ('other-id', first, 1, True), ('other-signer', second, 1, False)]:
            directory, payloads = copy_group(output, name, signer, records, version, other)
            groups[name] = directory
            report.setdefault('groups', {})[name] = {
                'payload_before_signing': payloads,
                'binaries': {name: metadata(directory / name, records) for name in NAMES}}
        require(all(report['groups']['v1']['payload_before_signing'][n] !=
                    report['groups']['v2']['payload_before_signing'][n] for n in NAMES),
                'v1/v2签名前载荷没有全部变化')
        checks = []
        for name in NAMES:
            a, b = report['groups']['v1']['binaries'][name], report['groups']['v2']['binaries'][name]
            for source, target in ((a, b), (b, a)):
                result = command(['codesign', '--verify', '--strict', '-R', '=' + source['requirement'],
                                  target['path']], records, None)
                checks.append({'requirement_from': source['path'], 'tested': target['path'],
                               'cli_accepted': result['returncode'] == 0,
                               'stderr': result['stderr']})
        report['v1_v2_cross_requirement_checks'] = checks
        report['equal_dr_and_valid_signatures'] = all(
            report['groups']['v1']['binaries'][name]['requirement'] ==
            report['groups']['v2']['binaries'][name]['requirement'] and
            report['groups']['v1']['binaries'][name]['static_valid'] and
            report['groups']['v2']['binaries'][name]['static_valid'] for name in NAMES)
        if mode == 'apple':
            from signing_apple import verify_signed
            report['apple_signature_checks'] = [
                verify_signed(item, report['selected_identity'], records, command)
                for name in ('v1', 'v2', 'other-id')
                for item in report['groups'][name]['binaries'].values()]
        report['requirement_check_boundary'] = (
            'Apple模式使用系统默认DR；全部Apple程序的实际叶证书、Authority、Team必须匹配所选身份，'
            'v1/v2双向CLI要求检查全部通过后才执行升级恢复。' if mode == 'apple' else
            '自签不受系统根信任；CLI额外-R可能返回CSSMERR_TP_NOT_TRUSTED。'
            '分别记录完整签名校验、DR字面相等与真实钥匙串访问，不将额外CLI拒绝写成通过。'
            if mode == 'self-signed' else 'ad hoc无签名者；程序字节变化后的身份连续性不能由相同identifier保证。')
        probe_source = ROOT / 'tools/native_storage/signing_probe.c'
        unsealed = output / 'probe-unsealed'
        command(['xcrun', 'clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                 '-framework', 'Security', '-framework', 'CoreFoundation', probe_source, '-o', unsealed], records)
        probes = {}
        for label, signer, identifier in [
                ('fifth-id', first, 'org.rocket-im.lab.fifth_reader'),
                ('same-id-new-content', first, 'org.rocket-im.lab.native_protection'),
                ('other-signer-same-id', second, 'org.rocket-im.lab.native_protection')]:
            path = output / f'probe-{label}'
            shutil.copy2(unsealed, path); sign(path, identifier, signer, records)
            probes[label] = path
            report.setdefault('probes', {})[label] = metadata(path, records)
            if mode == 'apple' and signer is not None:
                report['apple_signature_checks'].append(
                    verify_signed(report['probes'][label], report['selected_identity'], records, command))
        require(all(item['static_valid'] for group in report['groups'].values()
                    for item in group['binaries'].values()) and
                all(item['static_valid'] for item in report['probes'].values()),
                '身份对照或读取探针签名无效，不能作为钥匙串授权对照')
        return groups, probes
    finally:
        for signer in signers:
            signer.close()
            report.setdefault('signing_keychains_locked', []).append(str(signer.path))
