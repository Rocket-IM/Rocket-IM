"""为本轮实验副本签名、封包和独立安装；不修改历史 Release。"""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

from node_pack import all_hashes, node_binary, npm_command, sha, write_json
from persistent_release import ROOT, NAME
sys.path.insert(0, str(ROOT / 'tools/native_storage'))
from signing_keychain import LabIdentity
from signing_local import sign_local

IDENTIFIER = 'org.rocket-im.sdk.signing-lab.runtime'
RELATIVE = Path('bin/darwin-arm64/rocket-im-desktop-runtime')

def command(args, directory, label, expected=0):
    p = subprocess.run([str(x) for x in args], capture_output=True, text=True, timeout=60)
    write_json(directory / (label + '.json'), {'argv': [str(x) for x in args],
        'returncode': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr})
    if expected is not None:
        assert p.returncode == expected, f'{label}: {p.stderr}'
    return p

def requirement(identity, identifier=IDENTIFIER):
    return f'identifier "{identifier}" and certificate leaf = H"{identity.fingerprint}"'

def sign(path, identity, identifier=IDENTIFIER):
    before = sha(path)
    result = sign_local(path, identifier, identity.identity, 'designated => ' + requirement(identity, identifier))
    p = subprocess.run(['/usr/bin/codesign', '--verify', '--strict', str(path)], capture_output=True, text=True, timeout=15)
    assert p.returncode == 0, p.stderr
    info = subprocess.run(['/usr/bin/codesign', '-d', '-r-', '--verbose=4', str(path)], capture_output=True, text=True, timeout=15)
    assert info.returncode == 0
    details = info.stdout + info.stderr
    assert 'designated => ' + requirement(identity, identifier) in details, 'signed DR differs from requested requirement'
    assert 'Signature=adhoc' not in details
    return {**result, 'input_sha256': before, 'signed_sha256': sha(path),
        'certificate_sha1': identity.fingerprint, 'requirement': requirement(identity, identifier), 'codesign': details}

def manifest(stage):
    path = stage / 'artifact.json'
    original = json.loads(path.read_text())
    original['binarySha256'] = sha(stage / RELATIVE)
    original['filesSha256'] = {k: v for k, v in all_hashes(stage).items() if k != 'artifact.json'}
    write_json(path, original)

def pack(stage, directory):
    directory.mkdir(parents=True)
    p = subprocess.run([str(x) for x in npm_command() + ['pack', '--json', '--ignore-scripts', '--pack-destination', directory]],
        cwd=stage, capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    archive = directory / json.loads(p.stdout)[0]['filename']
    with tarfile.open(archive) as tar:
        actual = {}
        for member in tar.getmembers():
            assert member.isfile() and member.name.startswith('package/') and '..' not in Path(member.name).parts
            name = member.name[8:]; assert name not in actual
            import hashlib
            actual[name] = hashlib.sha256(tar.extractfile(member).read()).hexdigest()
    assert actual == all_hashes(stage)
    return archive

def verified_copy(source, target, identity, expected_archive):
    """核验实际旧包全部输入后只重签测试副本；同签名升级不修改原包或任何业务ACL。"""
    source, target = Path(source).resolve(), Path(target).resolve()
    original = json.loads((source / 'report.json').read_text())
    before = all_hashes(source / 'package')
    assert original['status'] == 'PASS_SCOPED'
    assert sha(Path(original['archive'])) == original['archive_sha256'] == expected_archive
    assert before == original['package_files']
    assert sha(source / 'fault-runtime') == original['fault_binary_sha256']
    assert all(sha(source / 'source' / n) == h for n, h in original['source_before'].items())
    target.mkdir()
    shutil.copytree(source / 'package', target / 'package')
    shutil.copytree(source / 'source', target / 'source')
    signing = sign(target / 'package' / RELATIVE, identity)
    manifest(target / 'package')
    archive = pack(target / 'package', target / 'archive')
    shutil.copy2(source / 'fault-runtime', target / 'fault-runtime')
    fault_signing = sign(target / 'fault-runtime', identity)
    report = {'status': 'PASS_SCOPED', 'kind': 'verified_resigned_copy_not_rebuild',
        'baseline_report': str(source / 'report.json'), 'baseline_archive_sha256': expected_archive,
        'source_before': original['source_before'], 'archive': str(archive), 'archive_sha256': sha(archive),
        'package_files': all_hashes(target / 'package'), 'signing': signing, 'fault_signing': fault_signing,
        'fault_binary_sha256': sha(target / 'fault-runtime')}
    assert all_hashes(source / 'package') == before and sha(Path(original['archive'])) == expected_archive
    write_json(target / 'report.json', report)
    return report

def install(archive, consumer, scripts, directory):
    consumer.mkdir(parents=True)
    for name in ('signing-cases.mjs', 'recovery-support.mjs'):
        shutil.copy2(scripts / name, consumer / name)
    write_json(consumer / 'package.json', {'name': 'isolated-signing-consumer', 'private': True, 'type': 'module'})
    p = subprocess.run([str(x) for x in npm_command() + ['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', archive]],
        cwd=consumer, capture_output=True, text=True, timeout=60)
    write_json(directory / ('install-' + consumer.name + '.json'), {'returncode': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr})
    assert p.returncode == 0, p.stderr
    package = consumer / 'node_modules' / NAME
    with tarfile.open(archive) as tar:
        import hashlib
        expected = {m.name[8:]: hashlib.sha256(tar.extractfile(m).read()).hexdigest() for m in tar.getmembers()}
    assert all_hashes(package) == expected
    return package

def consume(consumer, mode, data, keychain, stage, log):
    # 接入进程的 PATH 只含 Node，不依赖 Cargo、签名器或本仓库源文件。
    import os
    env = {k: v for k, v in os.environ.items() if not k.startswith('ROCKET_IM_TEST_')}
    env['PATH'] = str(Path(node_binary()).parent)
    args = [node_binary(), 'signing-cases.mjs', mode, data, keychain, stage]
    p = subprocess.run([str(x) for x in args], cwd=consumer, env=env, capture_output=True, text=True, timeout=60)
    write_json(log, {'returncode': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr})
    assert p.returncode == 0 and not p.stderr, f'consumer failed: {log}'
    result = json.loads(p.stdout); assert result['status'] == 'PASS'
    return result
