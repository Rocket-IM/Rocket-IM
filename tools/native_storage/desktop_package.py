"""TS 桌面实验包：冻结源码、实际 Release、许可、npm 白名单与独立离线消费。"""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tarfile

from support import ROOT, CRATE, run_command, require, sha, source_hashes, write_json
from crypto_verify import licenses
sys.path.insert(0, str(ROOT / 'tools/platform_release'))
from node_pack import node_binary, npm_command, COMPILER, command, all_hashes

OUTPUT = ROOT / 'dist/native-storage/ts-desktop'
PACKAGE = CRATE / 'package'
TEMPLATE = ROOT / 'tests/consumers/node-storage'
NAME = '@rocket-im/stage0-desktop-storage'
VERSION = '0.1.0-stage0.1'


def sources():
    result = source_hashes()
    result.update({str(p.relative_to(ROOT)): sha(p) for p in TEMPLATE.rglob('*') if p.is_file()})
    for name in ('node_pack.py',):
        p = ROOT / 'tools/platform_release' / name
        result[str(p.relative_to(ROOT))] = sha(p)
    return result


def build(run, report):
    frozen = run / 'source'
    for name in report['source_before']:
        dest = frozen / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, dest)
    crate = frozen / 'poc/native-storage'
    cargo = [ROOT / 'dist/toolchains/rust/cargo/bin/cargo', '+1.98.1']
    common = ['--manifest-path', crate / 'Cargo.toml', '--locked', '--offline']
    target = ['--target-dir', OUTPUT / 'target']
    records = report['commands']
    report['rustc'] = run_command([ROOT / 'dist/toolchains/rust/cargo/bin/rustc', '+1.98.1', '-vV'], run / 'rustc.log', records)
    require('host: aarch64-apple-darwin' in report['rustc'], '本轮仅支持实际 macOS ARM64 构建')
    run_command([*cargo, 'fmt', '--manifest-path', crate / 'Cargo.toml', '--check'], run / 'fmt.log', records)
    run_command([*cargo, 'clippy', *common, *target, '--release', '--all-targets', '--', '-D', 'warnings'], run / 'clippy.log', records)
    run_command([*cargo, 'test', *common, *target, '--release'], run / 'rust-tests.log', records)
    run_command([*cargo, 'build', *common, *target, '--release', '--bin', 'desktop_storage', '--bin', 'native_crypto'], run / 'build.log', records)
    metadata = json.loads(run_command([*cargo, 'metadata', *common, '--format-version', '1'], run / 'metadata.json', records))
    stage = run / 'package'
    stage.mkdir()
    report['dependency_count'] = licenses(metadata, stage)
    source_package = crate / 'package'
    for name in ('package.json', 'README.md'):
        shutil.copy2(source_package / name, stage / name)
    require(json.loads((COMPILER.parent.parent / 'package.json').read_text())['version'] == '5.9.3', 'TypeScript 缓存版本错误')
    command([node_binary(), COMPILER, '-p', source_package / 'tsconfig.json'], ROOT, run / 'typescript.log')
    shutil.copytree(source_package / 'dist', stage / 'dist')
    for name in ('artifact.mjs', 'transport.mjs', 'transport.d.mts'):
        shutil.copy2(source_package / 'src' / name, stage / 'dist' / name)
    binary = stage / 'bin/darwin-arm64/desktop_storage'
    binary.parent.mkdir(parents=True)
    shutil.copy2(OUTPUT / 'target/release/desktop_storage', binary)
    shutil.copy2(OUTPUT / 'target/release/native_crypto', run / 'native_crypto')
    report['binary_sha256'] = sha(binary)
    run_command(['/usr/bin/file', binary], run / 'binary-format.log', records)
    run_command(['/usr/bin/otool', '-L', binary], run / 'binary-libraries.log', records)
    for name in ('artifact.mjs', 'transport.mjs'):
        command([node_binary(), '--check', stage / 'dist' / name], stage, run / (name + '-syntax.log'))
    write_json(stage / 'artifact.json', {'version': VERSION, 'protocol': 1, 'target': 'darwin-arm64',
        'binarySha256': sha(binary), 'sourceSha256': report['source_before'], 'filesSha256': all_hashes(stage),
        'scope': 'stage0 synthetic SQLite; no production secret protection'})
    report['package_files'] = all_hashes(stage)
    command(npm_command() + ['pack', '--json', '--ignore-scripts', '--pack-destination', str(run)], stage, run / 'npm-pack.log')
    archive = run / json.loads((run / 'npm-pack.log').read_text())[0]['filename']
    with tarfile.open(archive) as tar:
        actual = {}
        for member in tar.getmembers():
            require(member.isfile() and member.name.startswith('package/') and '..' not in Path(member.name).parts, '非法包成员')
            name = member.name[8:]
            require(name not in actual, '重复包成员')
            actual[name] = hashlib.sha256(tar.extractfile(member).read()).hexdigest()
    require(actual == report['package_files'], '真实 TGZ 与来源清单不符')
    require(not any(p.endswith('.rs') or Path(p).name in ('Cargo.toml', 'Cargo.lock') for p in actual), '消费包混入 Rust 源码')
    report.update(archive=str(archive), archive_sha256=sha(archive), typescript='5.9.3')
    consumer = run / '独立消费 空格目录'
    shutil.copytree(TEMPLATE, consumer)
    command(npm_command() + ['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', str(archive)], consumer, run / 'npm-install.log')
    command([node_binary(), COMPILER, '-p', consumer / 'tsconfig.json'], consumer, run / 'consumer-types.log')
    report['installed_files'] = all_hashes(consumer / 'node_modules' / NAME)
    require(report['installed_files'] == actual, '安装内容与包摘要不符')
    # 消费仅保留 Node 路径，无 Cargo/Rust 工具；安装明确禁用脚本。
    report['consumer'] = str(consumer)
    return consumer, binary
