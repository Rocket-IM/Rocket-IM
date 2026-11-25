#!/usr/bin/env python3
"""dev.5 原件与构建事实补证；只写独立 run，不执行 SDK、不签名或组包。"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/native_storage'))
from q03_components import compilation_units
from support import require, sha, write_json

TARGET = ROOT / 'dist/platform-release/persistent/runs/9f78de72-b9cc-4020-b956-2ccfa3d36277/new-release'
NAME = 'rocket-im-desktop-runtime'


def command(run, name, args, cwd, env=None):
    log = run / name
    require(not log.exists(), f'不能覆盖已有命令日志：{name}')
    start = datetime.now(timezone.utc).isoformat()
    with log.open('x') as stream:
        result = subprocess.run([str(a) for a in args], cwd=cwd, env=env,
                                stdout=stream, stderr=subprocess.STDOUT)
    write_json(run / (name + '.command.json'), {
        'args': [str(a) for a in args], 'cwd': str(cwd), 'started_at': start,
        'finished_at': datetime.now(timezone.utc).isoformat(),
        'returncode': result.returncode, 'log_sha256': sha(log)})
    require(result.returncode == 0, f'命令失败，原日志保留：{log}')
    return log


def prepare(run):
    require(json.loads((run / 'case-sensitive.json').read_text())['case_sensitive'],
            '需要已实测大小写敏感的工作目录')
    report = json.loads((TARGET / 'report.json').read_text())
    for name, digest in report['source_before'].items():
        original = TARGET / 'source' / name
        require(sha(original) == digest and sha(ROOT / name) == digest, f'源码不匹配：{name}')
        destination = run / 'source' / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        require(not destination.exists(), '不覆盖已冻结来源')
        shutil.copy2(original, destination)
    archive = Path(report['archive'])
    require(sha(archive) == report['archive_sha256'], 'dev.5 原包摘要不符')
    package = run / 'package'
    package.mkdir()
    actual = {}
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            path = PurePosixPath(member.name)
            require(member.isfile() and path.parts[0] == 'package' and '..' not in path.parts,
                    '包内存在不支持的成员')
            relative = str(PurePosixPath(*path.parts[1:]))
            require(relative not in actual, '包内重复路径')
            data = tar.extractfile(member).read()
            actual[relative] = hashlib.sha256(data).hexdigest()
            destination = package / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            destination.chmod(member.mode)
    require(actual == report['package_files'], '真实 TGZ 与历史安装清单不符')
    metadata = json.loads((TARGET / 'metadata.json').read_text())
    lock = tomllib.loads((run / 'source/src/sdk/rust/Cargo.lock').read_text())
    checksums = {(p['name'], p['version']): p.get('checksum') for p in lock['package']}
    vendor = run / 'case-work/vendor'
    vendor.mkdir()
    archives = run / 'archives'
    archives.mkdir()
    rows = []
    for p in metadata['packages']:
        if not p['source']:
            continue
        require(p['source'].startswith('registry+'), '未实现非 registry 第三方来源')
        folder = Path(p['manifest_path']).parent
        name = f"{p['name']}-{p['version']}"
        original = folder.parents[2] / 'cache' / folder.parent.name / (name + '.crate')
        digest = checksums[(p['name'], p['version'])]
        require(sha(original) == digest, f'归档校验失败：{name}')
        shutil.copy2(original, archives / original.name)
        files = {}
        destination = vendor / name
        destination.mkdir()
        with tarfile.open(original) as tar:
            for member in tar.getmembers():
                if member.isdir():
                    continue
                parts = PurePosixPath(member.name).parts
                require(member.isfile() and parts[0] == name and '..' not in parts,
                        '归档含链接或越界成员')
                relative = str(PurePosixPath(*parts[1:]))
                require(relative not in files, '归档重复路径')
                data = tar.extractfile(member).read()
                files[relative] = hashlib.sha256(data).hexdigest()
                path = destination / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open('xb') as f:
                    f.write(data)
                path.chmod(member.mode)
        require(all(sha(destination / n) == h for n, h in files.items()), '原件展开不完整')
        write_json(destination / '.cargo-checksum.json', {'files': files, 'package': digest})
        collisions = {}
        for n in files:
            collisions.setdefault(n.casefold(), []).append(n)
        rows.append({'name': p['name'], 'version': p['version'], 'archive_sha256': digest,
                     'files': files, 'case_collisions': [v for v in collisions.values() if len(v) > 1],
                     'all_expanded_bytes_match': True})
    write_json(run / 'pristine-files.json', rows)
    write_json(run / 'preparation.json', {'status': 'PASS', 'source_inputs': len(report['source_before']),
               'original_archive': str(archive), 'archive_sha256': sha(archive),
               'package_files': len(actual), 'crate_archives': len(rows),
               'windows': 'NOT_TESTED', 'old_hpke': 'NOT_EXECUTED_PLATFORM_BLOCKED'})


def cargo_setup(run):
    env = dict(os.environ, CARGO_HOME=str(ROOT / 'dist/toolchains/rust/cargo'),
               RUSTUP_HOME=str(ROOT / 'dist/toolchains/rust/rustup'))
    base = [ROOT / 'dist/toolchains/rust/cargo/bin/cargo', '+1.98.1']
    rust = run / 'source/src/sdk/rust'
    fixed = ['--manifest-path', rust / 'Cargo.toml', '--locked', '--offline',
             '--config', 'source.crates-io.replace-with="q03-pristine"',
             '--config', f'source.q03-pristine.directory="{run / "case-work/vendor"}"']
    return env, base, rust, fixed


def complete_vendor(run):
    """目录源解析还需要锁内未启用的可选包；这些不因此成为运行成分。"""
    locked = tomllib.loads((run / 'source/src/sdk/rust/Cargo.lock').read_text())['package']
    rows = json.loads((run / 'pristine-files.json').read_text())
    for p in locked:
        name = f"{p['name']}-{p['version']}"
        destination = run / 'case-work/vendor' / name
        if not p.get('source', '').startswith('registry+') or destination.exists():
            continue
        candidates = list((ROOT / 'dist/toolchains/rust/cargo/registry/cache').glob(f'*/{name}.crate'))
        require(len(candidates) == 1 and sha(candidates[0]) == p['checksum'], '缺少精确锁定归档')
        shutil.copy2(candidates[0], run / 'archives' / candidates[0].name)
        files = {}
        destination.mkdir()
        with tarfile.open(candidates[0]) as tar:
            for m in tar.getmembers():
                if m.isdir():
                    continue
                parts = PurePosixPath(m.name).parts
                require(m.isfile() and parts[0] == name and '..' not in parts, '原件路径错误')
                n = str(PurePosixPath(*parts[1:]))
                require(n not in files, '重复原件')
                data = tar.extractfile(m).read()
                files[n] = hashlib.sha256(data).hexdigest()
                path = destination / n
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open('xb') as f:
                    f.write(data)
                path.chmod(m.mode)
        require(all(sha(destination / n) == h for n, h in files.items()), '补充原件摘要不符')
        write_json(destination / '.cargo-checksum.json', {'files': files, 'package': p['checksum']})
        rows.append({'name': p['name'], 'version': p['version'], 'archive_sha256': p['checksum'],
                     'files': files, 'case_collisions': [], 'all_expanded_bytes_match': True,
                     'reason': 'lockfile resolver input; not evidence of compilation'})
    require(not (run / 'pristine-complete.json').exists(), '不能覆盖原件核对')
    write_json(run / 'pristine-complete.json', rows)


def build(run):
    env, base, rust, fixed = cargo_setup(run)
    target = run / 'case-work/target'
    require(not target.exists(), '必须使用全新 target；不得覆盖失败轮')
    command(run, 'metadata-pristine.json', base + ['metadata', *fixed, '--format-version', '1'], rust, env)
    for filename, edges, targets in [('tree.txt', 'normal,build', 'aarch64-apple-darwin'),
                                     ('tree-with-dev.txt', 'normal,build,dev', 'aarch64-apple-darwin'),
                                     ('tree-all.txt', 'normal,build', 'all')]:
        command(run, filename, base + ['tree', *fixed, '-p', NAME, '--target', targets,
                                     '-e', edges, '--prefix', 'depth'], rust, env)
    command(run, 'build.log', base + ['build', *fixed, '--target-dir', target, '-p', NAME,
                                    '--release', '--message-format=json', '-vv'], rust, env)
    units = compilation_units(run, NAME)
    write_json(run / 'compiler-units-initial.json', units)
    capture_link(run)


def capture_link(run):
    env, _, rust, _ = cargo_setup(run)
    target = run / 'case-work/target'
    units = json.loads((run / 'compiler-units-initial.json').read_text())
    root = next(u for u in units if u['target']['name'] == NAME)
    args = root['command'].copy()
    out = run / 'case-work/link-audit-workspace'
    out.mkdir()
    args[args.index('--out-dir') + 1] = str(out)
    command(run, 'link-args-workspace.log', ['/usr/bin/env', *args, '--print', 'link-args'], rust, env)
    command(run, 'binary-link.log', ['/usr/bin/otool', '-L', target / 'release' / NAME], rust)
    command(run, 'binary-symbols.log', ['/usr/bin/nm', '-g', target / 'release' / NAME], rust)
    command(run, 'sysroot.log', [ROOT / 'dist/toolchains/rust/cargo/bin/rustc', '+1.98.1', '--print', 'sysroot'], rust, env)


def reproduce(run):
    """只统一编译器记录的源路径；原件字节和 Cargo 的 codegen 参数不变。"""
    env, base, rust, fixed = cargo_setup(run)
    target = run / 'case-work/target-remapped'
    require(not target.exists(), '复现必须使用独立空 target')
    metadata = json.loads((TARGET / 'metadata.json').read_text())
    registry = next(Path(p['manifest_path']).parent.parent for p in metadata['packages'] if p['source'])
    mappings = [f'{run / "case-work/vendor"}={registry}',
                f'{run / "source/src/sdk/rust"}={TARGET / "source/src/sdk/rust"}']
    wrapper = run / 'rustc-path-wrapper.py'
    recorded = run / 'remapped-commands'
    recorded.mkdir()
    wrapper.write_text('#!/usr/bin/python3\nimport os,sys,json\nfrom pathlib import Path\n'
        'args=sys.argv[1:]\n'
        f'maps={mappings!r}\n'
        'if "--crate-name" in args:\n'
        ' args += ["--remap-path-prefix="+m for m in maps]\n'
        f' Path({str(recorded)!r},str(os.getpid())+".json").write_text(json.dumps(args))\n'
        'os.execv(args[0],args)\n')
    wrapper.chmod(0o700)
    env['RUSTC_WRAPPER'] = str(wrapper)
    write_json(run / 'path-remapping.json', {'mappings': mappings, 'wrapper_sha256': sha(wrapper),
               'scope': 'normalize recorded source paths only; no source or binary patch'})
    command(run, 'build-remapped.log', base + ['build', *fixed, '--target-dir', target, '-p', NAME,
              '--release', '--message-format=json', '-vv'], rust, env)
    original = run / 'package/bin/darwin-arm64' / NAME
    reproduced = target / 'release' / NAME
    output = run / 'reproduction-remapped'
    output.mkdir()
    rows = []
    for name, source in [('original', original), ('rebuilt', reproduced)]:
        copy = output / name
        shutil.copy2(source, copy)
        command(run, f'remove-signature-{name}.log', ['/usr/bin/codesign', '--remove-signature', copy], run)
        rows.append({'name': name, 'original_sha256': sha(source), 'unsigned_sha256': sha(copy)})
    equal = (output / 'original').read_bytes() == (output / 'rebuilt').read_bytes()
    write_json(output / 'comparison.json', {'status': 'PASS' if equal else 'DIFFERENT', 'files': rows,
              'unsigned_bytes_equal': equal, 'originals_modified': False,
              'note': '仅比较副本移除签名；路径映射单独记录，不重新签名、发布或执行程序。'})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['prepare', 'complete-vendor', 'build', 'capture-link', 'reproduce'])
    parser.add_argument('--run', required=True, type=Path)
    args = parser.parse_args()
    run = args.run.resolve()
    require(run.parent == ROOT / 'dist/platform-release/persistent/runs', '输出路径不在独立 runs 中')
    {'prepare': prepare, 'complete-vendor': complete_vendor, 'build': build,
     'capture-link': capture_link, 'reproduce': reproduce}[args.phase](run)
    print(json.dumps({'phase': args.phase, 'status': 'PASS', 'run': str(run)}, ensure_ascii=False))
