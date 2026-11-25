#!/usr/bin/env python3
"""核对 dev.5 的 SQLCipher、标准库、系统链接及 JS 工具材料。"""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import tarfile
import tomllib

from persistent_q03 import ROOT, NAME, command
from persistent_q03_binary import ar_members
sys.path.insert(0, str(ROOT / 'tools/native_storage'))
from q03_materials import save
from support import require, sha, write_json

OLD = ROOT / 'dist/native-storage/ts-desktop/q03/runs/1f0c759a-3ef5-401d-9526-47462e5bf985'


def standard_library(run, output):
    sysroot = Path((run / 'sysroot.log').read_text().strip())
    manifest = sysroot / 'lib/rustlib/multirust-channel-manifest.toml'
    dist = tomllib.loads(manifest.read_text())['pkg']['rust-std']['target']['aarch64-apple-darwin']
    archive = OLD / 'upstream-refcheck-network' / dist['xz_url'].rsplit('/', 1)[1]
    require(sha(archive) == dist['xz_hash'], '固定 Rust std 发行归档摘要不符')
    save(output, 'native/rust-std/channel-manifest.toml', manifest.read_bytes())
    attribution = json.loads((run / 'link-input-attribution.json').read_text())
    inputs = sorted({x['source_rlib'] for x in attribution if x['role'] == 'rust_standard_library'})
    rows, notices = [], []
    with tarfile.open(archive) as tar:
        files = {m.name: m for m in tar.getmembers() if m.isfile()}
        for name in inputs:
            p = Path(name)
            matches = [n for n in files if n.endswith('/' + str(p.relative_to(sysroot)))]
            require(len(matches) == 1, '标准库发行成员不唯一')
            require(hashlib.sha256(tar.extractfile(files[matches[0]]).read()).hexdigest() == sha(p),
                    '当前标准库与官方发行原件不同')
            rows.append({'name': p.name, 'sha256': sha(p), 'archive_member': matches[0],
                         'release': '1.98.1', 'archive_bytes_match': True})
        for n, m in files.items():
            if Path(n).name in ['LICENSE-APACHE', 'LICENSE-MIT', 'COPYRIGHT', 'git-commit-hash', 'version']:
                notices.append(save(output, 'native/rust-std/' + Path(n).name, tar.extractfile(m).read()))
    doc = sysroot / 'share/doc/rust'
    for p in [doc / 'COPYRIGHT-library.html', *sorted((doc / 'licenses').glob('*'))]:
        if p.is_file():
            notices.append(save(output, f'native/rust-toolchain/{p.relative_to(doc)}', p.read_bytes()))
    return {'release': '1.98.1', 'source_url': dist['xz_url'], 'archive_sha256': sha(archive),
            'archive_path': str(archive.relative_to(ROOT)), 'inputs': rows, 'notices': notices,
            'access': '本轮离线重新核对既有准确发行归档；不声称本轮重新联网取得',
            'scope': '按 Rust 发行组件记版本；版权合集适用性仍待审，不借用 Cargo.lock 同名版本'}


def sqlcipher(run, output):
    folder = run / 'case-work/vendor/libsqlite3-sys-0.38.2'
    code = (folder / 'sqlcipher/sqlite3.c').read_text()
    files = [save(output, f'native/sqlcipher/{name}', (folder / name).read_bytes())
             for name in ['sqlcipher/sqlite3.c', 'sqlcipher/sqlite3.h', 'sqlcipher/LICENSE', 'build.rs', 'LICENSE']]
    archives = list((run / 'case-work/target-remapped/release/build').glob('libsqlite3-sys-*/out/libsqlcipher.a'))
    require(len(archives) == 1, 'SQLCipher 静态构建归档不唯一')
    native_members = ar_members(archives[0])
    attribution = json.loads((run / 'link-input-attribution.json').read_text())
    derived = next(x for x in attribution if x.get('member_bytes_match'))
    member_set = {(x['name'], x['sha256']) for x in derived['members']}
    require(all((x['name'], x['sha256']) in member_set for x in native_members),
            'SQLCipher C 对象未关联到真实链接输入')
    symbols = (run / 'binary-symbols.log').read_text()
    require('_sqlite3_key_v2' in symbols and '_CCCryptorCreate' in symbols,
            '缺少 SQLCipher/Apple CommonCrypto 符号证据')
    return {'container': 'libsqlite3-sys@0.38.2', 'sqlcipher_version': re.search(r'#define CIPHER_VERSION_NUMBER ([^\n]+)', code)[1],
            'sqlite_version': re.search(r'#define SQLITE_VERSION\s+"([^"]+)"', code)[1],
            'sqlite_source_id': re.search(r'#define SQLITE_SOURCE_ID\s+"([^"]+)"', code)[1],
            'source_url': 'https://static.crates.io/crates/libsqlite3-sys/libsqlite3-sys-0.38.2.crate',
            'archive_sha256': sha(run / 'archives/libsqlite3-sys-0.38.2.crate'), 'files': files,
            'static_archive_sha256': sha(archives[0]), 'native_members': native_members,
            'link_input': derived, 'crypto_provider': 'Apple CommonCrypto (system import)',
            'scope': 'SQLCipher、内含 SQLite、Rust wrapper 的声明分开记录；本轮不重新执行数据库测试'}


def javascript(run, output):
    ts = ROOT / 'src/sdk/typescript/node_modules/typescript'
    lock = json.loads((ROOT / 'src/sdk/typescript/package-lock.json').read_text())['packages']['node_modules/typescript']
    archive = ROOT / 'dist/platform-release/node/portable-dependencies/a0cd0d6b-fb54-4d5e-9295-04e6a53b7fef/typescript-5.9.3.tgz'
    integrity = 'sha512-' + base64.b64encode(hashlib.sha512(archive.read_bytes()).digest()).decode()
    require(integrity == lock['integrity'], 'TypeScript 归档不匹配 npm lock')
    notices, count = [], 0
    with tarfile.open(archive) as tar:
        for m in tar.getmembers():
            if not m.isfile():
                continue
            n = Path(*Path(m.name).parts[1:])
            data = tar.extractfile(m).read()
            require(sha(ts / n) == hashlib.sha256(data).hexdigest(), 'TypeScript 安装来源不同')
            count += 1
            if n.name in ['LICENSE.txt', 'ThirdPartyNoticeText.txt', 'package.json']:
                notices.append(save(output, f'build-tools/typescript/{n}', data))
    node = Path(shutil.which('node')).resolve()
    package = run / 'source/src/sdk/typescript/desktop'
    command(run, 'q03-typescript.log', [node, ts / 'bin/tsc', '-p', package / 'tsconfig.json'], package)
    generated = {str(p.relative_to(package)): sha(p) for p in (package / 'dist').rglob('*') if p.is_file()}
    require(len(generated) == 6, '生成文件范围发生变化')
    require(all(sha(run / 'package' / n) == h for n, h in generated.items()), 'TS 编译输出与原包不同')
    for name in ['transport.mjs', 'transport.d.mts', 'artifact.mjs']:
        require(sha(package / 'src' / name) == sha(run / 'package/dist' / name), '原样适配文件不同')
    manifest = json.loads((run / 'package/package.json').read_text())
    require(not any(manifest.get(k) for k in ['dependencies', 'optionalDependencies', 'peerDependencies']),
            '发现未归属 npm 运行依赖')
    command(run, 'q03-node-version.log', [node, '--version'], run)
    return {'package_name': manifest['name'], 'version': manifest['version'], 'license': manifest['license'],
            'private': manifest['private'], 'generated_files': generated, 'copied_files_match': 3,
            'typescript': {'version': '5.9.3', 'integrity': integrity, 'archive_sha256': sha(archive),
                          'source_url': lock['resolved'], 'installed_files_verified': count, 'notices': notices},
            'node': {'version': (run / 'q03-node-version.log').read_text().strip(), 'path': str(node), 'sha256': sha(node)},
            'role_boundary': 'TypeScript 为构建工具；Node 为外部宿主；npm 为封包/安装工具；均不包含于此 TGZ'}


def main(run, output):
    require(not (output / 'native-components.json').exists(), '不能覆盖旧 native 记录')
    result = {'sqlcipher': sqlcipher(run, output), 'rust_standard_library': standard_library(run, output),
              'javascript': javascript(run, output), 'distribution_approval': 'NOT_APPROVED'}
    original = run / 'package/bin/darwin-arm64' / NAME
    command(run, 'original-dynamic-libraries.log', ['/usr/bin/otool', '-L', original], run)
    old = (run / 'original-dynamic-libraries.log').read_text().splitlines()[1:]
    new = (run / 'binary-link-xcode.log').read_text().splitlines()[1:]
    require(old == new, '重建与原包的系统链接声明不同')
    result['system_dynamic_libraries'] = old
    result['system_scope'] = '系统提供，不随 TGZ 分发；未审计 dyld 递归实现，不将 current version 作为上游源码版本'
    xcode = json.loads((run / 'reproduction-xcode/comparison.json').read_text())
    result['apple_sdk'] = {'path': xcode['sdk_path'], 'linker_sha256': xcode['linker_sha256'],
                          'settings': save(output, 'native/apple-sdk/SDKSettings.json',
                                           (Path(xcode['sdk_path']) / 'SDKSettings.json').read_bytes())}
    write_json(output / 'native-components.json', result)
    print(json.dumps({'status': 'PASS', 'sqlcipher': result['sqlcipher']['sqlcipher_version'],
                      'sqlite': result['sqlcipher']['sqlite_version'], 'std_inputs': len(result['rust_standard_library']['inputs'])}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--inventory', type=Path, required=True)
    args = parser.parse_args()
    main(args.run.resolve(), args.inventory.resolve())
