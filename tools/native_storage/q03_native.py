"""补入 Cargo 图之外的 SQLite、Rust 标准库、系统库与宿主/构建工具证据。"""

import base64
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import tarfile
import tomllib

from q03_materials import save
from support import ROOT, require, sha


def collect_native(run, historical, output, units):
    metadata = json.loads((historical / 'metadata.json').read_text())
    package = next(p for p in metadata['packages'] if p['name'] == 'libsqlite3-sys')
    folder = Path(package['manifest_path']).parent
    sqlite_files = [save(output, f'native/sqlite/{p}', (folder / p).read_bytes())
                    for p in ('sqlite3/sqlite3.c', 'sqlite3/sqlite3.h', 'build.rs', 'LICENSE')]
    header = (folder / 'sqlite3/sqlite3.h').read_text()
    version = re.search(r'#define SQLITE_VERSION\s+"([^"]+)"', header)[1]
    source_id = re.search(r'#define SQLITE_SOURCE_ID\s+"([^"]+)"', header)[1]
    unit = next(u for u in units if u['package_id'] == package['id'] and u['target']['kind'] == ['lib'])
    require('bundled' in unit['features'] and 'bundled-sqlcipher' not in unit['features'], '不是预期 SQLite 构建')
    archives = list((run / 'target/release/build').glob('libsqlite3-sys-*/out/libsqlite3.a'))
    require(len(archives) == 1, 'SQLite 静态库归属不唯一')
    sqlite_archive = archives[0]
    link_line = next(line for line in (run / 'link-args-correct-cwd.log').read_text().splitlines()
                     if line.startswith('env '))
    link_args = shlex.split(link_line)
    require(str(sqlite_archive.parent) in link_args, '最终链接没有关联到 SQLite 构建目录')
    require('_sqlite3_libversion' in (run / 'binary-symbols.log').read_text(), '程序缺少 SQLite 正向符号证据')
    sysroot = Path((run / 'sysroot.log').read_text().strip())
    channel_path = sysroot / 'lib/rustlib/multirust-channel-manifest.toml'
    channel = tomllib.loads(channel_path.read_text())
    std_dist = channel['pkg']['rust-std']['target']['aarch64-apple-darwin']
    std_archive = run / 'upstream-refcheck-network' / std_dist['xz_url'].rsplit('/', 1)[1]
    require(sha(std_archive) == std_dist['xz_hash'], 'Rust std 下载归档不匹配工具链声明')
    std_inputs = [Path(arg) for arg in link_args if arg.endswith('.rlib') and str(sysroot) in arg]
    require(len(std_inputs) > 0, '没有标准库链接输入')
    std_rows, std_notices = [], []
    with tarfile.open(std_archive) as tar:
        entries = {entry.name: entry for entry in tar.getmembers() if entry.isfile()}
        for path in std_inputs:
            matches = [name for name in entries if name.endswith('/' + str(path.relative_to(sysroot)))]
            require(len(matches) == 1, '标准库发行成员不唯一')
            data = tar.extractfile(entries[matches[0]]).read()
            require(hashlib.sha256(data).hexdigest() == sha(path), '已安装标准库与固定发行原件不一致')
            std_rows.append({'name': path.name, 'release': '1.98.1', 'sha256': sha(path),
                             'installed_path': str(path), 'archive_member': matches[0],
                             'role': 'runtime_link_input', 'archive_bytes_match': True})
        for name, member in entries.items():
            if Path(name).name in ('LICENSE-APACHE', 'LICENSE-MIT', 'COPYRIGHT', 'git-commit-hash', 'version'):
                std_notices.append(save(output, f'native/rust-std/{Path(name).name}', tar.extractfile(member).read()))
    installed_notices = []
    doc = sysroot / 'share/doc/rust'
    for path in [doc / 'COPYRIGHT-library.html', *sorted((doc / 'licenses').glob('*'))]:
        if path.is_file():
            installed_notices.append(save(output, f'native/rust-toolchain/{path.relative_to(doc)}', path.read_bytes()))
    save(output, 'native/rust-toolchain/channel-manifest.toml', channel_path.read_bytes())
    sdk = Path(next(arg.split('=', 1)[1] for arg in link_args if arg.startswith('SDKROOT=')))
    sdk_info = save(output, 'native/apple-sdk/SDKSettings.json', (sdk / 'SDKSettings.json').read_bytes())
    binary_copies = [p for p in (run / 'link-audit-correct-cwd').iterdir() if p.suffix != '.d']
    require(len(binary_copies) == 1 and sha(binary_copies[0]) == sha(run / 'target/release/desktop_storage'),
            '捕获链接命令改变了程序字节')
    npm_manifest = json.loads((historical / 'package/package.json').read_text())
    require(not npm_manifest.get('dependencies'), '出现尚未归类的 npm 运行依赖')
    ts = ROOT / 'src/sdk/typescript/node_modules/typescript'
    ts_lock = json.loads((ROOT / 'src/sdk/typescript/package-lock.json').read_text())['packages']['node_modules/typescript']
    ts_archive = ROOT / 'dist/platform-release/node/portable-dependencies/a0cd0d6b-fb54-4d5e-9295-04e6a53b7fef/typescript-5.9.3.tgz'
    integrity = 'sha512-' + base64.b64encode(hashlib.sha512(ts_archive.read_bytes()).digest()).decode()
    require(integrity == ts_lock['integrity'], 'TypeScript 归档不匹配 npm lock')
    ts_notices, ts_count = [], 0
    with tarfile.open(ts_archive) as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            relative = Path(*Path(member.name).parts[1:])
            data = tar.extractfile(member).read()
            require(hashlib.sha256(data).hexdigest() == sha(ts / relative), 'TypeScript 已安装文件与归档不符')
            ts_count += 1
            if relative.name in ('LICENSE.txt', 'ThirdPartyNoticeText.txt', 'package.json'):
                ts_notices.append(save(output, f'build-tools/typescript/{relative}', data))
    node = Path(shutil.which('node')).resolve()
    npm_cli = Path(shutil.which('npm')).resolve()
    npm_root = npm_cli.parent.parent
    tool_fingerprints = {str(path): sha(path) for path in (node, npm_cli, sysroot / 'bin/rustc', sysroot / 'bin/cargo')}
    return {
        'sqlite': {'version': version, 'source_id': source_id, 'container_crate': 'libsqlite3-sys@0.38.2',
                   'source_url': 'https://static.crates.io/crates/libsqlite3-sys/libsqlite3-sys-0.38.2.crate',
                   'files': sqlite_files, 'built_static_library_sha256': sha(sqlite_archive),
                   'features': unit['features'], 'linkage': 'static',
                   'notice': 'sqlite3.c/sqlite3.h 内原始版权放弃声明；Rust 包 MIT 与内含 SQLite 分开记录。',
                   'sqlcipher': 'NOT_ENABLED'},
        'rust_standard_library': {'release': '1.98.1', 'compiler_commit': '48a229ceaefd4985c50990b14116b6d856af0985',
                                  'source_url': std_dist['xz_url'], 'archive_sha256': sha(std_archive),
                                  'inputs': std_rows, 'archive_notices': std_notices,
                                  'installed_notices': installed_notices,
                                  'note': '19 个内部 rlib 按固定 Rust 发行组件记版本；不得借用项目 Cargo.lock 的同名 crate 版本。完整版权材料包含保守合集，仍待分发适用性复核。'},
        'system_dynamic_libraries': [
            {'path': '/usr/lib/libiconv.2.dylib', 'compatibility_version': '7.0.0', 'current_version': '7.0.0'},
            {'path': '/usr/lib/libSystem.B.dylib', 'compatibility_version': '1.0.0', 'current_version': '1356.0.0'}],
        'system_scope': '来自原/补建程序 otool -L；系统提供且不随 TGZ 分发，未把 dylib current version 当上游源版本；没有扫描 dyld 递归实现。',
        'build_environment': {'rustc': (run / 'rustc-current.log').read_text(),
                              'clang': (run / 'clang.log').read_text(), 'sdkroot': str(sdk),
                              'tool_fingerprints': tool_fingerprints,
                              'sdk_settings': sdk_info, 'sdk_version_probe': '首个 xcrun 查询失败；最终真实链接参数及 SDKSettings 为依据'},
        'javascript': {'package': npm_manifest, 'runtime_dependencies': [],
                       'files': {p: h for p, h in json.loads((historical / 'report.json').read_text())['package_files'].items()
                                 if p.startswith('dist/')},
                       'typescript': {'version': '5.9.3', 'role': 'build_tool_not_distributed',
                                      'archive_path': str(ts_archive), 'archive_sha256': sha(ts_archive),
                                      'source_url': ts_lock['resolved'], 'integrity': integrity,
                                      'installed_files_verified': ts_count, 'files': ts_notices},
                       'node': 'v26.5.0 external host, not bundled runtime',
                       'npm': {'version_observed_now': json.loads((npm_root / 'package.json').read_text())['version'],
                               'scope': '历史打包/安装工具，不包含在 TGZ；本轮版本观察不补写为历史日志已有版本'}},
        'distribution_approval': 'NOT_APPROVED',
    }
