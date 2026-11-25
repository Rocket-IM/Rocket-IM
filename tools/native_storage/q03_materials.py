"""核对锁定 crate 原件与缓存，补采原文；保持声明、文本观察和审批状态分离。"""

import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
import tarfile
import tomllib

from support import ROOT, require, sha, write_json

sys.path.insert(0, str(ROOT / 'tools/platform_release'))
from collect_licenses import PREFIXES, repository_info, text_ids


def save(destination, relative, data):
    path = PurePosixPath(relative)
    require(not path.is_absolute() and '..' not in path.parts, '材料路径越界')
    target = destination / str(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return {'path': str(path), 'sha256': sha(target)}


def is_notice(path, data):
    parts = PurePosixPath(path).parts
    return (any(part.upper().startswith(PREFIXES) for part in parts)
            or (parts[-1].upper().startswith('AUTHORS') and bool(text_ids(data))))


def collect(historical, output, components, lock_relative='source/poc/native-storage/Cargo.lock',
            archive_root=None, metadata_relative='metadata.json'):
    metadata = json.loads((historical / metadata_relative).read_text())
    lock_path = historical / lock_relative
    locked = {(p['name'], p['version']): p for p in tomllib.loads(lock_path.read_text())['package']}
    previous_root = ROOT / 'dist/platform-release/licenses'
    previous_path = previous_root / 'dependencies.json'
    previous = {(p['name'], p['version']): p for p in json.loads(previous_path.read_text())['packages']}
    save(output, 'previous-license-index.json', previous_path.read_bytes())
    component_map = {(p['name'], p['version']): p for p in components}
    rows, archive_inventory = [], {}
    for package in sorted(metadata['packages'], key=lambda p: (p['name'], p['version'])):
        name, version = package['name'], package['version']
        key, folder = (name, version), Path(package['manifest_path']).parent
        row = {'name': name, 'version': version, 'declared_license': package['license'],
               'declared_license_file': package['license_file'], 'source': package['source'],
               'repository': package['repository'], 'roles': component_map[(name, version)]['roles'],
               'files': [], 'issues': [], 'distribution_approval': 'NOT_APPROVED',
               'review_owner': '依赖/发布负责人；实际姓名待用户指定',
               'acceptance': '核对适用原文/NOTICE及分发方案；存在冲突须先取得明确依据，不能用标准文本代替授权。'}
        if not package['source']:
            row.update(status='PROJECT_LICENSE_UNDECIDED', source_snapshot='历史 report.source_before 及 source/')
            rows.append(row)
            continue
        require(package['source'].startswith('registry+'), f'未实现来源类型：{package["source"]}')
        archive = ((archive_root / f'{name}-{version}.crate') if archive_root else
                   folder.parents[2] / 'cache' / folder.parent.name / f'{name}-{version}.crate')
        expected = locked[key]['checksum']
        require(sha(archive) == expected, f'归档与 Cargo.lock 不符：{name} {version}')
        copied = save(output, f'archives/{archive.name}', archive.read_bytes())
        row['archive'] = {**copied, 'lock_checksum': expected,
                          'source_url': f'https://static.crates.io/crates/{name}/{archive.name}',
                          'access': '本轮读取既有本地发行归档，没有重新下载'}
        manifest_files, cache_errors, entries = {}, [], {}
        with tarfile.open(archive) as tar:
            for member in tar.getmembers():
                if member.isdir():
                    continue
                relative = PurePosixPath(member.name)
                require(member.isfile() and relative.parts[0] == f'{name}-{version}'
                        and '..' not in relative.parts, '归档含不支持的链接或越界成员')
                path = str(PurePosixPath(*relative.parts[1:]))
                require(path not in entries, '归档成员重复')
                data = tar.extractfile(member).read()
                digest = hashlib.sha256(data).hexdigest()
                entries[path] = digest
                cached = folder / path
                if not cached.is_file() or sha(cached) != digest:
                    mismatch = {'path': path, 'archive_sha256': digest,
                                'cache_sha256': sha(cached) if cached.is_file() else None}
                    if cached.is_file():
                        mismatch['cache_copy'] = save(output, f'cache-differences/{name}-{version}/{path}', cached.read_bytes())
                    cache_errors.append(mismatch)
                if path in ('Cargo.toml', 'Cargo.toml.orig', '.cargo_vcs_info.json'):
                    manifest_files[path] = save(output, f'manifests/{name}-{version}/{path}', data)
                if (is_notice(path, data) or path == package['license_file']):
                    item = save(output, f'licenses/{name}-{version}/archive/{path}', data)
                    row['files'].append({**item, 'origin': 'crate_archive', 'source_path': path,
                                         'source_url': row['archive']['source_url'],
                                         'observed_texts': text_ids(data)})
        row.update(manifests=manifest_files, cache_matches_archive=not cache_errors,
                   cache_differences=cache_errors, archive_file_count=len(entries),
                   archive_notice_count=len(row['files']))
        cached_names = {str(p.relative_to(folder)) for p in folder.rglob('*') if p.is_file()}
        extra = sorted(cached_names - set(entries) - {'.cargo-ok', '.cargo-checksum.json'})
        require(not extra, f'缓存含未归属文件：{name} {extra}')
        row['cache_extra_files'] = extra
        folded = {}
        for path in entries:
            folded.setdefault(path.casefold(), []).append(path)
        row['case_collisions'] = [paths for paths in folded.values() if len(paths) > 1]
        if row['case_collisions']:
            row['issues'].append(
                '归档存在大小写同名文件；保留原归档与缓存差异，不能宣称逐文件无修改展开。'
                if cache_errors else '归档的大小写同名文件均完整保留，逐成员摘要匹配；不据此批准分发。')
        archive_inventory[f'{name}-{version}'] = entries
        # VCS/清单来源必须与归档匹配，其他差异显式保留、不得静默当作原版源码。
        require(not any(e['path'] in ('Cargo.toml', 'Cargo.toml.orig', '.cargo_vcs_info.json')
                        for e in cache_errors), '来源声明文件与归档不符')
        vcs = repository_info(package, folder)
        row['vcs'] = vcs
        old = previous.get(key, {})
        if old.get('vcs') == vcs and vcs and not vcs['archive_vcs_dirty']:
            for entry in old.get('files', []):
                # 标准 MPL 附件不是上游授权，本项不将它纳入上游许可材料。
                if entry['origin'] != 'repository_exact_commit':
                    continue
                data = (previous_root / entry['path']).read_bytes()
                require(hashlib.sha256(data).hexdigest() == entry['sha256'], '既有许可材料摘要不符')
                require(entry['vcs_commit'] == vcs['commit'], '许可提交与 crate VCS 不符')
                blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
                require(blob == entry['git_blob_sha1'], '既有 Git blob 摘要不符')
                item = save(output, f'licenses/{name}-{version}/upstream/{entry["source_path"]}', data)
                row['files'].append({**entry, **item, 'observed_texts': text_ids(data),
                                     'access': '本轮离线复核旧采集原件；非本轮全部重新访问',
                                     'previous_path': str((previous_root / entry['path']).relative_to(ROOT))})
        if not row['files']:
            row['status'] = 'MISSING_UPSTREAM_TEXT'
            row['issues'].append('归档和已匹配的精确提交缓存均无许可正文；待取得该版本原件')
        elif package['license'] == 'MPL-2.0' and not any('MPL-2.0' in f['observed_texts'] for f in row['files']):
            row['status'] = 'DECLARATION_TEXT_CONFLICT'
            row['issues'].append('Cargo 声明 MPL-2.0；准确提交所采正文为 Apache/MIT；授权适用范围未解决')
        else:
            row['status'] = 'TEXT_COLLECTED_REVIEW_PENDING'
        rows.append(row)
    write_json(output / 'archive-file-hashes.json', archive_inventory)
    return rows
