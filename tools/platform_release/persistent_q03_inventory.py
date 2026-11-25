#!/usr/bin/env python3
"""关联 dev.5 独立编译、最终链接与精确原件材料；不授予分发批准。"""

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import sys
import tomllib
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/native_storage'))
from q03_components import compilation_units, tree_keys
from q03_materials import collect
from support import require, sha, write_json
from persistent_q03 import NAME, TARGET
from persistent_q03_binary import ar_members


def lock_closure(run):
    packages = tomllib.loads((run / 'source/src/sdk/rust/Cargo.lock').read_text())['package']
    by_key = {(p['name'], p['version']): p for p in packages}
    by_name = defaultdict(list)
    for key in by_key:
        by_name[key[0]].append(key)
    pending, seen = [(NAME, '0.2.0-dev.5')], set()
    while pending:
        key = pending.pop()
        if key in seen:
            continue
        seen.add(key)
        for dep in by_key[key].get('dependencies', []):
            parts = dep.split()
            candidates = [k for k in by_name[parts[0]] if len(parts) == 1 or k[1] == parts[1]]
            require(len(candidates) == 1, '锁文件依赖归属不唯一')
            pending.append(candidates[0])
    return seen


def link_inputs(run, units):
    sysroot = Path((run / 'sysroot.log').read_text().strip())
    standard = list((sysroot / 'lib/rustlib/aarch64-apple-darwin/lib').glob('*.rlib'))
    by_stem = defaultdict(list)
    for unit in units:
        unit['final_link_files'] = []
        for name in unit['filenames']:
            path = Path(name)
            if path.suffix == '.rlib':
                by_stem[path.stem[3:]].append((unit, path))
    standard_stems = {p.stem[3:]: p for p in standard}
    root = next(u for u in units if u['target']['name'] == NAME)
    suffix = next(a.split('=', 1)[1] for a in root['command'] if a.startswith('extra-filename='))
    root_prefix = NAME.replace('-', '_') + suffix + '.'
    rows = json.loads((run / 'link-inputs/files.json').read_text())
    arguments = json.loads((run / 'link-inputs/arguments.json').read_text())
    require([a for a in arguments if Path(a).suffix in ('.o', '.a', '.rlib')]
            == [r['argument'] for r in rows], '链接输入记录与真实命令不完整对应')
    for row in rows:
        name = Path(row['argument']).name
        copy = run / 'link-inputs' / row['copy']
        require(sha(copy) == row['sha256'], '链接输入副本摘要不符')
        matches = [(u, p) for stem, values in by_stem.items()
                   if f'.{stem}.' in name or name == 'lib' + stem + '.rlib' for u, p in values]
        standards = [p for stem, p in standard_stems.items()
                     if f'.{stem}.' in name or name == 'lib' + stem + '.rlib']
        require(len(matches) + len(standards) <= 1, '链接输入归属不唯一')
        if matches:
            unit, source = matches[0]
            unit['final_link_files'].append(row['argument'])
            row.update(role='crate_link_input', unit_id=unit['id'], package_id=unit['package_id'])
            if copy.suffix == '.rlib':
                # rustc 在 LTO 后把绑定的 C 对象拆进临时 rlib；按成员字节关联，不能仅凭文件名。
                original = Path(str(source).replace('/target/', '/target-remapped/'))
                known = {(x['name'], x['sha256']) for x in ar_members(original)}
                members = ar_members(copy)
                require(all((x['name'], x['sha256']) in known for x in members), '临时 rlib 不匹配原编译归档')
                row.update(derived_from=str(original), members=members, member_bytes_match=True)
        elif standards:
            row.update(role='rust_standard_library', source_rlib=str(standards[0]),
                       source_sha256=sha(standards[0]))
        elif name.startswith(root_prefix) and (f'.{NAME.replace("-", "_")}.' in name
                or re.fullmatch(r'[a-z0-9]+\.rcgu\.o', name[len(root_prefix):])):
            unit = root
            unit['final_link_files'].append(row['argument'])
            row.update(role='root_codegen', unit_id=unit['id'], package_id=unit['package_id'])
        else:
            raise AssertionError(f'未归属的真实链接输入：{name}')
    write_json(run / 'link-input-attribution.json', rows)
    return rows


def components(run):
    metadata = json.loads((run / 'metadata-pristine.json').read_text())
    units = compilation_units(run, NAME)
    args = json.loads((run / 'link-inputs/arguments.json').read_text())
    link_inputs(run, units)
    by_package = defaultdict(list)
    for u in units:
        by_package[u['package_id']].append(u)
    native, all_targets, dev = (tree_keys(run / n) for n in ['tree.txt', 'tree-all.txt', 'tree-with-dev.txt'])
    closure = lock_closure(run)
    rows = []
    for p in sorted(metadata['packages'], key=lambda p: (p['name'], p['version'])):
        key = p['name'], p['version']
        actual = by_package.get(p['id'], [])
        roles = sorted({role for u in actual for role in u['roles']})
        if not roles:
            if key in dev:
                roles = ['dev_only']
            elif key in all_targets:
                roles = ['other_target_only']
            elif key in closure:
                roles = ['not_selected_features']
            else:
                roles = ['outside_root_lock_closure']
        rows.append({'name': p['name'], 'version': p['version'], 'id': p['id'], 'roles': roles,
                     'unit_ids': [u['id'] for u in actual],
                     'final_link_files': [f for u in actual for f in u['final_link_files']],
                     'final_link_input': any(u['final_link_files'] for u in actual),
                     'root_codegen_objects': any(u['target']['name'] == NAME for u in actual),
                     'features_by_unit': [{'id': u['id'], 'features': u['features'], 'kind': u['target']['kind']}
                                          for u in actual]})
    require({(p['name'], p['version']) for p in rows if p['unit_ids']} == native,
            '编译集合与目标 normal/build 图不一致')
    original = [json.loads(l) for l in (TARGET / 'build.jsonl').read_text().splitlines() if l.startswith('{')]
    original = [u for u in original if u.get('reason') == 'compiler-artifact']
    def unit_key(u):
        # 同一包可分别为宿主构建和目标运行编译；不能用字典合并丢掉其中一个。
        return (u['package_id'].split('#')[-1], u['target']['name'], tuple(u['target']['kind']),
                tuple(u['features']), json.dumps(u['profile'], sort_keys=True))
    require(Counter(map(unit_key, original)) == Counter(map(unit_key, units)),
            '历史编译单元/features/profile 多重集合不同')
    write_json(run / 'historical-unit-comparison.json', {'status': 'PASS', 'units': len(units),
               'features_and_profiles_match': True,
               'note': '历史 compiler-artifact 包含缓存命中；新增证据全部来自独立空 target。程序字节关联另见 reproduction。'})
    return rows, units, args


def main(run):
    output = run / 'inventory' / str(uuid.uuid4())
    output.mkdir(parents=True)
    report = {'status': 'RUNNING', 'scope': 'dev.5 artifact fact audit; no approval',
              'distribution_approval': 'NOT_APPROVED', 'windows': 'NOT_TESTED',
              'old_hpke': 'NOT_EXECUTED_PLATFORM_BLOCKED'}
    write_json(output / 'report.json', report)
    try:
        rows, units, args = components(run)
        write_json(output / 'components.json', rows)
        write_json(output / 'compiler-units.json', units)
        write_json(output / 'final-link-arguments.json', args)
        materials = collect(run, output, rows, 'source/src/sdk/rust/Cargo.lock',
                            run / 'archives', 'metadata-pristine.json')
        write_json(output / 'materials.json', materials)
        active = {(p['name'], p['version']) for p in rows if p['unit_ids']}
        package = json.loads((run / 'package/dependencies.json').read_text())
        gaps = []
        for entry in package['packages']:
            if entry['files']:
                continue
            match = next(p for p in materials if (p['name'], p['version']) == (entry['name'], entry['version']))
            gaps.append({'name': entry['name'], 'version': entry['version'], 'package_files': 0,
                         'supplement_files': len(match['files']), 'status': match['status'],
                         'sources': [f['path'] for f in match['files']]})
        write_json(output / 'package-gap-reconciliation.json', gaps)
        report.update(status='FACTS_COLLECTED_WITH_OPEN_ITEMS', metadata_packages=len(rows),
            compiler_units=len(units), compiled_packages=len(active),
            runtime_compile_packages=sum('runtime_compile_input' in p['roles'] for p in rows),
            final_link_packages=sum(p['final_link_input'] for p in rows),
            roles=dict(Counter(','.join(p['roles']) for p in rows)),
            material_files=sum(len(p['files']) for p in materials),
            active_material_files=sum(len(p['files']) for p in materials if (p['name'], p['version']) in active),
            missing_active=[p['name'] for p in materials if (p['name'], p['version']) in active
                            and p['status'] == 'MISSING_UPSTREAM_TEXT'],
            conflicts=[{'name': p['name'], 'version': p['version'], 'roles': p['roles']}
                       for p in materials if p['status'] == 'DECLARATION_TEXT_CONFLICT'],
            package_gaps=len(gaps), gaps_with_supplement=sum(bool(p['supplement_files']) for p in gaps))
    except Exception as error:
        report.update(status='FAIL', error=f'{type(error).__name__}: {error}')
    write_json(output / 'report.json', report)
    print(json.dumps({'output': str(output), **report}, ensure_ascii=False))
    return int(report['status'] == 'FAIL')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run', type=Path, required=True)
    run = p.parse_args().run.resolve()
    require(run.parent == ROOT / 'dist/platform-release/persistent/runs', '输出范围错误')
    raise SystemExit(main(run))
