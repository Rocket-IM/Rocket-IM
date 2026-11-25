"""从隔离 Release 的真实编译单元与 --extern 关系归类；不以 metadata 全集代替产物。"""

from collections import defaultdict
import json
from pathlib import Path
import re
import shlex

from support import require, sha


def package_key(package):
    return package['name'], package['version']


def tree_keys(path):
    return {match.groups() for line in path.read_text().splitlines()
            if (match := re.match(r'\d*([^ ]+) v([^ |]+)', line))}


def argument(args, name):
    return args[args.index(name) + 1]


def compilation_units(run, root_name='desktop_storage'):
    events, commands, running = [], [], None
    for line in (run / 'build.log').read_text().splitlines():
        if line.startswith('{'):
            events.append(json.loads(line))
        if line.strip().startswith('Running `'):
            require(running is None, '上一条命令没有完整结束')
            running = line.strip()[9:]
        elif running is not None:
            running += '\n' + line
        # Cargo 的包描述可含换行和反引号；必须等完整 shell 引号闭合。
        if running is not None and running.endswith('`'):
            try:
                args = shlex.split(running[:-1])
            except ValueError:
                continue
            if any('=' not in arg and Path(arg).name == 'rustc' for arg in args):
                commands.append(args)
            running = None
    require(running is None, '构建日志命令被截断')
    require(events[-1] == {'reason': 'build-finished', 'success': True}, '构建未完整成功')
    artifacts = [e for e in events if e.get('reason') == 'compiler-artifact']
    require(all(not e['fresh'] and not e['profile']['test'] for e in artifacts),
            '要求独立空 target 的非测试构建证据')
    units, file_to_unit = [], {}
    for artifact in artifacts:
        name = artifact['target']['name'].replace('-', '_')
        matches = []
        for args in commands:
            if argument(args, '--crate-name') != name:
                continue
            if f"CARGO_MANIFEST_DIR={Path(artifact['manifest_path']).parent}" not in args:
                continue
            suffix = next(arg.split('=', 1)[1] for arg in args if arg.startswith('extra-filename='))
            if (artifact['target']['name'] == root_name
                    or any(suffix in f for f in artifact['filenames'])):
                matches.append(args)
        require(len(matches) == 1, f'无法唯一关联真实编译命令：{artifact["package_id"]}/{name}')
        args = matches[0]
        extern_args = [args[i + 1] for i, arg in enumerate(args) if arg == '--extern']
        externs = [arg.split('=', 1)[1] for arg in extern_args if '=' in arg]
        unit = {key: artifact[key] for key in ('package_id', 'target', 'features', 'profile', 'filenames')}
        unit.update(id=len(units), command=args, extern_paths=externs,
                    sysroot_externs=[arg for arg in extern_args if '=' not in arg], dependencies=[], roles=[])
        for filename in artifact['filenames']:
            file_to_unit[filename] = unit['id']
        units.append(unit)
    require(len(commands) == len(units), '编译命令与产物数不相等')
    for unit in units:
        for filename in unit['extern_paths']:
            require(filename in file_to_unit, f'未归属的 --extern：{filename}')
            unit['dependencies'].append(file_to_unit[filename])
    root = [u['id'] for u in units if u['target']['name'] == root_name]
    require(len(root) == 1, f'必须恰有一个 {root_name}')
    pending = [(root[0], 'runtime_compile_input')]
    pending += [(u['id'], 'build_tool') for u in units
                if set(u['target']['kind']) & {'custom-build', 'proc-macro'}]
    while pending:
        ident, role = pending.pop()
        unit = units[ident]
        if role in unit['roles']:
            continue
        unit['roles'].append(role)
        for dependency in unit['dependencies']:
            child = units[dependency]
            child_role = ('build_tool' if role == 'build_tool' or 'proc-macro' in child['target']['kind']
                          else 'runtime_compile_input')
            pending.append((dependency, child_role))
    require(all(u['roles'] for u in units), '存在未能归类的编译单元')
    return units


def components(run, historical):
    metadata = json.loads((historical / 'metadata.json').read_text())
    units = compilation_units(run)
    link_line = next(line for line in (run / 'link-args-correct-cwd.log').read_text().splitlines()
                     if line.startswith('env '))
    linked_files = {arg for arg in shlex.split(link_line) if arg.endswith('.rlib')}
    known_files = {filename for unit in units for filename in unit['filenames']}
    require(all(path in known_files or '/rustup/toolchains/' in path for path in linked_files),
            '最终链接中存在未归属的 rlib')
    for unit in units:
        unit['final_link_files'] = sorted(set(unit['filenames']) & linked_files)
    by_package = defaultdict(list)
    for unit in units:
        by_package[unit['package_id']].append(unit)
    native_keys = tree_keys(run / 'tree.txt')
    all_keys = tree_keys(run / 'tree-all.txt')
    dev_keys = tree_keys(run / 'tree-with-dev.txt')
    rows = []
    for package in sorted(metadata['packages'], key=package_key):
        actual = by_package.get(package['id'], [])
        roles = sorted({role for unit in actual for role in unit['roles']})
        if not roles:
            if package_key(package) in dev_keys:
                roles = ['dev_only']
            elif package_key(package) in all_keys:
                roles = ['other_target_only']
            else:
                roles = ['not_selected_features']
        rows.append({'name': package['name'], 'version': package['version'], 'id': package['id'],
                     'roles': roles, 'unit_ids': [u['id'] for u in actual],
                     'final_link_files': [path for u in actual for path in u['final_link_files']],
                     'final_link_input': any(u['final_link_files'] for u in actual),
                     'features_by_unit': [{'id': u['id'], 'kind': u['target']['kind'], 'features': u['features']}
                                          for u in actual],
                     'declared_dependency_kinds': sorted({d.get('kind') or 'normal' for d in package['dependencies']}),
                     'note': '编译路径、最终链接输入及优化后保留代码有区别；宏/构建脚本生成物仍可能进入程序，未逐符号统计最终保留字节。'})
    built_keys = {(p['name'], p['version']) for p in rows if p['unit_ids']}
    require(built_keys == native_keys, '实际编译集合与 cargo tree normal/build 不符')
    require(len(by_package) == len(built_keys), '存在 metadata 未记录的编译包')
    binary = run / 'target/release/desktop_storage'
    old_report = json.loads((historical / 'report.json').read_text())
    require(sha(binary) == old_report['binary_sha256'], '补建程序与历史二进制不一致，不能继承其成分关联')
    return rows, units
