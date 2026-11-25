#!/usr/bin/env python3
"""以本轮真实多行编译日志验证审计器拒绝截断、缓存命中、缺命令及未归属依赖。"""

import argparse
import json
from pathlib import Path
import re
import tempfile
import uuid

from q03_components import compilation_units
from support import require, utc_now, write_json


def change_event(text):
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.startswith('{'):
            event = json.loads(line)
            if event.get('reason') == 'compiler-artifact':
                event['fresh'] = True
                lines[i] = json.dumps(event)
                return '\n'.join(lines) + '\n'
    raise AssertionError('没有可变异的真实产物')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--root-name', default='desktop_storage')
    args = parser.parse_args()
    run = args.run.resolve()
    output = run / 'audit-tests' / str(uuid.uuid4())
    output.mkdir(parents=True)
    log = (run / 'build.log').read_text()
    units = compilation_units(run, args.root_name)
    require(len(units) == 168, '本项基线编译单元数改变，需要重新核对范围')
    require(any('\n' in arg for u in units for arg in u['command']), '没有覆盖多行环境值')
    cases = [{'name': 'complete_multiline_real_build', 'status': 'PASS', 'units': len(units)}]
    mutations = {
        'missing_build_finished': '\n'.join(line for line in log.splitlines()
                                            if '"reason":"build-finished"' not in line),
        'cached_artifact_not_clean_rebuild': change_event(log),
        'unresolved_extern': re.sub(r'(--extern \w+=)(\S+\.rlib)', r'\1/not-a-build-input.rlib', log, count=1),
        'missing_root_compiler_command': '\n'.join(line for line in log.splitlines()
                                                    if not line.strip().startswith('Running `CARGO=')
                                                    or f'CARGO_BIN_NAME={args.root_name}' not in line),
    }
    for name, mutated in mutations.items():
        require(mutated != log, f'未执行变异：{name}')
        with tempfile.TemporaryDirectory(dir=output) as folder:
            path = Path(folder)
            (path / 'build.log').write_text(mutated)
            try:
                compilation_units(path, args.root_name)
            except AssertionError as error:
                cases.append({'name': name, 'status': 'PASS', 'expected_rejection': str(error)})
            else:
                cases.append({'name': name, 'status': 'FAIL', 'error': '错误证据被接受'})
    report = {'status': 'PASS' if all(c['status'] == 'PASS' for c in cases) else 'FAIL',
              'cases': cases, 'finished_at': utc_now(), 'scope': '审计器门禁；非消息/密码运行矩阵'}
    write_json(output / 'report.json', report)
    print(json.dumps({'output': str(output), **report}, ensure_ascii=False, indent=2))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
