#!/usr/bin/env python3
"""真实 ThinLTO 审计输入的缺失、错归属和内容篡改拒绝检查。"""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import uuid

from persistent_q03_inventory import link_inputs
from persistent_q03 import write_json, require


def main(run):
    output = run / 'link-audit-tests' / str(uuid.uuid4())
    output.mkdir(parents=True)
    units = json.loads((run / 'compiler-units-initial.json').read_text())
    cases = []
    for name in ['complete', 'missing_input', 'wrong_owner', 'changed_bytes', 'forged_native_member']:
        with tempfile.TemporaryDirectory(dir=output) as directory:
            fixture = Path(directory)
            shutil.copy2(run / 'sysroot.log', fixture / 'sysroot.log')
            shutil.copytree(run / 'link-inputs', fixture / 'link-inputs')
            rows = json.loads((fixture / 'link-inputs/files.json').read_text())
            arguments = json.loads((fixture / 'link-inputs/arguments.json').read_text())
            if name == 'missing_input':
                rows.pop()
            elif name == 'wrong_owner':
                original = rows[0]['argument']
                rows[0]['argument'] = '/not-a-package/unknown.o'
                arguments[arguments.index(original)] = rows[0]['argument']
            elif name == 'changed_bytes':
                path = fixture / 'link-inputs' / rows[0]['copy']
                path.write_bytes(path.read_bytes()[:-1])
            elif name == 'forged_native_member':
                row = next(r for r in rows if Path(r['argument']).name.startswith('liblibsqlite3_sys'))
                path = fixture / 'link-inputs' / row['copy']
                data = bytearray(path.read_bytes())
                data[-8] ^= 1
                path.write_bytes(data)
                row['sha256'] = hashlib.sha256(data).hexdigest()
            write_json(fixture / 'link-inputs/files.json', rows)
            write_json(fixture / 'link-inputs/arguments.json', arguments)
            try:
                result = link_inputs(fixture, copy.deepcopy(units))
            except AssertionError as error:
                require(name != 'complete', f'真实正例失败：{error}')
                cases.append({'name': name, 'status': 'PASS', 'expected_rejection': str(error)})
            else:
                require(name == 'complete', f'坏证据被接受：{name}')
                cases.append({'name': name, 'status': 'PASS', 'inputs': len(result)})
    write_json(output / 'report.json', {'status': 'PASS', 'cases': cases,
               'scope': '审计工具门禁，不是 SDK 或密码运行矩阵'})
    print(json.dumps({'output': str(output), 'status': 'PASS', 'cases': len(cases)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    main(parser.parse_args().run.resolve())
