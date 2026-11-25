#!/usr/bin/env python3
"""只读已有构建证据，每次在新 ID 下生成 macOS SQLite 包成分及许可材料。"""

import argparse
from collections import Counter
import json
from pathlib import Path
import sys
import uuid

from q03_components import components
from q03_materials import collect
from q03_native import collect_native
from support import ROOT, require, sha, utc_now, write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True, type=Path, help='本项独立构建与基线所在目录')
    args = parser.parse_args()
    run = args.run.resolve()
    require(run.parent == ROOT / 'dist/native-storage/ts-desktop/q03/runs', '只接受 Q03 独立 run')
    provenance = json.loads((run / 'report.json').read_text())
    historical = ROOT / provenance['target_run']
    require(historical.parent == ROOT / 'dist/native-storage/ts-desktop/runs', '历史来源范围错误')
    output = run / 'inventory' / str(uuid.uuid4())
    output.mkdir(parents=True, exist_ok=False)
    report = {'status': 'RUNNING', 'started_at': utc_now(), 'source_run': str(run.relative_to(ROOT)),
              'historical_run': str(historical.relative_to(ROOT)),
              'scope': '成分与材料事实核对；非法律/分发批准，不关闭完整 Q03',
              'tool_sources': {str(p.relative_to(ROOT)): sha(p) for p in Path(__file__).parent.glob('q03_*.py')}}
    write_json(output / 'report.json', report)
    try:
        rows, units = components(run, historical)
        write_json(output / 'components.json', rows)
        write_json(output / 'compiler-units.json', units)
        materials = collect(historical, output, rows)
        write_json(output / 'materials.json', materials)
        native = collect_native(run, historical, output, units)
        write_json(output / 'native-components.json', native)
        report.update(status='FACTS_COLLECTED_WITH_OPEN_ITEMS',
                      components=len(rows), compiler_units=len(units),
                      compiled_packages=sum(bool(r['unit_ids']) for r in rows),
                      final_link_crate_inputs=sum(r['final_link_input'] for r in rows),
                      roles=dict(Counter(','.join(r['roles']) for r in rows)),
                      material_statuses=dict(Counter(r['status'] for r in materials)),
                      missing_text=[f"{r['name']}@{r['version']}" for r in materials
                                    if r['status'] == 'MISSING_UPSTREAM_TEXT'],
                      conflicts=[{'name': r['name'], 'version': r['version'], 'roles': r['roles']}
                                 for r in materials if r['status'] == 'DECLARATION_TEXT_CONFLICT'],
                      archive_count=sum('archive' in r for r in materials),
                      license_files=sum(len(r['files']) for r in materials),
                      cache_differences=[{'name': r['name'], 'files': r['cache_differences']}
                                         for r in materials if r.get('cache_differences')],
                      rust_std_inputs=len(native['rust_standard_library']['inputs']),
                      sqlite_version=native['sqlite']['version'],
                      reproduction_binary_sha256=sha(run / 'target/release/desktop_storage'))
    except Exception as error:
        report.update(status='FAIL', error=f'{type(error).__name__}: {error}')
    finally:
        report['finished_at'] = utc_now()
        write_json(output / 'report.json', report)
    print(json.dumps({'output': str(output), **report}, ensure_ascii=False, indent=2))
    return 1 if report['status'] == 'FAIL' else 0


if __name__ == '__main__':
    sys.exit(main())
