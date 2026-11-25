#!/usr/bin/env python3
"""捕获 ThinLTO 的真实链接对象和临时归档；用固定 Xcode SDK 对照原包。"""

import argparse
import json
import os
from pathlib import Path
import shutil
import sys

from persistent_q03 import ROOT, NAME, command
from persistent_q03_binary import compare
sys.path.insert(0, str(ROOT / 'tools/native_storage'))
from support import require, sha, write_json


def main(run):
    xcode = Path('/Applications/Xcode-26.1.1.app/Contents/Developer')
    clang = xcode / 'Toolchains/XcodeDefault.xctoolchain/usr/bin/clang'
    sdk = xcode / 'Platforms/MacOSX.platform/Developer/SDKs/MacOSX26.1.sdk'
    require(clang.is_file() and sdk.is_dir(), '固定 Xcode SDK 不存在')
    root = next(u for u in json.loads((run / 'compiler-units-initial.json').read_text())
                if u['target']['name'] == NAME)
    candidates = [json.loads(p.read_text()) for p in (run / 'remapped-commands').glob('*.json')]
    args = next(a for a in candidates if '--crate-name' in a and a[a.index('--crate-name') + 1] == NAME.replace('-', '_'))
    out = run / 'case-work/link-capture-xcode'
    out.mkdir()
    inputs = run / 'link-inputs'
    inputs.mkdir()
    wrapper = run / 'capture-linker.py'
    wrapper.write_text('#!/usr/bin/python3\nimport sys,os,json,hashlib,shutil\nfrom pathlib import Path\n'
        f'out=Path({str(inputs)!r})\nrows=[]\n'
        'for i,a in enumerate(sys.argv[1:]):\n'
        ' p=Path(a)\n'
        ' if p.is_file() and p.suffix in (".rlib",".o",".a"):\n'
        '  data=p.read_bytes();n=str(i)+"-"+p.name; (out/n).write_bytes(data)\n'
        '  rows.append({"argument":a,"copy":n,"sha256":hashlib.sha256(data).hexdigest()})\n'
        '(out/"arguments.json").write_text(json.dumps(sys.argv[1:],indent=2))\n'
        '(out/"files.json").write_text(json.dumps(rows,indent=2))\n'
        f'os.execv({str(clang)!r},[{str(clang)!r},*sys.argv[1:]])\n')
    wrapper.chmod(0o700)
    args[args.index('--out-dir') + 1] = str(out)
    args += ['-C', f'linker={wrapper}', '-C', 'link-arg=-isysroot', '-C', f'link-arg={sdk}']
    env = os.environ.copy()
    for a in root['command']:
        if '=' not in a:
            break
        key, value = a.split('=', 1)
        env[key] = value.replace(str(run / 'case-work/target'), str(run / 'case-work/target-remapped'))
    env.update(SDKROOT=str(sdk), DEVELOPER_DIR=str(xcode))
    command(run, 'link-xcode.log', args, run / 'source/src/sdk/rust', env)
    binary = next(p for p in out.iterdir() if p.name.startswith(NAME.replace('-', '_')) and p.suffix != '.d')
    original = run / 'package/bin/darwin-arm64' / NAME
    comparison = run / 'reproduction-xcode'
    comparison.mkdir()
    for name, source in [('original', original), ('rebuilt', binary)]:
        dest = comparison / name
        shutil.copy2(source, dest)
        command(run, f'unsigned-xcode-{name}.log', ['/usr/bin/codesign', '--remove-signature', dest], run)
    result = compare(comparison / 'original', comparison / 'rebuilt')
    result.update(original_sha256=sha(original), rebuilt_sha256=sha(binary),
                  unsigned_original_sha256=sha(comparison / 'original'),
                  unsigned_rebuilt_sha256=sha(comparison / 'rebuilt'),
                  linker_path=str(clang), linker_sha256=sha(clang), sdk_path=str(sdk),
                  all_sections_equal=not result['section_differences'],
                  wrapper_sha256=sha(wrapper), sources_modified=False, originals_modified=False)
    write_json(comparison / 'comparison.json', result)
    command(run, 'binary-link-xcode.log', ['/usr/bin/otool', '-L', binary], run)
    print(json.dumps({'unsigned_bytes_equal': result['unsigned_bytes_equal'],
                      'all_sections_equal': result['all_sections_equal'], 'report': str(comparison / 'comparison.json')}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    args = parser.parse_args()
    main(args.run.resolve())
