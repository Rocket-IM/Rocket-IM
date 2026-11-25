#!/usr/bin/env python3
"""将独立Go SDK冻结为本机版本化模块代理；不发布、不选择许可证。"""
from pathlib import Path
import datetime
import hashlib
import json
import shutil
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
MODULE = 'rocket-im.local/server-sdk'
VERSION = 'v0.1.0-alpha.4'

def pack(destination):
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    source = ROOT/'src/server-sdk/go'
    files = sorted(p for p in source.iterdir() if p.is_file() and (p.suffix == '.go' or p.name in ('go.mod', 'README.md')))
    snapshot = destination/'source'; snapshot.mkdir()
    hashes = {}
    for path in files:
        shutil.copy2(path, snapshot/path.name)
        hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    proxy = destination/'proxy'/MODULE/'@v'; proxy.mkdir(parents=True)
    archive = proxy/(VERSION+'.zip')
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
        for path in files:
            item = zipfile.ZipInfo(MODULE+'@'+VERSION+'/'+path.name, (2026, 11, 24, 0, 0, 0))
            item.external_attr = 0o644 << 16
            z.writestr(item, (snapshot/path.name).read_bytes())
    (proxy/(VERSION+'.mod')).write_bytes((snapshot/'go.mod').read_bytes())
    (proxy/(VERSION+'.info')).write_text(json.dumps({'Version': VERSION, 'Time': datetime.datetime.now(datetime.timezone.utc).isoformat()}))
    (proxy/'list').write_text(VERSION+'\n')
    report = {'status':'PACKAGED_NOT_YET_ACCEPTED','module':MODULE,'version':VERSION,'source_sha256':hashes,'archive':str(archive),'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'proxy':str(destination/'proxy'),'distribution':'NOT_APPROVED'}
    (destination/'report.json').write_text(json.dumps(report,indent=2))
    return report

if __name__ == '__main__':
    report = pack(sys.argv[1]); print(json.dumps({'archive':report['archive'],'sha256':report['archive_sha256']}))
