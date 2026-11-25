#!/usr/bin/env python3
"""联网Alpha维护者入口：新合成签名、冻结Release与实际包回归，不发布。"""
from pathlib import Path
import os
import sys
import uuid
import persistent_release as release
from persistent_signing_packages import LabIdentity, sign, verified_copy, write_json

def build(run, upgrade=False):
    signer = None
    report = {'status': 'RUNNING'}
    record = Path(run).parent / (Path(run).name + '-signer.json')
    try:
        temporary=Path('/private/tmp')/('Rocket IM Network Signing '+str(uuid.uuid4()))
        signer=LabIdentity(temporary,'network-alpha')
        report.update(keychain=str(signer.path), certificate_sha1=signer.fingerprint)
        if upgrade:
            from service_backup import BASE, BASE_SHA
            target = Path(run).parent / (Path(run).name + '-dev9')
            old = verified_copy(BASE, target, signer, BASE_SHA)
            report['dev9'] = {'release': str(target), 'archive_sha256': old['archive_sha256']}
        result = release.main(Path(run),signer=lambda binary:sign(binary,signer))
        report['status'] = 'PASS_SCOPED' if result == 0 else 'FAIL'
        return result
    finally:
        if signer is not None:
            signer.close(); report['signing_keychain_locked'] = True
        write_json(record, report)

if __name__=='__main__':
    if len(sys.argv)!=3 or sys.argv[1] not in ('build','build-upgrade'): raise SystemExit('usage: persistent_network.py build|build-upgrade ABSOLUTE_RUN_DIRECTORY')
    sys.exit(build(sys.argv[2], upgrade=sys.argv[1]=='build-upgrade'))
