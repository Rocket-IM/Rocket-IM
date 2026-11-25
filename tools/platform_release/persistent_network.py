#!/usr/bin/env python3
"""联网Alpha维护者入口：新合成签名、冻结Release与实际包回归，不发布。"""
from pathlib import Path
import os
import sys
import uuid
import persistent_release as release
from persistent_signing_packages import LabIdentity, sign, verified_copy, write_json

def build(run, upgrade=False, capacity=False, reserve=False, workset=False, repeated=False):
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
        if capacity:
            source=release.OUTPUT/'runs/a727bfee-5bd4-4862-bc87-16b235c55543/dev10-r04'
            target=Path(run).parent/(Path(run).name+'-dev10')
            old=verified_copy(source,target,signer,'8ee61f10db59475ffccbdbff3074ad773dcbf65939f6ed1c9545a78c073074ec')
            report['dev10']={'release':str(target),'archive_sha256':old['archive_sha256']}
        if reserve:
            source=release.OUTPUT/'runs/eb56aef4-6ce2-4a69-b429-cedf3b950dda/dev11-r02'
            target=Path(run).parent/(Path(run).name+'-dev11')
            old=verified_copy(source,target,signer,'fbedacca80737e29d379f7760c8e18101ac9b6b27ed32363b7ca79558e166feb')
            report['dev11']={'release':str(target),'archive_sha256':old['archive_sha256']}
        if workset:
            source=release.OUTPUT/'runs/a113058b-4419-47df-aacb-21f94837b5b4/dev12-r02'
            target=Path(run).parent/(Path(run).name+'-dev12')
            old=verified_copy(source,target,signer,'777c34f9b6293533c4ef47929446e630e0be0d540f9bcebc870cf8f68da66076')
            report['dev12']={'release':str(target),'archive_sha256':old['archive_sha256']}
        if repeated:
            source=release.OUTPUT/'runs/ad1ef4d1-0715-47c7-aad7-e6632d9b568a/dev13-r03'
            target=Path(run).parent/(Path(run).name+'-dev13')
            old=verified_copy(source,target,signer,'a0a2c29d27c0a2a768b82f6518a1a158bf7dda0867d5c3c87e81fd8f01e370f9')
            report['dev13']={'release':str(target),'archive_sha256':old['archive_sha256']}
        result = release.main(Path(run),signer=lambda binary:sign(binary,signer))
        report['status'] = 'PASS_SCOPED' if result == 0 else 'FAIL'
        return result
    finally:
        if signer is not None:
            signer.close(); report['signing_keychain_locked'] = True
        write_json(record, report)

if __name__=='__main__':
    if len(sys.argv)!=3 or sys.argv[1] not in ('build','build-upgrade','build-capacity','build-reserve','build-workset','build-repeated-workset'): raise SystemExit('usage: persistent_network.py build|build-upgrade|build-capacity|build-reserve|build-workset|build-repeated-workset ABSOLUTE_RUN_DIRECTORY')
    sys.exit(build(sys.argv[2], upgrade=sys.argv[1]=='build-upgrade',capacity=sys.argv[1]=='build-capacity',reserve=sys.argv[1]=='build-reserve',workset=sys.argv[1]=='build-workset',repeated=sys.argv[1]=='build-repeated-workset'))
