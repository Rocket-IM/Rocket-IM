#!/usr/bin/env python3
"""真实 dev.7/dev.8 副本共同签名；原归档和冻结源码逐项保留，不构造旧版能力。"""
from pathlib import Path
import json
import shutil
import sys
import traceback
from node_pack import all_hashes, sha, write_json
import persistent_release as release
from persistent_signing import evidence_hashes, tamper
from persistent_signing_packages import LabIdentity, sign, manifest, pack, command, requirement, RELATIVE, IDENTIFIER

BASELINES = {
    'old': ('25529dae-4a8f-431f-a3b6-cb351cbc57f2/release-03', '880a6ec96559e8c0126e59ae85371c4a72cba91ef33f2d09a9224fec20f1405d'),
    'new': ('54571f34-0522-4475-9e76-4ee668e55237/release-04', 'e17d2c670a01eedc39fc41977da66cfbe06f8b31e9b2b5b132ec4ea7d9de5d66'),
}

def prepare(run):
    run = Path(run).resolve()
    assert run.parent == release.OUTPUT / 'runs' and (run / 'baseline.json').is_file()
    output = run / 'packages'; output.mkdir()
    temporary = Path('/private/tmp') / ('Rocket IM Network Upgrade ' + run.name)
    temporary.mkdir(mode=0o700)
    report = {'status':'RUNNING', 'temporary':str(temporary), 'packages':{}, 'historical':{},
              'stage0':'NOT_COMPLETE', 'distribution':'NOT_APPROVED', 'windows':'NOT_TESTED'}
    identities = []
    try:
        signer = LabIdentity(temporary / 'signer', 'recognized'); identities.append(signer)
        other = LabIdentity(temporary / 'other-signer', 'unrecognized'); identities.append(other)
        report['signers'] = [{'certificate_sha1':x.fingerprint, 'keychain':str(x.path)} for x in identities]
        for label, (relative, digest) in BASELINES.items():
            original = release.OUTPUT / 'runs' / relative
            before = evidence_hashes(original)
            old = json.loads((original / 'report.json').read_text())
            assert old['status']=='PASS_SCOPED' and sha(Path(old['archive']))==old['archive_sha256']==digest
            assert all_hashes(original / 'package')==old['package_files']
            assert {n:sha(original / 'source' / n) for n in old['source_before']}==old['source_before']
            target=output/label; target.mkdir()
            shutil.copytree(original/'package',target/'package')
            shutil.copytree(original/'source',target/'source')
            signing=sign(target/'package'/RELATIVE,signer); manifest(target/'package')
            archive=pack(target/'package',target/'archive')
            shutil.copy2(original/'fault-runtime',target/'fault-runtime')
            fault_signing=sign(target/'fault-runtime',signer)
            assert b'ROCKET_IM_TEST_' not in (target/'package'/RELATIVE).read_bytes()
            result={'status':'PASS_SCOPED','kind':'verified_resigned_copy_not_rebuild',
                    'source_before':old['source_before'],
                    'baseline_report':str(original/'report.json'),'archive':str(archive),'archive_sha256':sha(archive),
                    'binary_sha256':sha(target/'package'/RELATIVE),'package_files':all_hashes(target/'package'),
                    'signing':signing,'fault_signing':fault_signing,'fault_binary_sha256':sha(target/'fault-runtime')}
            write_json(target/'report.json',result)
            report['packages'][label]={'release':str(target),'archive':str(archive),'sha256':sha(archive),'signing':signing}
            assert evidence_hashes(original)==before
            report['historical'][label]={'path':str(original),'files':before,'preserved':True}
        for label in ('other-signer','other-id','adhoc','stale-hash','wrong-version','tampered'):
            target=output/label;shutil.copytree(output/'new/package',target/'package')
            stage=target/'package';binary=stage/RELATIVE
            if label in ('other-signer','stale-hash'):signing=sign(binary,other)
            elif label=='other-id':signing=sign(binary,signer,IDENTIFIER+'.other')
            elif label=='adhoc':command(['/usr/bin/codesign','--force','--sign','-','--identifier',IDENTIFIER,binary],target,'adhoc')
            elif label=='tampered':report['tampered_offset']=tamper(binary)
            if label!='stale-hash':manifest(stage)
            if label=='wrong-version':
                p=stage/'artifact.json';value=json.loads(p.read_text());value['version']='0.0.0-invalid';write_json(p,value)
            archive=pack(stage,target/'archive')
            report['packages'][label]={'release':str(target),'archive':str(archive),'sha256':sha(archive)}
        for label in ('old','new','other-signer','other-id','adhoc'):
            result=command(['/usr/bin/codesign','--verify','--strict','-R','='+requirement(signer),output/label/'package'/RELATIVE],output,'requirement-'+label,None)
            assert (result.returncode==0)==(label in ('old','new'))
        # 消费装置单独冻结，不改写旧版 source 或声称旧版已提供新公开方法。
        inputs=release.sources()
        names=set(inputs)
        names.update(str(p.relative_to(release.ROOT)) for p in (release.ROOT/'tests/interop/network_alpha').glob('*') if p.is_file())
        for name in sorted(names):
            path=run/'inputs'/name;path.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(release.ROOT/name,path)
        report['input_sha256']={n:sha(release.ROOT/n) for n in sorted(names)}
        report['status']='PASS_SCOPED'
    except Exception as e:
        report.update(status='FAIL',error=str(e),trace=traceback.format_exc())
    finally:
        for identity in identities:identity.close()
        report['signing_keychains_locked']=len(identities)
        write_json(run/'package-preparation.json',report)
    print(json.dumps({'status':report['status'],'report':str(run/'package-preparation.json'),'error':report.get('error')}),flush=True)
    return 0 if report['status']=='PASS_SCOPED' else 1

if __name__=='__main__':sys.exit(prepare(sys.argv[1]))
