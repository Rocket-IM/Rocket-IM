#!/usr/bin/env python3
"""冻结正式 SDK 源码，构建实际 Release 包并在仓库外独立消费。只做本机开发验收。"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import uuid

from node_pack import all_hashes, command, COMPILER, node_binary, npm_command, sha, write_json
from persistent_protection import run as protected_cases
ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / 'dist/platform-release/persistent'
PACKAGE = ROOT / 'src/sdk/typescript/desktop'
CONSUMER = ROOT / 'tests/consumers/node-persistent'
VERSION = '0.2.0-dev.12'
NAME = '@rocket-im/desktop-dev'

def sources():
    names = subprocess.check_output(['git','ls-files','-co','--exclude-standard','-z'],cwd=ROOT).decode().split('\0')
    return {name:sha(ROOT/name) for name in sorted(set(names)) if name and (ROOT/name).is_file()
        and not name.startswith('src/sdk/typescript/desktop/dist/') and
        (name.startswith(('src/sdk/rust/','src/sdk/typescript/desktop/','tests/consumers/node-persistent/'))
         or name.startswith('tools/platform_release/persistent_')
         or name in ('tools/native_storage/signing_local.py','tools/native_storage/signing_keychain.py','tools/native_storage/support.py')
         or name in ('tools/platform_release/persistent_release.py','tools/platform_release/persistent_faults.py','tools/platform_release/persistent_negatives.mjs','tools/platform_release/node_pack.py'))}

def licenses(metadata, artifacts, stage):
    ids = {row['package_id'] for row in artifacts if row.get('reason') == 'compiler-artifact'}
    records = []
    for package in metadata['packages']:
        if package['id'] not in ids or package['source'] is None:
            continue
        source = Path(package['manifest_path']).parent
        paths = {p for pattern in ('LICENSE*','LICENCE*','COPYING*','NOTICE*') for p in source.glob(pattern) if p.is_file()}
        if package.get('license_file'):
            paths.add(source/package['license_file'])
        if package['name']=='libsqlite3-sys':
            paths.add(source/'sqlcipher/LICENSE')
        files = []
        for path in sorted(paths):
            label = 'SQLCipher-LICENSE' if path.parent.name=='sqlcipher' else path.name
            dest = stage/'licenses'/f"{package['name']}-{package['version']}"/label
            dest.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(path,dest)
            files.append({'path':str(dest.relative_to(stage)),'sha256':sha(dest)})
        records.append({'name':package['name'],'version':package['version'],'declared_license':package['license'],'files':files})
    write_json(stage/'dependencies.json', {'scope':'actual compiler-artifact packages including build inputs; not a final-link SBOM',
        'distribution_approval':'NOT_APPROVED','known_open_items':['Existing HPKE declared license versus license-text conflict remains open'], 'packages':records})
    return len(records)

def main(run=None, signer=None):
    run = run or OUTPUT/'runs'/str(uuid.uuid4()); run.mkdir(parents=True)
    report = {'status':'RUNNING','started_at':datetime.now(timezone.utc).isoformat(),'source_before':sources(),'commands':[],
        'stage0':'NOT_COMPLETE','windows':'NOT_TESTED','production':'NOT_APPROVED'}
    write_json(run/'report.json',report)
    def cmd(args, cwd, name, timeout=300):
        result=command(args,cwd,run/name,timeout=timeout); report['commands'].append(result); write_json(run/'report.json',report)
        return (run/name).read_text()
    try:
        assert platform.system() == 'Darwin' and platform.machine() == 'arm64'
        frozen=run/'source'
        for name in report['source_before']:
            dest=frozen/name; dest.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(ROOT/name,dest)
        rust=frozen/'src/sdk/rust'
        cargo=ROOT/'dist/toolchains/rust/cargo/bin/cargo'
        env=['/usr/bin/env',f'CARGO_HOME={ROOT}/dist/toolchains/rust/cargo',f'RUSTUP_HOME={ROOT}/dist/toolchains/rust/rustup']
        base=[*env,cargo,'+1.98.1']
        report['runtime']={'platform':platform.platform(),'node':cmd([node_binary(),'--version'],run,'node-version.log').strip(),'rustc':cmd([*env,ROOT/'dist/toolchains/rust/cargo/bin/rustc','+1.98.1','-vV'],run,'rustc-version.log').strip()}
        fixed=['--manifest-path',rust/'Cargo.toml','--locked','--offline','--target-dir',OUTPUT/'target-protected']
        cmd(base+['fmt','--manifest-path',rust/'Cargo.toml','--all','--check'],rust,'fmt.log')
        cmd(base+['clippy',*fixed,'-p','rocket-im-desktop-runtime','-p','rocket-im-sdk','-p','rocket-crypto-core','--all-targets','--release','--','-D','warnings'],rust,'clippy.log')
        cmd(base+['clippy',*fixed,'-p','rocket-im-desktop-runtime','--features','test-hooks','--all-targets','--release','--','-D','warnings'],rust,'clippy-test-hooks.log')
        cmd(base+['test',*fixed,'-p','rocket-crypto-core','-p','rocket-im-sdk','--features','rocket-im-sdk/persistent,rocket-im-sdk/network','--release'],rust,'tests-persistent.log')
        cmd(base+['test',*fixed,'-p','rocket-im-sdk','--features','protected-storage,network','--release'],rust,'tests-protected.log')
        cmd(base+['test',*fixed,'-p','rocket-crypto-core','-p','rocket-im-sdk','--release'],rust,'tests-memory.log')
        cmd(base+['check',*fixed,'-p','rocket-bindings-uniffi','-p','rocket-bindings-flutter'],rust,'legacy-native-check.log')
        cmd(base+['check',*fixed,'-p','rocket-bindings-wasm','--target','wasm32-unknown-unknown'],rust,'legacy-wasm-check.log')
        tree=cmd(base+['tree','--manifest-path',rust/'Cargo.toml','--locked','--offline','-p','rocket-bindings-wasm','--target','wasm32-unknown-unknown','-e','normal'],rust,'legacy-wasm-tree.log')
        assert 'rusqlite' not in tree
        output=cmd(base+['build',*fixed,'-p','rocket-im-desktop-runtime','--release','--message-format=json'],rust,'build.jsonl')
        artifacts=[json.loads(line) for line in output.splitlines() if line.startswith('{')]
        metadata=json.loads(cmd(base+['metadata','--manifest-path',rust/'Cargo.toml','--locked','--offline','--format-version','1'],rust,'metadata.json'))
        stage=run/'package'; stage.mkdir()
        package=frozen/'src/sdk/typescript/desktop'
        for name in ('package.json','README.md'): shutil.copy2(package/name,stage/name)
        assert json.loads((COMPILER.parent.parent/'package.json').read_text())['version']=='5.9.3'
        cmd([node_binary(),COMPILER,'-p',package/'tsconfig.json'],package,'typescript.log')
        shutil.copytree(package/'dist',stage/'dist')
        for name in ('transport.mjs','transport.d.mts','artifact.mjs'): shutil.copy2(package/'src'/name,stage/'dist'/name)
        cmd([node_binary(),frozen/'tools/platform_release/persistent_capacity.mjs',stage],stage,'capacity-validation.log')
        binary=stage/'bin/darwin-arm64/rocket-im-desktop-runtime';binary.parent.mkdir(parents=True)
        executable=next(Path(row['executable']) for row in artifacts if row.get('executable') and row['target']['name']=='rocket-im-desktop-runtime')
        assert executable.parent==OUTPUT/'target-protected/release'
        shutil.copy2(executable,binary)
        # 先签实际交付副本，再生成摘要和 TGZ；默认仍保持本地 ad hoc 模式。
        if signer is not None:
            report['signing'] = signer(binary)
        report['compiled_dependency_count']=licenses(metadata,artifacts,stage)
        cmd(['/usr/bin/file',binary],run,'binary-format.log');cmd(['/usr/bin/otool','-L',binary],run,'binary-link.log')
        write_json(stage/'artifact.json',{'version':VERSION,'protocol':3,'target':'darwin-arm64','binarySha256':sha(binary),'sourceSha256':report['source_before'],'filesSha256':all_hashes(stage)})
        output=cmd(npm_command()+['pack','--json','--ignore-scripts','--pack-destination',run],stage,'npm-pack.log')
        archive=run/json.loads(output)[0]['filename'];expected=all_hashes(stage)
        with tarfile.open(archive) as tar:
            actual={}
            for member in tar.getmembers():
                assert member.isfile() and member.name.startswith('package/') and '..' not in Path(member.name).parts
                name=member.name[8:];assert name not in actual
                actual[name]=hashlib.sha256(tar.extractfile(member).read()).hexdigest()
        assert actual==expected
        assert not any(name.endswith('.rs') or Path(name).name in ('Cargo.toml','Cargo.lock') for name in actual)
        report.update(archive=str(archive),archive_sha256=sha(archive),binary_sha256=sha(binary),package_files=actual)
        consumer=Path('/private/tmp')/f'Rocket IM 双持久端 {run.name}-{uuid.uuid4()}'
        report['consumer']=str(consumer)
        shutil.copytree(frozen/'tests/consumers/node-persistent',consumer)
        cmd(npm_command()+['install','--offline','--ignore-scripts','--no-audit','--no-fund',archive],consumer,'consumer-install.log')
        assert all_hashes(consumer/'node_modules'/NAME)==expected
        cmd([node_binary(),COMPILER,'-p',consumer/'tsconfig.json'],consumer,'consumer-types.log')
        # 接入运行只给 Node 可执行目录；没有 Rust/Cargo 或生成器，也不读取仓库源码。
        node=Path(node_binary());limited=run/'consumer-path';limited.mkdir();(limited/'node').symlink_to(node)
        independent=['/usr/bin/env',f'PATH={limited}',node]
        report['consumer']=str(consumer)
        cmd(base+['build',*fixed,'-p','rocket-im-desktop-runtime','--features','test-hooks','--release'],rust,'fault-build.log')
        fault_binary=run/'fault-runtime';shutil.copy2(OUTPUT/'target-protected/release/rocket-im-desktop-runtime',fault_binary)
        if signer is not None:
            report['fault_signing'] = signer(fault_binary)
        report['fault_binary_sha256']=sha(fault_binary)
        installed=consumer/'node_modules'/NAME/'bin/darwin-arm64/rocket-im-desktop-runtime'
        report['protection']=protected_cases(installed,fault_binary,consumer,run/'protection',independent,stage,frozen/'tools/platform_release/persistent_negatives.mjs')
        report['source_after']=sources();assert report['source_after']==report['source_before'], '源码在冻结后发生变化，结果不能标为最终通过'
        report['frozen_source_after']={name:sha(frozen/name) for name in report['source_before']}
        assert report['frozen_source_after']==report['source_before'], '冻结输入被构建修改，结果不能标为最终通过'
        report['status']='PASS_SCOPED'
    except Exception as e:
        report.update(status='FAIL',error=f'{type(e).__name__}: {e}')
    report['finished_at']=datetime.now(timezone.utc).isoformat()
    write_json(run/'report.json',report)
    print(json.dumps({'status':report['status'],'report':str(run/'report.json'),'archive':report.get('archive'),'consumer':report.get('consumer'),'error':report.get('error')},ensure_ascii=False))
    return 0 if report['status']=='PASS_SCOPED' else 1
if __name__=='__main__': sys.exit(main())
