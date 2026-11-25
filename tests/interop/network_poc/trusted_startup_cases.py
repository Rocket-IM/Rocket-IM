"""B01—B10具名攻击前置与真实进程证据；合成暂停和共同回滚单列。"""
import base64
import copy
import json
import secrets
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from .fixture import check
from .trusted_startup_fixture import StartupLab, sha

def b01(lab):
    lab.group(); s=lab.install(apply=False)
    lab.reject(codes=('startup_stale',))
    bad=lab.sign_approval(s,'install',s['config']['manifest'],seed=secrets.token_hex(32))
    e=lab.authority({'op':'apply','directory':str(s['authority']),'approval':bad},1)
    check(e['code']=='permission_signature','错误批准钥未拒绝')
    lab.authority({'op':'apply','directory':str(s['authority']),'approval':s['install_approval']})
    s['manifest']=s['config']['manifest'];lab.install('b1');lab.continued('installed')
    environment=lab.environment('a1');environment.pop('RIM_TRUSTED_STARTUP_CONFIG')
    request=lab.command('a1','inspect')
    before=sha(lab.snapshot('a1'))
    p=subprocess.run([str(lab.binary)],input=json.dumps(request),env=environment,text=True,capture_output=True,timeout=12)
    check(p.returncode==1 and json.loads(p.stdout)['error']['code']=='startup_required' and sha(lab.snapshot('a1'))==before,'可信启动器必需模式允许省略配置')
    lab.reject(operation='init',codes=('anchor_initialization',))

def b02(lab):
    lab.setup();s=lab.startups['a1'];original=copy.deepcopy(s['config'])
    for field in ('business_key','receipt_key'):
        bad=copy.deepcopy(original);bad['manifest']['roots'][field]=lab.authority({'op':'public_key','seed':secrets.token_hex(32)})['public_key']
        lab.update_config('a1',bad);lab.reject(codes=('startup_stale',))
    for field in ('store_id','identity_key'):
        bad=copy.deepcopy(original);bad['manifest']['scope'][field]=secrets.token_hex(32)
        lab.update_config('a1',bad);lab.reject(codes=('startup_stale',))
    bad=copy.deepcopy(original);bad['manifest']['anchor_public_key']=lab.materials['b1']['config']['anchor_public_key']
    lab.update_config('a1',bad);lab.reject(codes=('startup_stale',))
    lab.update_config('a1',original)
    saved=lab.configs['a1'].read_bytes();lab.config_change('a1',journal_key=secrets.token_hex(32))
    lab.reject(codes=('startup_anchor_binding',));lab.configs['a1'].write_bytes(saved)
    bad=copy.deepcopy(original);bad['authority_directory']=str(lab.startups['b1']['authority'])
    lab.update_config('a1',bad);lab.reject(codes=('startup_transport',))
    lab.update_config('a1',original);lab.continued('after-substitution')
    pending=lab.install('a2',apply=False)
    wrong=copy.deepcopy(pending['config']['manifest']);wrong['roots']['business_key']=lab.authority({'op':'public_key','seed':secrets.token_hex(32)})['public_key']
    signed=lab.sign_approval(pending,'install',wrong)
    lab.authority({'op':'apply','directory':str(pending['authority']),'approval':signed})
    pending['config']['manifest']=wrong;lab.update_config('a2',pending['config'])
    lab.reject('a2',operation='inspect',codes=('startup_root_binding',))

def disable(lab,s):
    proof=lab.sign_approval(s,'disable')
    lab.authority({'op':'apply','directory':str(s['authority']),'approval':proof})
    return proof

def b03(lab):
    lab.setup();s=lab.startups['a1'];backup=lab.backup('device',lab.directory/'a1') if hasattr(lab,'backup') else lab.directory/'device-backup'
    if not backup.exists():shutil.copytree(lab.directory/'a1',backup)
    oldconfig=s['path'].read_bytes();disable(lab,s)
    shutil.rmtree(lab.directory/'a1');shutil.copytree(backup,lab.directory/'a1');s['path'].write_bytes(oldconfig)
    lab.reject(codes=('startup_disabled',))
    lab.authority({'op':'init','directory':str(s['authority']),'slot':s['manifest']['slot'],
                   'approval_key':s['config']['authority_key'],'response_seed':secrets.token_hex(32)},1)
    lab.reject(codes=('startup_disabled',))

def b04(lab):
    lab.setup();s=lab.startups['a1']
    directory=lab.directory/'next';directory.mkdir(mode=0o700)
    other=StartupLab(lab.binary,directory,lab.permission_verifier,lab.receipt_signer,lab.helper,startup_helper=lab.startup_helper)
    try:
        other.initialize();other.group();m=other.prepare('a1',slot=s['manifest']['slot'],generation='2')
        proof=lab.sign_approval(s,'rotate',m)
        lab.authority({'op':'apply','directory':str(s['authority']),'approval':proof})
        lab.reject(codes=('startup_stale',))
        new=copy.deepcopy(s);new['manifest']=m;new['config']=s['config']|{'manifest':m};new['path']=other.directory/'startup-config.json'
        other.write_private(new['path'],new['config']);other.startups['a1']=new;other.install('b1')
        other.continued('rotated-new-identity')
        retired=copy.deepcopy(s['manifest']);retired['generation']='3'
        e=other.authority({'op':'apply','directory':str(s['authority']),
                          'approval':other.sign_approval(new,'rotate',retired)},1)
        check(e['code']=='startup_retired','旧scope被复活')
        other.continued('retired-refused');lab.reject(codes=('startup_stale',))
        lab.case_evidence['successor']=other.case_evidence
    finally:other.close()

def b05(lab):
    lab.setup();s=lab.startups['a1'];proof=disable(lab,s)
    lab.reject(codes=('startup_disabled',));lab.restart();lab.reject(codes=('startup_disabled',))
    lab.authority({'op':'apply','directory':str(s['authority']),'approval':proof})
    for proof in (s['install_approval'],lab.sign_approval(s,'rotate',s['manifest'])):
        e=lab.authority({'op':'apply','directory':str(s['authority']),'approval':proof},1)
        check(e['code']=='startup_disabled','停用后重新启用')
    lab.reject(codes=('startup_disabled',))

def b06(lab):
    lab.setup();s=lab.startups['a1'];config=copy.deepcopy(s['config'])
    old=lab.authority({'op':'check','directory':str(s['authority']),'slot':s['manifest']['slot'],'challenge':secrets.token_hex(32)})
    wrapper=s['path'].parent/'replay';wrapper.write_text('#!/usr/bin/env python3\nimport json,sys\njson.load(sys.stdin)\nprint('+repr(json.dumps(old))+')\n');wrapper.chmod(0o700)
    # 固定根仍是真钥；仅在控制器明确替换传输的故障装置里重放旧签名响应。
    config['helper_path']=str(wrapper);lab.update_config('a1',config)
    lab.reject(codes=('startup_response',),env={'RIM_TRUSTED_STARTUP_HELPER':str(wrapper)})
    tampered=copy.deepcopy(old);sig=bytearray(base64.b64decode(tampered['response']['signature_bytes']));sig[0]^=1
    tampered['response']['signature_bytes']=base64.b64encode(sig).decode()
    wrapper.write_text('#!/usr/bin/env python3\nimport json,sys\njson.load(sys.stdin)\nprint('+repr(json.dumps(tampered))+')\n');wrapper.chmod(0o700)
    lab.reject(codes=('permission_signature',),env={'RIM_TRUSTED_STARTUP_HELPER':str(wrapper)})
    config['helper_path']='/private/tmp/missing-startup-'+secrets.token_hex(8);lab.update_config('a1',config)
    lab.reject(codes=('anchor_unavailable',),env={'RIM_TRUSTED_STARTUP_HELPER':config['helper_path']})
    lab.update_config('a1',s['config']);lab.continued('after-transport-failures')

def b07(lab, mode='pause'):
    from .recovery_capacity_cases import fixture
    lab.group();fixture(lab,'a1',mode);lab.install('a1');lab.install('b1')
    lab.reject(codes=('consistency_paused',))
    lab.reject(operation='identity_source',command={'kind':'configure','roots':lab.roots},codes=('consistency_paused',))
    lab.restart();lab.reject(codes=('consistency_paused',))
    lab.case_evidence['pause_precondition']='explicit probe '+mode+'; only tests startup composition, not evidence formation'

def b07_rollback(lab):
    lab.setup();backup=lab.directory/'old-device';shutil.copytree(lab.directory/'a1',backup)
    lab.continued('advance-after-backup')
    shutil.rmtree(lab.directory/'a1');shutil.copytree(backup,lab.directory/'a1')
    lab.reject(codes=('anchor_conflict',));lab.reject(codes=('anchor_paused',))
    lab.restart();lab.reject(codes=('anchor_paused',))

def b08(lab):
    lab.group();s=lab.install(apply=False)
    before=sha(s['authority']/'state.enc')
    for point,exitcode in [('before_save',86),('before_rename',87)]:
        lab.authority({'op':'apply','directory':str(s['authority']),'approval':s['install_approval'],'failpoint':point},exitcode)
        check(sha(s['authority']/'state.enc')==before,'提交前中断改变旧配置');lab.reject(codes=('startup_stale',))
    lab.authority({'op':'apply','directory':str(s['authority']),'approval':s['install_approval'],'failpoint':'after_save'},88)
    lab.authority({'op':'apply','directory':str(s['authority']),'approval':s['install_approval']})
    s['manifest']=s['config']['manifest'];lab.install('b1');lab.continued('after-exits')
    proof=lab.sign_approval(s,'disable')
    request={'op':'apply','directory':str(s['authority']),'approval':proof}
    # 两个真实竞争进程：busy可精确重试，最终同一停用事实只推进一次。
    def invoke(_):return subprocess.run([str(lab.startup_helper)],input=json.dumps(request),text=True,capture_output=True,timeout=12)
    with ThreadPoolExecutor(2) as pool: results=list(pool.map(invoke,range(2)))
    check(any(p.returncode==0 for p in results),'竞争没有成功提交')
    for p in results:
        value=json.loads(p.stdout);check(p.returncode==0 or value['error']['code']=='startup_busy','竞争出现未知错误')
    result=lab.authority(request);check(result['generation']=='2','精确重试多次推进代次');lab.reject(codes=('startup_disabled',))
    race=lab.directory/'cas-race-authority'
    pending=copy.deepcopy(s);pending['manifest']=None
    pub=lab.authority({'op':'public_key','seed':s['approval_seed']})['public_key']
    lab.authority({'op':'init','directory':str(race),'slot':s['manifest']['slot'],'approval_key':pub,'response_seed':secrets.token_hex(32)})
    candidates=[s['manifest'],lab.prepare('b1',slot=s['manifest']['slot'])]
    requests=[{'op':'apply','directory':str(race),'approval':lab.sign_approval(pending,'install',m)} for m in candidates]
    def compete(req):return subprocess.run([str(lab.startup_helper)],input=json.dumps(req),text=True,capture_output=True,timeout=12)
    with ThreadPoolExecutor(2) as pool:results=list(pool.map(compete,requests))
    check(sum(p.returncode==0 for p in results)==1,'异配置CAS有多个/零成功者')
    winner=next(i for i,p in enumerate(results) if p.returncode==0)
    lab.authority(requests[winner])
    error=lab.authority(requests[1-winner],1);check(error['code']=='startup_cas','CAS败者没有保持拒绝')
    result=lab.authority({'op':'check','directory':str(race),'slot':s['manifest']['slot'],'challenge':secrets.token_hex(32)})
    current=json.loads(base64.b64decode(result['response']['statement_bytes']))
    check(current['generation']=='1' and current['manifest_sha256']==lab.manifest_hash(candidates[winner]),'CAS保存不是准确胜者')

def b09(lab):
    lab.setup();s=lab.startups['a1'];config=copy.deepcopy(s['config']);config['protocol_version']='rim-startup-client-0'
    lab.update_config('a1',config);lab.reject(codes=('startup_config',))
    lab.update_config('a1',s['config'])
    m=copy.deepcopy(s['manifest']);m['generation']='9';proof=lab.sign_approval(s,'rotate',m)
    e=lab.authority({'op':'apply','directory':str(s['authority']),'approval':proof},1)
    check(e['code']=='startup_generation','跳代未拒绝');lab.continued('compatibility')
    lab.case_evidence['capacity']='64 retired manifests saturation and disable reserve verified by Rust automated test; not natural multi-device lifetime throughput'

def b10(lab):
    lab.setup();s=lab.startups['a1'];backup=lab.directory/'authority-backup';shutil.copytree(s['authority'],backup)
    backups=[]
    for device in ('a1','b1'):
        for label,path in [('device',lab.directory/device),('anchor',lab.materials[device]['authority'])]:
            target=lab.directory/(device+'-'+label+'-backup');shutil.copytree(path,target);backups.append((target,path))
        path=lab.startups[device]['path'];backups.append((path.read_bytes(),path))
    lab.continued('advance-before-common-rollback')
    disable(lab,s);lab.reject(codes=('startup_disabled',))
    shutil.rmtree(s['authority']);shutil.copytree(backup,s['authority'])
    for source,path in backups:
        if isinstance(source,bytes):path.write_bytes(source)
        else:shutil.rmtree(path);shutil.copytree(source,path)
    # 双端设备/锚及可信配置同时恢复，隐藏已提交的停用，明确不算攻击防护通过。
    lab.continued('common-rollback')
    lab.case_evidence['negative_control']='EXPECTED_UNDETECTABLE: controller restored startup authority, both devices/anchors and trusted configs together'

CASES=[('B01',b01),('B02',b02),('B03',b03),('B04',b04),('B05',b05),('B06',b06),('B07',b07),('B07_fork',lambda lab:b07(lab,'startup_fork_pause')),('B07_rollback',b07_rollback),('B08',b08),('B09',b09),('B10',b10)]
