"""可信启动隔离装置：批准私钥只留控制器，运行端仅固定公钥与独立权威位置。"""
import copy
import hashlib
import json
import secrets
import subprocess
from pathlib import Path
from .identity_source_fixture import IdentitySourceLab
from .fixture import check

def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()

class StartupLab(IdentitySourceLab):
    def __init__(self, *args, startup_helper, **kwargs):
        super().__init__(*args, **kwargs)
        self.startup_helper = Path(startup_helper)
        self.startups = {}

    def environment(self, device, additions=None):
        env = super().environment(device)
        for k in list(env):
            if k.startswith('RIM_TRUSTED_STARTUP_'): env.pop(k)
        if device in self.startups:
            s = self.startups[device]
            env.update(RIM_TRUSTED_STARTUP_CONFIG=str(s['path']), RIM_TRUSTED_STARTUP_REQUIRED='1',
                       RIM_TRUSTED_STARTUP_KEY=s['config']['authority_key'],
                       RIM_TRUSTED_STARTUP_HELPER=str(self.startup_helper),
                       RIM_TRUSTED_STARTUP_AUTHORITY=str(s['authority']))
        return env | (additions or {})

    def authority(self, request, expected=0):
        p = subprocess.run([str(self.startup_helper)], input=json.dumps(request), text=True,
                           capture_output=True, timeout=12)
        self.process_count += 1
        check(p.returncode == expected, '启动权威错误: '+p.stdout[:500])
        if expected in (86,87,88):
            check(not p.stdout.strip(), '中断提前输出结果'); return None
        value = json.loads(p.stdout)
        check(value['ok'] == (expected == 0), '响应与退出码不符')
        self.case_evidence.setdefault('startup_rpc', []).append({'op':request['op'], 'exit':p.returncode,
            'request_sha256':hashlib.sha256(json.dumps(request,sort_keys=True).encode()).hexdigest(),
            'response':value})
        return value.get('result',value) if expected == 0 else value['error']

    def prepare(self, device='a1', slot=None, generation='1'):
        if device not in self.configs: self.enable(device)
        anchor = self.materials[device]['config']
        return {'protocol_version':'rim-startup-manifest-1', 'slot':slot or 'install-'+device,
                'generation':generation, 'roots':self.roots, 'scope':anchor['scope'],
                'anchor_public_key':anchor['anchor_public_key'],
                'anchor_config_sha256':sha(self.configs[device])}

    def sign_approval(self, s, action, manifest=None, previous=None, seed=None):
        old = previous or s['manifest']
        body = {'protocol_version':'rim-startup-approval-1', 'slot':s['config']['manifest']['slot'],
                'previous_generation':old['generation'] if old else '0',
                'previous_sha256':self.manifest_hash(old) if old else 'absent',
                'action':action, 'manifest':manifest}
        return self.authority({'op':'sign', 'approval':body, 'seed':seed or s['approval_seed']})['approval']

    @staticmethod
    def manifest_hash(m):
        # Rust manifest字段按上方插入顺序序列化；JSON紧凑UTF-8与协议固定序一致。
        return hashlib.sha256(json.dumps(m,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

    def install(self, device='a1', apply=True):
        manifest = self.prepare(device)
        seed = secrets.token_hex(32)
        pub = self.authority({'op':'public_key','seed':seed})['public_key']
        authority = self.directory/('startup-authority-'+device)
        response = self.authority({'op':'init','directory':str(authority),'slot':manifest['slot'],
                                  'approval_key':pub,'response_seed':secrets.token_hex(32)})
        trusted = self.directory/('startup-trusted-'+device); trusted.mkdir(mode=0o700)
        path = trusted/'config.json'
        config = {'protocol_version':'rim-startup-client-1','manifest':manifest,
                  'authority_key':response['public_key'],'helper_path':str(self.startup_helper),
                  'authority_directory':str(authority)}
        s = {'manifest':None,'config':config,'path':path,'authority':authority,'approval_seed':seed}
        approval = self.sign_approval(s,'install',manifest)
        if apply:
            self.authority({'op':'apply','directory':str(authority),'approval':approval})
            s['manifest'] = manifest
        s['install_approval'] = approval
        self.write_private(path,config); self.startups[device] = s
        return s

    def reject(self, device='a1', operation='send', codes=(), **fields):
        before = sha(self.snapshot(device))
        anchor = (self.materials[device]['authority']/'state.enc').read_bytes()
        if operation == 'send': fields = {'id':'must-block-'+secrets.token_hex(4),'payload':'blocked',**fields}
        error = self.rust(device, operation, expected_exit=1, **fields)
        check(not codes or error['code'] in codes, '意外错误: '+str(error))
        check(sha(self.snapshot(device)) == before, '拒绝改变设备快照')
        check((self.materials[device]['authority']/'state.enc').read_bytes() == anchor, '启动拒绝消耗锚预约')
        self.case_evidence.setdefault('rejections',[]).append(error['code']); return error

    def update_config(self, device, config): self.write_private(self.startups[device]['path'],config)

    def setup(self):
        self.group()
        self.install('a1'); self.install('b1')
        self.continued('trusted-startup')
