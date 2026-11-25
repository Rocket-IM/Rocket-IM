"""实际旧新 TGZ 切换安装目录，原规范数据路径和系统项始终不变。"""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
from recovery_harness import RecoveryLab
from harness import Worker, require, wait, node_binary, npm_command, all_hashes, sha
from persistent_signing_acl import inspect


class UpgradeLab(RecoveryLab):
    def __init__(self, task, environment, run, relocate=False):
        self.task=Path(task);self.prepared=json.loads((self.task/'package-preparation.json').read_text())
        require(self.prepared['status']=='PASS_SCOPED','verified signed copies')
        self.install_serial=0;self.versions=['old','old'];self.relocate=relocate
        super().__init__(self.task/'packages/old',environment,run)
        for name,digest in self.report['source_before'].items():
            source=Path(__file__).resolve().parents[3]/name
            require(sha(source)==digest,'freeze acceptance input')
            target=self.run/'executed-inputs'/name;target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(source,target)

    def build(self,proxy=True):
        super().build(proxy=proxy)
        # 新验收命令由同一个公开 API 消费器发出；仍加载原封 dev.7 安装树。
        for i,worker in enumerate(self.workers):
            worker.close()
            for name in ('network-worker.mjs','renewal-provider.mjs'):
                shutil.copy2(self.scripts()/name,worker.directory/name)
            self.workers[i]=Worker(worker.directory,worker.options);self.setup(i)
        self.acls=self.inspect_acls()
        self.report['original_scopes']=[w.options['scope'] for w in self.workers]
        self.report['original_acls']=self.acls
        self.report['versions']={k:v['sha256'] for k,v in self.prepared['packages'].items()}

    def scripts(self):return self.task/'inputs/tests/consumers/node-persistent'

    def initial(self):
        if not hasattr(self,'original_identities'):
            return super().initial()
        # 组合回归已由旧包建立起点；保留原随机正文和请求，不用同号新正文重建。
        for i in range(2):self.auto(i);self.online(i)
        require([w.call('state')['identity'] for w in self.workers]==self.original_identities,'upgraded original identities')
        for i in range(2):
            require(self.history(i)[:len(self.original_history[i])]==self.original_history[i],'upgraded original history prefix')

    def install(self,label):
        self.install_serial+=1
        directory=self.root/('installation-'+str(self.install_serial)+'-'+label)
        directory.mkdir();(directory/'path').mkdir();(directory/'path/node').symlink_to(node_binary())
        (directory/'package.json').write_text(json.dumps({'name':'upgrade-consumer','private':True,'type':'module'}))
        for name in ('network-worker.mjs','renewal-provider.mjs','upgrade-probe.mjs'):
            shutil.copy2(self.scripts()/name,directory/name)
        package=self.prepared['packages'][label]
        require(sha(Path(package['archive']))==package['sha256'],'signed archive unchanged')
        self.command(npm_command()+['install','--offline','--ignore-scripts','--no-audit','--no-fund',package['archive']],directory,'install-'+str(self.install_serial))
        require(all_hashes(directory/'node_modules/@rocket-im/desktop-dev')==all_hashes(Path(package['release'])/'package'),'actual install bytes')
        return directory

    def inspect_acls(self):
        return [inspect(Path(w.options['keychain']),Path(w.options['path']),scope=w.options['scope']) for w in self.workers]

    def switch(self,index,label='new'):
        old=self.workers[index];old.close()
        before=sha(Path(old.options['path']))
        directory=self.install(label)
        current=Worker(directory,old.options);self.workers[index]=current;self.setup(index)
        require(sha(Path(current.options['path']))==before,'open must not rewrite old data')
        require(self.inspect_acls()==self.acls,'upgrade preserves original public ACL')
        self.versions[index]=label
        self.release=self.task/'packages'/('new' if self.versions==['new','new'] else 'old')
        self.report.setdefault('switches',[]).append({'index':index,'version':label,'installation':str(directory),
            'data_path':current.options['path'],'unchanged_database_sha256':before,'pid':current.pid})
        return current

    def restore(self,index):
        if self.relocate and self.versions[index]=='new':return self.switch(index)
        return super().restore(index)

    def both(self,label='new'):
        for i in range(2):self.switch(i,label)

    def probe(self,index,label,expected=None,directory=None,check_acl=True):
        directory=directory or self.install(label)
        shutil.copy2(self.scripts()/'upgrade-probe.mjs',directory/'upgrade-probe.mjs')
        options={**self.workers[index].options,'create':False};path=directory/'probe-options.json'
        path.write_text(json.dumps(options));path.chmod(0o600)
        before=sha(Path(options['path']));acls=self.inspect_acls() if check_acl else None
        env={k:v for k,v in os.environ.items() if not k.startswith(('CARGO','RUST','ROCKET_IM_TEST_'))};env['PATH']=str(directory/'path')
        p=subprocess.run([node_binary(),'upgrade-probe.mjs',path],cwd=directory,env=env,capture_output=True,text=True,timeout=25)
        require(p.returncode==0 and not p.stderr,'independent probe exit')
        reply=json.loads(p.stdout)
        require(reply.get('ok') if expected is None else not reply.get('ok') and reply.get('code') in expected,'probe '+label+': '+str(reply))
        require(sha(Path(options['path']))==before,'probe cannot alter data')
        if check_acl:require(self.inspect_acls()==acls,'probe cannot alter public ACL')
        self.report.setdefault('gates',[]).append({'version':label,'result':reply,'unchanged_database_sha256':before})
        return reply

    def stable_pages(self,index,first):
        items=list(first['items']);page=first
        while not page['done']:
            page=self.workers[index].call('history',query={'direction':'forward','page_size':1,'cursor':page['next_cursor']})
            require(page['upper_bound']==first['upper_bound'],'old snapshot upper unchanged')
            items+=page['items']
        return items

    def aligned(self):
        for i in range(2):
            wait(lambda:(s:=self.workers[i].call('network'))['downloaded']==s['processed']==s['reported'],'contiguous cursors '+str(i))

    def record(self,label):
        self.report.setdefault('continuity',[]).append({'label':label,'identities':[w.call('state')['identity'] for w in self.workers],
            'histories':[hashlib.sha256(json.dumps(self.history(i),sort_keys=True).encode()).hexdigest() for i in range(2)],
            'cursors':[{k:w.call('network')[k] for k in ('downloaded','processed','reported')} for w in self.workers]})

    def audit_original_storage(self):
        from commit_faults import FaultRuntime
        for i in range(2):
            self.workers[i].call('disconnect');before=sha(Path(self.workers[i].options['path']))
            fault=FaultRuntime(self,i,'audit_only',connect=False)
            try:
                # 多轮恢复档案的逐样本全文件扫描不属于普通SDK命令时限。
                result=fault.call({'op':'audit_protection'},timeout=180)
                require(result['sample_count']>20 and all(x['matches']==0 for x in result['files']),'private key and crypto state samples absent from encrypted storage')
                self.report.setdefault('private_state_audits',[]).append(result)
            finally:fault.close()
            require(sha(Path(self.workers[i].options['path']))==before,'read-only secret audit leaves original data unchanged')
            self.restore(i)

    def close(self):
        try:
            if hasattr(self,'acls'):
                # logout 回归有意销毁 A 的系统项，故在其执行前完成 ACL 核验。
                self.report['preserved_data_paths']=[w.options['path'] for w in self.workers]
        finally:super().close()
