"""同签名dev.9原库升级；原件、ACL与旧格式门禁从真实独立安装验证。"""
from pathlib import Path
import json
import os
import shutil
import subprocess
from harness import Worker, require, wait, node_binary, npm_command, all_hashes, sha
from persistent_signing_acl import inspect
from rejection_cases import prepare_full, finish

def baseline(task, new):
    report=json.loads((new/'report.json').read_text());fingerprint=report['signing']['certificate_sha1']
    matches=[]
    for path in Path(task).glob('*-signer.json'):
        r=json.loads(path.read_text())
        if r.get('status')=='PASS_SCOPED' and r.get('certificate_sha1')==fingerprint and r.get('dev9'):
            matches.append(r['dev9'])
    require(len(matches)==1,'one exact same-signer verified dev9 baseline')
    old=Path(matches[0]['release']);r=json.loads((old/'report.json').read_text())
    require(r['archive_sha256']==matches[0]['archive_sha256']==sha(Path(r['archive'])),'verified dev9 archive')
    require(all_hashes(old/'package')==r['package_files'],'verified dev9 files')
    return old

def install(lab,release,label):
    report=json.loads((release/'report.json').read_text());archive=Path(report['archive'])
    require(sha(archive)==report['archive_sha256'],'upgrade archive unchanged')
    directory=lab.root/label;directory.mkdir();(directory/'path').mkdir();(directory/'path/node').symlink_to(node_binary())
    (directory/'package.json').write_text(json.dumps({'name':'rejection-upgrade','private':True,'type':'module'}))
    for name in ('network-worker.mjs','renewal-provider.mjs','upgrade-probe.mjs','backup-probe.mjs'):
        shutil.copy2(release/'source/tests/consumers/node-persistent'/name,directory/name)
    lab.command(npm_command()+['install','--offline','--ignore-scripts','--no-audit','--no-fund',archive],directory,label+'-install')
    files=all_hashes(directory/'node_modules/@rocket-im/desktop-dev');require(files==report['package_files'],'upgrade independently installed exact files')
    lab.report.setdefault('upgrade_installations',[]).append({'directory':str(directory),'archive_sha256':sha(archive),'files':files})
    return directory

def acls(lab):
    return [inspect(Path(w.options['keychain']),Path(w.options['path']),scope=w.options['scope']) for w in lab.workers]

def run(lab,new):
    old=lab.release;accepted,rejected=prepare_full(lab)
    lab.auto(1)
    state=wait(lambda:(s if (s:=lab.workers[1].call('network'))['connection']=='blocked' else False),'real dev9 blocked at original permanent refusal')
    require(state['error']['code']=='message_limit' and state['processed']=='254','exact dev9 predecessor limitation')
    lab.offline();before=[lab.snapshot(i) for i in range(2)];access=acls(lab)
    pages=[w.call('history',query={'direction':'forward','page_size':1}) for w in lab.workers]
    for i in range(2):
        prior=lab.workers[i];prior.close();digest=sha(Path(prior.options['path']))
        directory=install(lab,new,'upgrade-dev10-'+str(i))
        lab.workers[i]=Worker(directory,prior.options);lab.setup(i);lab.instrument(lab.workers[i],i);lab.track()
        require(sha(Path(prior.options['path']))==digest,'opening valid dev9 format does not rewrite')
        require(lab.snapshot(i)==before[i],'same original state/history/request projections before rejection migration')
        require(lab.pages(i,pages[i])==before[i]['history'],'dev9 history cursor survives version switch')
    require(acls(lab)==access,'upgrade never adds new binary to business ACL')
    lab.release=new
    lab.auto(0);lab.online(0)
    finish(lab,accepted,rejected)
    lab.offline()
    def old_gate():
        worker=lab.workers[1];worker.close();path=Path(worker.options['path']);before=sha(path)
        directory=install(lab,old,'old-dev9-format-gate');options=directory/'probe.json';options.write_text(json.dumps(worker.options));options.chmod(0o600)
        env={k:v for k,v in os.environ.items() if not k.startswith(('CARGO','RUST','ROCKET_IM_TEST_'))};env['PATH']=str(directory/'path')
        p=subprocess.run([node_binary(),'upgrade-probe.mjs',options],cwd=directory,env=env,capture_output=True,text=True,timeout=25)
        require(p.returncode==0 and not p.stderr,'old public probe exits cleanly')
        result=json.loads(p.stdout);require(result=={'ok':False,'code':'store_format_unsupported'},'old dev9 explicitly refuses v5')
        require(sha(path)==before,'old rejected open preserves database bytes')
        lab.restore(1);require(acls(lab)==access,'same original ACL after all recovery and old gate')
        lab.report['dev9_to_dev10']={'old':str(old),'new':str(new),'old_format_gate':result,'public_acl_unchanged':True,'identities_unchanged':True}
    lab.case('real_dev9_cannot_read_new_terminal_format',old_gate)
