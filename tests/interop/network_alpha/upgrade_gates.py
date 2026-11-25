"""系统签名门禁和装配门禁分开验证；不增加业务 ACL 应用。"""
import os
import shutil
from harness import require, wait, persistent_keychain
from persistent_signing_packages import RELATIVE, manifest


def run(lab):
    for w in lab.workers:w.call('disconnect')
    for label in ('other-signer','other-id','adhoc'):
        lab.probe(0,label,{'keychain_auth_failed','keychain_interaction_denied'})
    for label,errors in [('stale-hash',{'artifact_hash_mismatch'}),('wrong-version',{'artifact_version_mismatch'}),
                         ('tampered',{'process_exit_unknown','process_start_failed'})]:
        lab.probe(0,label,errors)
    # 相同安装路径原子替换程序；摘要同步重算，须由 OS 拒绝访问旧业务项。
    original=lab.workers[0];original.close();package=original.directory/'node_modules/@rocket-im/desktop-dev'
    binary=package/RELATIVE;raw=binary.read_bytes();artifact=(package/'artifact.json').read_bytes()
    try:
        replacement=binary.with_name('replacement')
        shutil.copy2(lab.task/'packages/other-signer/package'/RELATIVE,replacement);os.replace(replacement,binary);manifest(package)
        lab.probe(0,'other-signer',{'keychain_auth_failed','keychain_interaction_denied'},original.directory)
    finally:
        replacement=binary.with_name('restore');replacement.write_bytes(raw);replacement.chmod(0o755);os.replace(replacement,binary)
        (package/'artifact.json').write_bytes(artifact)
    lab.restore(0)
    require(lab.inspect_acls()==lab.acls,'original ACL unchanged after same-path substitution')
    # 老包的 networkRecovery 方法确实不存在，绝不把新版能力投射给旧版。
    require(lab.probe(0,'old')['networkRecovery'] is False,'dev7 has no networkRecovery')


def old_reader(lab,index=0):
    lab.workers[index].call('disconnect')
    lab.probe(index,'old',{'store_invalid'})
    require(lab.inspect_acls()==lab.acls,'incompatible old reader cannot rewrite public ACL')


def locked_upgrade(lab):
    a=lab.workers[0];a.call('disconnect');before=a.call('state');history=lab.history(0)
    a.call('authFault',mode='hang',count=1);lab.auto(0,timeout=30000)
    wait(lambda:lab.stats(0)['active']==1,'pending authentication before original keychain lock')
    path=a.options['keychain'];password=lab.keychain_passwords[0]
    try:
        require(persistent_keychain.run({'op':'lock','keychain':path})['status']==0,'lock original dev7-created keychain')
        wait(lambda:lab.stats(0)['active']==0,'storage denial cancels credential callback')
        require(lab.stats(0)['aborted']==1,'locked original storage explicit auth cancellation')
        # 系统锁定时公开 ACL 本身也拒读；在解锁后与锁定前原件核对。
        lab.probe(0,'new',{'keychain_locked'},check_acl=False)
    finally:
        require(persistent_keychain.run({'op':'unlock','keychain':path,'password':password})['status']==0,'unlock only known newly created original item')
    require(a.call('state')==before and lab.history(0)==history,'unlock keeps original identity and history exact')
    require(a.call('network')['connection']=='offline','locked owner cannot reconnect by late result')
    require(lab.inspect_acls()==lab.acls,'lock does not edit ACL')
    lab.auto(0);lab.online(0)
