"""真实dev.10/alpha.5原件升级，未配置权限保持原配置摘要，旧备份由新产物读取。"""
from pathlib import Path
import json
from capacity_cases import start
from diagnostics_cases import observe, secret_samples
from harness import Worker, require, sha
from rejection_upgrade import install, acls


def run(lab, new_client):
    old = lab.release
    lab.case('actual_dev10_alpha5_e2ee',lambda:start(lab))
    lab.fill(8,'old-e2ee');lab.offline()
    lab.case('old_live_credential_samples',lambda:secret_samples(lab))
    backup,_ = lab.export(0,'actual-dev10-guarded')
    # 设备0已建立备份guard，设备1保持旧未备份格式；均不由测试代码开库。
    before = [lab.snapshot(i) for i in range(2)]
    access = acls(lab)
    history_pages = [w.call('history',query={'direction':'forward','page_size':1}) for w in lab.workers]
    config = json.loads(lab.config.read_text())
    require(all('capacity_read' not in p for p in config['business']['principals']), 'old configuration permission omitted')
    lab.stop_service()
    service_before = lab.database_snapshot()
    service_backup = lab.export_service('actual-alpha5')
    lab.install_new_service()
    lab.import_service(service_backup)
    require(lab.database_snapshot() == service_before, 'old complete backup restored exactly by alpha.6')
    lab.start_service()
    lab.report['old_backup_read'] = {'client_sha256':sha(backup),'service_sha256':sha(service_backup),'old_service_version':'0.1.0-alpha.5'}
    for i in range(2):
        previous = lab.workers[i]
        previous.close()
        checksum = sha(Path(previous.options['path']))
        directory = install(lab,new_client,'diagnostic-upgrade-'+str(i))
        lab.workers[i] = Worker(directory,previous.options)
        lab.setup(i);lab.instrument(lab.workers[i],i);lab.track()
        require(sha(Path(previous.options['path'])) == checksum, 'valid old database not rewritten by new open')
        require(lab.snapshot(i) == before[i], 'original identities history and cursors survived')
        require(lab.pages(i,history_pages[i]) == before[i]['history'], 'old history cursor valid')
    lab.release = new_client
    require(acls(lab) == access, 'original dedicated keychain ACL unchanged')
    lab.consumer().call('capacity',{},code='forbidden')
    lab.case('upgraded_device_scope_without_new_global_permission',lambda:observe(lab,'old-config-new-runtime',global_scope=False))
    lab.case('old_sdk_backup_read_by_new_package',lambda:lab.roundtrip(0,backup))
    lab.case('old_sdk_backup_diagnostic_preserves_original',lambda:observe(lab,'old-client-backup',global_scope=False))
    # 只读新增接口没有升级持久格式，旧包仍读取同一原库；未解锁前项钥匙串。
    for i in range(2):
        current = lab.workers[i];current.close()
        checksum = sha(Path(current.options['path']))
        directory = install(lab,old,'dev10-readback-'+str(i))
        prior = Worker(directory,current.options)
        try:require(prior.call('state') == before[i]['state'], 'old public SDK still reads unchanged format')
        finally:prior.close()
        require(sha(Path(current.options['path'])) == checksum, 'old readback preserves original bytes')
        lab.restore(i)
    require(acls(lab) == access, 'ACL unchanged through old backup and readback')
    lab.case('upgrade_real_secret_samples',lambda:secret_samples(lab))
    lab.report['upgrade_compatibility'] = {'client':'dev.10 → dev.11 → dev.10 readback','service':'alpha.5 backup → alpha.6','permission':'omitted; ordinary business remains forbidden','database_format_changed':False,'old_originals_untouched':True}
