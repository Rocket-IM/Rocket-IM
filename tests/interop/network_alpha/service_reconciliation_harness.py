"""真实alpha.5异常退出对账；仅通过维护CLI重开，不修改客户端库或门禁。"""
from pathlib import Path
import json
import subprocess
from service_backup_harness import ServiceBackupLab,digest
from harness import require,PG

class ServiceReconciliationLab(ServiceBackupLab):
    def start_service(self):
        if not getattr(self,'evidence_enabled',True):
            return super().start_service()
        config=json.loads(self.config.read_text())
        if 'recovery_state' not in config:
            folder=self.root/'maintenance';folder.mkdir(mode=0o700)
            config['recovery_state']=str(folder/'head.json')
            self.config.write_text(json.dumps(config));self.config.chmod(0o600)
            self.maintenance('enroll');self.maintenance('enable-reconciliation')
        super().start_service()
    def build(self,proxy=True):
        super().build(proxy)
        self.report['public_runtime']+=' with explicit reconciliation'
    def crash(self,label):
        require(self.service and self.service.poll() is None,'live real Service before SIGKILL')
        pid=self.service.pid;self.service.kill();code=self.service.wait(timeout=10)
        require(code==-9,'actual Service SIGKILL')
        state=json.loads(self.head.read_text())
        require(state['phase']=='running','SIGKILL retains running gate')
        self.report.setdefault('service_sigkills',[]).append({'label':label,'pid':pid,'returncode':code,'run_id':state['evidence']['run_id'],'pending':state['evidence'].get('pending') is not None})
        self.save()
    def restart_service(self):
        self.crash('active-restart');self.maintenance('reconcile');self.start_service()
    def cycle(self,label,reconnect=True,reopen=True):
        self.offline();before=self.database_snapshot();states=[self.snapshot(i) for i in range(2)]
        first=[w.call('history',query={'direction':'forward','page_size':1}) for w in self.workers]
        self.crash(label)
        self.maintenance('serve',expected='service_reconciliation_required')
        self.maintenance('backup',self.root/(label+'-unsealed.rimservice'),expected='service_reconciliation_required')
        receipt=self.maintenance('reconcile')
        require(self.maintenance('reconcile')==receipt,'idempotent complete reconciliation')
        require(self.database_snapshot()==before,'all twelve Service tables exact across reconciliation')
        backup=self.export_service('reconciled-'+label)
        for i in range(2):
            if reopen:self.workers[i].close();self.restore(i)
            after=self.snapshot(i)
            require(after['state']==states[i]['state'] and after['history']==states[i]['history'],'original SDK identity and complete history')
            for key in ('downloaded','processed','reported','sending','unavailable_history'):
                require(after['network'][key]==states[i]['network'][key],'SDK durable '+key)
            require(self.pages(i,first[i])==states[i]['history'],'stable history upper and pagination')
        self.report.setdefault('reconciled_checkpoints',[]).append({'label':label,'receipt':receipt,'tables':{key:{'count':len(value),'sha256':digest(value)} for key,value in before.items()},'sdk_cursors':[{k:state['network'][k] for k in ('downloaded','processed','reported')} for state in states]})
        self.start_service()
        if reconnect:
            for i in range(2):self.auto(i);self.online(i)
        return backup
    def controlled_restore(self,label):
        return ServiceBackupLab.cycle(self,label)
    def install_database_fixture(self,data):
        # 仅离线负例构造：将已保存的合成Service行恢复到同一目标，不改可信记录。
        # 绝不接触客户端SQLite；生产维护入口不接受此SQL。
        require(self.service.poll() is not None,'fixture mutation requires stopped Service')
        statements=['BEGIN']
        statements += [f'DELETE FROM {self.schema}.{name}' for name in reversed(data)]
        for name,rows in data.items():
            raw=json.dumps(rows);require('$fixture$' not in raw,'controlled SQL delimiter')
            statements.append(f'INSERT INTO {self.schema}.{name} SELECT * FROM jsonb_populate_recordset(NULL::{self.schema}.{name},$fixture${raw}$fixture$::jsonb)')
        statements.append('COMMIT')
        p=subprocess.run([PG/'psql','-h',Path(self.env['directory'])/'socket','-U','alpha','-d',self.database,'-Aqt','-v','ON_ERROR_STOP=1'],input=';'.join(statements),text=True,capture_output=True,timeout=30)
        require(p.returncode==0,'controlled isolated database fixture install')
