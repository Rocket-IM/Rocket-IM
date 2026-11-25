#!/usr/bin/env python3
"""共同签名的真实 dev.7→dev.8，或升级后新恢复阶段的同版本搬迁续接。"""
import argparse
import json
import traceback
from upgrade_harness import UpgradeLab
from harness import require
import upgrade_cases

p=argparse.ArgumentParser();p.add_argument('--task',required=True);p.add_argument('--environment',required=True)
p.add_argument('--run',required=True);p.add_argument('--suite',choices=['ordinary','unknown','faults','renewal','lifecycle'],required=True)
a=p.parse_args();lab=UpgradeLab(a.task,a.environment,a.run,relocate=a.suite=='faults')
try:
    lab.build(proxy=True)
    if a.suite in ('ordinary','unknown'):getattr(upgrade_cases,a.suite)(lab)
    else:
        lab.case('actual_dev7_history_before_upgrade',lab.initial)
        for w in lab.workers:w.call('disconnect')
        lab.both()
        require([w.call('state')['identity'] for w in lab.workers]==lab.original_identities,'original signed identity')
        for i in range(2):require(lab.history(i)==lab.original_history[i],'original histories unchanged')
        if a.suite=='faults':
            from recovery_faults import run
            run(lab)
        elif a.suite=='lifecycle':
            from recovery_lifecycle import run
            lab.case('original_upgraded_private_state_protection',lab.audit_original_storage)
            run(lab)
        else:
            from renewal_cases import run
            run(lab)
    if a.suite!='lifecycle':lab.case('original_upgraded_private_state_protection',lab.audit_original_storage)
    require(lab.sources()==lab.report['source_before'],'source changed during acceptance')
    lab.report['status']='PASS_SCOPED'
except Exception as e:lab.report.update(status='FAIL',error=str(e),trace=traceback.format_exc())
finally:lab.close();lab.save()
print(json.dumps({'status':lab.report['status'],'error':lab.report.get('error'),'report':str(lab.run/'network-report.json')},ensure_ascii=False),flush=True)
raise SystemExit(0 if lab.report['status']=='PASS_SCOPED' else 1)
