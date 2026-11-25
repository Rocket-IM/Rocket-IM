#!/usr/bin/env python3
"""真实新Release自动续期验收入口，保留逐轮失败与来源，不发布。"""
import argparse
import json
import traceback
from renewal_harness import RenewalLab
from renewal_cases import run
from renewal_lifecycle import run as lifecycle
from harness import require

p=argparse.ArgumentParser();p.add_argument('--release',required=True);p.add_argument('--environment',required=True);p.add_argument('--run',required=True);p.add_argument('--proxy',action='store_true');args=p.parse_args()
lab=RenewalLab(args.release,args.environment,args.run)
try:
    lab.build(proxy=args.proxy);run(lab);lifecycle(lab)
    require(lab.sources()==lab.report['source_before'],'source changed during acceptance')
    lab.report['status']='PASS_SCOPED'
except Exception as e:lab.report.update(status='FAIL',error=str(e),trace=traceback.format_exc())
finally:
    lab.close();lab.save()
print(json.dumps({'status':lab.report['status'],'error':lab.report.get('error'),'report':str(lab.run/'network-report.json')},ensure_ascii=False))
raise SystemExit(0 if lab.report['status']=='PASS_SCOPED' else 1)
