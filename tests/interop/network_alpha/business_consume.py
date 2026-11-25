#!/usr/bin/env python3
"""运行实际Go模块及Node包的业务接入验收，独立目录保留每次失败与来源。"""
import argparse
import json
import traceback
from business_harness import BusinessLab
from business_cases import run
from harness import require

p=argparse.ArgumentParser();p.add_argument('--release',required=True);p.add_argument('--environment',required=True);p.add_argument('--run',required=True);args=p.parse_args()
lab=BusinessLab(args.release,args.environment,args.run)
try:
    lab.build();run(lab)
    require(lab.sources()==lab.report['source_before'],'source changed during acceptance')
    lab.report['status']='PASS_SCOPED'
except Exception as e:
    lab.report.update(status='FAIL',error=str(e),trace=traceback.format_exc())
finally:
    lab.close();lab.save()
print(json.dumps({'status':lab.report['status'],'error':lab.report.get('error'),'report':str(lab.run/'network-report.json')},ensure_ascii=False))
raise SystemExit(0 if lab.report['status']=='PASS_SCOPED' else 1)
