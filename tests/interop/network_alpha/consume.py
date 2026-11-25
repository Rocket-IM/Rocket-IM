#!/usr/bin/env python3
"""运行本机实际TGZ+Go Service消费；每次使用新schema/消费目录，保留失败记录。"""
import argparse
import json
from harness import Lab, require
from cases import run
p=argparse.ArgumentParser();p.add_argument('--release',required=True);p.add_argument('--environment',required=True);p.add_argument('--run',required=True);args=p.parse_args()
lab=Lab(args.release,args.environment,args.run)
try:
    lab.build();run(lab)
    require(lab.sources()==lab.report['source_before'],'sources changed during consumption')
    lab.report['status']='PASS_SCOPED'
except Exception as e:
    lab.report.update(status='FAIL',error=str(e))
finally:
    lab.close();lab.save()
print(json.dumps({'status':lab.report['status'],'error':lab.report.get('error'),'report':str(lab.run/'network-report.json')},ensure_ascii=False))
raise SystemExit(0 if lab.report['status']=='PASS_SCOPED' else 1)
