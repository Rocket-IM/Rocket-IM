#!/usr/bin/env python3
"""真实新TGZ联网恢复验收；每轮独立业务/设备/数据库，保留失败原件。"""
import argparse,json,traceback
from recovery_harness import RecoveryLab
from recovery_cases import run
from harness import require
p=argparse.ArgumentParser();p.add_argument('--release',required=True);p.add_argument('--environment',required=True);p.add_argument('--run',required=True);p.add_argument('--proxy',action='store_true');p.add_argument('--suite',choices=['core','faults','boundaries','lifecycle'],default='core');args=p.parse_args()
lab=RecoveryLab(args.release,args.environment,args.run)
try:
    lab.build(proxy=args.proxy)
    if args.suite=='faults':
        from recovery_faults import run as faults
        faults(lab)
    elif args.suite=='boundaries':
        from recovery_boundaries import run as boundaries
        require(args.proxy,'boundary suite needs actual transport proxy');boundaries(lab)
    elif args.suite=='lifecycle':
        from recovery_lifecycle import run as lifecycle
        require(args.proxy,'lifecycle suite needs actual transport proxy');lifecycle(lab)
    else:run(lab)
    require(lab.sources()==lab.report['source_before'],'source changed during acceptance')
    lab.report['status']='PASS_SCOPED'
except Exception as e:lab.report.update(status='FAIL',error=str(e),trace=traceback.format_exc())
finally:lab.close();lab.save()
print(json.dumps({'status':lab.report['status'],'error':lab.report.get('error'),'report':str(lab.run/'network-report.json')},ensure_ascii=False))
raise SystemExit(0 if lab.report['status']=='PASS_SCOPED' else 1)
