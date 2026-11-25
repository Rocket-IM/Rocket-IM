#!/usr/bin/env python3
"""构建真实 TS 桌面 SQLite 包并执行独立 macOS 消费；逐轮保留失败与冻结来源。"""
import json
import platform
from pathlib import Path
import re
import sys
import uuid
from desktop_package import OUTPUT, build, sources, sha, all_hashes, node_binary, command
from desktop_cases import normal, isolation, lifecycle, lock_and_cancel
from desktop_faults import fault_case
from desktop_negatives import input_cases, package_cases, public_gate
from crypto_support import redact
from support import utc_now, write_json, require


def main():
    run = OUTPUT/'runs'/str(uuid.uuid4());run.mkdir(parents=True,mode=0o700)
    report = {'status':'RUNNING','started_at':utc_now(),'source_before':sources(),'commands':[],'cases':[],
              'runtime_matrix':{'macOS_arm64_Node':'NOT_TESTED','Windows':'NOT_TESTED'},
              'scope':'one persistent TypeScript endpoint; separate synthetic memory peer; stage0 POC',
              'not_tested':['Windows','persistent peer join','production secrets/rollback anchor',
                            'formal SDK integration or final desktop binding','physical power/disk failure',
                            'production capacity','Q05 and complete Stage 0'],
              'host':{'system':platform.system(),'release':platform.release(),'machine':platform.machine()}}
    write_json(run/'report.json',report)
    print(json.dumps({'run':str(run)}),flush=True)
    try:
        consumer,binary = build(run,report)
        peer_binary = run/'native_crypto'
        report['peer_binary_sha256'] = sha(peer_binary)
        counts = re.findall(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored', (run/'rust-tests.log').read_text())
        require(counts and all(s == 'ok' and f == '0' for s,_,f,_ in counts),'Rust 测试失败')
        report['rust_tests'] = {'passed':sum(int(p) for _,p,_,_ in counts), 'failed':0}
        command([node_binary(),'-p','JSON.stringify({node:process.version,platform:process.platform,arch:process.arch})'],consumer,run/'node-version.json')
        report['node'] = json.loads((run/'node-version.json').read_text())
        cases = [(name,lambda d,r,fn=fn:fn(consumer,peer_binary,d,r)) for name,fn in
                 [('normal_restart',normal),('scope_isolation',isolation),('lifecycle_events',lifecycle),('input_database_errors',input_cases)]]
        for mode in ('locked','cancel','timeout','killed'):
            cases.append((mode,lambda d,r,m=mode:lock_and_cancel(consumer,peer_binary,d,r,m)))
        for op in ('send','process','download'):
            for fault in ('after_sql','refuse_commit','before_commit','after_commit'):
                cases.append((op+'_'+fault,lambda d,r,o=op,f=fault:fault_case(consumer,peer_binary,d,r,o,f)))
        cases.extend([('package_negatives',lambda d,r:package_cases(consumer,d,report)),
                      ('public_gate',lambda d,r:public_gate(binary,d))])
        for name, action in cases:
            directory=run/name;directory.mkdir(mode=0o700)
            records=[];item={'name':name,'status':'RUNNING','started_at':utc_now()};report['cases'].append(item)
            write_json(run/'report.json',report)
            try: item.update(status='PASS_SCOPED',evidence=redact(action(directory,records)))
            except Exception as error: item.update(status='FAIL',error=f'{type(error).__name__}: {error}')
            finally:
                item['finished_at']=utc_now()
                write_json(directory/'case.json',item)
                (directory/'commands.jsonl').write_text(''.join(json.dumps(redact(r),ensure_ascii=False)+'\n' for r in records))
                item['records_sha256']=sha(directory/'commands.jsonl')
                write_json(run/'report.json',report)
                print(json.dumps({k:item[k] for k in ('name','status','error') if k in item}),flush=True)
        report['status']='PASS_SCOPED' if all(c['status']=='PASS_SCOPED' for c in report['cases']) else 'FAIL'
        report['runtime_matrix']['macOS_arm64_Node']=report['status']
        report['binary_stable']=sha(binary)==report['binary_sha256']
        report['archive_stable']=sha(Path(report['archive']))==report['archive_sha256']
        report['installed_stable']=all_hashes(consumer/'node_modules/@rocket-im/stage0-desktop-storage')==report['installed_files']
        require(report['binary_stable'] and report['archive_stable'] and report['installed_stable'],'运行产物在验证中变化')
    except Exception as error: report.update(status='FAIL',error=f'{type(error).__name__}: {error}')
    finally:
        report['source_after']=sources()
        report['source_stable']=report['source_before']==report['source_after']
        if not report['source_stable']: report.update(status='FAIL',source_error='验证期间源码变化')
        report['runtime_matrix']['macOS_arm64_Node'] = report['status']
        report['finished_at']=utc_now()
        report['counts']={status:sum(c['status']==status for c in report['cases']) for status in ('PASS_SCOPED','FAIL')}
        write_json(run/'report.json',report)
        print(json.dumps({'status':report['status'],'counts':report['counts'],'report':str(run/'report.json'),'error':report.get('error')}),flush=True)
    return int(report['status'] != 'PASS_SCOPED')

if __name__ == '__main__': sys.exit(main())
