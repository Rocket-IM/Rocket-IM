#!/usr/bin/env python3
"""固定双设备容量/时延验收入口，复用冻结产物和原维护装置。"""
from pathlib import Path
import json
import sys
import traceback
import uuid
from persistent_release import ROOT
from node_pack import write_json


def verify(task, release, label, suite):
    task=Path(task).resolve(); release=Path(release).resolve(); run=task/label
    sys.path.insert(0,str(ROOT/'tests/interop/network_alpha'))
    from environment import prepare, stop
    from capacity_harness import CapacityLab
    from capacity_cases import baseline, overflow, start, startup
    root=Path('/private/tmp')/('Rocket IM Capacity '+uuid.uuid4().hex[:12]); lab=None
    try:
        prepare(root)
        if suite.startswith(('diagnostics','reserve','workset')):
            from diagnostics_harness import DiagnosticsLab
            lab=DiagnosticsLab(release,root/'environment.json',run)
        else:lab=CapacityLab(release,root/'environment.json',run)
        new_client=lab.release
        if suite=='workset-repeat-upgrade':
            from diagnostics_harness import old_client
            lab.release=old_client(task,new_client,'dev13')
            lab.old_service='repeat';lab.operator=False
        if suite in ('workset-upgrade','workset-upgrade-legacy','workset-upgrade-full'):
            from diagnostics_harness import old_client
            lab.release=old_client(task,new_client,'dev12')
            lab.old_service='workset';lab.operator=False
        if suite in ('reserve-upgrade','reserve-upgrade-full'):
            from diagnostics_harness import old_client
            lab.release=old_client(task,new_client,'dev11')
            lab.old_service='reserve';lab.operator=False
        if suite=='diagnostics-upgrade':
            from diagnostics_harness import old_client
            lab.release=old_client(task,new_client)
            lab.old_service=True;lab.operator=False
        if suite in ('rejection-upgrade','rejection-upgrade-guarded'):
            from rejection_upgrade import baseline
            lab.release=baseline(task,new_client)
        lab.build(proxy=True)
        if suite=='workset-repeat':
            from workset_repeat import run as repeat_run
            repeat_run(lab)
        elif suite=='workset-repeat-full':
            from workset_repeat import full as repeat_full
            repeat_full(lab)
        elif suite=='workset-repeat-upgrade':
            from workset_repeat_upgrade import run as repeat_upgrade
            repeat_upgrade(lab,new_client)
        elif suite=='workset-repeat-lifecycle':
            from workset_lifecycle import run as repeat_lifecycle
            repeat_lifecycle(lab,repeated=True)
        elif suite=='workset':
            from workset_cases import run as workset_run
            workset_run(lab)
        elif suite=='workset-lifecycle':
            from workset_lifecycle import run as workset_lifecycle
            workset_lifecycle(lab)
        elif suite=='workset-full':
            from workset_cases import full as workset_full
            workset_full(lab)
        elif suite=='workset-upgrade-full':
            from workset_upgrade_full import run as workset_upgrade_full
            workset_upgrade_full(lab,new_client)
        elif suite in ('workset-upgrade','workset-upgrade-legacy'):
            from workset_upgrade import run as workset_upgrade
            workset_upgrade(lab,new_client,legacy=suite=='workset-upgrade-legacy')
        elif suite=='reserve':
            from reserve_cases import run as reserve_run
            reserve_run(lab)
        elif suite=='reserve-full':
            from reserve_cases import full as reserve_full
            reserve_full(lab)
        elif suite in ('reserve-upgrade','reserve-upgrade-full'):
            from reserve_upgrade import run as reserve_upgrade_run
            reserve_upgrade_run(lab,new_client,full=suite=='reserve-upgrade-full')
        elif suite=='diagnostics':
            from diagnostics_cases import run as diagnostics_run
            diagnostics_run(lab)
        elif suite=='diagnostics-full':
            from diagnostics_cases import full as diagnostics_full
            diagnostics_full(lab)
        elif suite=='diagnostics-upgrade':
            from diagnostics_upgrade import run as diagnostics_upgrade_run
            diagnostics_upgrade_run(lab,new_client)
        elif suite=='startup':lab.case('first_device_waits_for_peer_group_material',lambda:startup(lab))
        elif suite=='baseline':baseline(lab)
        elif suite=='overflow':overflow(lab)
        elif suite in ('rejection','rejection-multiple'):
            from rejection_cases import run as rejection_run
            rejection_run(lab,multiple=suite=='rejection-multiple')
        elif suite=='rejection-faults':
            from rejection_faults import run as rejection_faults_run
            rejection_faults_run(lab)
        elif suite in ('rejection-upgrade','rejection-upgrade-guarded'):
            from rejection_upgrade import run as rejection_upgrade_run
            if suite=='rejection-upgrade-guarded':
                for i in range(2):
                    lab.case('dev9_enable_backup_guard_'+str(i),lambda i=i:lab.export(i,'dev9-guarded-'+str(i)))
            rejection_upgrade_run(lab,new_client)
        elif suite=='large-local':
            from capacity_limits import large_local_budget
            lab.case('large_plaintext_reaches_local_byte_budget_without_crypto_reservation',lambda:large_local_budget(lab))
        elif suite in ('recovery','renewal','lifecycle','successor','unknown'):
            start(lab);lab.fill(224 if suite in ('successor','unknown') else 128,'preload');lab.offline()
            if suite=='recovery':
                from service_backup_cases import core
                import commit_faults
                for i in range(2):lab.auto(i)
                for i in range(2):lab.online(i)
                commit_faults.run(lab);lab.track();lab.offline()
                for i,w in enumerate(lab.workers):lab.setup(i);lab.instrument(w,i)
                core(lab)
            elif suite=='successor':
                from service_reconciliation_upgrade import successor
                successor(lab)
            elif suite=='unknown':
                from service_backup_cases import unknown
                unknown(lab)
            elif suite=='renewal':
                import renewal_cases
                for i in range(2):lab.setup(i,ttl=2)
                renewal_cases.run(lab,orderly_stop=True)
            else:
                import renewal_lifecycle
                for i in range(2):lab.auto(i);lab.online(i)
                renewal_lifecycle.run(lab)
            lab.save_samples()
        else:raise ValueError('unknown capacity suite')
        lab.report['status']='PASS_SCOPED'
    except Exception as error:
        if lab:lab.report.update(status='FAIL',error=str(error),trace=traceback.format_exc())
        else:run.mkdir(parents=True,exist_ok=True);write_json(run/'failure.json',{'status':'FAIL','error':str(error),'trace':traceback.format_exc(),'environment':str(root)})
    finally:
        if lab:
            try:lab.save_samples();lab.close()
            except Exception as error:lab.report.update(status='FAIL',cleanup_error=str(error));lab.save()
        try:stop(root)
        except Exception as error:
            if lab:lab.report.update(status='FAIL',postgres_cleanup_error=str(error));lab.save()
        if lab:
            lab.report['postgres_stopped']=not (root/'postgres/postmaster.pid').exists()
            lab.report['environment']=str(root);lab.save()
    status=lab.report['status'] if lab else 'FAIL'
    print(json.dumps({'status':status,'run':str(run),'environment':str(root),'error':lab.report.get('error') if lab else None}),flush=True)
    return 0 if status=='PASS_SCOPED' else 1


if __name__=='__main__':
    if len(sys.argv)!=6 or sys.argv[1]!='verify':
        raise SystemExit('verify <task-root> <frozen-service-release> <new-label> workset-repeat|workset-repeat-full|workset-repeat-upgrade|workset-repeat-lifecycle|workset|workset-full|workset-lifecycle|workset-upgrade|workset-upgrade-legacy|workset-upgrade-full|reserve|reserve-full|reserve-upgrade|reserve-upgrade-full|diagnostics|diagnostics-upgrade|diagnostics-full|startup|baseline|overflow|rejection|rejection-multiple|rejection-faults|rejection-upgrade|rejection-upgrade-guarded|large-local|recovery|renewal|lifecycle|successor|unknown')
    sys.exit(verify(*sys.argv[2:]))
