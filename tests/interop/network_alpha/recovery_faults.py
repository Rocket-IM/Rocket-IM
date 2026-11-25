"""复用真实退出与提交拒绝装置，逐阶段验证已授权轮的准确材料续接。"""
import json
from harness import require,wait
from commit_faults import FaultRuntime

def run(lab):
    lab.case('fault_matrix_original_history',lab.initial)
    phases=[('recovery_after_offer',0),('recovery_after_accept',1),('recovery_after_create_crypto',1),
        ('recovery_after_approval',1),('recovery_after_join_reserve',0),('recovery_after_join_crypto',0),
        ('recovery_after_ready',0),('recovery_after_confirm',1),('recovery_after_finish',0),
        ('network_recovery_after_publish',0),('refuse_commit',1)]
    for serial,(phase,index) in enumerate(phases):
        def case(phase=phase,index=index,serial=serial):
            for w in lab.workers:w.call('disconnect')
            request,action=lab.unknown(0,'phase-'+str(serial))
            fault=FaultRuntime(lab,index,phase,refuse=phase=='refuse_commit')
            other=1-index;lab.auto(other)
            def status():return fault.call({'op':'network_recovery','command':{'kind':'status'}})
            try:
                if index==0:
                    fault.call({'op':'network_recovery','command':{'kind':'begin','request_id':request,'action':action}})
                    if phase not in ('recovery_after_offer','network_recovery_after_publish'):
                        r=wait(lambda:lab.phase(1,'approval_required'),'normal peer sees signed offer')
                        lab.approve(1,r['round_id'])
                else:
                    lab.begin(0,request,action)
                    r=wait(lambda:(s if (s:=status()) and s['phase']=='approval_required' else False),'fault peer receives signed offer')
                    fault.call({'op':'network_recovery','command':{'kind':'approve','round_id':r['round_id']}})
                if phase=='refuse_commit':
                    s=wait(lambda:(s if (s:=fault.call({'op':'network_state'}))['connection']=='blocked' else False),'real recovery commit rejected')
                    require(s['error']['code']=='recovery_commit_unknown','commit rejection preserved unknown error');fault.close()
                else:fault.exited()
            finally:fault.close()
            lab.restore(index);lab.auto(index)
            current=wait(lambda:lab.recovery(index),'reopened same recovery')
            if current['phase'] in ('building','joining'):
                lab.workers[index].call('networkRecovery',command={'kind':'seal','round_id':current['round_id']})
                for i in range(2):wait(lambda:lab.phase(i,'closed'),'bilateral seal '+str(i))
                lab.begin(0,request,action)
                r=wait(lambda:lab.phase(1,'approval_required'),'new round after bilateral sealing')
                lab.approve(1,r['round_id'])
            elif phase in ('recovery_after_offer','network_recovery_after_publish'):
                r=wait(lambda:lab.phase(1,'approval_required'),'published offer after interruption')
                lab.approve(1,r['round_id'])
            lab.complete();lab.communicate('phase-after-'+str(serial));r=lab.save_round_proof()
            require(lab.workers[0].call('request',requestId=request)['status']=='retired','original unknown request preserved terminal')
            lab.report.setdefault('recovery_phase_faults',[]).append({'phase':phase,'index':index,'exit':None if phase=='refuse_commit' else 86,'final_round':r['reservation']['id'],'status':'PASS'})
        lab.case('recovery_real_process_'+phase,case)
    lab.case('fault_matrix_secret_surfaces',lab.snapshot_secrets)
