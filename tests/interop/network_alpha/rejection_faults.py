"""拒绝/丢失/退出分开取证；真实SIGKILL与test-hooks事务边界明确分列。"""
import json
import time
from commit_faults import FaultRuntime
from harness import require, wait
from rejection_cases import prepare_full, terminal, verify_originals

def run(lab):
    accepted,rejected=prepare_full(lab,rejected=8,remaining=8)
    original=lab.snapshot(1)
    def unknown_response():
        lab.control.write_text(json.dumps({'mode':'hold_send_rejection'}))
        lab.auto(1)
        def attempts():
            return len([o for o in json.loads(lab.observations.read_text()) if o['request']=='req-'+rejected[0]])
        wait(lambda:attempts()>=2,'real permanent Service refusal withheld and precisely retried',15)
        require(lab.status(1,rejected[0],'local_saved') and not terminal(lab,rejected[0]),'transport loss is not rejection proof')
        lab.workers[1].call('cancel',expected='cancelled')
        require(lab.workers[1].call('request',requestId='cancelled')['status']=='missing','pre-cancel no reservation')
        lab.workers[1].call('disconnect')
        require(lab.snapshot(1)['state']==original['state'],'disconnect keeps original request/crypto state')
        lab.auto(1);wait(lambda:attempts()>=3,'real rejection retry before orderly close',15)
        pid=lab.workers[1].pid;lab.workers[1].close();lab.restore(1)
        require(lab.snapshot(1)['state']==original['state'] and lab.status(1,rejected[0],'local_saved'),'orderly close cannot infer remote refusal')
        lab.report['rejection_orderly_close']={'pid':pid,'terminal':False,'original_state_preserved':True}
        lab.auto(1);wait(lambda:attempts()>=4,'real rejection retry before SIGKILL',15)
        pid=lab.workers[1].pid;lab.restart_worker(1,kill=True);lab.setup(1)
        require(lab.snapshot(1)['state']==original['state'] and lab.status(1,rejected[0],'local_saved'),'normal Release SIGKILL cannot guess response')
        lab.report.setdefault('normal_sdk_sigkills',[]).append({'pid':pid,'boundary':'actual Service refusal withheld before client proof','terminal':False})
        lab.control.write_text('{}')
    lab.case('actual_rejection_lost_timeout_disconnect_close_cancel_and_normal_sigkill',unknown_response)

    for phase in ('network_after_rejection','before_commit','refuse_commit','after_commit','network_after_rejection_commit'):
        def boundary(phase=phase):
            before=lab.snapshot(1);done=sum(terminal(lab,id) for id in rejected)
            fault=FaultRuntime(lab,1,phase,refuse=phase=='refuse_commit')
            lab.report.setdefault('rejection_fault_processes',[]).append({'pid':fault.process.pid,'phase':phase})
            try:
                if phase=='refuse_commit':
                    state=wait(lambda:(s if (s:=fault.call({'op':'network_state'}))['connection']=='blocked' else False),'refused rejection commit explicit failure')
                    require(state['error']['code']=='storage_failure','transaction rejection reason retained')
                    require(all(s['status']!='rejected' for s in state['sending'] if s['message_id'] in rejected),'uncommitted terminal never published')
                else:fault.exited()
            finally:fault.close()
            lab.restore(1)
            now=sum(terminal(lab,id) for id in rejected)
            expected=done+int(phase in ('after_commit','network_after_rejection_commit'))
            require(now==expected,'only committed rejection visible after exact boundary')
            require(lab.snapshot(1)['state']==before['state'],'rejection does not execute crypto or advance processed')
            lab.report.setdefault('rejection_commit_faults',[]).append({'phase':phase,'before':done,'after':now,'test_hooks':True})
        lab.case('rejection_transaction_'+phase,boundary)

    def candidate():
        fault=FaultRuntime(lab,1,'after_candidate')
        lab.report['rejection_fault_processes'].append({'pid':fault.process.pid,'phase':'after_candidate'})
        try:fault.exited()
        finally:fault.close()
        lab.restore(1)
        require(all(terminal(lab,id) for id in rejected),'all rejections precede downloaded candidate')
        state=lab.workers[1].call('state');require(state['pending_request'] is not None,'exact received candidate retained')
        before=lab.workers[1].call('network');require(int(before['processed'])<256,'candidate has not fabricated processing')
        lab.auto(1);lab.online(1);lab.drain(accepted,'rejection_candidate_resume');lab.aligned()
        require(lab.workers[1].call('state')['pending_request'] is None,'normal Release installed complete candidate')
    lab.case('all_rejections_then_complete_receive_candidate_resumes',candidate)

    def committed_kill():
        lab.offline();before=lab.snapshot(1);pid=lab.workers[1].pid
        lab.restart_worker(1,kill=True);lab.setup(1)
        require(lab.snapshot(1)==before,'normal Release SIGKILL retains committed rejection and cursor')
        lab.report['normal_sdk_sigkills'].append({'pid':pid,'boundary':'public terminal and full cursor already committed','terminal':True})
        for i in range(2):lab.auto(i);lab.online(i)
        verify_originals(lab,rejected)
    lab.case('normal_release_sigkill_after_terminal_and_processing',committed_kill)
    lab.case('rejection_fault_service_secret_samples',lab.snapshot_secrets)
    for i in range(2):lab.case('rejection_fault_client_broad_samples_'+str(i),lambda i=i:lab.audit(i))
