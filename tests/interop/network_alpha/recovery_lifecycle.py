"""恢复轮进行中的真实认证与传输取消；随后回归实际多空间/销钥生命周期。"""
import json,time
from harness import Worker,require,wait
from renewal_lifecycle import run as original_lifecycle

def run(lab):
    lab.case('lifecycle_original_history',lab.initial)
    def active():
        lab.workers[0].call('disconnect');request,action=lab.unknown(0,'lifecycle-unknown');lab.auto(0)
        lab.begin(0,request,action);r=wait(lambda:lab.phase(1,'approval_required'),'pending bilateral recovery')
        old=lab.workers[0];old.call('authFault',mode='late_success',count=1)
        wait(lambda:lab.stats(0)['held']==1,'actual expiry starts held host callback',10)
        lab.approve(1,r['round_id']);wait(lambda:lab.phase(1,'prepared'),'peer durably prepared while target auth suspended')
        identity=old.call('state')['identity'];history=lab.history(0)
        old.call('disconnect');old.call('events');old.call('authRelease');wait(lambda:old.call('authStats')['active']==0,'late callback settled')
        require(old.call('network')['connection']=='offline' and not old.call('events'),'cancelled authorization transport cannot resurrect')
        lab.restart_service()
        lab.control.write_text(json.dumps({'mode':'delay_recovery_ack','material':'ready','consumed':False}))
        lab.auto(0);wait(lambda:json.loads(lab.control.read_text()).get('consumed'),'actual recovery response in flight')
        start=time.monotonic();old.call('closeKeep');require(time.monotonic()-start<5 and not old.call('alive')['alive'],'bounded native network cancellation')
        old.call('events')
        newer=Worker(old.directory,old.options);lab.workers[0]=newer;lab.setup(0)
        require(newer.call('state')['identity']==identity and lab.history(0)==history,'new public object preserves original identity and history')
        lab.auto(0);lab.complete();lab.communicate('lifecycle-resumed')
        require(not old.call('events') and not old.call('alive')['alive'],'old object and late recovery reply cannot revive')
        old.close();lab.save_round_proof()
    lab.case('active_recovery_expiry_callback_disconnect_close_inflight_new_object',active)
    original_lifecycle(lab)
