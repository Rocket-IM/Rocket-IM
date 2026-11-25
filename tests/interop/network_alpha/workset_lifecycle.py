"""共同记录与原取消、完整候选及明确授权后继门禁的组合回归。"""
import json
import hashlib
import secrets
from backup_harness import BackupFault
from capacity_cases import start
from commit_faults import FaultRuntime
from diagnostics_cases import secret_samples
from harness import require, wait
from workset_harness import enable, source, service_state, originals, transport


def run(lab, repeated=False):
    enable(lab);start(lab);lab.aligned();lab.offline()
    first = None
    if repeated:
        from workset_repeat import enable_repeat, settle
        enable_repeat(lab)
        source(lab, 0, 'common-lifecycle-first');lab.workers[0].call('prepareWorkset');first=settle(lab,0)
    source(lab, 0, 'common-lifecycle')
    local = lab.workers[0].call('prepareNextWorkset', previous=first['workset']['id']) if first else lab.workers[0].call('prepareWorkset')
    def delayed():
        lab.control.write_text(json.dumps({'mode': 'delay_workset_ack', 'field': 'capacity_workset_prepare'}))
        lab.auto(0)
        wait(lambda: json.loads(lab.control.read_text()).get('hits') == 1, 'real delayed prepare reply')
        lab.workers[0].call('disconnect');lab.control.write_text('{}')
        state = lab.workers[0].call('workset')
        # 取消不是回滚：在取消完成前已核对的原回复可提交confirmed，但不能凭prepare变active。
        require(state['phase'] in ('prepared', 'confirmed') and state['workset'] == local['workset'], 'late valid receipt never fabricates common activation')
        require(service_state(lab, 0)['phase'] == 'prepared', 'only Service prepare actually committed')
        lab.report['late_workset_reply'] = {'local_phase': state['phase'], 'service_phase': 'prepared', 'cancel_does_not_revoke': True}
    lab.case('delayed_reply_cancel_and_close', delayed)
    def candidate():
        action = {'kind': 'send', 'message_id': 'common-candidate', 'text': 'WORKSET_CANDIDATE_'+secrets.token_hex(24)}
        lab.texts.append(action['text']);request = 'req-common-candidate'
        fault = BackupFault(lab, 0, 'after_candidate')
        try:fault.interrupt({'op': 'execute', 'request_id': request, 'action': action})
        finally:fault.close()
        lab.restore(0);audit = lab.audit(0)
        require(audit['candidate_outcome_hash'] is not None, 'real full candidate persists alongside fixed workset')
        before = lab.workers[0].call('workset')
        result = lab.workers[0].call('recoverRequest', requestId=request, action=action)
        digest = hashlib.sha256(json.dumps({'status': 'complete', 'outcome': result}, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
        require(digest == audit['candidate_outcome_hash'], 'exact saved crypto candidate installed without reexecution')
        require(lab.workers[0].call('workset') == before, 'candidate installation cannot replace promise')
    lab.case('complete_crypto_candidate_retains_workset', candidate)
    def recovery():
        request, action = lab.unknown(0, 'common-unknown')
        original = lab.workers[0].call('workset')
        # 仅查询已有记录，不将未知新密码操作列入共同承诺。
        require(lab.workers[0].call('prepareWorkset') == original, 'unknown execution cannot allocate replacement promise')
        for i in range(2):lab.auto(i)
        round_id = lab.begin(0, request, action)['round_id']
        wait(lambda: lab.phase(1, 'approval_required'), 'original explicit peer approval gate')
        lab.offline();lab.approve(1, round_id)
        fault = FaultRuntime(lab, 0, 'network_recovery_after_known_commit', connect=False)
        lab.report.setdefault('fault_processes', []).append({'pid': fault.process.pid, 'phase': 'network_recovery_after_known_commit'})
        try:
            fault.call({'op': 'connect', 'options': lab.connect_options[0]});lab.auto(1);fault.exited()
        finally:fault.close()
        lab.restore(0);lab.workers[1].call('disconnect')
        require(lab.workers[0].call('workset')['workset'] == original['workset'], 'known target candidate retains exact workset')
        for i in range(2):lab.auto(i)
        lab.complete()
        wait(lambda: lab.workers[0].call('workset')['phase'] == 'settled', 'original common range settles after authorized recovery')
        lab.aligned();lab.offline()
        state = lab.workers[0].call('workset')
        require(state['workset'] == local['workset'] and lab.workers[0].call('state')['context'] != local['workset']['context'], 'retired crypto context is not reactivated')
        require(service_state(lab, 0) == state, 'same original terminal range on Service')
        originals(lab, 0, state)
    lab.case('unknown_gate_authorized_successor_and_original_settlement', recovery)
    if repeated:
        def successor_round():
            from workset_repeat import settle, histories, replay_reply
            from workset_harness import manifest_id
            second=lab.workers[0].call('workset')
            source(lab,0,'repeat-after-successor')
            next_state=lab.workers[0].call('prepareNextWorkset',previous=second['workset']['id'])
            require(next_state['workset']['context']!=second['workset']['context'],'new round belongs to authorized current context')
            retired={**next_state['workset'],'context':second['workset']['context']};retired['id']=manifest_id(retired)
            before=lab.database_snapshot();reply=lab.rpc(0,'capacity_workset_prepare',retired)
            require(not reply['ok'] and reply['error']['code']=='workset_context_mismatch','retired context cannot prepare new round')
            require(before==lab.database_snapshot(),'retired context refusal preserves predecessor and originals')
            replay_reply(lab,0,second,'prepare');settle(lab,0);histories(lab,0,[first,second])
        lab.case('third_round_current_context_and_old_reply_replay',successor_round)
    lab.case('lifecycle_common_service_restore', lambda: lab.controlled_restore('common-lifecycle', reconnect=False))
    for i in range(2):
        path, _ = lab.export(i, 'common-lifecycle-'+str(i))
        lab.case('lifecycle_common_client_restore_'+str(i), lambda i=i,path=path: lab.roundtrip(i, path))
    lab.case('lifecycle_common_secret_samples', lambda: secret_samples(lab))
