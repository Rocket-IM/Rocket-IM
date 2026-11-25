"""Q02 联合边界：真实原件及自然交换满额，合成独立渠道明确标识。"""
import copy
from datetime import datetime, timezone

from .fixture import check
from . import exchange_cases as exchange
from . import consistency_cases as consistency


def capacity_import(lab):
    """128次真实交换后在新请求前拒绝；未接收的分叉不能算已检出。"""
    left, right = exchange.branches(lab)
    for index in range(128):
        request = exchange.begin(lab, source='a1')['request']
        package = exchange.export(lab, request, 'exchange_left', source='a1')['package']
        reply = lab.rust('b1', 'consistency_exchange_import', package=package)
        check(reply['outcome'] == 'matched', '自然累积交换没有真实匹配')
    before_bytes = (lab.directory / 'b1/state.enc').read_bytes()
    error = exchange.begin(lab, expected_exit=1)
    check(error['code'] == 'resource_exhausted', '满额后仍创建新的活动请求')
    check((lab.directory / 'b1/state.enc').read_bytes() == before_bytes,
          '未创建请求却改变原件或检查状态')
    check(exchange.inspect(lab)['import_count'] == 128 and exchange.inspect(lab)['active'] is None,
          '自然满额未明确保持原件和拒绝新交换')
    lab.restart()
    check(exchange.begin(lab, expected_exit=1)['code'] == 'resource_exhausted',
          '重启后满额闸消失')
    lab.case_evidence.update({'natural_imports': 128, 'next_request_rejected': error,
                         'incoming_conflict_not_observed': True,
                         'left_record': left, 'right_record': right})


def isolated_fork_window(lab):
    exchange.branches(lab)
    observed = {}
    for device in ('b1', 'a2'):
        observed[device] = lab.rust(device, 'permission_inspect')['checkpoint']
        consistency.assert_status(lab, 'no_known_conflict', device)
        consistency.send(lab, device, logical='isolated-'+device)
    check(observed['b1'] != observed['a2'], '没有真实构造不同已应用分支')
    start = datetime.now(timezone.utc).isoformat()
    request = exchange.begin(lab)['request']
    package = exchange.export(lab, request, 'exchange_right')['package']
    reply = lab.rust('b1', 'consistency_exchange_import', package=package)
    check(reply['outcome'] == 'fork_detected', '真实对照未检出另一后继')
    consistency.blocked(lab)
    lab.restart()
    consistency.blocked(lab)
    lab.case_evidence.update({'before_comparison': 'EXPECTED_UNDETECTABLE',
                         'observed_branches': observed, 'comparison_started_utc': start,
                         'conflict_saved_utc': datetime.now(timezone.utc).isoformat(),
                         'request': request, 'package': package, 'after': reply,
                         'window_upper_bound': None})


def verified_full_capacity(lab, mode='imports', anchored=False):
    """已验证原件复制成合成满额状态；不是正常串行路径或自然容量证明。"""
    from .recovery_capacity_cases import fixture
    from .join_review_regressions import enable_anchor
    exchange.branches(lab)
    first = exchange.begin(lab, source='a1')['request']
    first_package = exchange.export(lab, first, 'exchange_left', source='a1')['package']
    lab.rust('b1', 'consistency_exchange_import', package=first_package)
    # 先真实保存一份head，使近满装置复制的是已验证原件。
    consistency.observe(lab, consistency.current_head(lab))
    if mode == 'imports':
        request = exchange.begin(lab)['request']
        proof = exchange.export(lab, request, 'exchange_right')['package']
        operation, fields = 'consistency_exchange_import', {'package': proof}
    else:
        proof = consistency.sign_head(lab, lab.rust('a2','permission_inspect')['checkpoint'])
        operation, fields = 'consistency_observe_head', {'head': proof}
    seeded = fixture(lab, 'b1', 'q02_'+mode)
    before = fixture(lab, 'b1', 'inspect')
    bad = copy.deepcopy(proof)
    bad['signature_bytes'] = consistency.mutate_bytes(bad['signature_bytes'])
    bad_fields = {'package' if mode == 'imports' else 'head': bad}
    path = lab.directory/'b1/state.enc';original=path.read_bytes()
    lab.rust('b1', operation, **bad_fields, expected_exit=1)
    check(path.read_bytes()==original,'满额坏签名误改快照')
    if anchored: enable_anchor(lab,'b1')
    reply=lab.rust('b1',operation,**fields)
    consistency.assert_status(lab,'evidence_capacity_exhausted')
    check(fixture(lab,'b1','inspect')==before,'容量失败改变原件/MLS/候选')
    lab.restart()
    if mode=='imports':lab.rust('b1','consistency_exchange_cancel')
    head=consistency.sign_head(lab,lab.rust('b1','permission_inspect')['checkpoint'])
    lab.rust('b1','consistency_resume',head=head)
    consistency.assert_status(lab,'evidence_capacity_exhausted')
    consistency.blocked(lab)
    check(fixture(lab,'b1','inspect')==before if mode=='heads' else
          exchange.inspect(lab)['import_count']==128,'恢复丢失原件')
    lab.case_evidence.update({'synthetic_full_active_state':seeded,'valid_unretained_proof':proof,
                       'saved_pause_reply':reply,'anchored':anchored})


def offline_anchor_bidirectional(lab):
    from .join_review_regressions import enable_anchor
    exchange.same_branch(lab)
    request = exchange.begin(lab)['request']
    lab.stop()
    count = lab.http_count
    package = exchange.export(lab, request, 'exchange_same')['package']
    reply = lab.rust('b1','consistency_exchange_import',package=package)
    check(reply['outcome']=='matched' and lab.http_count==count,'离线对照依赖Relay')
    enable_anchor(lab,'b1')
    lab.start()
    from .first_trust_fixture import roundtrip
    roundtrip(lab,'after-independent-anchor',sender='b1',recipients=('a1',))
    roundtrip(lab,'reply-independent-anchor',sender='a1',recipients=('b1',))
    lab.restart()
    checkpoint=lab.rust('b1','anchor_inspect')
    check(checkpoint['status']=='ready' and checkpoint['freshness']=='unknown',
          '锚重启未持有完整当前承诺或夸大了新鲜度')
    roundtrip(lab,'after-restart',sender='b1',recipients=('a1',))
    lab.case_evidence['offline_anchor_bridge']={'request':request,'package':package,
        'matched':reply,'anchor_after_restart':checkpoint,'real_bidirectional_mls':True}


def paused_old_rebuild(lab, kind='capacity'):
    """拒绝带暂停的旧范围；负例计划中的未决txn为显式无效前置，绝不模拟成功预约。"""
    from .rebuild_states import pause_state
    if kind=='capacity':
        from .recovery_capacity_cases import fixture
        fixture(lab,'a1','pause')
    else:
        pause_state(lab,kind)
    lab.enable(rebuild_trust=lab.trust)
    lab.old_fact=lab.rust('a1','anchor_inspect')
    check(lab.old_fact['active_txn'] is None,'拒绝前置不应已有密码预约')
    # 只为构造结构有效的拒绝输入；实际锚中不写入该事务。
    lab.old_fact['active_txn']='a'*64
    lab.old_fact['revision']='1'
    lab.offer();lab.approve()
    before=lab.snapshot().read_bytes()
    error=lab.link(expected_exit=1)
    check(error['code'] in ('rebuild_consistency','rebuild_permission'),
          '旧范围没有在健康守卫拒绝: '+str(error))
    check(lab.snapshot().read_bytes()==before,'重建拒绝改变旧证据')
    lab.evidence['paused_old_rebuild']={'kind':kind,'error':error,
        'hypothetical_txn_and_revision_not_reserved':True,'old_snapshot_unchanged':True}


def successor_verification_scope(lab):
    from .first_trust_session import public_identity, TrustSession
    lab.unresolved();lab.offer();lab.approve();lab.link();lab.configure_successor()
    before=lab.rust('successor','anchor_inspect')
    error=lab.rust('successor','identity_trust_observe',identity=public_identity(lab,'c1'),expected_exit=1)
    check(error['code']=='rebuild_trust','后继能观察未批准成员')
    check(lab.rust('successor','anchor_inspect')==before,'错误范围核验消耗锚')
    with TrustSession(lab,'successor') as session:
        session.request('identity_trust_prepare',target=lab.identities['source'],
                        purpose='reset',expected_error=('rebuild_trust','identity_invalid'))
    check(lab.rust('successor','anchor_inspect')==before,'隔离换钥请求消耗锚')
    error=lab.rust('successor','wire_send',logical_message_id='before-welcome',attempt_id='P1',payload='synthetic',expected_exit=1)
    check(error['code']=='rebuild_quarantined','身份核验入口意外解封发送')
    # 错误普通发送可能留下原锚闸；它不授予许可。只有完整匹配承诺可清辅助闸。
    lab.resume('successor')
    lab.rust('successor','permission_join',**lab.joining())
    lab.communicate('after-exact-verification')
    lab.evidence['successor_identity_boundary']={'unapproved_member_rejected':True,
        'reset_rejected':True,'before_welcome_send_rejected':True,'real_join_after_verify':True}
