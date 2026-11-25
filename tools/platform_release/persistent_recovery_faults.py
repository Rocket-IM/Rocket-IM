"""真实进程退出/SQLite拒绝提交。这里只制造故障，恢复与通信交给独立TGZ的公开TS API。"""
import hashlib
import json
import sqlite3
from persistent_faults import Runtime

PHASES = ('after_reserve','after_begin','after_crypto','before_candidate','after_candidate','before_commit','after_commit','refuse_commit','refuse_candidate')

def audit(path):
    connection = sqlite3.connect(f'file:{path}?mode=ro',uri=True)
    try:
        connection.execute('BEGIN')
        data,crypto,digest,meta = connection.execute('SELECT data,crypto,digest,recovery FROM sdk_state WHERE id=1').fetchone()
        connection.commit()
        m=json.loads(meta); d=json.loads(data)
        seed=m.get('journal',{}).get('seed') if m.get('journal') else None
        identity=d['state']['identity']
        if seed:
            identity={'scope':d['state']['scope'],'identity_key':bytes(json.loads(bytes(seed))['public_key']).hex()}
        return {'data_sha256':hashlib.sha256(data).hexdigest(),'crypto_sha256':hashlib.sha256(crypto).hexdigest(),
            'meta_sha256':hashlib.sha256(meta).hexdigest(),'identity':identity}
    finally: connection.close()

def setup(normal, folder, account, operation):
    folder.mkdir(parents=True)
    other='bob' if account=='alice' else 'alice'
    t=Runtime(normal,folder/f'{account}.db',account,create=True)
    p=Runtime(normal,folder/f'{other}.db',other,create=True)
    try:
        p.execute('init',{'kind':'initialize'})
        if operation!='initialize': t.execute('init',{'kind':'initialize'})
        if operation=='initialize': action={'kind':'initialize'}
        else:
            tm=t.call({'op':'joining_material'});pm=p.call({'op':'joining_material'})
            if operation=='create': action={'kind':'create_group','conversation':'chat','peer':pm['identity'],'key_package':pm['key_package']}
            elif operation=='join':
                w=p.execute('create',{'kind':'create_group','conversation':'chat','peer':tm['identity'],'key_package':tm['key_package']})['value']['welcome']
                action={'kind':'join_group','conversation':'chat','peer':pm['identity'],'welcome':w}
            else:
                w=t.execute('create',{'kind':'create_group','conversation':'chat','peer':pm['identity'],'key_package':pm['key_package']})['value']['welcome']
                p.execute('join',{'kind':'join_group','conversation':'chat','peer':tm['identity'],'welcome':w})
                for sender,receiver,label in ((t,p,'old-target'),(p,t,'old-peer')):
                    e=sender.execute(label,{'kind':'send','message_id':label,'text':label})['value']['envelope']
                    receiver.execute(label,{'kind':'receive','envelope':e})
                if operation=='send': action={'kind':'send','message_id':'uncertain','text':'中断的发送'}
                else:
                    e=p.execute('incoming',{'kind':'send','message_id':'incoming','text':'中断的接收'})['value']['envelope']
                    action={'kind':'receive','envelope':e}
        return {'target':{'account':account,'path':str(folder/f'{account}.db')},'peer':{'account':other,'path':str(folder/f'{other}.db')},
                'operation':operation,'action':action,'before':t.call({'op':'state'}),'peer_before':p.call({'op':'state'}),
                'history':operation in ('send','receive')}
    finally: t.close();p.close()

def crash(binary, job, phase, operation=None, role='target'):
    d=job[role]
    r=Runtime(binary,d['path'],d['account'],fault=phase if phase not in ('refuse_commit','refuse_candidate') else None,
              refuse=phase=='refuse_commit',refuse_journal=phase=='refuse_candidate')
    try:
        command=operation or {'op':'execute','request_id':'target','action':job['action']}
        r.call(command,exited=phase not in ('refuse_commit','refuse_candidate'),
               error='commit_unknown' if phase=='refuse_commit' else 'candidate_unknown' if phase=='refuse_candidate' else None)
    finally: r.close()

def call(normal,job,role,command):
    d=job[role];r=Runtime(normal,d['path'],d['account'])
    try: return r.call({'op':'recovery','command':command})
    finally: r.close()

def prepare(normal,fault,directory):
    jobs=[]
    for account in ('alice','bob'):
        for operation in ('initialize','create','join','send','receive'):
            for phase in PHASES:
                name=f'{account}-{operation}-{phase}'
                job=setup(normal,directory/name,account,operation)
                job.update(name=name,phase=phase,category='operation',original_audit=audit(job['target']['path']))
                crash(fault,job,phase)
                job['fault_audit']=audit(job['target']['path'])
                jobs.append(job)
    stages=('recovery_before_offer','recovery_after_offer','recovery_after_accept','recovery_after_create_crypto',
            'recovery_after_approval','recovery_after_join_reserve','recovery_after_join_crypto','recovery_after_ready',
            'confirm_before_commit','confirm_after_commit','finish_before_commit','finish_after_commit','target_close','peer_close')
    for stage in stages:
        job=setup(normal,directory/stage,'alice','send');job.update(name=stage,phase=stage,category='recovery',original_audit=audit(job['target']['path']))
        crash(fault,job,'after_crypto')
        job['fault_audit']=audit(job['target']['path'])
        begin={'kind':'begin','request_id':'target','action':job['action']}
        if stage in ('recovery_before_offer','recovery_after_offer'):
            crash(fault,job,stage,{'op':'recovery','command':begin})
        else:
            offer=call(normal,job,'target',begin)['packet']
            accept={'kind':'accept','offer':offer,'peer':job['before']['identity']}
            if stage in ('recovery_after_accept','recovery_after_create_crypto','recovery_after_approval','peer_close'):
                crash(fault,job,'recovery_after_create_crypto' if stage=='peer_close' else stage,{'op':'recovery','command':accept},'peer')
                if stage=='peer_close': crash(fault,job,'recovery_after_close',{'op':'recovery','command':{'kind':'close','peer_close':None}},'peer')
            else:
                approval=call(normal,job,'peer',accept)['packet'];join={'kind':'join','approval':approval}
                if stage in ('recovery_after_join_reserve','recovery_after_join_crypto','recovery_after_ready','target_close'):
                    crash(fault,job,'recovery_after_join_crypto' if stage=='target_close' else stage,{'op':'recovery','command':join})
                    if stage=='target_close': crash(fault,job,'recovery_after_close',{'op':'recovery','command':{'kind':'close','peer_close':None}})
                else:
                    ready=call(normal,job,'target',join)['packet'];confirm={'kind':'confirm','ready':ready}
                    if stage.startswith('confirm_'): crash(fault,job,stage.removeprefix('confirm_'),{'op':'recovery','command':confirm},'peer')
                    else:
                        receipt=call(normal,job,'peer',confirm)['packet']
                        crash(fault,job,stage.removeprefix('finish_'),{'op':'recovery','command':{'kind':'finish','receipt':receipt}})
        jobs.append(job)
    # 恢复完整候选再次在提交前退出；两个真实端同时各有未知发送。
    for name in ('repeat-candidate-interruption','both-pending'):
        job=setup(normal,directory/name,'alice','send');job.update(name=name,phase=name,category='recovery',original_audit=audit(job['target']['path']))
        crash(fault,job,'after_candidate' if name.startswith('repeat') else 'after_crypto')
        job['fault_audit']=audit(job['target']['path'])
        if name.startswith('repeat'):
            crash(fault,job,'before_commit',{'op':'recover_request','request_id':'target','action':job['action']})
        else:
            crash(fault,job,'after_crypto',{'op':'execute','request_id':'other-pending','action':{'kind':'send','message_id':'other-pending','text':'双端中断'}},'peer')
        jobs.append(job)
    advanced=[]
    for name in ('concurrent-offer','closed-material','archived-receipt','closed-round-replay'):
        job=setup(normal,directory/name,'alice','send');job.update(name=name,phase='after_crypto',category='advanced',original_audit=audit(job['target']['path']))
        crash(fault,job,'after_crypto');job['fault_audit']=audit(job['target']['path'])
        if name=='closed-round-replay':
            offer=call(normal,job,'target',{'kind':'begin','request_id':'target','action':job['action']})['packet']
            approval=call(normal,job,'peer',{'kind':'accept','offer':offer,'peer':job['before']['identity']})['packet']
            crash(fault,job,'recovery_after_join_crypto',{'op':'recovery','command':{'kind':'join','approval':approval}})
            job.update(old_offer=offer,old_approval=approval)
        advanced.append(job)
    (directory/'advanced.json').write_text(json.dumps(advanced,ensure_ascii=False,indent=2))
    manifest=directory/'jobs.json';manifest.write_text(json.dumps(jobs,ensure_ascii=False,indent=2))
    return manifest

def prepare_recovery_refusals(normal,fault,directory):
    jobs=[]
    for step in ('offer','accept','approval','join','ready','confirm','finish','close'):
        job=setup(normal,directory/step,'alice','send');job.update(name='recovery-refuse-'+step,phase=step,category='recovery-refusal',original_audit=audit(job['target']['path']))
        crash(fault,job,'after_crypto');job['fault_audit']=audit(job['target']['path'])
        begin={'kind':'begin','request_id':'target','action':job['action']}
        def reject(role,command,phase,error):
            d=job[role];r=Runtime(fault,d['path'],d['account'],refuse_recovery=phase)
            try:r.call({'op':'recovery','command':command},error=error)
            finally:r.close()
        if step=='offer':reject('target',begin,'offered','recovery_write_unknown')
        else:
            offer=call(normal,job,'target',begin)['packet'];accept={'kind':'accept','offer':offer,'peer':job['before']['identity']}
            if step in ('accept','approval'):reject('peer',accept,'building' if step=='accept' else 'prepared','storage_failure' if step=='accept' else 'recovery_write_unknown')
            else:
                approval=call(normal,job,'peer',accept)['packet'];join={'kind':'join','approval':approval}
                if step in ('join','ready'):reject('target',join,'joining' if step=='join' else 'ready','storage_failure' if step=='join' else 'recovery_write_unknown')
                elif step=='close':
                    crash(fault,job,'recovery_after_join_crypto',{'op':'recovery','command':join})
                    reject('target',{'kind':'close','peer_close':None},'closing','recovery_write_unknown')
                else:
                    ready=call(normal,job,'target',join)['packet'];confirm={'kind':'confirm','ready':ready}
                    if step=='confirm':reject('peer',confirm,'committed','recovery_commit_unknown')
                    else:
                        receipt=call(normal,job,'peer',confirm)['packet'];reject('target',{'kind':'finish','receipt':receipt},'finished','recovery_commit_unknown')
        jobs.append(job)
    manifest=directory/'jobs.json';manifest.write_text(json.dumps(jobs,ensure_ascii=False,indent=2));return manifest
