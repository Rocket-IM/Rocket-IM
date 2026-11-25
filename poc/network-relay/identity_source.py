"""Q01显式业务入口；不经过fixture主体认证，不降级到旧注册路径。"""
import base64
import hmac
import json
import secrets
import urllib.request
from contract import fields, encode_json, parse_json, validate_id, decode_bytes
from storage import now_ms, token_hash, identifier
from registration_contract import challenge, proof as registration_proof, registered
from identity_source_contract import document, verify, sign, fail, digest, record_digest, envelope
from identity_source_storage import snapshots, advance

def backend(store,token):
    if not hmac.compare_digest(token_hash(token),store.identity_config['backend_token_hash']):fail('unauthenticated',401)

def active(store,subject,account):
    config=store.identity_config
    request=urllib.request.Request(config['issuer_url']+'/status',data=encode_json({'subject':subject,'account_id':account}),headers={'Authorization':'Bearer '+config['status_token'],'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(request,timeout=2) as response:value=parse_json(response.read(4097))
    except Exception:fail('identity_authority_unavailable',503)
    if value!={'ok':True,'result':{'active':True}}:fail('identity_subject_inactive',403)

def execute(store,db,token,req):
    if not hasattr(store,'identity_config'):fail('identity_source_required',403)
    kind=req.get('kind');roots=store.identity_config['roots']
    if kind=='challenge':
        backend(store,token);fields(req,('kind','account_id','subject','device_id','signature_key','registration_id','purpose'))
        for k in ('account_id','subject','device_id','registration_id'):validate_id(req[k],k)
        if req['purpose'] not in ('first_device','add_device') or len(decode_bytes(req['signature_key'],'signature_key',32))!=32:fail()
        active(store,req['subject'],req['account_id'])
        mapping=db.execute('SELECT subject FROM identity_source_accounts WHERE account=?',(req['account_id'],)).fetchone()
        if mapping and mapping[0]!=req['subject']:fail('identity_source_subject',403)
        if not mapping:
            if db.execute('SELECT count(*) FROM identity_source_accounts').fetchone()[0]>=16:fail('resource_exhausted',429)
            if db.execute('SELECT 1 FROM identity_source_accounts WHERE subject=?',(req['subject'],)).fetchone():fail('identity_source_subject',403)
            db.execute('INSERT INTO identity_source_accounts VALUES (?,?)',(req['account_id'],req['subject']))
        pair=(req['account_id'],req['device_id']);old=db.execute('SELECT bytes,purpose FROM identity_source_challenges WHERE account=? AND device=? AND registration_id=?',(*pair,req['registration_id'])).fetchone()
        if old:
            c=challenge(old['bytes'])
            if c['signature_key']!=req['signature_key'] or old['purpose']!=req['purpose']:fail('idempotency_conflict')
            return {'challenge_bytes':old['bytes']}
        if db.execute('SELECT 1 FROM identity_source_entries WHERE account=? AND device=?',pair).fetchone():fail('registration_conflict')
        if db.execute('SELECT count(*) FROM identity_source_challenges').fetchone()[0]>=64:fail('resource_exhausted',429)
        now=now_ms();c={'protocol_version':'rim-device-registration-1','service_id':roots['service_id'],'account_id':pair[0],'device_id':pair[1],'registration_id':req['registration_id'],'signature_key':req['signature_key'],'purpose':'register_device','challenge_nonce':base64.b64encode(secrets.token_bytes(32)).decode(),'issued_at_ms':str(now),'expires_at_ms':str(now+300000)}
        raw=base64.b64encode(encode_json(c)).decode();challenge(raw)
        db.execute('INSERT INTO identity_source_challenges VALUES (?,?,?,?,?)',(*pair,req['registration_id'],raw,req['purpose']))
        return {'challenge_bytes':raw}
    if kind=='complete':
        backend(store,token);fields(req,('kind','permit','registration','approval','access_token'))
        doc=verify(store,req['permit'],roots['business_key'])
        if doc['protocol_version']!='rim-business-permit-1':fail()
        p=doc['body'];r=registration_proof(req['registration']);target={k:r[k] for k in ('account_id','device_id','signature_key')};pair=(r['account_id'],r['device_id'])
        if (p['service_id'],p['issuer'],p['audience'])!=(roots['service_id'],roots['issuer'],roots['audience']):fail('identity_source_root')
        if p['target']!=target or p['challenge_nonce']!=r['challenge_nonce'] or p['challenge_sha256']!=digest(base64.b64decode(req['registration']['statement_bytes'])) or r['service_id']!=roots['service_id']:fail('identity_source_binding')
        active(store,p['subject'],pair[0])
        if not isinstance(req['access_token'],str) or not 32<=len(req['access_token'])<=256:fail()
        # Exact successful retries check current access before returning; no signature/authority regression.
        old=db.execute('SELECT entry,result FROM identity_source_entries WHERE account=? AND device=?',pair).fetchone()
        ordered=lambda record: {k:record[k] for k in ('statement_bytes','signature_bytes')} if record else None
        entry={'registration':ordered(req['registration']),'permit':ordered(req['permit']),'approval':ordered(req['approval']),'accepted_at_ms':'0','status':'active'}
        if old:
            saved=json.loads(old['entry']);entry['accepted_at_ms']=saved['accepted_at_ms'];entry['status']=saved['status']
            current=db.execute('SELECT revoked,token_hash FROM devices WHERE account=? AND device=?',pair).fetchone()
            if current['revoked']:fail('device_revoked',403)
            if entry!=saved or current['token_hash']!=token_hash(req['access_token']):fail('idempotency_conflict')
            return json.loads(old['result'])
        c=db.execute('SELECT bytes,purpose FROM identity_source_challenges WHERE account=? AND device=? AND registration_id=?',(*pair,r['registration_id'])).fetchone()
        mapping=db.execute('SELECT subject FROM identity_source_accounts WHERE account=?',(pair[0],)).fetchone()
        if c is None or c['bytes']!=req['registration']['statement_bytes'] or c['purpose']!=p['purpose'] or mapping is None or mapping[0]!=p['subject']:fail('identity_source_binding')
        chain=snapshots(db,pair[0]);now=now_ms()
        if not int(p['issued_at_ms'])<=now<int(p['expires_at_ms']) or not int(r['issued_at_ms'])<=now<int(r['expires_at_ms']):fail('identity_source_expired')
        store.permission_verifier.verify_device_registration(req['registration'])
        if chain:
            if not any(e['status']=='active' for e in chain[-1]['devices']):fail('identity_account_recovery_required')
            if p['purpose']!='add_device' or req['approval'] is None:fail('identity_source_approval')
            a_doc=document(req['approval'])
            if a_doc['protocol_version']!='rim-account-device-approval-1':fail('identity_source_approval')
            a=a_doc['body'];verify(store,req['approval'],a['actor']['signature_key'])
            actor=a['actor'];actor_registration=db.execute('SELECT d.revoked,k.signature_key FROM devices d JOIN device_public_keys k USING(account,device) WHERE d.account=? AND d.device=?',(actor['account_id'],actor['device_id'])).fetchone()
            if (a['service_id']!=roots['service_id'] or actor['account_id']!=pair[0] or actor['device_id']==pair[1] or a['target']!=target or a['permit_sha256']!=record_digest(req['permit']) or a['previous_version']!=chain[-1]['version'] or a['previous_sha256']!=digest(encode_json(chain[-1])) or actor_registration is None or actor_registration['revoked'] or actor_registration['signature_key']!=actor['signature_key']):fail('identity_source_approval')
            if now>=int(a['expires_at_ms']):fail('identity_source_expired')
        elif p['purpose']!='first_device' or req['approval'] is not None:fail('identity_source_first')
        if db.execute('SELECT 1 FROM device_public_keys WHERE signature_key=?',(target['signature_key'],)).fetchone():fail('registration_conflict')
        active(store,p['subject'],pair[0])
        entry['accepted_at_ms']=str(now_ms())
        if not int(p['issued_at_ms'])<=int(entry['accepted_at_ms'])<int(p['expires_at_ms']) or not int(r['issued_at_ms'])<=int(entry['accepted_at_ms'])<int(r['expires_at_ms']) or (req['approval'] is not None and int(entry['accepted_at_ms'])>=int(a['expires_at_ms'])):fail('identity_source_expired')
        # These writes share the existing outer BEGIN IMMEDIATE and commit hooks.
        db.execute('INSERT INTO devices(account,device,token_hash,stream_id) VALUES (?,?,?,?)',(*pair,token_hash(req['access_token']),identifier()))
        db.execute('INSERT INTO stream_watermarks(account,device,high_watermark,floor) VALUES (?,?,0,0)',pair)
        db.execute('INSERT INTO device_public_keys VALUES (?,?,?)',(*pair,target['signature_key']))
        result=registered(r)
        db.execute('INSERT INTO device_registrations VALUES (?,?,?,?,?,?)',(*pair,r['registration_id'],c['bytes'],encode_json(ordered(req['registration'])).decode(),encode_json(result).decode()))
        db.execute('INSERT INTO identity_source_entries VALUES (?,?,?,?,?)',(*pair,p['permit_id'],encode_json(entry).decode(),encode_json(result).decode()))
        advance(store,db,pair[0])
        from key_package_storage import directory_update
        directory_update(db,pair[0])
        return result
    if kind=='directory':
        fields(req,('kind','service_id','requester','account_id','request_id','challenge'))
        actor=store.authenticate(db,token)
        key=db.execute('SELECT signature_key FROM device_public_keys WHERE account=? AND device=?',(actor['account'],actor['device'])).fetchone()
        if req['service_id']!=roots['service_id'] or req['requester']!={'account_id':actor['account'],'device_id':actor['device'],'signature_key':key[0]}:fail('identity_source_binding',403)
        chain=snapshots(db,req['account_id'])
        if not chain:fail('directory_missing',404)
        body={k:req[k] for k in ('service_id','requester','account_id','request_id','challenge')};body['snapshots']=chain
        doc=envelope('rim-authorized-directory-response-1',body);receipt=sign(store,doc)
        verify(store,receipt,roots['receipt_key'],roots)
        return {'receipt':receipt}
    if kind=='revoke':
        backend(store,token);fields(req,('kind','account_id','device_id'))
        pair=(req['account_id'],req['device_id']);row=db.execute('SELECT entry FROM identity_source_entries WHERE account=? AND device=?',pair).fetchone()
        if row is None:fail('identity_source_binding')
        e=json.loads(row[0]);e['status']='revoked';db.execute('UPDATE identity_source_entries SET entry=? WHERE account=? AND device=?',(encode_json(e).decode(),*pair));db.execute('UPDATE devices SET revoked=1 WHERE account=? AND device=?',pair)
        from key_package_storage import revoke
        revoke(db,pair);advance(store,db,pair[0]);return {'status':'revoked'}
    fail()
