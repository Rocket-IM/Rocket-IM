"""独立授权账本与原注册/目录同一事务；只在显式配置时启用。"""
import json
from urllib.parse import urlparse
from contract import fields, validate_id, decode_bytes, validate_state_ref
from identity_source_contract import digest, fail
from contract import encode_json
SCHEMA='''
CREATE TABLE identity_source_config (singleton INTEGER PRIMARY KEY CHECK(singleton=1), config TEXT NOT NULL);
CREATE TABLE identity_source_accounts (account TEXT PRIMARY KEY, subject TEXT UNIQUE NOT NULL);
CREATE TABLE identity_source_challenges (account TEXT, device TEXT, registration_id TEXT, bytes TEXT NOT NULL, purpose TEXT NOT NULL, PRIMARY KEY(account,device,registration_id));
CREATE TABLE identity_source_entries (account TEXT, device TEXT, permit_id TEXT UNIQUE NOT NULL, entry TEXT NOT NULL, result TEXT NOT NULL, PRIMARY KEY(account,device));
CREATE TABLE identity_source_directories (account TEXT,version INTEGER, snapshot TEXT NOT NULL, PRIMARY KEY(account,version));
'''
def install(store,config,db):
    fields(config,('roots','backend_token_hash','issuer_url','status_token'))
    roots=config['roots'];fields(roots,('service_id','issuer','audience','business_key','receipt_key'))
    for name in ('service_id','issuer','audience'):validate_id(roots[name],name)
    for name in ('business_key','receipt_key'):
        if len(decode_bytes(roots[name],name,32))!=32:fail('identity_source_root')
    url=urlparse(config['issuer_url'])
    if (url.scheme!='http' or url.hostname!='127.0.0.1' or not url.port or url.path or url.query or url.fragment or url.username or url.password or roots['business_key']==roots['receipt_key'] or roots['receipt_key']!=store.receipt_signer.signature_key or roots['service_id']!=store.meta(db,'service_id')):fail('identity_source_root')
    validate_state_ref(config['backend_token_hash'])
    if not isinstance(config['status_token'],str) or not 16<=len(config['status_token'])<=256:fail('identity_source_root')
    if not db.in_transaction: raise ValueError('身份来源初始化必须在启动事务内')
    exists=db.execute("SELECT 1 FROM sqlite_master WHERE name='identity_source_config'").fetchone()
    encoded=encode_json(config).decode()
    if not exists:
        if db.execute('SELECT 1 FROM devices').fetchone():fail('identity_source_legacy')
        for sql in SCHEMA.strip().split(';'):
            if sql.strip():db.execute(sql)
        db.execute('INSERT INTO identity_source_config VALUES (1,?)',(encoded,))
    elif db.execute('SELECT config FROM identity_source_config').fetchone()[0]!=encoded:fail('identity_source_root')
    from identity_source_contract import sign, verify, envelope
    for account, in db.execute('SELECT DISTINCT account FROM identity_source_directories'):
        chain=snapshots(db,account)
        if not chain or len(chain)>16:fail('identity_source_state')
        from registration_contract import proof
        reg=proof(chain[-1]['devices'][0]['registration'])
        requester={k:reg[k] for k in ('account_id','device_id','signature_key')}
        response=envelope('rim-authorized-directory-response-1',{'service_id':config['roots']['service_id'],'requester':requester,'account_id':account,'request_id':'startup-validation','challenge':'0'*64,'snapshots':chain})
        verify(store,sign(store,response),config['roots']['receipt_key'],config['roots'])
        entries=[json.loads(row[0]) for row in db.execute('SELECT entry FROM identity_source_entries WHERE account=? ORDER BY device',(account,))]
        if entries!=chain[-1]['devices']:fail('identity_source_state')
        for entry in entries:
            r=proof(entry['registration']);pair=(account,r['device_id'])
            row=db.execute('SELECT d.revoked,k.signature_key FROM devices d JOIN device_public_keys k USING(account,device) WHERE d.account=? AND d.device=?',pair).fetchone()
            if row is None or row['signature_key']!=r['signature_key'] or bool(row['revoked'])!=(entry['status']=='revoked'):fail('identity_source_state')
    if db.execute('SELECT 1 FROM devices d LEFT JOIN identity_source_entries e USING(account,device) WHERE e.account IS NULL').fetchone():fail('identity_source_state')

def snapshots(db,account):return [json.loads(row[0]) for row in db.execute('SELECT snapshot FROM identity_source_directories WHERE account=? ORDER BY version',(account,))]
def advance(store,db,account):
    chain=snapshots(db,account)
    if len(chain)>=16:fail('resource_exhausted',429)
    entries=[json.loads(row[0]) for row in db.execute('SELECT entry FROM identity_source_entries WHERE account=? ORDER BY device',(account,))]
    if not entries or len(entries)>8:fail('resource_exhausted',429)
    s={'protocol_version':'rim-authorized-device-directory-1','service_id':store.identity_config['roots']['service_id'],'account_id':account,'version':str(len(chain)+1),'previous_sha256':digest(encode_json(chain[-1])) if chain else '0'*64,'devices':entries}
    db.execute('INSERT INTO identity_source_directories VALUES (?,?,?)',(account,len(chain)+1,encode_json(s).decode()))
    return s
