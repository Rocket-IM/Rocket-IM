#!/usr/bin/env python3
"""独立本机业务签发实验：验证实验会话、稳定映射并签准确登记许可。"""
import argparse
import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import sys
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from contract import encode_json,parse_json,fields,ProtocolError
from receipt_signer import ReceiptSigner
from identity_source_contract import envelope,digest,fail
from registration_contract import challenge as parse_challenge

class IssuerServer(ThreadingHTTPServer):
    daemon_threads=True
    request_queue_size=8
    def __init__(self,*args):
        self.slots=threading.BoundedSemaphore(8)
        super().__init__(*args)
    def process_request(self,request,address):
        if not self.slots.acquire(blocking=False):self.shutdown_request(request);return
        try:super().process_request(request,address)
        except BaseException:self.slots.release();raise
    def process_request_thread(self,request,address):
        try:super().process_request_thread(request,address)
        finally:self.slots.release()

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*_args):pass
    def do_POST(self):
        try:
            if self.headers.get('Content-Type')!='application/json':fail('invalid_request',400)
            size=int(self.headers.get('Content-Length','0'))
            if not 1<=size<=1024*1024:fail('resource_exhausted',413)
            self.connection.settimeout(5)
            req=parse_json(self.rfile.read(size));token=self.headers.get('Authorization','').removeprefix('Bearer ')
            # Config is an experiment authority record; no mutation endpoint or implicit account mapping.
            config=parse_json(self.server.config.read_bytes())
            if self.path=='/status':
                fields(req,('subject','account_id'))
                if not hmac.compare_digest(token,config['status_token']):fail('unauthenticated',401)
                value={'active':any(x['subject']==req['subject'] and x['account_id']==req['account_id'] and x['active'] for x in config['sessions'])}
            else:
                session=next((x for x in config['sessions'] if hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(),x['token_hash']) and x['active']),None)
                if session is None:fail('unauthenticated',401)
                if self.path=='/challenge':
                    fields(req,('device_id','signature_key','registration_id','purpose'))
                    forwarded={'kind':'challenge','account_id':session['account_id'],'subject':session['subject'],**req}
                    c=self.forward(config,forwarded)
                    raw=base64.b64decode(c['challenge_bytes']);statement=parse_challenge(c['challenge_bytes'])
                    expected=(config['roots']['service_id'],session['account_id'],req['device_id'],req['signature_key'],req['registration_id'])
                    actual=tuple(statement[k] for k in ('service_id','account_id','device_id','signature_key','registration_id'))
                    if actual!=expected:fail('identity_source_binding',403)
                    if not int(statement['issued_at_ms'])<=int(time.time()*1000)<int(statement['expires_at_ms']):fail('identity_source_expired')
                    body={'service_id':config['roots']['service_id'],'issuer':config['roots']['issuer'],'audience':config['roots']['audience'],'subject':session['subject'],'permit_id':'permit-'+digest(encode_json([session['subject'],session['account_id'],req['device_id'],req['registration_id']]))[:40],
                          'target':{k:statement[k] for k in ('account_id','device_id','signature_key')},'challenge_sha256':digest(raw),'challenge_nonce':statement['challenge_nonce'],'purpose':req['purpose'],'issued_at_ms':statement['issued_at_ms'],'expires_at_ms':statement['expires_at_ms']}
                    doc=envelope('rim-business-permit-1',body)
                    # Persist the exact issued bytes/result under one bounded writer transaction.
                    with self.server.lock:
                        db=sqlite3.connect(self.server.database,isolation_level=None)
                        try:
                            db.execute('BEGIN IMMEDIATE');old=db.execute('SELECT request,result FROM permits WHERE account=? AND device=? AND id=?',(session['account_id'],req['device_id'],req['registration_id'])).fetchone()
                            encoded=encode_json(doc).decode()
                            if old:
                                if old[0]!=encoded:fail('idempotency_conflict')
                                value=json.loads(old[1])
                            else:
                                if db.execute('SELECT count(*) FROM permits').fetchone()[0]>=64:fail('resource_exhausted',429)
                                signer=self.server.signer
                                permit=signer._call({'operation':'sign','statement':doc,'expected_signature_key':config['roots']['business_key']})['receipt']
                                value={**c,'permit':permit}
                                db.execute('INSERT INTO permits VALUES (?,?,?,?,?)',(session['account_id'],req['device_id'],req['registration_id'],encoded,encode_json(value).decode()))
                            db.commit()
                        except BaseException:db.rollback();raise
                        finally:db.close()
                elif self.path=='/complete':
                    fields(req,('permit','registration','approval','access_token'))
                    body=json.loads(base64.b64decode(req['permit']['statement_bytes']))['body']
                    if body['subject']!=session['subject'] or body['target']['account_id']!=session['account_id']:fail('identity_source_subject',403)
                    value=self.forward(config,{'kind':'complete',**req})
                else:fail('unsupported_operation',404)
            self.reply(200,{'ok':True,'result':value})
        except ProtocolError as error:self.reply(error.status,{'ok':False,'error':{'code':error.code,'message':error.message}})
        except Exception:self.reply(503,{'ok':False,'error':{'code':'identity_authority_unavailable','message':'签发实验请求失败，查询或重试原件'}})
    def forward(self,config,req):
        url=config['relay_url']+'/v1/identity_source'
        request=urllib.request.Request(url,data=encode_json(req),headers={'Content-Type':'application/json','Authorization':'Bearer '+config['backend_token']})
        try:
            with urllib.request.urlopen(request,timeout=4) as response:result=parse_json(response.read(1024*1024+1))
        except urllib.error.HTTPError as error:result=parse_json(error.read(1024*1024+1))
        if not result['ok']:fail(result['error']['code'],409)
        return result['result']
    def reply(self,status,value):
        raw=encode_json(value);self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.send_header('Connection','close');self.end_headers();self.wfile.write(raw);self.close_connection=True

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',type=Path,required=True);p.add_argument('--database',type=Path,required=True);p.add_argument('--signer',type=Path,required=True);p.add_argument('--key',type=Path,required=True);p.add_argument('--port',type=int,default=0);a=p.parse_args()
    if not all(x.is_absolute() for x in (a.config,a.database,a.signer,a.key)):p.error('所有路径必须绝对路径')
    if not 0<=a.port<=65535:p.error('port 范围无效')
    signer=ReceiptSigner(a.signer,a.key);config=parse_json(a.config.read_bytes())
    if signer.public_key()!=config['roots']['business_key']:p.error('业务钥与固定根不符')
    with sqlite3.connect(a.database) as db:db.execute('CREATE TABLE IF NOT EXISTS permits(account TEXT,device TEXT,id TEXT,request TEXT,result TEXT,PRIMARY KEY(account,device,id))')
    a.database.chmod(0o600)
    server=IssuerServer(('127.0.0.1',a.port),Handler);server.config=a.config;server.database=a.database;server.signer=signer;server.lock=threading.Lock()
    print(json.dumps({'status':'ready','url':f'http://127.0.0.1:{server.server_port}'}),flush=True)
    try:server.serve_forever(poll_interval=.1)
    except KeyboardInterrupt:pass
    finally:server.server_close()
if __name__=='__main__':main()
