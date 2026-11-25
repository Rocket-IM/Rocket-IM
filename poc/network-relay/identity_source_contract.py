"""Q01公开对象边界；实际签名和授权链由Rust验证，Python不实现密码算法。"""
import base64
import hashlib
from contract import ProtocolError, fields, encode_json, parse_json, decode_bytes

def fail(code='identity_source_invalid', status=409):
    raise ProtocolError(code, '身份来源、授权或目录证据不满足契约', status=status)

def digest(raw): return hashlib.sha256(raw).hexdigest()
def record_digest(record): return digest(encode_json({k:record[k] for k in ('statement_bytes','signature_bytes')}))
def document(record):
    fields(record, ('statement_bytes','signature_bytes'))
    if len(decode_bytes(record['signature_bytes'],'signature_bytes',64))!=64: fail()
    return parse_json(decode_bytes(record['statement_bytes'],'statement_bytes',384*1024))

def verify(store,record,key,roots=None):
    request={'operation':'verify_identity_source','proof':record,'key':key,'roots':roots}
    return store.permission_verifier._call(request)['document']

def sign(store,doc):
    if store.receipt_signer is None: fail('receipt_signer_unavailable',503)
    return store.receipt_signer._call({'operation':'sign','statement':doc,'expected_signature_key':store.receipt_signer.signature_key})['receipt']

def envelope(version,body):return {'protocol_version':version,'body':body}
