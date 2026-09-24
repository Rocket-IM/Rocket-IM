"""终态事务测试用明确替身；不实现或验证任何密码签名。"""

import base64
import json
import sys
import time

from contract import ProtocolError, encode_json
from http_test_support import RelayHTTPFixture
from permission_tests import VerifiedFixture, permission_fixture, proof
from receipt_contract import proof_digest, signed_statement, validate_close

SERVICE_KEY = base64.b64encode(bytes([29]) * 32).decode()


def signed(statement):
    return {"statement_bytes": base64.b64encode(encode_json(statement)).decode(),
            "signature_bytes": base64.b64encode(bytes(64)).decode()}


def close_for(change):
    statement = signed_statement({name: change[name] for name in ("statement_bytes", "signature_bytes")})
    return signed({"protocol_version": "rim-permission-close-1", "service_id": statement["service_id"],
                   "conversation_id": statement["conversation_id"], "actor": statement["actor"],
                   "change_id": statement["change_id"], "proof_sha256": proof_digest(change)})


def receipt_fixture():
    value = permission_fixture()
    value["relay_receipt_key"] = SERVICE_KEY
    return value


class VerifiedCloseFixture(VerifiedFixture):
    def verify_close(self, checkpoint, change, close):
        return {"statement": validate_close(close)}


class ReceiptFixture:
    def __init__(self, key=SERVICE_KEY):
        self.key = key
        self.signature_key = None
        self.calls = 0
        self.fail = False

    def public_key(self):
        return self.key

    def sign(self, statement):
        self.calls += 1
        if self.fail:
            raise ProtocolError("receipt_signer_unavailable", "合成签名器故障", status=503)
        return signed(statement)


VERIFIER_FIXTURE = '''import base64,json,sys
v=json.load(sys.stdin)
statement=json.loads(base64.b64decode(v['close' if 'close' in v else 'change']['statement_bytes']))
result={'statement':statement}
if 'close' not in v:
 cp=v['checkpoint']; action=statement['action']
 if action['kind'] in {'add_member','add_device'}:
  assert 'join' in v
  members=sorted(cp['members']+[action['member']],key=lambda m:(m['account_id'],m['device_id']))
 else: members=[m for m in cp['members'] if not(m['account_id']==action['account_id'] and(action['kind']=='remove_member' or m['device_id']==action['device_id']))]
 result['checkpoint']={**cp,'members':members,'authorization_version':statement['authorization_version'],'crypto_state_ref':statement['to_state_ref']}
print(json.dumps({'ok':True,'result':result}))
'''
SIGNER_FIXTURE = '''import base64,json,sys
v=json.load(sys.stdin)
key=open(v['key_path']).read().strip()
if v['operation']=='public_key': result={'signature_key':key}
elif v.get('expected_signature_key')!=key: sys.exit(1)
else: result={'receipt':{'statement_bytes':base64.b64encode(json.dumps(v['statement'],separators=(',',':')).encode()).decode(),'signature_bytes':base64.b64encode(bytes(64)).decode()}}
print(json.dumps({'ok':True,'result':result}))
'''


class ReceiptHTTPFixture(RelayHTTPFixture):
    def fixture_value(self):
        return receipt_fixture()

    def prepare_runtime(self):
        self.verifier_path = self.path / "fixture-permission-verifier"
        self.signer_path = self.path / "fixture-receipt-signer"
        for path, source in ((self.verifier_path, VERIFIER_FIXTURE), (self.signer_path, SIGNER_FIXTURE)):
            path.write_text(f"#!{sys.executable}\n" + source)
            path.chmod(0o700)
        self.key_path = self.path / "fixture-receipt-key"
        self.key_path.write_text(SERVICE_KEY)
        self.key_path.chmod(0o600)
        self.change = proof()
        statement = json.loads(base64.b64decode(self.change["statement_bytes"]))
        statement["issued_at_unix_secs"] = str(int(time.time()))
        statement["expires_at_unix_secs"] = str(int(time.time()) + 300)
        self.change["statement_bytes"] = base64.b64encode(encode_json(statement)).decode()

    def start(self, controls=True, verifier=None):
        super().start(controls, self.verifier_path, self.signer_path, self.key_path)
