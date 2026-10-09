"""真实HTTP/SQLite提交窗口；明确使用验签替身，不报告密码学PoP通过。"""

import http.client
import sqlite3
import sys
from contextlib import closing

from http_test_support import RelayHTTPFixture
from registration_test_support import SYNTHETIC_SIGNATURE, encoded, proof, request


class RegistrationHTTPTests(RelayHTTPFixture):
    def prepare_runtime(self):
        self.verifier = self.path / "transaction_only_verifier.py"
        # 此独立进程仅标记验证器调用成功/失败；真实签名由联合Rust矩阵另验。
        self.verifier.write_text(f"#!{sys.executable}\n" + '''
import base64, json, sys
request = json.load(sys.stdin)
assert request["operation"] == "verify_device_registration"
proof = request["proof"]
''' + f'if proof["signature_bytes"] != {SYNTHETIC_SIGNATURE!r}:\n' + '''
    print(json.dumps({"ok": False, "error": {"code": "registration_signature", "message": "synthetic rejection"}}))
    sys.exit(1)
print(json.dumps({"ok": True, "result": {"statement": json.loads(base64.b64decode(proof["statement_bytes"]))}}))
''')
        self.verifier.chmod(0o700)

    def start(self, **options):
        super().start(verifier=self.verifier, **options)

    def state(self):
        uri = (self.path / "relay.sqlite3").resolve().as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, isolation_level=None)) as db:
            db.execute("BEGIN")
            catalog = tuple(db.execute("SELECT type,name,sql FROM sqlite_master ORDER BY type,name"))
            result = {"__schema__": catalog}
            for kind, name, _ in catalog:
                if kind == "table":
                    quoted = '"' + name.replace('"', '""') + '"'
                    result[name] = tuple(db.execute(f"SELECT * FROM {quoted} ORDER BY rowid"))
            db.commit()
            return result

    def begin(self, value=None):
        status, body = self.request("begin_device_registration", value or request())
        self.assertEqual(status, 200, body)
        return body["result"]

    def complete(self, challenge):
        value = {"service_id": "S1", "proof": proof(challenge)}
        status, body = self.request("complete_device_registration", value)
        self.assertEqual(status, 200, body)
        return body["result"]

    def fault(self, operation, value, hook):
        self.control({"action": "hook", "hook": hook})
        with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError)):
            self.request(operation, value)
        if hook != "drop_after_commit":
            self.assertEqual(self.process.wait(timeout=3), 86 if hook == "before_commit_exit" else 87)
            self.stop()

    def test_begin_before_commit_exit_has_no_challenge_and_retry_creates_one(self):
        before = self.state()
        self.fault("begin_device_registration", request(), "before_commit_exit")
        self.assertEqual(self.state(), before)
        self.start()
        challenge = self.begin()
        self.assertEqual(self.begin(), challenge)
        self.assertEqual(len(self.state()["device_registrations"]), 1)

    def test_begin_after_commit_exit_restores_exact_saved_challenge(self):
        self.fault("begin_device_registration", request(), "after_commit_exit")
        saved = self.state()
        self.start()
        self.assertEqual(self.begin(), {"challenge_bytes": saved["device_registrations"][0][3]})
        self.assertEqual(self.state(), saved)

    def test_begin_dropped_committed_response_keeps_one_challenge(self):
        self.fault("begin_device_registration", request(), "drop_after_commit")
        saved = self.state()
        self.assertEqual(self.begin(), {"challenge_bytes": saved["device_registrations"][0][3]})
        self.assertEqual(self.state(), saved)

    def test_complete_before_commit_exit_rolls_back_binding_and_consumption(self):
        challenge = self.begin()
        before = self.state()
        self.fault("complete_device_registration", {"service_id": "S1", "proof": proof(challenge)}, "before_commit_exit")
        self.assertEqual(self.state(), before)
        self.start()
        self.assertEqual(self.complete(challenge)["status"], "registered")

    def test_complete_after_commit_exit_restores_exact_binding_and_result(self):
        challenge = self.begin()
        self.fault("complete_device_registration", {"service_id": "S1", "proof": proof(challenge)}, "after_commit_exit")
        saved = self.state()
        self.assertEqual(len(saved["device_public_keys"]), 1)
        self.assertIsNotNone(saved["device_registrations"][0][-2])
        self.start()
        first = self.complete(challenge)
        self.assertEqual(self.complete(challenge), first)
        self.assertEqual(self.state(), saved)

    def test_complete_dropped_committed_response_does_not_duplicate_binding(self):
        challenge = self.begin()
        self.fault("complete_device_registration", {"service_id": "S1", "proof": proof(challenge)}, "drop_after_commit")
        saved = self.state()
        self.assertEqual(self.complete(challenge)["status"], "registered")
        self.assertEqual(self.state(), saved)

    def test_signature_and_scope_rejections_leave_armed_hook_and_original_rows(self):
        challenge = self.begin()
        original = {"service_id": "S1", "proof": proof(challenge)}
        self.control({"action": "hook", "hook": "before_commit_exit"})
        before = self.state()
        status, body = self.request("complete_device_registration", original, "synthetic-A2-token")
        self.assertEqual((status, body["error"]["code"]), (403, "registration_context"))
        status, body = self.request("complete_device_registration", {"service_id": "S1", "proof": {
            **proof(challenge), "signature_bytes": encoded(bytes(64))}})
        self.assertEqual((status, body["error"]["code"]), (403, "registration_signature"))
        self.assertEqual(self.state(), before)
        with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError)):
            self.request("complete_device_registration", original)
        self.assertEqual(self.process.wait(timeout=3), 86)
        self.stop()
        self.assertEqual(self.state(), before)
