"""历史迁移事务的明确合成装置；没有执行 HPKE 或真实设备签名。"""

import base64
import sys
import time
from pathlib import Path

from device_join_test_support import DeviceJoinHTTPFixture, device_join_request
from history_contract import (ciphertext_digest, package_digest, request_digest,
                              validate_history_package, validate_history_request)
from join_test_support import VerifiedJoinFixture
from receipt_contract import message_envelope_digest
from receipt_test_support import VERIFIER_FIXTURE, signed
from test_support import envelope


def selection_item(accepted, envelope):
    return {"acceptance_id": accepted["acceptance_id"], "envelope_sha256": message_envelope_digest(
        base64.b64decode(envelope["header_bytes"]), base64.b64decode(envelope["payload_bytes"]))}


def transfer(selection, transfer_id="T1", nonce="f" * 64, current_time=False, **changes):
    start = int(time.time()) if current_time else 1000
    statement = {"protocol_version": "rim-history-request-1", "transfer_id": transfer_id, "service_id": "S1", "conversation_id": "G1",
                 "source": {"account_id": "B", "device_id": "B1"}, "target": {"account_id": "B", "device_id": "B3"},
                 "authorization_version": "2", "crypto_state_ref": "b" * 64, "recipient_key": base64.b64encode(bytes([31]) * 32).decode(),
                 "selection": sorted(selection, key=lambda i: i["acceptance_id"]), "nonce": nonce,
                 "issued_at_unix_secs": str(start), "expires_at_unix_secs": str(start + 300)}
    statement.update(changes)
    request = signed(statement)
    package = {"kem_output": base64.b64encode(bytes([32]) * 32).decode(), "ciphertext": base64.b64encode(bytes(32)).decode()}
    package.update(signed({"protocol_version": "rim-history-package-1", "transfer_id": transfer_id,
                           "request_sha256": request_digest(request), "ciphertext_sha256": ciphertext_digest(package)}))
    return {"service_id": "S1", "conversation_id": "G1", "request": request, "package": package}


def verified_result(request, package):
    return {"request": validate_history_request(request), "package": validate_history_package(package),
            "request_sha256": request_digest(request), "package_sha256": package_digest(package)}


class VerifiedHistoryFixture(VerifiedJoinFixture):
    def verify_history_transfer(self, checkpoint, request, package):
        return verified_result(request, package)


class HistoryTransferHTTPFixture(DeviceJoinHTTPFixture):
    def prepare_runtime(self):
        super().prepare_runtime()
        branch = (f"sys.path.insert(0,{str(Path(__file__).parent)!r})\n"
                  "if v.get('operation')=='verify_history_transfer':\n"
                  " from history_transfer_test_support import verified_result\n"
                  " print(json.dumps({'ok':True,'result':verified_result(v['request'],v['package'])}));sys.exit(0)\n")
        self.verifier_path.write_text(f"#!{sys.executable}\n" + VERIFIER_FIXTURE.replace("statement=json.loads", branch + "statement=json.loads", 1))

    def setUp(self):
        super().setUp()
        targets = [m for m in self.fixture_value()["conversation"]["members"] if m["device_id"] != "A1"]
        original = envelope(recipients=targets)
        status, accepted = self.request("submit_message", {"envelope": original})
        self.assertEqual(status, 200, accepted)
        self.item = selection_item(accepted["result"], original)
        self.assertEqual(self.submit_device(device_join_request(current_time=True))[0], 200)
        self.transfer = transfer([self.item], current_time=True)

    def submit_transfer(self, value=None, token="synthetic-B1-token"):
        return self.request("submit_history_transfer", value or self.transfer, token)

    def get_transfer(self, token="synthetic-B3-token"):
        return self.request("get_history_transfer", {"service_id": "S1", "conversation_id": "G1", "transfer_id": "T1"}, token)
