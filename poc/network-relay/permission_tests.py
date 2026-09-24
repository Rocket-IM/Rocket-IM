"""权限持久化与公共 helper 边界回归；合成验证替身不作为密码验签证据。"""

import base64
import copy
import hashlib
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import permissions
from contract import ProtocolError, encode_json, validate_request
from controls import TestControls
from permission_contract import validate_checkpoint, validate_proof
from permission_verifier import PermissionVerifier
from server import DISPATCH
from storage import Store
from test_support import fixture


def permission_fixture():
    value = fixture()
    value["devices"].append({"account_id": "A", "device_id": "A3", "token": "synthetic-A3-token"})
    for index, device in enumerate(value["devices"]):
        device["signature_key"] = base64.b64encode(bytes([index + 1]) * 32).decode()
    members = sorted([{name: device[name] for name in ("account_id", "device_id", "signature_key")} for device in value["devices"]], key=lambda item: (item["account_id"], item["device_id"]))
    value["conversation"]["members"] = [{name: member[name] for name in ("account_id", "device_id")} for member in members]
    value["permission_checkpoint"] = {"service_id": "S1", "conversation_id": "G1", "authorization_version": "1",
                                      "crypto_state_ref": "a" * 64, "owner_account_id": "A", "members": members}
    return value


def proof(change_id="C1", version="1", nonce="c" * 64, action=None, commit=b"synthetic-commit"):
    statement = {"protocol_version": "rim-permission-1", "change_id": change_id, "service_id": "S1", "conversation_id": "G1",
                 "actor": {"account_id": "A", "device_id": "A1"}, "previous_authorization_version": version,
                 "authorization_version": str(int(version) + 1), "from_state_ref": "a" * 64 if version == "1" else "b" * 64,
                 "to_state_ref": "b" * 64 if version == "1" else "d" * 64, "action": action or {"kind": "remove_member", "account_id": "B"},
                 "commit_sha256": hashlib.sha256(commit).hexdigest(), "nonce": nonce, "issued_at_unix_secs": "1000", "expires_at_unix_secs": "1300"}
    return {"statement_bytes": base64.b64encode(encode_json(statement)).decode(), "signature_bytes": base64.b64encode(bytes(64)).decode(), "commit_bytes": base64.b64encode(commit).decode()}


class VerifiedFixture:
    """只提供预先指定的已验证输出，测试事务层而非复制密码学实现。"""
    def verify(self, checkpoint, change, statement):
        action = statement["action"]
        members = [m for m in checkpoint["members"] if not (m["account_id"] == action["account_id"] and (action["kind"] == "remove_member" or m["device_id"] == action["device_id"]))]
        return {"statement": statement, "checkpoint": {**checkpoint, "members": members,
                "authorization_version": statement["authorization_version"], "crypto_state_ref": statement["to_state_ref"]}}


class PermissionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "relay.sqlite3"
        self.fixture = permission_fixture()
        self.store = Store(self.path, self.fixture, VerifiedFixture())
        self.controller = TestControls(True)

    def tearDown(self):
        self.directory.cleanup()

    def call(self, operation, req, token="synthetic-A1-token", now=1100):
        validate_request(operation, req)
        with self.store.transaction() as db, patch("permissions.time.time", return_value=now):
            device = self.store.authenticate(db, token)
            return DISPATCH[operation](self.store, db, device, req)

    def submit(self, change, **kwargs):
        return self.call("submit_permission_change", {"service_id": "S1", "conversation_id": "G1", "change": change}, **kwargs)

    def page(self, after="1", limit="32", token="synthetic-A1-token"):
        return self.call("get_permission_changes", {"service_id": "S1", "conversation_id": "G1", "after_version": after, "limit": limit}, token)

    def assert_code(self, code, call):
        with self.assertRaises(ProtocolError) as caught:
            call()
        self.assertEqual(caught.exception.code, code)

    def test_accept_exact_retry_after_expiry_and_immutable_proof(self):
        change = proof()
        accepted = self.submit(change)
        self.assertEqual(self.submit(change, now=999999), accepted)
        changed = {**change, "commit_bytes": "AQ=="}
        self.assert_code("idempotency_conflict", lambda: self.submit(changed))
        self.assertEqual(self.page()["changes"], [change])
        self.assertEqual(self.page()["authorization_version"], "2")
        self.assert_code("permission_denied", lambda: self.submit(change, token="synthetic-A2-token"))

    def test_first_acceptance_time_window_is_right_open(self):
        for now in (999, 1300, 999999):
            self.assert_code("permission_expired", lambda: self.submit(proof(), now=now))
            self.assertEqual(self.page()["changes"], [])
        self.assertEqual(self.submit(proof(), now=1000)["authorization_version"], "2")

    def test_global_nonce_replay_and_revoke_are_atomic(self):
        self.submit(proof())
        action = {"kind": "revoke_device", "account_id": "A", "device_id": "A2"}
        self.assert_code("permission_replay", lambda: self.submit(proof("C2", "2", action=action)))
        change = proof("C2", "2", nonce="d" * 64, action=action)
        self.submit(change)
        self.assert_code("device_revoked", lambda: self.page(token="synthetic-A2-token"))
        self.assertEqual(self.page()["authorization_version"], "3")
        self.assertEqual(len(self.page()["changes"]), 2)

    def test_removed_member_keeps_token_but_loses_history_and_cannot_override(self):
        self.submit(proof())
        self.assert_code("permission_denied", lambda: self.page(token="synthetic-B1-token"))
        with self.store.transaction() as db:
            self.assertEqual(self.store.authenticate(db, "synthetic-B1-token")["revoked"], 0)
        for action in ("set_state", "revoke_device", "add_control"):
            with self.assertRaises(ProtocolError) as caught, self.store.transaction() as db:
                self.controller.execute(self.store, db, self.fixture["controller_token"], {"action": action})
            self.assertEqual(caught.exception.code, "permission_denied")

    def test_pages_and_restarts_preserve_initial_version_and_original_bytes(self):
        first = proof(commit=b"x" * (512 * 1024))
        second = proof("C2", "2", nonce="d" * 64, action={"kind": "revoke_device", "account_id": "A", "device_id": "A2"}, commit=b"y" * (512 * 1024))
        self.submit(first)
        self.submit(second)
        page = self.page()
        self.assertEqual(page["changes"], [first])
        self.assertEqual((page["next_after_version"], page["authorization_version"], page["has_more"]), ("2", "3", True))
        self.assertLess(len(encode_json({"ok": True, "result": page})), 900 * 1024)
        self.assertEqual(self.page(after="2")["changes"], [second])
        self.assert_code("cursor_invalid", lambda: self.page(after="0"))
        self.assert_code("cursor_invalid", lambda: self.page(after="18446744073709551615"))
        self.store = Store(self.path, fixture(), VerifiedFixture())
        self.assertTrue(self.store.permission_enabled)
        self.assertEqual(self.page(), page)

    def test_signed_mode_requires_evidence_chain_instead_of_old_control_channel(self):
        self.assert_code("permission_chain_required", lambda: self.call("get_crypto_dependencies",
                         {"service_id": "S1", "conversation_id": "G1", "from_state_ref": "a" * 64, "to_state_ref": "b" * 64, "limit": "1"}))

    def test_public_helper_failure_does_not_change_database(self):
        self.store.permission_verifier = None
        self.assert_code("permission_verifier_unavailable", lambda: self.submit(proof()))
        self.assertEqual(self.page()["changes"], [])
        self.assertEqual(self.page()["authorization_version"], "1")

    def test_bootstrap_rejects_missing_reused_and_mismatched_keys(self):
        for kind in ("missing", "reused", "mismatch"):
            value = copy.deepcopy(self.fixture)
            if kind == "missing":
                del value["devices"][0]["signature_key"]
            elif kind == "reused":
                value["permission_checkpoint"]["members"][1]["signature_key"] = value["permission_checkpoint"]["members"][0]["signature_key"]
            else:
                value["permission_checkpoint"]["crypto_state_ref"] = "f" * 64
            with self.assertRaises((ValueError, ProtocolError)):
                Store(Path(self.directory.name) / f"{kind}.sqlite3", value)

    def test_new_database_initialization_rolls_back_as_a_whole(self):
        target = Path(self.directory.name) / "interrupted.sqlite3"
        with patch("permissions.PERMISSION_SCHEMA", permissions.PERMISSION_SCHEMA + "INVALID SQL;"), self.assertRaises(sqlite3.OperationalError):
            Store(target, self.fixture)
        db = sqlite3.connect(target)
        try:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0], 0)
        finally:
            db.close()
        recovered = Store(target, self.fixture)
        self.assertTrue(recovered.permission_enabled)

    def test_legacy_database_cannot_receive_a_fixture_checkpoint(self):
        target = Path(self.directory.name) / "legacy.sqlite3"
        Store(target, fixture())
        with self.assertRaises(ValueError):
            Store(target, self.fixture)
        self.assertFalse(Store(target, fixture()).permission_enabled)


class PublicVerifierTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "fixture-verifier"
        self.checkpoint = permission_fixture()["permission_checkpoint"]
        self.change = proof()
        self.statement = validate_proof(self.change)

    def tearDown(self):
        self.directory.cleanup()

    def verifier(self, source):
        self.path.write_text(f"#!{sys.executable}\n" + source)
        self.path.chmod(0o700)
        return PermissionVerifier(self.path)

    def assert_unavailable(self, source):
        with self.assertRaises(ProtocolError) as caught:
            self.verifier(source).verify(self.checkpoint, self.change, self.statement)
        self.assertEqual(caught.exception.code, "permission_verifier_unavailable")

    def test_missing_timeout_oversize_and_malformed_helper_outputs_fail_closed(self):
        self.assert_unavailable("print('not-json')\n")
        self.assert_unavailable("print('x' * 70000)\n")
        with patch("permission_verifier.VERIFIER_TIMEOUT", 0.05):
            self.assert_unavailable("import time\ntime.sleep(5)\n")
        verifier = self.verifier("print('{}')\n")
        self.path.unlink()
        with self.assertRaises(ProtocolError) as caught:
            verifier.verify(self.checkpoint, self.change, self.statement)
        self.assertEqual(caught.exception.code, "permission_verifier_unavailable")

    def test_expected_helper_rejection_is_typed(self):
        source = "import sys\nsys.stdin.buffer.read()\nprint('{\"ok\":false,\"error\":{\"code\":\"permission_signature\",\"message\":\"invalid\"}}')\nsys.exit(1)\n"
        with self.assertRaises(ProtocolError) as caught:
            self.verifier(source).verify(self.checkpoint, self.change, self.statement)
        self.assertEqual((caught.exception.code, caught.exception.status), ("permission_signature", 403))

    def test_success_output_must_match_exact_statement_and_derived_checkpoint(self):
        result = VerifiedFixture().verify(self.checkpoint, self.change, self.statement)
        source = "import sys\nsys.stdin.buffer.read()\nprint(" + repr(json.dumps({"ok": True, "result": result})) + ")\n"
        self.assertEqual(self.verifier(source).verify(self.checkpoint, self.change, self.statement), result)
        result["checkpoint"]["owner_account_id"] = "B"
        self.assert_unavailable("import sys\nsys.stdin.buffer.read()\nprint(" + repr(json.dumps({"ok": True, "result": result})) + ")\n")


if __name__ == "__main__":
    unittest.main()
