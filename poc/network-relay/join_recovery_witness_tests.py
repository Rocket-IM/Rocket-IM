"""可信启动配置与原子迁移；使用真实公共验证程序，不构造 MLS 负例。"""
import base64
from contextlib import closing
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from contract import ProtocolError, encode_json
from permission_verifier import PermissionVerifier
from storage import Store


class WitnessConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        binary = os.environ.get("RIM_TEST_PERMISSION_VERIFIER")
        if not binary:
            raise unittest.SkipTest("需显式提供真实 Release 公共验证程序")
        cls.verifier = PermissionVerifier(binary)
        cls.vector = json.loads((Path(__file__).resolve().parents[2] /
                                 "api/realtime/join-recovery-witness-vectors.json").read_text())

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        self.database = self.path / "relay.sqlite3"
        self.config_path = self.path / "trusted-config.json"
        self.activation = copy.deepcopy(self.vector["unsigned_objects"]["activation"]["decoded"])
        policy = self.vector["unsigned_objects"]["policy"]["decoded"]
        fact = self.vector["unsigned_objects"]["installation_fact"]["decoded"]
        self.checkpoint = fact["previous"]["checkpoint"]
        self.domains = [{"member": member, "control_domain_id": (
            policy["independence"]["control_domain_id"] if member == policy["witness"]
            else "domain_" + member["account_id"])} for member in self.checkpoint["members"]]
        self.fixture = {
            "service_id": self.checkpoint["service_id"],
            "controller_token": "synthetic-controller-token",
            "devices": [{**member, "token": "synthetic-" + member["device_id"] + "-token"}
                        for member in self.checkpoint["members"]],
            "conversation": {
                "conversation_id": self.checkpoint["conversation_id"],
                "authorization_version": self.checkpoint["authorization_version"],
                "crypto_state_ref": self.checkpoint["crypto_state_ref"],
                "members": [{key: member[key] for key in ("account_id", "device_id")}
                            for member in self.checkpoint["members"]]},
            "permission_checkpoint": self.checkpoint,
        }

    def config(self, activation=None, domains=None):
        activation = self.activation if activation is None else activation
        return encode_json({
            "activation_bytes": base64.b64encode(encode_json(activation)).decode(),
            "policy_bytes": (self.vector["unsigned_objects"]["policy"]["raw_bytes"]
                             if activation["policy_ref"] is not None else None),
            "control_domains": self.domains if domains is None else domains,
        })

    def load(self, raw, pin=None):
        self.config_path.write_bytes(raw)
        pin = hashlib.sha256(raw).hexdigest() if pin is None else pin
        with patch.dict(os.environ, {"RIM_RECOVERY_WITNESS_CONFIG_SHA256": pin}):
            return Store(self.database, self.fixture, self.verifier,
                         recovery_witness_config=self.config_path)

    def snapshot(self):
        with closing(sqlite3.connect(self.database)) as db:
            db.execute("BEGIN")
            result = tuple(db.iterdump())
            db.commit()
            return result

    def rejected(self, raw, expected, pin=None):
        before = self.snapshot()
        with self.assertRaises((ValueError, ProtocolError)) as caught:
            self.load(raw, pin)
        if isinstance(caught.exception, ProtocolError):
            self.assertEqual(caught.exception.code, expected)
        else:
            self.assertIn(expected, str(caught.exception))
        self.assertEqual(before, self.snapshot())

    def test_exact_trusted_config_preserved_and_restart_idempotent(self):
        raw = self.config()
        self.load(raw)
        before = self.snapshot()
        self.load(raw)
        self.assertEqual(before, self.snapshot())
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute("SELECT config_bytes FROM recovery_witness_configs")
                             .fetchone()[0], raw)

    def test_activation_and_policy_can_have_distinct_trusted_authority_sources(self):
        self.activation["trusted_authorization_ref"] = {
            "source_id": "separate_activation_authority", "source_sha256": "cd" * 32}
        self.load(self.config())

    def test_no_policy_activation_then_authorized_monotonic_binding_retains_original(self):
        no_policy = self.activation | {"policy_ref": None}
        original = self.config(no_policy)
        self.load(original)
        before = self.snapshot()
        self.activation["activation_version"] = "2"
        bound = self.config()
        self.load(bound)
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute("SELECT version,config_bytes FROM recovery_witness_configs "
                                        "ORDER BY version").fetchall(), [("1", original), ("2", bound)])
            self.assertEqual(db.execute("SELECT count(*) FROM recovery_witness_bindings").fetchone()[0], 0)
        self.assertNotEqual(before, self.snapshot())

    def test_latest_activation_cannot_roll_back_or_remove_policy(self):
        self.activation["activation_version"] = "2"
        self.load(self.config())
        self.rejected(self.config(self.activation | {"activation_version": "1"}), "w1_activation_rollback")
        self.rejected(self.config(self.activation | {"activation_version": "3", "policy_ref": None}),
                      "w1_policy_mismatch")

    def test_same_revision_different_original_is_not_an_exact_retry(self):
        self.load(self.config())
        self.rejected(self.config(self.activation | {"activation_id": "changed_bytes"}),
                      "w1_activation_unauthorized")

    def test_config_pin_rejects_unauthorized_revision_without_writes(self):
        original = self.config()
        self.load(original)
        self.activation["activation_version"] = "2"
        self.rejected(self.config(), "独立固定摘要不符", hashlib.sha256(original).hexdigest())

    def test_same_policy_cannot_rebind_control_domains(self):
        self.load(self.config())
        self.activation["activation_version"] = "2"
        domains = copy.deepcopy(self.domains)
        domains[0]["control_domain_id"] = "replacement_actor_domain"
        self.rejected(self.config(domains=domains), "w1_policy_mismatch")

    def test_enabled_restart_requires_original_trusted_configuration(self):
        self.load(self.config())
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "重启必须提供"):
            Store(self.database, self.fixture, self.verifier)
        self.assertEqual(before, self.snapshot())

    def test_missing_pin_rejects_without_changing_configuration(self):
        raw = self.config()
        self.load(raw)
        before = self.snapshot()
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "缺少独立摘要"):
                Store(self.database, self.fixture, self.verifier,
                      recovery_witness_config=self.config_path)
        self.assertEqual(before, self.snapshot())
