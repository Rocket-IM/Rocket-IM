"""M07/M09 装置回归：SQLite 屏障与 helper 配置；替身不作为真实签名验收。"""

import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from email.message import Message
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import concurrency_relay
from concurrency_relay import ObservedStore, TransactionProbe
from contract import ProtocolError
from messages import submit
from permission_tests import VerifiedFixture, permission_fixture
from receipt_test_support import ReceiptFixture, receipt_fixture
from test_support import envelope, fixture


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rim-m07-probe-")
        self.data = fixture()
        self.token = self.data["controller_token"]
        self.probe = TransactionProbe(self.token, True)
        self.store = ObservedStore(Path(self.temporary.name) / "relay.sqlite", self.data, self.probe)

    def tearDown(self):
        self.probe.close()
        self.temporary.cleanup()

    def arm(self, **options):
        return self.probe.execute(self.token, {"action": "arm", "labels": [{"label": "tx1", **options}]})["key"]

    @staticmethod
    def headers(key, label="tx1"):
        headers = Message()
        headers["X-RIM-Test-Transaction"] = label
        headers["X-RIM-Test-Key"] = key
        return headers

    def wait_stage(self, stage):
        with self.probe.condition:
            self.assertTrue(self.probe.condition.wait_for(
                lambda: any(event["stage"] == stage for event in self.probe.events), timeout=2))
            return next(event for event in self.probe.events if event["stage"] == stage)

    def release(self, point, decision):
        return self.probe.execute(self.token, {"action": "release", "label": "tx1", "point": point, "decision": decision})

    def send(self, key):
        with self.probe.bind(self.headers(key)):
            with self.store.transaction() as db:
                device = self.store.authenticate(db, "synthetic-A1-token")
                return submit(self.store, db, device, {"envelope": envelope()})

    def visible(self):
        with closing(self.store.connect()) as db:
            db.execute("BEGIN")
            counts = tuple(db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]
                           for table in ("attempts", "events"))
            db.commit()
            return counts

    def assert_code(self, code, operation):
        with self.assertRaises(ProtocolError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_commit_waits_with_uncommitted_fanout_and_actual_begin_trace(self):
        key = self.arm(hold_before_commit=True)
        with ThreadPoolExecutor(1) as pool:
            future = pool.submit(self.send, key)
            event = self.wait_stage("before_commit_waiting")
            self.assertEqual((event["pending"]["accepted"], event["pending"]["message_events"]), ("1", "2"))
            self.assertEqual(sorted(s["events"] for s in event["pending"]["streams"]), ["0", "0", "1", "1"])
            self.assertEqual(self.visible(), (0, 0))
            self.assertFalse(future.done())
            self.release("before_commit", "commit")
            self.assertEqual(future.result(timeout=2)["outcome"], "accepted")
        self.assertEqual(self.visible(), (1, 2))
        stages = [event["stage"] for event in self.probe.events]
        self.assertEqual(stages, ["requested", "begin_requested", "acquired", "before_commit_waiting",
                                  "before_commit_released", "committed"])

    def test_controlled_rollback_uses_original_transaction_and_reuses_sequence(self):
        key = self.arm(hold_before_commit=True)
        with ThreadPoolExecutor(1) as pool:
            future = pool.submit(self.send, key)
            self.wait_stage("before_commit_waiting")
            self.release("before_commit", "rollback")
            error = self.assert_code("test_transaction_rollback", lambda: future.result(timeout=2))
            self.assertEqual((error.status, error.outcome), (503, "not_recorded"))
        self.assertEqual(self.visible(), (0, 0))
        self.assertEqual(self.probe.events[-1]["stage"], "rolled_back")
        with self.store.transaction() as db:
            device = self.store.authenticate(db, "synthetic-A1-token")
            submit(self.store, db, device, {"envelope": envelope(logical_id="M2")})
            self.assertEqual([row[0] for row in db.execute("SELECT seq FROM events")], [1, 1])

    def test_before_begin_gate_releases_without_claiming_database_transaction(self):
        key = self.arm(hold_before_begin=True)
        with ThreadPoolExecutor(1) as pool:
            future = pool.submit(self.send, key)
            self.wait_stage("before_begin_waiting")
            self.assertEqual([event["stage"] for event in self.probe.events], ["requested", "before_begin_waiting"])
            self.release("before_begin", "continue")
            self.assertEqual(future.result(timeout=2)["outcome"], "accepted")
        self.assertEqual(self.visible(), (1, 2))

    def test_real_sqlite_trace_signals_waiter_before_writer_releases(self):
        key = self.probe.execute(self.token, {"action": "arm", "labels": [
            {"label": "tx1", "hold_before_commit": True}, {"label": "tx2"}]})["key"]

        def read_waiter():
            with self.probe.bind(self.headers(key, "tx2")):
                with self.store.transaction() as db:
                    return db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]

        with ThreadPoolExecutor(2) as pool:
            writer = pool.submit(self.send, key)
            self.wait_stage("before_commit_waiting")
            reader = pool.submit(read_waiter)
            with self.probe.condition:
                self.assertTrue(self.probe.condition.wait_for(lambda: any(
                    event["label"] == "tx2" and event["stage"] == "begin_requested"
                    for event in self.probe.events), timeout=2))
                self.assertFalse(any(event["label"] == "tx2" and event["stage"] == "acquired"
                                     for event in self.probe.events))
            self.assertFalse(reader.done())
            self.release("before_commit", "commit")
            self.assertEqual(writer.result(timeout=2)["outcome"], "accepted")
            self.assertEqual(reader.result(timeout=2), 1)

    def test_timeout_rolls_back_and_marks_finished(self):
        self.probe.gate_timeout = 0.02
        key = self.arm(hold_before_commit=True)
        error = self.assert_code("test_transaction_timeout", lambda: self.send(key))
        self.assertEqual((error.status, error.outcome), (503, "not_recorded"))
        self.assertEqual(self.visible(), (0, 0))
        self.assertEqual([event["stage"] for event in self.probe.events][-2:], ["before_commit_timeout", "rolled_back"])
        self.assertTrue(self.probe.execute(self.token, {"action": "status"})["labels"][0]["finished"])

    def test_close_wakes_waiter_and_rolls_back_without_leaking_thread_binding(self):
        key = self.arm(hold_before_commit=True)
        cleared = threading.Event()

        def run():
            try:
                self.send(key)
            finally:
                if self.probe.current_label() is None:
                    cleared.set()

        with ThreadPoolExecutor(1) as pool:
            future = pool.submit(run)
            self.wait_stage("before_commit_waiting")
            self.probe.close()
            self.assert_code("test_transaction_timeout", lambda: future.result(timeout=2))
        self.assertTrue(cleared.is_set())
        self.assertEqual(self.visible(), (0, 0))

    def test_authorization_one_shot_labels_and_secret_free_evidence(self):
        self.assert_code("permission_denied", lambda: self.probe.execute("wrong", {"action": "status"}))
        self.assert_code("permission_denied", lambda: self.probe.execute("错误凭证", {"action": "status"}))
        key = self.arm()
        self.assert_code("state_conflict", self.arm)

        def bind(headers):
            with self.probe.bind(headers):
                pass

        self.assert_code("permission_denied", lambda: bind(self.headers("wrong")))
        self.assert_code("permission_denied", lambda: bind(self.headers("错误密钥")))
        self.assert_code("state_conflict", lambda: bind(self.headers(key, "unknown")))
        duplicated = self.headers(key)
        duplicated["X-RIM-Test-Key"] = key
        self.assert_code("test_transaction_invalid", lambda: bind(duplicated))
        self.send(key)
        self.assert_code("state_conflict", lambda: bind(self.headers(key)))
        evidence = json.dumps(self.probe.execute(self.token, {"action": "status"}))
        self.assertNotIn(key, evidence)
        self.assertNotIn(self.token, evidence)
        self.assertIsNone(self.probe.current_label())

    def test_strict_control_shapes_and_limits(self):
        for labels in ([], [{"label": "tx1", "hold_before_commit": 1}],
                       [{"label": "tx1"}, {"label": "tx1"}], [{"label": "bad label"}],
                       [{"label": "tx1", "extra": False}], [{"label": "tx" + str(i)} for i in range(9)]):
            with self.subTest(labels=labels):
                self.assert_code("test_transaction_invalid", lambda: self.probe.execute(self.token, {"action": "arm", "labels": labels}))
        key = self.arm(hold_before_commit=True)
        self.assert_code("state_conflict", lambda: self.release("before_commit", "commit"))
        self.assert_code("test_transaction_invalid", lambda: self.release("before_commit", "continue"))
        self.assert_code("test_transaction_invalid", lambda: self.probe.execute(self.token, {"action": "status", "extra": key}))
        self.probe.control_count = 512
        self.assert_code("resource_exhausted", lambda: self.probe.execute(self.token, {"action": "status"}))
        disabled = TransactionProbe(self.token, False)
        self.assert_code("permission_denied", lambda: disabled.execute(self.token, {"action": "status"}))


class WrapperConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rim-message-wrapper-")
        self.directory = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def arguments(self, value, *options):
        fixture_path = self.directory / "fixture.json"
        fixture_path.write_text(json.dumps(value))
        return ["concurrency_relay.py", "--database", str(self.directory / "relay.sqlite"),
                "--fixture", str(fixture_path), "--enable-test-controls", *options]

    def test_original_unsigned_default_uses_real_store_and_closes_probe(self):
        with patch("sys.argv", self.arguments(fixture())), patch.object(
                concurrency_relay, "RelayServer") as server, patch("sys.stdout", new=StringIO()):
            server.return_value.server_port = 0
            concurrency_relay.main()
        store = server.call_args.args[1]
        self.assertFalse(store.permission_enabled)
        self.assertFalse(store.receipt_enabled)
        self.assertIsNone(store.permission_verifier)
        self.assertIsNone(store.receipt_signer)
        self.assertTrue(store.probe.closed)
        server.return_value.server_close.assert_called_once()

    def test_permission_checkpoint_requires_explicit_verifier_before_listener(self):
        with patch("sys.argv", self.arguments(permission_fixture())), patch.object(
                concurrency_relay, "RelayServer") as server, patch("sys.stderr", new=StringIO()) as diagnostic:
            with self.assertRaises(SystemExit) as stopped:
                concurrency_relay.main()
        self.assertEqual(stopped.exception.code, 2)
        self.assertIn("必须配置 --permission-verifier", diagnostic.getvalue())
        server.assert_not_called()

    def test_receipt_signer_and_key_must_be_configured_together(self):
        for option in ("--receipt-signer", "--receipt-key"):
            with self.subTest(option=option), patch("sys.argv", self.arguments(
                    fixture(), option, str(self.directory / "helper"))), patch.object(
                    concurrency_relay, "RelayServer") as server, patch("sys.stderr", new=StringIO()) as diagnostic:
                with self.assertRaises(SystemExit) as stopped:
                    concurrency_relay.main()
                self.assertEqual(stopped.exception.code, 2)
                self.assertIn("必须同时提供", diagnostic.getvalue())
                server.assert_not_called()

    def test_configured_helpers_reach_original_store_and_pinned_receipt_key(self):
        # 只验证装配和持久固定公钥；真实 Rust 验签由 M09 联合运行证明。
        verifier, signer = VerifiedFixture(), ReceiptFixture()
        verifier_path, signer_path, key_path = (self.directory / name for name in ("verifier", "signer", "key"))
        arguments = self.arguments(receipt_fixture(), "--permission-verifier", str(verifier_path),
                                   "--receipt-signer", str(signer_path), "--receipt-key", str(key_path))
        with patch("sys.argv", arguments), patch.object(concurrency_relay, "PermissionVerifier", return_value=verifier) as make_verifier, patch.object(
                concurrency_relay, "ReceiptSigner", return_value=signer) as make_signer, patch.object(
                concurrency_relay, "RelayServer") as server, patch("sys.stdout", new=StringIO()):
            server.return_value.server_port = 0
            concurrency_relay.main()
        make_verifier.assert_called_once_with(verifier_path)
        make_signer.assert_called_once_with(signer_path, key_path)
        store = server.call_args.args[1]
        self.assertTrue(store.permission_enabled and store.receipt_enabled)
        self.assertIs(store.permission_verifier, verifier)
        self.assertIs(store.receipt_signer, signer)
        with store.transaction() as db:
            self.assertEqual(store.meta(db, "relay_receipt_key"), signer.key)
        self.assertEqual(signer.signature_key, signer.key)


if __name__ == "__main__":
    unittest.main()
