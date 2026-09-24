"""重建流的事务、输入与访问边界；签名替身只测存储，真实验签由跨进程验证覆盖。"""

import base64
import concurrent.futures
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from contract import ProtocolError, encode_json, validate_request
from device_join_test_support import device_join_fixture, device_join_request
from join_test_support import VerifiedJoinFixture
from receipt_contract import proof_digest, signed_statement
from receipt_test_support import ReceiptFixture, signed
from rebuild_stream_contract import signed_digest, validate_binding, validate_page_receipt
from rebuild_stream_storage import authorize_operation
from server import DISPATCH
from storage import Store
from synchronization import set_availability
from test_support import envelope


class VerifiedStreamFixture(VerifiedJoinFixture):
    def verify_rebuild_stream(self, trusted, registration):
        return {"request": signed_statement(registration["request"]), "request_sha256": signed_digest(registration["request"])}

    def verify_rebuild_pull(self, binding, request):
        return {"pull": signed_statement(request), "request_sha256": signed_digest(request)}


class RebuildStreamTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "relay.sqlite3"
        self.fixture = device_join_fixture()
        self.target = next(d for d in self.fixture["devices"] if d["device_id"] == "B3")
        checkpoint = self.fixture["permission_checkpoint"]
        authorizer = next(m for m in checkpoint["members"] if m["device_id"] == "B1")
        self.trusted = {"old_scope": {"service": "S1", "account": "B", "device": "B0", "identity_key": "ee" * 32, "store_id": "a" * 64},
                        "anchor_public_key": "b" * 64,
                        "trust": {"authorizer": authorizer, "checkpoint": copy.deepcopy(checkpoint), "relay_receipt_key": self.fixture["relay_receipt_key"]}}
        self.target["rebuild_trust"] = self.trusted
        self.signer = ReceiptFixture()
        self.verifier = VerifiedStreamFixture()
        self.store = Store(self.path, self.fixture, self.verifier, self.signer)
        self.join = device_join_request()
        self.successor = {"service": "S1", "account": "B", "device": "B3",
                          "identity_key": base64.b64decode(self.target["signature_key"]).hex(), "store_id": "c" * 64}

    def call(self, operation, req, token="synthetic-B3-token"):
        validate_request(operation, req)
        with self.store.transaction() as db, patch("permissions.time.time", return_value=1100):
            device = self.store.authenticate(db, token)
            authorize_operation(db, device, operation)
            return DISPATCH[operation](self.store, db, device, req)

    def assert_code(self, code, call):
        with self.assertRaises(ProtocolError) as error:
            call()
        self.assertEqual(error.exception.code, code)

    def prepare(self):
        result = self.call("submit_permission_change", self.join, "synthetic-B1-token")
        statement = signed_statement({name: self.join["change"][name] for name in ("statement_bytes", "signature_bytes")})
        plan = {"protocol_version": "rim-anchor-rebuild-1", "rebuild_id": "d" * 64,
                **self.trusted, "old_head": "1" * 64, "old_txn": "2" * 64, "old_revision": "1",
                "old_conversation_id": "OLD", "old_group_id": "AQ==", "successor_scope": self.successor,
                "successor_head": "3" * 64, "successor_client_public_key": "4" * 64,
                "key_package_sha256": statement["action"]["key_package_sha256"]}
        request = {"protocol_version": "rim-rebuild-stream-request-1", "plan_sha256": "5" * 64,
                   "successor_scope": self.successor, "conversation_id": "G1", "stream_id": "6" * 64,
                   "initial_cursor": "0", "join_proof_sha256": proof_digest(self.join["change"])}
        self.registration = {"plan": plan, "approval": signed({}), "anchor_request": signed({}), "anchor_response": signed({}),
                             "request": signed(request), "join_record": {"change": self.join["change"], "receipt": result["receipt"]}}

    def register(self, registration=None):
        return self.call("register_rebuild_stream", {"service_id": "S1", "registration": registration or self.registration})

    def pull(self, binding, **changes):
        statement = {"protocol_version": "rim-rebuild-stream-pull-1", "service_id": "S1", "conversation_id": "G1",
                     "successor_scope": self.successor, "stream_id": "6" * 64, "binding_sha256": signed_digest(binding),
                     "after_seq": "0", "limit": "100", "challenge": "7" * 64, **changes}
        return self.call("pull_rebuild_events", {"service_id": "S1", "request": signed(statement)})

    def send(self, logical="M1", payload=b"opaque-fixture"):
        with self.store.transaction() as db:
            conv = db.execute("SELECT * FROM conversation").fetchone()
            recipients = [{"account_id": a, "device_id": d} for a, d in self.store.members(db) if (a, d) != ("B", "B1")]
        value = envelope(logical_id=logical, payload=payload, sender={"account_id": "B", "device_id": "B1"},
                         recipients=recipients, authorization_version=conv["authorization_version"], crypto_state_ref=conv["crypto_state_ref"])
        return self.call("submit_message", {"envelope": value}, "synthetic-B1-token")

    def rows(self):
        with self.store.transaction() as db:
            return list(db.iterdump())

    def test_pending_and_bound_devices_cannot_use_ordinary_stream_or_pending_send(self):
        pull = {"service_id": "S1", "after_seq": "0", "limit": "1"}
        self.assert_code("rebuild_stream_denied", lambda: self.call("pull_events", pull))
        self.assert_code("rebuild_stream_denied", lambda: self.call("pull_events_signed", pull))
        self.assert_code("rebuild_stream_pending", lambda: self.call("submit_message", {"envelope": envelope()}))
        self.prepare()
        self.register()
        self.assert_code("rebuild_stream_denied", lambda: self.call("pull_events", pull))
        self.assert_code("rebuild_stream_denied", lambda: self.call("pull_events_signed", pull))

    def test_pending_messages_survive_registration_and_page_binds_original_bytes(self):
        self.prepare()
        self.send()
        with self.store.transaction() as db:
            events = [tuple(r) for r in db.execute("SELECT * FROM events WHERE account='B' AND device='B3'")]
        binding = self.register()["binding"]
        page = self.pull(binding)
        raw = base64.b64decode(page["page_bytes"])
        statement = validate_page_receipt(page["receipt"])
        self.assertEqual(statement["page_sha256"], hashlib.sha256(raw).hexdigest())
        decoded = json.loads(raw)
        self.assertEqual((decoded["next_after_seq"], decoded["watermark"], decoded["events"][0]["event_seq"]), ("1", "1", "1"))
        self.assertEqual(statement["binding_sha256"], signed_digest(binding))
        with self.store.transaction() as db:
            self.assertEqual(events, [tuple(r) for r in db.execute("SELECT * FROM events WHERE account='B' AND device='B3'")])

    def availability_after_registration(self, availability, registered):
        self.prepare()
        binding = self.register()["binding"] if registered else None
        accepted = self.send()
        with self.store.transaction() as db:
            original = dict(db.execute("SELECT seq,event_id,content FROM events WHERE account='B' AND device='B3'").fetchone())
            temporary_stream = db.execute("SELECT stream_id FROM devices WHERE account='B' AND device='B3'").fetchone()[0]
            set_availability(db, accepted["acceptance_id"], availability)
            saved = [tuple(r) for r in db.execute("SELECT * FROM events WHERE account='B' AND device='B3' ORDER BY seq")]
        if binding is None:
            binding = self.register()["binding"]
            self.assertNotEqual(temporary_stream, "6" * 64)
        response = self.pull(binding)
        raw = base64.b64decode(response["page_bytes"])
        page = json.loads(raw)
        statement = validate_page_receipt(response["receipt"])
        self.assertEqual(statement["page_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual((page["stream_id"], page["next_after_seq"], page["watermark"]), ("6" * 64, "2", "2"))
        target, notification = page["events"]
        self.assertEqual(target, {"stream_id": "6" * 64, "event_seq": "1", "event_id": original["event_id"], "availability": availability})
        self.assertEqual(notification["event"], {"type": "message_availability", "target_event_seq": "1",
            "target_event_id": original["event_id"], "acceptance_id": accepted["acceptance_id"],
            "attempt_id": accepted["attempt_id"], "availability": availability})
        self.assertEqual(notification["availability"], "available")
        tail = json.loads(base64.b64decode(self.pull(binding, after_seq="1")["page_bytes"]))
        self.assertEqual(tail["events"], [notification])
        with self.store.transaction() as db:
            self.assertEqual(saved, [tuple(r) for r in db.execute("SELECT * FROM events WHERE account='B' AND device='B3' ORDER BY seq")])
        self.store = Store(self.path, self.fixture, self.verifier, self.signer)
        self.assertEqual(self.pull(binding), response)

    def test_pending_deletion_notification_survives_registered_stream_rebinding(self):
        self.availability_after_registration("deleted", registered=False)

    def test_pending_expiration_notification_survives_registered_stream_rebinding(self):
        self.availability_after_registration("expired", registered=False)

    def test_bound_deletion_notification_is_signed_and_survives_restart(self):
        self.availability_after_registration("deleted", registered=True)

    def test_bound_expiration_notification_is_signed_and_survives_restart(self):
        self.availability_after_registration("expired", registered=True)

    def test_availability_notice_rejects_wrong_target_acceptance_and_terminal_before_signing(self):
        self.prepare()
        binding = self.register()["binding"]
        accepted = self.send("M1")
        other = self.send("M2")
        with self.store.transaction() as db:
            set_availability(db, accepted["acceptance_id"], "deleted")
            row = db.execute("SELECT content,event_id FROM events WHERE account='B' AND device='B3' AND seq=3").fetchone()
            original = json.loads(row["content"])
            foreign_id = db.execute("SELECT event_id FROM events WHERE account='A' AND device='A1' AND seq=1").fetchone()[0]
            notice_id = row["event_id"]
        changes = [{"target_event_seq": "0"}, {"target_event_seq": "2"}, {"target_event_seq": "3"},
                   {"target_event_seq": "4"}, {"target_event_id": "missing"}, {"target_event_id": foreign_id},
                   {"target_event_id": notice_id}, {"acceptance_id": other["acceptance_id"]},
                   {"attempt_id": "other"}, {"availability": "expired"}, {"availability": "available"},
                   {"stream_id": "old-stream"}]
        for changed in changes:
            with self.subTest(changed=changed):
                with self.store.transaction() as db:
                    db.execute("UPDATE events SET content=? WHERE account='B' AND device='B3' AND seq=3", (encode_json({**original, **changed}).decode(),))
                before, count = self.rows(), self.signer.calls
                self.assert_code("rebuild_stream_context", lambda: self.pull(binding, after_seq="2"))
                self.assertEqual(self.signer.calls, count)
                self.assertEqual(self.rows(), before)

    def test_availability_notice_cannot_relabel_before_join_or_other_conversation_history(self):
        self.prepare()
        binding = self.register()["binding"]
        accepted = self.send()
        with self.store.transaction() as db:
            set_availability(db, accepted["acceptance_id"], "deleted")
            row = db.execute("SELECT header FROM attempts WHERE acceptance_id=?", (accepted["acceptance_id"],)).fetchone()
            header = json.loads(row["header"])
        for changed in ({"authorization_version": "0"}, {"conversation_id": "OLD"}, {"service_id": "OTHER"}):
            with self.subTest(changed=changed):
                with self.store.transaction() as db:
                    db.execute("UPDATE attempts SET header=? WHERE acceptance_id=?", (encode_json({**header, **changed}), accepted["acceptance_id"]))
                before, count = self.rows(), self.signer.calls
                self.assert_code("rebuild_stream_context", lambda: self.pull(binding, after_seq="1"))
                self.assertEqual(self.signer.calls, count)
                self.assertEqual(self.rows(), before)

    def test_availability_notice_requires_original_message_bytes_and_acceptance_proof(self):
        self.prepare()
        binding = self.register()["binding"]
        accepted = self.send()
        with self.store.transaction() as db:
            set_availability(db, accepted["acceptance_id"], "deleted")
            original = json.loads(db.execute("SELECT content FROM events WHERE account='B' AND device='B3' AND seq=1").fetchone()[0])
        changed_payload = copy.deepcopy(original)
        changed_payload["envelope"]["payload_bytes"] = base64.b64encode(b"different-fixture").decode()
        candidates = [{**original, "type": "delivery"}, {**original, "acceptance_receipt": None}, changed_payload]
        for value in candidates:
            with self.subTest(value=value):
                with self.store.transaction() as db:
                    db.execute("UPDATE events SET content=? WHERE account='B' AND device='B3' AND seq=1", (encode_json(value).decode(),))
                before, count = self.rows(), self.signer.calls
                self.assert_code("rebuild_stream_context", lambda: self.pull(binding, after_seq="1"))
                self.assertEqual(self.signer.calls, count)
                self.assertEqual(self.rows(), before)

    def test_exact_retry_and_restart_preserve_binding_and_reject_second_generation(self):
        self.prepare()
        first = self.register()
        self.send()
        self.pull(first["binding"])
        before, count = self.rows(), self.signer.calls
        self.assertEqual(first, self.register())
        self.assertEqual(count, self.signer.calls)
        self.assertEqual(before, self.rows())
        self.store = Store(self.path, self.fixture, self.verifier, self.signer)
        self.assertEqual(first, self.register())
        changed = copy.deepcopy(self.registration)
        changed["request"] = signed({**signed_statement(changed["request"]), "stream_id": "8" * 64})
        self.assert_code("rebuild_stream_context", lambda: self.register(changed))
        self.assertEqual(before, self.rows())

    def test_new_database_trust_cannot_be_changed_removed_or_added_on_restart(self):
        for change in ("remove", "alter"):
            fixture = copy.deepcopy(self.fixture)
            target = next(d for d in fixture["devices"] if d["device_id"] == "B3")
            if change == "remove":
                del target["rebuild_trust"]
            else:
                target["rebuild_trust"]["anchor_public_key"] = "f" * 64
            with self.assertRaises(ValueError):
                Store(self.path, fixture, self.verifier, self.signer)
        other = self.path.parent / "legacy.sqlite3"
        Store(other, device_join_fixture(), self.verifier, self.signer)
        with self.assertRaises(ValueError):
            Store(other, self.fixture, self.verifier, self.signer)

    def test_binding_signer_failure_rolls_back_then_concurrent_exact_retry_is_single(self):
        self.prepare()
        before = self.rows()
        self.signer.fail = True
        self.assert_code("receipt_signer_unavailable", self.register)
        self.assertEqual(before, self.rows())
        self.signer.fail = False
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            results = list(pool.map(lambda _: self.register(), range(2)))
        self.assertEqual(results[0], results[1])
        self.assertEqual(validate_binding(results[0]["binding"])["initial_cursor"], "0")

    def test_wrong_database_join_receipt_or_bearer_cannot_register(self):
        self.prepare()
        changed = copy.deepcopy(self.registration)
        changed["join_record"]["receipt"] = signed({**signed_statement(changed["join_record"]["receipt"]), "proof_sha256": "9" * 64})
        self.assert_code("rebuild_stream_denied", lambda: self.register(changed))
        self.assert_code("rebuild_stream_denied", lambda: self.call("register_rebuild_stream", {"service_id": "S1", "registration": self.registration}, "synthetic-B1-token"))

    def test_signed_pull_rejects_other_binding_and_no_longer_current_member(self):
        self.prepare()
        binding = self.register()["binding"]
        self.assert_code("rebuild_stream_context", lambda: self.pull(binding, binding_sha256="0" * 64))
        with self.store.transaction() as db:
            db.execute("DELETE FROM members WHERE account='B' AND device='B3'")
        self.assert_code("permission_denied", lambda: self.pull(binding))

    def test_cross_conversation_event_even_as_tombstone_is_never_signed(self):
        self.prepare()
        self.send()
        binding = self.register()["binding"]
        with self.store.transaction() as db:
            row = db.execute("SELECT header FROM attempts WHERE outcome='accepted'").fetchone()
            header = json.loads(row["header"])
            header["conversation_id"] = "OLD"
            db.execute("UPDATE attempts SET header=?", (encode_json(header),))
            db.execute("UPDATE events SET availability='deleted'")
        before, count = self.rows(), self.signer.calls
        self.assert_code("rebuild_stream_context", lambda: self.pull(binding))
        self.assertEqual(count, self.signer.calls)
        self.assertEqual(before, self.rows())

    def test_maximum_ciphertexts_page_within_cli_limit_and_resume_exact_next(self):
        self.prepare()
        self.send("M1", b"x" * (512 * 1024))
        self.send("M2", b"x" * (512 * 1024))
        binding = self.register()["binding"]
        first = self.pull(binding)
        self.assertLess(len(encode_json({"ok": True, "result": first})), 1024 * 1024)
        page = json.loads(base64.b64decode(first["page_bytes"]))
        self.assertEqual((len(page["events"]), page["next_after_seq"], page["watermark"], page["has_more"]), (1, "1", "2", True))
        second = json.loads(base64.b64decode(self.pull(binding, after_seq="1")["page_bytes"]))
        self.assertEqual(second["events"][0]["event_seq"], "2")

    def test_other_member_cannot_transfer_history_to_rebuilt_target(self):
        from history_transfers import check_access
        self.prepare()
        for registered in (False, True):
            if registered:
                self.register()
            with self.store.transaction() as db:
                conv = db.execute("SELECT * FROM conversation").fetchone()
                device = self.store.authenticate(db, "synthetic-B1-token")
                statement = {"service_id": "S1", "conversation_id": "G1", "source": {"account_id": "B", "device_id": "B1"},
                             "target": {"account_id": "B", "device_id": "B3"}, "authorization_version": conv["authorization_version"],
                             "crypto_state_ref": conv["crypto_state_ref"]}
                self.assert_code("history_denied", lambda: check_access(self.store, db, device, statement, "S1", "G1"))

    def test_missing_rebuild_table_cannot_silently_downgrade_to_ordinary_stream(self):
        with self.store.transaction() as db:
            db.execute("DROP TABLE rebuild_streams")
        with self.assertRaises(ValueError):
            Store(self.path, device_join_fixture(), self.verifier, self.signer)

    def test_same_old_scope_cannot_pin_two_targets_by_reordering_json_keys(self):
        fixture = copy.deepcopy(self.fixture)
        second = next(d for d in fixture["devices"] if d["device_id"] == "A3")
        second.update(account_id="B", device_id="B4")
        trusted = copy.deepcopy(self.trusted)
        trusted["old_scope"] = dict(reversed(list(trusted["old_scope"].items())))
        second["rebuild_trust"] = trusted
        with self.assertRaises(ValueError):
            Store(self.path.parent / "duplicate.sqlite3", fixture, self.verifier, self.signer)


class RebuildStreamContractTests(unittest.TestCase):
    def test_availability_event_fixed_shape_vectors(self):
        from rebuild_streams import availability_target_sequence
        path = Path(__file__).resolve().parents[2] / "api/realtime/vectors.json"
        vectors = json.loads(path.read_text())["message_availability_vectors"]
        for vector in vectors:
            with self.subTest(vector=vector["name"]):
                before = copy.deepcopy(vector["value"])
                if vector["expected_code"] is None:
                    self.assertEqual(availability_target_sequence(vector["value"]), int(vector["value"]["target_event_seq"]))
                else:
                    with self.assertRaises(ProtocolError) as error:
                        availability_target_sequence(vector["value"])
                    self.assertEqual(error.exception.code, vector["expected_code"])
                self.assertEqual(vector["value"], before)

    def test_fixed_digest_uses_original_statement_and_signature_bytes(self):
        path = Path(__file__).resolve().parents[2] / "api/realtime/vectors.json"
        vector = json.loads(path.read_text())["rebuild_stream_signed_digest_vector"]
        self.assertEqual(signed_digest(vector["signed"]), vector["sha256"])
        changed = {**vector["signed"], "statement_bytes": base64.b64encode(b'{"x": 1}').decode()}
        self.assertNotEqual(signed_digest(changed), vector["sha256"])

    def test_api_statements_match_runtime_fields_and_limits(self):
        from rebuild_stream_contract import MAX_PAGE_BYTES
        path = Path(__file__).resolve().parents[2] / "api/realtime/message.schema.json"
        definitions = json.loads(path.read_text())["$defs"]
        common = {"protocol_version", "plan_sha256", "successor_scope", "conversation_id", "stream_id", "initial_cursor", "join_proof_sha256"}
        pull = {"protocol_version", "service_id", "conversation_id", "successor_scope", "stream_id", "binding_sha256", "after_seq", "limit", "challenge"}
        for name, expected in (("RebuildStreamRequestStatement", common), ("RebuildStreamBindingStatement", common | {"request_sha256"}),
                               ("RebuildStreamPullStatement", pull), ("RebuildStreamPageStatement", pull | {"request_sha256", "page_sha256"})):
            definition = definitions[name]
            self.assertEqual(set(definition["properties"]), expected)
            self.assertEqual(set(definition["required"]), expected)
            self.assertFalse(definition["additionalProperties"])
        self.assertEqual(definitions["RebuildStreamPageResult"]["properties"]["page_bytes"]["x-max-decoded-bytes"], MAX_PAGE_BYTES)

    def test_signer_whitelist_checks_binding_and_page_output_exactly(self):
        import sys
        from receipt_signer import ReceiptSigner
        successor = {"service": "S", "account": "A", "device": "D", "identity_key": "1" * 64, "store_id": "2" * 64}
        binding = {"protocol_version": "rim-rebuild-stream-binding-1", "request_sha256": "3" * 64,
                   "plan_sha256": "4" * 64, "successor_scope": successor, "conversation_id": "G", "stream_id": "5" * 64,
                   "initial_cursor": "0", "join_proof_sha256": "6" * 64}
        page = {"protocol_version": "rim-rebuild-stream-page-1", "binding_sha256": "7" * 64, "request_sha256": "8" * 64,
                "service_id": "S", "conversation_id": "G", "successor_scope": successor, "stream_id": "5" * 64,
                "after_seq": "0", "limit": "10", "challenge": "9" * 64, "page_sha256": "a" * 64}
        signer = ReceiptSigner(Path(sys.executable), Path("/unused-test-seed"))
        signer.signature_key = "fixture"
        for statement in (binding, page):
            with patch.object(signer, "_call", return_value={"receipt": signed(statement)}):
                self.assertEqual(signer.sign(statement), signed(statement))
            with patch.object(signer, "_call", return_value={"receipt": signed({**statement, "stream_id": "b" * 64})}):
                with self.assertRaises(ProtocolError) as error:
                    signer.sign(statement)
                self.assertEqual(error.exception.code, "receipt_signer_unavailable")


if __name__ == "__main__":
    unittest.main()
