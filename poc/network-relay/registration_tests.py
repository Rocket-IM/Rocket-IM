"""真实注册调度/事务/迁移边界；签名替身范围见registration_test_support。"""

from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from contract import ProtocolError, encode_json
from permission_verifier import PermissionVerifier, unavailable
from registration_storage import reserved_bytes
from registration_test_support import RegistrationFixture, encoded, proof, request
from storage import Store


class RegistrationTests(RegistrationFixture):
    def test_keyless_device_registers_once_and_original_survives_restart_and_expiry(self):
        initial = self.snapshot()
        with patch("device_registration.now_ms", return_value=1000):
            challenge = self.begin()
            pending = self.snapshot()
            self.assertEqual(self.begin(), challenge)
            result = self.complete(challenge)
        self.assertEqual(result, {"status": "registered", "service_id": "S1", "account_id": "A",
                                  "device_id": "A1", "registration_id": "R1", "signature_key": request()["signature_key"]})
        saved = self.snapshot()
        self.assertEqual(len(saved["device_public_keys"]), 1)
        self.assertIsNone(pending["device_registrations"][0][-1])
        for table in set(initial) - {"device_public_keys", "device_registrations"}:
            self.assertEqual(saved[table], initial[table])
        self.store = Store(self.path, self.fixture, self.verifier)
        with patch("device_registration.now_ms", return_value=999999999):
            self.assertEqual(self.complete(challenge), result)
            self.assertEqual(self.begin(), challenge)
        self.assertEqual(self.snapshot(), saved)
        self.assertEqual(self.verifier.calls, 1)

    def test_copy_token_id_and_key_cannot_complete_without_signature_and_does_not_consume(self):
        challenge = self.begin()
        bogus = {"service_id": "S1", "proof": {**proof(challenge), "signature_bytes": encoded(bytes(64))}}
        self.reject("registration_signature", "complete_device_registration", bogus)
        self.assertEqual(self.complete(challenge)["status"], "registered")

    def test_context_byte_replacement_and_replay_refuse_without_partial_state(self):
        challenge = self.begin()
        original = {"service_id": "S1", "proof": proof(challenge)}
        self.reject("registration_context", "complete_device_registration", original, "synthetic-A2-token")
        self.reject("registration_context", "complete_device_registration", {**original, "service_id": "S2"})
        for field, value in (("service_id", "S2"), ("account_id", "B"), ("device_id", "B1"),
                             ("registration_id", "missing"), ("signature_key", request(key_byte=12)["signature_key"]),
                             ("challenge_nonce", encoded(bytes(32)))):
            with self.subTest(field=field):
                changed = {**self.statement(challenge), field: value}
                code = "registration_context" if field in {"service_id", "account_id", "device_id"} else "registration_conflict"
                self.reject(code, "complete_device_registration", {"service_id": "S1", "proof": {
                    **proof(challenge), "statement_bytes": encoded(encode_json(changed))}})
        altered = {**proof(challenge), "statement_bytes": encoded(encode_json(self.statement(challenge)) + b" ")}
        self.reject("registration_conflict", "complete_device_registration", {"service_id": "S1", "proof": altered})
        self.complete(challenge)
        self.reject("registration_conflict", "complete_device_registration", {"service_id": "S1", "proof": {
            **proof(challenge), "signature_bytes": encoded(bytes(64))}})
        self.reject("registration_conflict", "begin_device_registration", request("R2"))

    def test_expired_future_and_cancelled_access_never_consume_challenge(self):
        with patch("device_registration.now_ms", return_value=1000):
            challenge = self.begin()
        for current in (999, 301000, 301001):
            with self.subTest(current=current), patch("device_registration.now_ms", return_value=current):
                self.reject("registration_expired", "complete_device_registration", {"service_id": "S1", "proof": proof(challenge)})
        with patch("device_registration.now_ms", return_value=300999):
            self.complete(challenge)
        with self.store.transaction() as db:
            db.execute("UPDATE devices SET revoked=1 WHERE account='A' AND device='A1'")
        self.reject("device_revoked", "complete_device_registration", {"service_id": "S1", "proof": proof(challenge)})

    def test_legacy_key_cannot_be_rebound_and_does_not_count_as_completed_proof(self):
        with self.store.transaction() as db:
            db.execute("INSERT INTO device_public_keys VALUES ('A','A1',?)", (request()["signature_key"],))
        self.store = Store(self.path, self.fixture, self.verifier)
        self.assertEqual(self.snapshot()["device_registrations"], ())
        self.reject("registration_conflict", "begin_device_registration", request(key_byte=12))
        self.reject("registration_conflict", "begin_device_registration", request(), "synthetic-A2-token")
        self.complete(self.begin())

    def test_expiry_during_public_verifier_prevents_binding_and_consumption(self):
        with patch("device_registration.now_ms", return_value=1000):
            challenge = self.begin()
        with patch("device_registration.now_ms", side_effect=(300999, 301000)):
            self.reject("registration_expired", "complete_device_registration", {"service_id": "S1", "proof": proof(challenge)})
        self.assertEqual(self.verifier.calls, 1)
        with patch("device_registration.now_ms", return_value=300999):
            self.complete(challenge)

    def test_signature_helper_failure_rolls_back_and_returned_statement_must_match(self):
        challenge = self.begin()
        with patch.object(self.verifier, "verify_device_registration", side_effect=unavailable()):
            self.reject("permission_verifier_unavailable", "complete_device_registration", {"service_id": "S1", "proof": proof(challenge)})
        verifier = PermissionVerifier.__new__(PermissionVerifier)
        with patch.object(verifier, "_call", return_value={"statement": {}}):
            with self.assertRaises(ProtocolError) as caught:
                verifier.verify_device_registration(proof(challenge))
            self.assertEqual(caught.exception.code, "permission_verifier_unavailable")
        self.complete(challenge)

    def test_outer_field_order_is_irrelevant_but_signed_original_bytes_are_fixed(self):
        challenge = self.begin()
        expected = self.complete(challenge)
        value = proof(challenge)
        request_reordered = {"proof": {"signature_bytes": value["signature_bytes"], "statement_bytes": value["statement_bytes"]}, "service_id": "S1"}
        before = self.snapshot()
        self.assertEqual(self.call("complete_device_registration", request_reordered), expected)
        self.assertEqual(self.snapshot(), before)

    def test_invalid_shapes_are_registration_errors_without_challenge_consumption(self):
        challenge = self.begin()
        statement = self.statement(challenge)
        for field, value in (("purpose", []), ("protocol_version", {}), ("issued_at_ms", 1),
                             ("expires_at_ms", "01"), ("challenge_nonce", "AA=="),
                             ("signature_key", None), ("account_id", "A\n"), ("purpose", "other")):
            with self.subTest(field=field, value=value):
                changed = {**statement, field: value}
                self.reject("registration_invalid", "complete_device_registration", {"service_id": "S1", "proof": {
                    **proof(challenge), "statement_bytes": encoded(encode_json(changed))}})
        self.reject("registration_invalid", "begin_device_registration", {**request(), "extra": True})
        self.reject("registration_invalid", "complete_device_registration", {"service_id": "S1", "proof": []})
        repeated = encode_json(statement)[:-1] + b',"purpose":"register_device"}'
        self.reject("registration_invalid", "complete_device_registration", {"service_id": "S1", "proof": {
            **proof(challenge), "statement_bytes": encoded(repeated)}})

    def test_transaction_failure_after_key_insert_rolls_back_both_key_and_consumption(self):
        challenge = self.begin()
        before = self.snapshot()
        with patch("device_registration.registered", side_effect=RuntimeError("synthetic after-insert failure")):
            with self.assertRaises(RuntimeError):
                self.complete(challenge)
        self.assertEqual(self.snapshot(), before)
        self.complete(challenge)

    def test_parallel_exact_completion_commits_one_binding_and_verifies_once(self):
        challenge = self.begin()
        barrier = Barrier(2)

        def complete():
            barrier.wait(timeout=3)
            return self.complete(challenge)

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(complete) for _ in range(2)]
            results = [future.result(timeout=8) for future in futures]
        self.assertEqual(results[0], results[1])
        self.assertEqual(self.verifier.calls, 1)
        self.assertEqual(len(self.snapshot()["device_public_keys"]), 1)

    def test_parallel_different_challenges_cannot_complete_two_bindings(self):
        challenges = (self.begin(), self.begin(request("R2")))
        barrier = Barrier(2)

        def complete(challenge):
            barrier.wait(timeout=3)
            try:
                return self.complete(challenge)["status"]
            except ProtocolError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(complete, challenge) for challenge in challenges]
            results = [future.result(timeout=8) for future in futures]
        self.assertEqual(sorted(results), ["registered", "registration_conflict"])
        saved = self.snapshot()
        self.assertEqual(len(saved["device_public_keys"]), 1)
        self.assertEqual(sum(row[-2] is not None for row in saved["device_registrations"]), 1)
        self.assertEqual(self.verifier.calls, 1)

    def test_actual_count_limit_allows_original_and_reserved_completion_without_new_charge(self):
        challenges = []
        for index in range(32):
            challenges.append(self.begin(request(f"R{index}")))
        self.reject("resource_exhausted", "begin_device_registration", request("over"))
        before = self.snapshot()
        self.assertEqual(self.begin(request("R0")), challenges[0])
        self.assertEqual(self.snapshot(), before)
        with self.store.transaction() as db:
            reserved = sum(reserved_bytes(row) for row in db.execute("SELECT * FROM device_registrations"))
        self.complete(challenges[0])
        with self.store.transaction() as db:
            self.assertEqual(sum(reserved_bytes(row) for row in db.execute("SELECT * FROM device_registrations")), reserved)

    def test_global_count_limit_is_reached_through_real_challenge_operations(self):
        for device, key_byte in (("A1", 11), ("A2", 12), ("B1", 13), ("B2", 14)):
            for index in range(32):
                self.begin(request(f"R{index}", key_byte), f"synthetic-{device}-token")
        self.reject("resource_exhausted", "begin_device_registration", request("new", 15), "synthetic-C1-token")

    def test_byte_budget_reserves_complete_record_and_exact_retry_bypasses_full_budget(self):
        first = self.begin()
        with self.store.transaction() as db:
            row = dict(db.execute("SELECT * FROM device_registrations").fetchone())
        # 仅降低门限至真实当前账本成本；不声称自然触达2MiB（128条合法记录先封顶）。
        size = reserved_bytes(row)
        with patch("registration_storage.MAX_REGISTRATION_BYTES", size):
            self.reject("resource_exhausted", "begin_device_registration", request("R2"))
            self.assertEqual(self.begin(), first)
            self.complete(first)
            self.assertEqual(self.complete(first)["status"], "registered")
        self.assertEqual(self.verifier.calls, 1)
