"""验证持久化一致性和访问边界；真实 MLS 互通由仓库级验证入口执行。"""

import base64
import concurrent.futures
import tempfile
import threading
import unittest
from pathlib import Path

from contract import ProtocolError, encode_json, validate_request
from controls import TestControls
from server import DISPATCH
from storage import Store
from test_support import envelope, fixture, key


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "relay.sqlite3"
        self.fixture = fixture()
        self.store = Store(self.path, self.fixture)
        self.controller = TestControls(True)

    def tearDown(self):
        self.directory.cleanup()

    def call(self, operation, req, token="synthetic-A1-token"):
        validate_request(operation, req)
        with self.store.transaction() as db:
            device = self.store.authenticate(db, token)
            return DISPATCH[operation](self.store, db, device, req)

    def control(self, req):
        with self.store.transaction() as db:
            return self.controller.execute(self.store, db, self.fixture["controller_token"], req)

    def pull(self, device="B1", **fields):
        return self.call("pull_events", {"service_id": "S1", "after_seq": "0", "limit": "100", **fields}, f"synthetic-{device}-token")

    def assert_code(self, code, operation, req, token="synthetic-A1-token"):
        with self.assertRaises(ProtocolError) as error:
            self.call(operation, req, token)
        self.assertEqual(error.exception.code, code)

    def test_retry_exact_bytes_and_one_atomic_fanout(self):
        req = {"envelope": envelope()}
        accepted = self.call("submit_message", req)
        self.assertEqual(self.call("submit_message", req), accepted)
        self.assert_code("idempotency_conflict", "submit_message", {"envelope": envelope(payload=b"other")})
        self.assert_code("logical_message_already_accepted", "submit_message", {"envelope": envelope(attempt_id="P2")})
        self.assertEqual(self.control({"action": "stats"})["message_events"], "2")
        self.assertEqual(len(self.pull()["events"]), 1)

    def test_close_unknown_then_late_packet_and_successor_race(self):
        closure = self.call("close_attempt", key())
        self.assertEqual(self.call("close_attempt", key()), closure)
        self.assert_code("attempt_closed", "submit_message", {"envelope": envelope()})
        barrier = threading.Barrier(2)

        def successor(attempt):
            barrier.wait()
            try:
                return self.call("submit_message", {"envelope": envelope(attempt_id=attempt),
                                 "replaces_attempt_id": "P1", "closure_id": closure["closure_id"]})["outcome"]
            except ProtocolError as error:
                return error.code
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            futures = [pool.submit(successor, attempt) for attempt in ("P2", "P3")]
            outcomes = [future.result() for future in futures]
        self.assertEqual(sorted(outcomes), ["accepted", "logical_message_already_accepted"])
        self.assertEqual(self.control({"action": "stats"})["accepted"], "1")

    def test_rejected_state_persists_closure_and_cannot_skip_chain(self):
        req = {"envelope": envelope(authorization_version="0")}
        rejected = self.call("submit_message", req)
        self.assertEqual(rejected["outcome"], "rejected_final")
        self.assertEqual(self.call("get_attempt", key()), rejected)
        self.assert_code("state_stale", "submit_message", req)
        self.assert_code("attempt_chain_conflict", "submit_message", {"envelope": envelope(attempt_id="P2")})
        self.assertEqual(self.call("close_attempt", key()), rejected)
        result = self.call("submit_message", {"envelope": envelope(attempt_id="P2"), "replaces_attempt_id": "P1", "closure_id": rejected["closure_id"]})
        self.assertEqual(result["outcome"], "accepted")

    def test_unknown_inflight_successor_can_close_with_predecessor_proof(self):
        first = self.call("close_attempt", key())
        second_request = {**key(attempt_id="P2"), "replaces_attempt_id": "P1", "closure_id": first["closure_id"]}
        self.assert_code("attempt_chain_conflict", "close_attempt", key(attempt_id="P2"))
        second = self.call("close_attempt", second_request)
        self.assertEqual(second["outcome"], "cancelled_before_accept")
        self.assertEqual(self.call("close_attempt", second_request), second)
        self.assert_code("attempt_closed", "submit_message", {"envelope": envelope(attempt_id="P2"),
                         "replaces_attempt_id": "P1", "closure_id": first["closure_id"]})
        accepted = self.call("submit_message", {"envelope": envelope(attempt_id="P3"),
                             "replaces_attempt_id": "P2", "closure_id": second["closure_id"]})
        self.assertEqual(accepted["outcome"], "accepted")

    def test_large_page_stops_at_last_returned_slot_within_cli_budget(self):
        for i in range(3):
            self.call("submit_message", {"envelope": envelope(logical_id=f"L{i}", payload=b"x" * (512 * 1024))})
        page = self.pull()
        self.assertLess(len(encode_json({"ok": True, "result": page})), 900 * 1024)
        self.assertLess(len(encode_json({"context": "x" * 16384, "page": page})), 1024 * 1024)
        self.assertEqual((len(page["events"]), page["next_after_seq"], page["watermark"], page["has_more"]), (1, "1", "3", True))
        following = self.pull(stream_id=page["stream_id"], after_seq="1")
        self.assertEqual(following["events"][0]["event_seq"], "2")

    def test_large_dependency_pages_fit_cli_and_keep_resume_position(self):
        payload = base64.b64encode(b"x" * (512 * 1024)).decode()
        for control_id, before, after in [("C1", "a", "b"), ("C2", "b", "c")]:
            self.control({"action": "add_control", "control": {"control_id": control_id,
                          "from_state_ref": before * 64, "to_state_ref": after * 64, "payload_bytes": payload},
                          "recipients": [{"account_id": "B", "device_id": "B1"}], "append_events": False})
        req = {"service_id": "S1", "conversation_id": "G1", "from_state_ref": "a" * 64, "to_state_ref": "c" * 64, "limit": "32"}
        page = self.call("get_crypto_dependencies", req, "synthetic-B1-token")
        self.assertEqual((len(page["controls"]), page["next_after_control_id"], page["has_more"]), (1, "C1", True))
        self.assertLess(len(encode_json({"ok": True, "result": page})), 900 * 1024)
        self.assertLess(len(encode_json({"context": "x" * 16384, "page": page})), 1024 * 1024)
        following = self.call("get_crypto_dependencies", {**req, "after_control_id": "C1"}, "synthetic-B1-token")
        self.assertEqual(following["controls"][0]["control_id"], "C2")
        self.assertFalse(following["has_more"])

    def test_full_target_stream_rolls_back_all_fanout_and_attempt(self):
        with self.store.transaction() as db:
            db.executemany("INSERT INTO events(account,device,seq,event_id,content) VALUES ('B','B1',?,?,?)",
                           [(i, f"full_{i}", '{"type":"fixture"}') for i in range(1, 10001)])
        self.assert_code("resource_exhausted", "submit_message", {"envelope": envelope()})
        self.assertEqual(self.call("get_attempt", key())["outcome"], "not_found")
        self.assertEqual(self.pull(device="A2")["watermark"], "0")

    def test_transaction_rollback_has_no_partial_attempt_or_cursor(self):
        with self.assertRaises(RuntimeError):
            with self.store.transaction() as db:
                device = self.store.authenticate(db, "synthetic-A1-token")
                DISPATCH["submit_message"](self.store, db, device, {"envelope": envelope()})
                raise RuntimeError("synthetic rollback")
        self.assertEqual(self.call("get_attempt", key())["outcome"], "not_found")
        self.assertEqual(self.pull()["watermark"], "0")
        self.call("submit_message", {"envelope": envelope(logical_id="M2")})
        self.assertEqual(self.pull()["events"][0]["event_seq"], "1")

    def test_restart_uses_persisted_state_and_stream(self):
        accepted = self.call("submit_message", {"envelope": envelope()})
        before = self.pull()
        changed_fixture = fixture()
        changed_fixture["conversation"]["authorization_version"] = "900"
        changed_fixture["devices"][0]["token"] = "different-synthetic-token"
        self.store = Store(self.path, changed_fixture)
        self.assertEqual(self.pull(), before)
        self.assertEqual(self.call("submit_message", {"envelope": envelope()}), accepted)

    def test_pagination_bound_to_device_and_contiguous_prefix(self):
        for i in range(5):
            self.call("submit_message", {"envelope": envelope(logical_id=f"M{i}")})
        page = self.pull(limit="2")
        self.assertEqual((page["next_after_seq"], page["watermark"], page["has_more"]), ("2", "5", True))
        self.assert_code("cursor_invalid", "pull_events", {"service_id": "S1", "stream_id": page["stream_id"], "after_seq": "0", "limit": "2"}, "synthetic-A2-token")
        self.assert_code("cursor_invalid", "pull_events", {"service_id": "S1", "stream_id": page["stream_id"], "after_seq": "18446744073709551615", "limit": "2"}, "synthetic-B1-token")
        next_page = self.pull(stream_id=page["stream_id"], after_seq="2", limit="2")
        self.assertEqual([e["event_seq"] for e in next_page["events"]], ["3", "4"])

    def test_receipts_are_target_bound_and_separate_read(self):
        accepted = self.call("submit_message", {"envelope": envelope()})
        event = self.pull()["events"][0]
        req = {"service_id": "S1", "acceptance_id": accepted["acceptance_id"], "attempt_id": "P1", "event_id": event["event_id"]}
        self.assert_code("permission_denied", "report_delivery", req, "synthetic-A2-token")
        delivered = self.call("report_delivery", req, "synthetic-B1-token")
        self.assertFalse(delivered["read"])
        count = self.control({"action": "stats"})["events"]
        self.assertEqual(self.call("report_delivery", req, "synthetic-B1-token"), delivered)
        self.assertEqual(self.control({"action": "stats"})["events"], count)
        read = self.call("report_read", {"service_id": "S1", "acceptance_ids": [accepted["acceptance_id"]]}, "synthetic-B1-token")
        self.assertTrue(read["receipts"][0]["read"])

    def test_expiry_keeps_slot_and_idempotency_and_revocation_denies(self):
        req = {"envelope": envelope()}
        accepted = self.call("submit_message", req)
        event = self.pull()["events"][0]
        self.control({"action": "set_availability", "acceptance_id": accepted["acceptance_id"], "availability": "expired"})
        projected = self.control({"action": "set_availability", "acceptance_id": accepted["acceptance_id"], "availability": "deleted"})
        self.assertEqual(projected["availability"], "expired")
        expired = self.pull()["events"][0]
        self.assertEqual(expired["event_id"], event["event_id"])
        self.assertNotIn("event", expired)
        self.assertEqual(self.call("submit_message", req)["availability"], "expired")
        self.control({"action": "revoke_device", "account_id": "B", "device_id": "B1"})
        self.assert_code("device_revoked", "pull_events", {"service_id": "S1", "after_seq": "0", "limit": "1"}, "synthetic-B1-token")

    def test_removed_member_has_placeholders_and_new_member_no_history(self):
        self.call("submit_message", {"envelope": envelope()})
        members = [{"account_id": "A", "device_id": "A1"}, {"account_id": "A", "device_id": "A2"}, {"account_id": "B", "device_id": "B2"}]
        self.control({"action": "set_state", "authorization_version": "2", "crypto_state_ref": "b" * 64, "members": members})
        self.assertEqual(self.pull()["events"][0]["availability"], "access_removed")
        self.assertEqual(self.pull(device="B2")["events"], [])
        self.assertEqual(self.call("submit_message", {"envelope": envelope()})["outcome"], "accepted")

    def test_dependency_is_independent_paged_and_history_authorized(self):
        controls = [{"control_id": f"C{i}", "from_state_ref": before * 64, "to_state_ref": after * 64, "payload_bytes": "AQ=="}
                    for i, before, after in [(1, "a", "b"), (2, "b", "c")]]
        for control in controls:
            self.control({"action": "add_control", "control": control, "recipients": [{"account_id": "B", "device_id": "B1"}], "append_events": False})
        req = {"service_id": "S1", "conversation_id": "G1", "from_state_ref": "a" * 64, "to_state_ref": "c" * 64, "limit": "1"}
        first = self.call("get_crypto_dependencies", req, "synthetic-B1-token")
        self.assertEqual(first["controls"], controls[:1])
        self.assertTrue(first["has_more"])
        second = self.call("get_crypto_dependencies", {**req, "after_control_id": "C1"}, "synthetic-B1-token")
        self.assertEqual(second["controls"], controls[1:])
        self.assertEqual(self.pull()["watermark"], "0")
        self.assert_code("permission_denied", "get_crypto_dependencies", req, "synthetic-A2-token")


if __name__ == "__main__":
    unittest.main()
