"""原配额回收/单调序号的SQLite模块验证；合成占额、时钟和签名替身不代表真实MLS。"""

import base64
from copy import deepcopy
from unittest.mock import patch

from contract import ProtocolError
from controls import TestControls
from quota_test_support import QuotaFixture
from receipt_test_support import ReceiptFixture, VerifiedCloseFixture, receipt_fixture, signed
from reclamation_contract import validate_reclaim_receipt, validate_retention_receipt
from storage import Store
from test_support import envelope, key


class ReclamationTests(QuotaFixture):
    def setUp(self):
        super().setUp()
        self.fixture = receipt_fixture()
        extra = {"account_id": "C", "device_id": "C1", "token": "synthetic-C1-token",
                 "signature_key": base64.b64encode(bytes([39]) * 32).decode()}
        self.fixture["devices"].append(extra)
        self.fixture["permission_checkpoint"]["members"].append({name: extra[name] for name in ("account_id", "device_id", "signature_key")})
        self.members = [{name: item[name] for name in ("account_id", "device_id")} for item in self.fixture["permission_checkpoint"]["members"]]
        self.fixture["conversation"]["members"] = self.members
        self.path = self.path.with_name("reclamation.sqlite3")
        self.signer = ReceiptFixture()
        self.store = Store(self.path, self.fixture, VerifiedCloseFixture(), self.signer)

    def reopen(self):
        before = self.snapshot()
        self.store = Store(self.path, self.fixture, VerifiedCloseFixture(), self.signer)
        self.controller = TestControls(True)
        self.assertEqual(self.snapshot(), before)

    def terminal(self, logical="M1"):
        request = self.message(logical)
        accepted = self.call("submit_message", request)
        self.control({"action": "set_availability", "acceptance_id": accepted["acceptance_id"], "availability": "deleted"})
        return request, accepted

    def confirmation(self, device, accepted, plan="P1"):
        with self.store.transaction() as db:
            row = db.execute("SELECT account,stream_id FROM devices WHERE device=?", (device,)).fetchone()
            high = db.execute("SELECT COALESCE(MAX(seq),0) FROM events WHERE account=? AND device=?", (row["account"], device)).fetchone()[0]
        return {"service_id": "S1", "conversation_id": "G1", "plan_id": plan,
                "stream_id": row["stream_id"], "processed_seq": str(high), "acceptance_ids": [accepted["acceptance_id"]]}

    def ready(self, accepted, plan="P1"):
        requests = {member["device_id"]: self.confirmation(member["device_id"], accepted, plan) for member in self.members}
        for index, (device, request) in enumerate(requests.items()):
            result = self.call("confirm_reclaim", request, f"synthetic-{device}-token")
            self.assertEqual(result["status"], "ready" if index == len(requests) - 1 else "pending")
        return {device: self.call("confirm_reclaim", request, f"synthetic-{device}-token")["receipt"] for device, request in requests.items()}

    def finish(self, device, receipt, plan="P1"):
        return self.call("finish_reclaim", {"service_id": "S1", "conversation_id": "G1", "plan_id": plan, "receipt": receipt}, f"synthetic-{device}-token")

    def error(self, code, action):
        before = self.snapshot()
        with self.assertRaises(ProtocolError) as caught:
            action()
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(self.snapshot(), before)
        return caught.exception

    def test_all_finishes_required_retry_proof_and_signed_floor_survive_reopen(self):
        request, accepted = self.terminal()
        original = self.call("get_attempt", key())
        receipts = self.ready(accepted)
        for device, receipt in list(receipts.items())[:-1]:
            self.assertEqual(self.finish(device, receipt)["status"], "pending")
        with self.store.transaction() as db:
            self.assertIsNotNone(db.execute("SELECT payload FROM attempts WHERE acceptance_id=?", (accepted["acceptance_id"],)).fetchone()[0])
        device, receipt = list(receipts.items())[-1]
        self.assertEqual(self.finish(device, receipt)["status"], "complete")
        for reopened in (False, True):
            if reopened:
                self.reopen()
            before = self.snapshot()
            self.assertEqual(self.finish(device, receipt)["status"], "complete")
            self.assertEqual(self.call("submit_message", request), original)
            self.assertEqual(self.call("get_attempt", key()), original)
            self.assertEqual(self.call("close_attempt", key()), original)
            self.assertEqual(self.snapshot(), before)
            changed = {"envelope": envelope(payload=b"changed", recipients=self.members[1:])}
            self.error("idempotency_conflict", lambda: self.call("submit_message", changed))
            self.error("logical_message_already_accepted", lambda: self.call("submit_message", {"envelope": envelope(attempt_id="P2", recipients=self.members[1:])}))
            error = self.error("cursor_reclaimed", lambda: self.call("pull_events_signed", {"service_id": "S1", "after_seq": "0", "limit": "1"}, "synthetic-B1-token"))
            statement = validate_retention_receipt(error.details["retention_receipt"])
            self.assertEqual((statement["after_seq"], statement["limit"], statement["floor"], statement["watermark"]), ("0", "1", "2", "2"))

    def test_original_global_and_stream_limits_recover_without_sequence_reuse(self):
        _, accepted = self.terminal()
        self.seed_streams({member["device_id"]: 10000 for member in self.members})
        self.error("resource_exhausted", lambda: self.call("submit_message", self.message("M2")))
        receipts = self.ready(accepted)
        for device, receipt in receipts.items():
            result = self.finish(device, receipt)
        self.assertEqual(result["status"], "complete")
        new = self.call("submit_message", self.message("M2"))
        self.assertEqual(new["outcome"], "accepted")
        with self.store.transaction() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 60005)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events WHERE compacted=0").fetchone()[0], 59995)
            self.assertEqual(db.execute("SELECT MIN(seq) FROM events WHERE acceptance_id=?", (new["acceptance_id"],)).fetchone()[0], 10001)

    def test_original_attempt_limit_releases_only_live_slot_and_keeps_terminal(self):
        request, accepted = self.terminal()
        self.seed_attempts(10000)
        self.error("resource_exhausted", lambda: self.call("submit_message", self.message("M2")))
        for device, receipt in self.ready(accepted).items():
            self.finish(device, receipt)
        self.assertEqual(self.call("submit_message", self.message("M2"))["outcome"], "accepted")
        self.assertEqual(self.call("submit_message", request)["acceptance_id"], accepted["acceptance_id"])
        with self.store.transaction() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0], 10001)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM attempts WHERE compacted=0").fetchone()[0], 10000)

    def test_available_wrong_scope_and_unprocessed_prefix_are_rejected_before_plan(self):
        accepted = self.call("submit_message", self.message("M1"))
        req = self.confirmation("B1", accepted)
        self.error("reclamation_pending", lambda: self.call("confirm_reclaim", req, "synthetic-B1-token"))
        self.control({"action": "set_availability", "acceptance_id": accepted["acceptance_id"], "availability": "deleted"})
        req = self.confirmation("B1", accepted)
        self.error("reclamation_pending", lambda: self.call("confirm_reclaim", {**req, "processed_seq": "1"}, "synthetic-B1-token"))
        self.error("reclamation_conflict", lambda: self.call("confirm_reclaim", req, "synthetic-A2-token"))
        self.assertEqual(self.call("confirm_reclaim", req, "synthetic-B1-token")["status"], "pending")
        self.error("reclamation_conflict", lambda: self.call("confirm_reclaim", {**req, "processed_seq": "1"}, "synthetic-B1-token"))

    def test_plan_signer_failure_rolls_back_last_confirmation_and_partial_receipts(self):
        _, accepted = self.terminal()
        requests = {m["device_id"]: self.confirmation(m["device_id"], accepted) for m in self.members}
        for device, req in list(requests.items())[:-1]:
            self.call("confirm_reclaim", req, f"synthetic-{device}-token")
        device, req = list(requests.items())[-1]
        sign, calls = self.signer.sign, []

        def fail_second(statement):
            calls.append(statement)
            if len(calls) == 2:
                raise ProtocolError("receipt_signer_unavailable", "合成第二次签名失败", status=503)
            return sign(statement)

        with patch.object(self.signer, "sign", side_effect=fail_second):
            self.error("receipt_signer_unavailable", lambda: self.call("confirm_reclaim", req, f"synthetic-{device}-token"))
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.call("confirm_reclaim", req, f"synthetic-{device}-token")["status"], "ready")

    def test_final_transaction_failure_restores_payload_proofs_and_completion(self):
        _, accepted = self.terminal()
        receipts = self.ready(accepted)
        for device, receipt in list(receipts.items())[:-1]:
            self.finish(device, receipt)
        device, receipt = list(receipts.items())[-1]
        with patch("reclamation.advance_floor", side_effect=ProtocolError("state_conflict", "合成回收后提交前失败", status=409)):
            self.error("state_conflict", lambda: self.finish(device, receipt))
        self.reopen()
        self.assertEqual(self.finish(device, receipt)["status"], "complete")

    def test_proof_and_plan_budget_refuse_before_creating_plan(self):
        _, accepted = self.terminal()
        req = self.confirmation("B1", accepted)
        for target in ("reclamation_storage.MAX_COMPACT_ATTEMPTS", "reclamation_storage.MAX_COMPACT_EVENTS",
                       "reclamation_budget.MAX_PROOF_BYTES", "reclamation.MAX_PLANS", "reclamation.MAX_PLAN_TOTAL_BYTES"):
            with self.subTest(budget=target), patch(target, 0):
                self.error("resource_exhausted", lambda: self.call("confirm_reclaim", req, "synthetic-B1-token"))

    def test_other_device_finish_and_new_history_reference_are_rejected(self):
        _, accepted = self.terminal()
        receipts = self.ready(accepted)
        self.error("reclamation_conflict", lambda: self.finish("B1", receipts["A1"]))
        from history_transfers import check_original
        with self.store.transaction() as db:
            with self.assertRaises(ProtocolError) as caught:
                check_original(db, ("A", "A1"), "S1", "G1", {"acceptance_id": accepted["acceptance_id"], "envelope_sha256": "0" * 64})
            self.assertEqual(caught.exception.code, "reclamation_pending")

    def test_sparse_selected_slots_do_not_advance_floor_over_unselected_history(self):
        self.call("submit_message", self.message("unselected"))
        _, accepted = self.terminal()
        for device, receipt in self.ready(accepted).items():
            self.finish(device, receipt)
        with self.store.transaction() as db:
            marks = db.execute("SELECT high_watermark,floor FROM stream_watermarks WHERE account='B' AND device='B1'").fetchone()
            self.assertEqual(tuple(marks), (3, 0))
        page = self.call("pull_events", {"service_id": "S1", "after_seq": "0", "limit": "100"}, "synthetic-B1-token")
        self.assertEqual([slot["event_seq"] for slot in page["events"]], ["1", "2", "3"])
        self.assertEqual(page["events"][0]["event"]["type"], "message")

    def test_delayed_receipt_cannot_add_new_transition_or_event_after_confirmation(self):
        accepted = self.call("submit_message", self.message("M1"))
        delivery = self.delivery(accepted)
        saved = self.call("report_delivery", delivery, "synthetic-B1-token")
        self.control({"action": "set_availability", "acceptance_id": accepted["acceptance_id"], "availability": "deleted"})
        for device, receipt in self.ready(accepted).items():
            self.finish(device, receipt)
        before = self.snapshot()
        self.assertEqual(self.call("report_delivery", delivery, "synthetic-B1-token"), saved)
        self.assertEqual(self.snapshot(), before)
        self.error("reclamation_conflict", lambda: self.call("report_read", {"service_id": "S1", "acceptance_ids": [accepted["acceptance_id"]]}, "synthetic-B1-token"))

    def test_malformed_terminal_type_is_protocol_error(self):
        _, accepted = self.terminal()
        receipt = next(iter(self.ready(accepted).values()))
        statement = validate_reclaim_receipt(receipt)
        for invalid in ([], {}):
            malformed = deepcopy(statement)
            malformed["messages"][0]["availability"] = invalid
            self.error("invalid_envelope", lambda: self.call("finish_reclaim", {"service_id": "S1", "conversation_id": "G1", "plan_id": "P1", "receipt": signed(malformed)}))
