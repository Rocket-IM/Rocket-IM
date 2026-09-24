"""消息删除/到期的增量通知、原槽归属与事务边界；载荷及签名使用合成替身。"""

import base64
import concurrent.futures
import json
import threading
from unittest.mock import patch

from contract import ProtocolError
from quota_test_support import QuotaFixture
from receipt_test_support import ReceiptFixture, VerifiedCloseFixture, receipt_fixture
from storage import Store
from test_support import envelope, key


class MessageLifecycleTests(QuotaFixture):
    def accept(self, logical="M1", at=1000):
        members = self.fixture["conversation"]["members"]
        request = {"envelope": envelope(logical, recipients=members[1:])}
        with patch("messages.now_ms", return_value=at):
            return self.call("submit_message", request)

    def terminal(self, accepted, availability="deleted"):
        return self.control({"action": "set_availability", "acceptance_id": accepted["acceptance_id"],
                             "availability": availability})

    def page(self, device="B1", after="0", limit="100", signed=False):
        with self.store.transaction() as db:
            stream_id = db.execute("SELECT stream_id FROM devices WHERE device=?", (device,)).fetchone()[0]
        result = self.call("pull_events_signed" if signed else "pull_events",
                           {"service_id": "S1", "stream_id": stream_id, "after_seq": after, "limit": limit},
                           f"synthetic-{device}-token")
        return json.loads(base64.b64decode(result["page_bytes"])) if signed else result

    def events(self, device=None):
        with self.store.transaction() as db:
            rows = db.execute("SELECT account,device,seq,event_id,content,acceptance_id,availability "
                              "FROM events ORDER BY account,device,seq").fetchall()
            return [dict(row) for row in rows if device is None or row["device"] == device]

    def notifications(self, device=None):
        return [row for row in self.events(device) if json.loads(row["content"])["type"] == "message_availability"]

    def assert_error(self, code, operation):
        with self.assertRaises(ProtocolError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def observe_appends(self, observed):
        original = Store.append_event

        def append(db, pair, event, acceptance_id=None):
            original(db, pair, event, acceptance_id)
            observed.append((pair, event))
        return patch("message_lifecycle.Store.append_event", side_effect=append)

    def test_delete_tail_notifies_each_original_slot_without_changing_identity_or_receipts(self):
        accepted = self.accept()
        delivery = self.delivery(accepted)
        self.call("report_delivery", delivery, "synthetic-B1-token")
        with self.store.transaction() as db:
            original = db.execute("SELECT content FROM events WHERE device='B1' AND seq=1").fetchone()[0]
            Store.append_event(db, ("B", "B1"), json.loads(original), accepted["acceptance_id"])
        before, receipt_before = self.events(), self.snapshot()["receipts"]
        tails = {device: max([row["seq"] for row in before if row["device"] == device], default=0)
                 for device in ("A1", "A2", "B1", "B2", "C1", "C2")}
        self.terminal(accepted)
        after = {row["event_id"]: row for row in self.events()}
        for row in before:
            self.assertEqual(after[row["event_id"]], {**row, "availability": "deleted"})
        originals = [row for row in before if json.loads(row["content"])["type"] == "message"]
        notices = self.notifications()
        self.assertEqual(len(notices), len(originals))
        for row in originals:
            matches = [notice for notice in notices if json.loads(notice["content"])["target_event_id"] == row["event_id"]]
            self.assertEqual(len(matches), 1)
            notice = matches[0]
            self.assertEqual((notice["account"], notice["device"], notice["acceptance_id"], notice["availability"]),
                             (row["account"], row["device"], accepted["acceptance_id"], "available"))
            self.assertEqual(json.loads(notice["content"]), {
                "type": "message_availability", "target_event_seq": str(row["seq"]),
                "target_event_id": row["event_id"], "acceptance_id": accepted["acceptance_id"],
                "attempt_id": accepted["attempt_id"], "availability": "deleted"})
        with patch("synchronization.now_ms", return_value=1000):
            for device, tail in tails.items():
                page = self.page(device, str(tail))
                expected = [row for row in notices if row["device"] == device]
                self.assertEqual(len(page["events"]), len(expected))
                self.assertTrue(all(item["event"]["type"] == "message_availability" for item in page["events"]))
                self.assertFalse(page["has_more"])
        self.assertEqual(self.notifications("A1"), [])
        self.assertEqual(self.snapshot()["receipts"], receipt_before)
        self.assertEqual(self.call("get_attempt", key())["availability"], "deleted")

    def test_first_terminal_wins_and_restart_retries_do_not_project_away_notifications(self):
        for index, first in enumerate(("deleted", "expired")):
            accepted = self.accept(f"M{index}")
            self.terminal(accepted, first)
            before = self.snapshot()
            for later in ("deleted", "expired", first):
                self.assertEqual(self.terminal(accepted, later)["availability"], first)
                self.assertEqual(self.snapshot(), before)
            self.reopen()
            self.assertEqual(self.terminal(accepted, first)["availability"], first)
            self.assertEqual(self.snapshot(), before)
        self.assertTrue(all(row["availability"] == "available" for row in self.notifications()))

    def test_removed_readded_revoked_and_new_members_receive_no_old_message_notice(self):
        self.fixture["conversation"]["members"] = self.members[:-1]
        self.path = self.path.with_name("restricted.sqlite3")
        self.store = Store(self.path, self.fixture)
        accepted = self.accept()
        active = [member for member in self.members if member["device_id"] not in {"B1", "C1"}]
        self.control({"action": "set_state", "authorization_version": "2", "crypto_state_ref": "b" * 64,
                      "members": active})
        self.control({"action": "revoke_device", "account_id": "C", "device_id": "C1"})
        self.control({"action": "set_state", "authorization_version": "3", "crypto_state_ref": "c" * 64,
                      "members": [member for member in self.members if member["device_id"] != "C1"]})
        before = self.events()
        self.terminal(accepted)
        self.assertEqual({row["device"] for row in self.notifications()}, {"A2", "B2"})
        self.assertEqual(self.notifications("C2"), [])
        for device in ("B1", "C1"):
            self.assertEqual(self.events(device), [row for row in before if row["device"] == device])
            self.assertEqual(self.events(device)[0]["availability"], "access_removed")
        with patch("synchronization.now_ms", return_value=1000):
            self.assertEqual(self.page("C2")["events"], [])
            self.assert_error("device_revoked", lambda: self.page("C1"))

    def test_exact_expiry_boundary_is_visible_from_previous_tail_in_same_page(self):
        accepted = self.accept()
        deadline = int(accepted["expires_at_unix_ms"])
        with patch("synchronization.now_ms", return_value=deadline - 1):
            old = self.page()
            before = self.snapshot()
            tail = self.page(after=old["next_after_seq"])
            self.assertEqual((tail["events"], tail["watermark"]), ([], "1"))
            self.assertEqual(self.snapshot(), before)
        with patch("synchronization.now_ms", return_value=deadline):
            change = self.page(after="1")
        self.assertEqual((change["next_after_seq"], change["watermark"], change["has_more"]), ("2", "2", False))
        self.assertEqual(change["events"][0]["event"]["availability"], "expired")
        before = self.snapshot()
        with patch("synchronization.now_ms", return_value=deadline + 1):
            self.assertEqual(self.page(after="2")["events"], [])
        self.assertEqual(self.snapshot(), before)
        self.reopen()
        self.assertEqual(self.snapshot(), before)

    def test_future_cursor_cannot_skip_the_expiration_it_would_trigger(self):
        accepted = self.accept()
        before = self.snapshot()
        with patch("synchronization.now_ms", return_value=int(accepted["expires_at_unix_ms"])):
            self.assert_error("cursor_invalid", lambda: self.page(after="2"))
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.notifications(), [])

    def test_terminal_pagination_preserves_contiguous_prefix_and_limit(self):
        for index in range(3):
            self.terminal(self.accept(f"M{index}"))
        collected, after = [], "0"
        with patch("synchronization.now_ms", return_value=1000):
            while True:
                page = self.page(after=after, limit="1")
                self.assertEqual(len(page["events"]), 1)
                collected += page["events"]
                after = page["next_after_seq"]
                if not page["has_more"]:
                    break
        self.assertEqual([row["event_seq"] for row in collected], [str(i) for i in range(1, 7)])
        self.assertEqual([row["event"]["target_event_seq"] for row in collected if "event" in row], ["1", "3", "5"])

    def test_concurrent_terminal_requests_commit_one_state_and_one_notice_per_slot(self):
        accepted = self.accept()
        barrier = threading.Barrier(2)

        def transition(availability):
            barrier.wait(timeout=5)
            return self.terminal(accepted, availability)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            pending = [pool.submit(transition, value) for value in ("deleted", "expired")]
            outcomes = [item.result(timeout=10)["availability"] for item in pending]
        self.assertEqual(len(set(outcomes)), 1)
        self.assertEqual(len(self.notifications()), 5)
        self.assertTrue(all(json.loads(row["content"])["availability"] == outcomes[0] for row in self.notifications()))

    def test_full_target_stream_rolls_back_projection_and_earlier_notification(self):
        accepted = self.accept()
        self.seed_stream("B1", 10000)
        before, inserted = self.snapshot(), []
        with self.observe_appends(inserted):
            error = self.assert_error("resource_exhausted", lambda: self.terminal(accepted))
        self.assertEqual((error.status, error.outcome, len(inserted)), (429, "not_recorded", 1))
        self.assertEqual(self.snapshot(), before)
        self.reopen()
        self.assert_error("resource_exhausted", lambda: self.terminal(accepted))
        self.assertEqual(self.snapshot(), before)

    def test_global_limit_mid_fanout_rolls_back_two_notifications_and_original_projection(self):
        accepted = self.accept()
        self.seed_streams({"A1": 10000, "A2": 9999, "B1": 9999, "B2": 10000, "C1": 10000, "C2": 10000})
        before, inserted = self.snapshot(), []
        self.assertEqual(len(before["events"]), 59998)
        with self.observe_appends(inserted):
            self.assert_error("resource_exhausted", lambda: self.terminal(accepted))
        self.assertEqual(len(inserted), 2)
        self.assertEqual(self.snapshot(), before)

    def test_expiration_quota_failure_returns_no_page_and_preserves_original_tail(self):
        accepted = self.accept()
        self.seed_stream("B1", 10000)
        before, inserted = self.snapshot(), []
        with self.observe_appends(inserted), patch("synchronization.now_ms", return_value=int(accepted["expires_at_unix_ms"])):
            self.assert_error("resource_exhausted", lambda: self.page("A2", after="1"))
        self.assertEqual(len(inserted), 1)
        self.assertEqual(self.snapshot(), before)

    def test_signed_page_failure_rolls_back_projection_and_all_pending_notifications(self):
        self.fixture = receipt_fixture()
        self.path = self.path.with_name("signed.sqlite3")
        signer = ReceiptFixture()
        self.store = Store(self.path, self.fixture, VerifiedCloseFixture(), signer)
        accepted = self.accept()
        before, inserted = self.snapshot(), []
        signer.fail = True
        with self.observe_appends(inserted), patch("synchronization.now_ms", return_value=int(accepted["expires_at_unix_ms"])):
            self.assert_error("receipt_signer_unavailable", lambda: self.page("A2", after="1", signed=True))
        self.assertEqual(len(inserted), 4)
        self.assertEqual(self.snapshot(), before)
        signer.fail = False
        with patch("synchronization.now_ms", return_value=int(accepted["expires_at_unix_ms"])):
            page = self.page("A2", after="1", signed=True)
        self.assertEqual((page["watermark"], page["events"][0]["event"]["availability"]), ("2", "expired"))

    def test_controller_rejects_invalid_or_absent_target_without_mutation(self):
        accepted = self.accept()
        before = self.snapshot()
        for value in ("available", "access_removed", "unknown"):
            self.assert_error("invalid_envelope", lambda: self.terminal(accepted, value))
        self.assert_error("invalid_envelope", lambda: self.terminal({"acceptance_id": "absent"}))
        self.assertEqual(self.snapshot(), before)
