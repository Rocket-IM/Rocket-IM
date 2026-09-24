"""M11 控制器与真实 SQLite 事务测试；合成字节不作为密码验证证据。"""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from .slot_relay import ProtocolError, SlotControls, Store
from messages import submit
from synchronization import pull_events, report_delivery
from test_support import envelope, fixture


class SlotControlsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rim-m11-slots-")
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "relay.sqlite"
        self.fixture = fixture()
        self.store = Store(self.path, self.fixture)
        self.controls = SlotControls(True)
        self.token = self.fixture["controller_token"]
        with self.store.transaction() as db:
            sender = self.store.authenticate(db, "synthetic-A1-token")
            self.accepted = submit(self.store, db, sender, {"envelope": envelope()})
            device = self.store.authenticate(db, "synthetic-B1-token")
            page = pull_events(self.store, db, device, {"service_id": "S1", "after_seq": "0", "limit": "100"})
        self.source = page["events"][0]
        self.request = {"action": "duplicate_message_slot", "account_id": "B", "device_id": "B1",
                        "event_id": self.source["event_id"]}

    def execute(self, request=None, token=None, controls=None):
        with self.store.transaction() as db:
            return (controls or self.controls).execute(self.store, db, token or self.token,
                                                        request if request is not None else self.request)

    def rows(self):
        with self.store.transaction() as db:
            return [tuple(row) for row in db.execute(
                "SELECT account,device,seq,event_id,content,acceptance_id,availability FROM events ORDER BY account,device,seq")]

    def rejects_unchanged(self, code, status, **arguments):
        before = self.rows()
        with self.assertRaises(ProtocolError) as caught:
            self.execute(**arguments)
        self.assertEqual((caught.exception.code, caught.exception.status), (code, status))
        self.assertEqual(self.rows(), before)

    def test_control_requires_explicit_enable_and_controller_token(self):
        self.rejects_unchanged("permission_denied", 403, controls=SlotControls(False))
        self.rejects_unchanged("permission_denied", 403, token="synthetic-B1-token")
        self.rejects_unchanged("permission_denied", 403, token="incorrect-controller-token")

    def test_exact_shape_rejects_missing_fields_and_arbitrary_bytes(self):
        for removed in ("account_id", "device_id", "event_id"):
            with self.subTest(removed=removed):
                request = dict(self.request)
                del request[removed]
                self.rejects_unchanged("invalid_envelope", 400, request=request)
        for field, value in (("envelope", envelope()), ("payload_bytes", "YXJiaXRyYXJ5"),
                             ("acceptance_id", self.accepted["acceptance_id"]), ("event_seq", "10")):
            with self.subTest(extra=field):
                self.rejects_unchanged("invalid_envelope", 400, request={**self.request, field: value})
        self.rejects_unchanged("invalid_envelope", 400, request={**self.request, "event_id": 1})

    def test_missing_or_foreign_event_cannot_be_copied(self):
        self.rejects_unchanged("test_slot_unavailable", 409, request={**self.request, "event_id": "missing"})
        self.rejects_unchanged("test_slot_unavailable", 409,
                               request={**self.request, "account_id": "A", "device_id": "A2"})

    def test_revoked_nonmember_and_unknown_target_are_denied(self):
        self.rejects_unchanged("permission_denied", 403, request={**self.request, "device_id": "B2"})
        self.rejects_unchanged("permission_denied", 403, request={**self.request, "device_id": "missing"})
        with self.store.transaction() as db:
            db.execute("UPDATE devices SET revoked=1 WHERE account='B' AND device='B1'")
        self.rejects_unchanged("permission_denied", 403)

    def test_unavailable_message_is_not_resurrected(self):
        for availability in ("expired", "deleted", "access_removed"):
            with self.subTest(availability=availability):
                with self.store.transaction() as db:
                    db.execute("UPDATE events SET availability=? WHERE event_id=?",
                               (availability, self.source["event_id"]))
                self.rejects_unchanged("test_slot_unavailable", 409)

    def test_expired_acceptance_is_not_copied_before_projection(self):
        with self.store.transaction() as db:
            accepted = dict(self.accepted, expires_at_unix_ms="1")
            db.execute("UPDATE attempts SET result=? WHERE acceptance_id=?",
                       (json.dumps(accepted), self.accepted["acceptance_id"]))
        self.rejects_unchanged("test_slot_unavailable", 409)

    def test_delivery_event_cannot_be_copied(self):
        with self.store.transaction() as db:
            device = self.store.authenticate(db, "synthetic-B1-token")
            report_delivery(self.store, db, device, {"service_id": "S1", "acceptance_id": self.accepted["acceptance_id"],
                            "attempt_id": "P1", "event_id": self.source["event_id"]})
            event_id = db.execute("SELECT event_id FROM events WHERE account='B' AND device='B1' AND seq=2").fetchone()[0]
        self.rejects_unchanged("test_slot_unavailable", 409, request={**self.request, "event_id": event_id})

    def test_duplicate_uses_new_id_contiguous_sequence_and_unchanged_content(self):
        original = self.rows()
        first, second = self.execute(), self.execute()
        self.assertEqual([first["event_seq"], second["event_seq"]], ["2", "3"])
        self.assertEqual(len({self.source["event_id"], first["event_id"], second["event_id"]}), 3)
        for result in (first, second):
            self.assertEqual(result["source_event_id"], self.source["event_id"])
            self.assertEqual(result["stream_id"], self.source["stream_id"])
            self.assertEqual(result["acceptance_id"], self.accepted["acceptance_id"])
        rows = self.rows()
        self.assertEqual([row for row in rows if row[3] in {r[3] for r in original}], original)
        own = [row for row in rows if row[:2] == ("B", "B1")]
        self.assertEqual([row[2] for row in own], [1, 2, 3])
        self.assertTrue(all(row[4:] == own[0][4:] for row in own))
        self.store = Store(self.path, self.fixture)
        self.assertEqual(self.rows(), rows)
        with self.store.transaction() as db:
            device = self.store.authenticate(db, "synthetic-B1-token")
            page = pull_events(self.store, db, device, {"service_id": "S1", "after_seq": "0", "limit": "100"})
        self.assertEqual([slot["event"] for slot in page["events"]], [self.source["event"]] * 3)
        self.assertEqual(page["watermark"], "3")

    def test_append_keeps_original_per_stream_bound(self):
        with patch("storage.MAX_STREAM_EVENTS", 1):
            self.rejects_unchanged("resource_exhausted", 429)

    def test_append_rolls_back_with_outer_transaction(self):
        before = self.rows()
        with self.assertRaisesRegex(RuntimeError, "synthetic_abort"):
            with self.store.transaction() as db:
                self.controls.execute(self.store, db, self.token, self.request)
                raise RuntimeError("synthetic_abort")
        self.assertEqual(self.rows(), before)

    def test_existing_controls_remain_available(self):
        self.assertEqual(self.execute({"action": "stats"})["accepted"], "1")


if __name__ == "__main__":
    unittest.main()
