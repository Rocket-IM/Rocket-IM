"""终态回执的最小公开引用；沿原事务与签页入口，签名替身只证明摘要绑定。"""

import base64
import hashlib
import json
import unittest
from copy import deepcopy
from unittest.mock import patch

import stream_page_tests
from contract import encode_json
from message_lifecycle import set_availability
from storage import remove_access


class TerminalReferenceTests(unittest.TestCase):
    def setUp(self):
        # 复用既有装置方法，避免继承后重复执行其六个原测试。
        self.f = stream_page_tests.StreamPageTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)

    def page(self, **options):
        request = options.pop("request", self.f.request)
        return self.f.page(request={**request, "include_terminal_references": True}, **options)

    def accepted_with_receipts(self, logical="M1"):
        accepted = self.f.submit(logical)
        self.f.call({"service_id": "S1", "acceptance_ids": [accepted["acceptance_id"]]},
                    "synthetic-A2-token", "report_read")
        return accepted

    def terminal(self, accepted, availability="deleted"):
        with self.f.store.transaction() as db:
            set_availability(db, accepted["acceptance_id"], availability)

    def references(self, page):
        return [slot["terminal_reference"] for slot in page["events"] if "terminal_reference" in slot]

    def expected(self, accepted):
        return [{"type": kind, "acceptance_id": accepted["acceptance_id"],
                 "attempt_id": accepted["attempt_id"], "device": {"account_id": "A", "device_id": "A2"}}
                for kind in ("delivery", "read")]

    def test_deleted_receipts_keep_exact_slot_identity_and_minimal_public_reference(self):
        accepted = self.accepted_with_receipts()
        _, before, old_statement = self.page()
        self.assertEqual(self.references(before), [])
        self.terminal(accepted)
        _, after, statement = self.page()
        self.assertEqual(self.references(after), self.expected(accepted))
        for old, new in zip(before["events"], after["events"]):
            self.assertEqual({key: old[key] for key in ("stream_id", "event_seq", "event_id")},
                             {key: new[key] for key in ("stream_id", "event_seq", "event_id")})
            self.assertEqual(new["availability"], "deleted")
            self.assertNotIn("event", new)
            if old["event"]["type"] == "message":
                self.assertNotIn("terminal_reference", new)
        self.assertNotEqual(statement["page_sha256"], old_statement["page_sha256"])

    def test_expiration_projects_references_in_the_original_signed_transaction(self):
        accepted = self.accepted_with_receipts()
        with patch("synchronization.now_ms", return_value=int(accepted["expires_at_unix_ms"])):
            _, page, _ = self.page()
        self.assertEqual(self.references(page), self.expected(accepted))
        self.assertTrue(all(slot["availability"] == "expired" for slot in page["events"]
                            if "terminal_reference" in slot))

    def test_unsigned_default_and_false_pages_keep_original_anonymous_bytes(self):
        from synchronization import event_page
        accepted = self.accepted_with_receipts()
        self.terminal(accepted)
        unsigned = self.f.call(operation="pull_events")
        with self.f.store.transaction() as db:
            device = self.f.store.authenticate(db, "synthetic-A2-token")
            internal = event_page(self.f.store, db, device, self.f.request)
        self.assertEqual(internal, unsigned)
        self.assertEqual(self.references(unsigned), [])
        default, page, _ = self.f.page()
        disabled, _, _ = self.f.page(request={**self.f.request, "include_terminal_references": False})
        self.assertEqual(page, unsigned)
        self.assertEqual(base64.b64decode(default["page_bytes"]), encode_json(unsigned))
        self.assertEqual(default, disabled)
        enabled, _, _ = self.page()
        self.assertNotEqual(default["page_bytes"], enabled["page_bytes"])
        self.assertEqual(len(self.references(self.page()[1])), 2)

    def test_capability_requires_boolean_and_unsigned_rejects_even_false(self):
        before = self.f.rows()
        calls = self.f.signer.calls
        for value in (None, 0, 1, "true", "false", [], {}):
            with self.subTest(signed_value=value):
                request = {**self.f.request, "include_terminal_references": value}
                self.f.assert_code("invalid_envelope", lambda: self.f.call(request))
        for value in (False, True):
            with self.subTest(unsigned_value=value):
                request = {**self.f.request, "include_terminal_references": value}
                self.f.assert_code("invalid_envelope", lambda: self.f.call(request, operation="pull_events"))
        self.assertEqual(self.f.rows(), before)
        self.assertEqual(self.f.signer.calls, calls)

    def test_access_removed_slots_never_emit_terminal_references(self):
        accepted = self.accepted_with_receipts()
        with self.f.store.transaction() as db:
            remove_access(db, ("A", "A2"))
            set_availability(db, accepted["acceptance_id"], "deleted")
        _, page, _ = self.page()
        self.assertTrue(page["events"])
        self.assertTrue(all(slot["availability"] == "access_removed" for slot in page["events"]))
        self.assertEqual(self.references(page), [])
        self.assertTrue(all("event" not in slot for slot in page["events"]))

    def test_reference_allowlist_does_not_copy_other_persisted_fields(self):
        accepted = self.accepted_with_receipts()
        with self.f.store.transaction() as db:
            rows = db.execute("SELECT seq,content FROM events WHERE device='A2'").fetchall()
            for row in rows:
                content = json.loads(row["content"])
                if content["type"] not in {"delivery", "read"}:
                    continue
                # 额外字段仅作为泄漏哨兵，不能进入终态引用。
                content.update(envelope={"private": "sentinel"}, acceptance_receipt="sentinel", payload="sentinel")
                content["device"]["extra"] = "sentinel"
                db.execute("UPDATE events SET content=? WHERE device='A2' AND seq=?",
                           (encode_json(content).decode(), row["seq"]))
        self.terminal(accepted)
        result, page, _ = self.page()
        self.assertEqual(self.references(page), self.expected(accepted))
        self.assertNotIn(b"sentinel", base64.b64decode(result["page_bytes"]))

    def test_compaction_keeps_receipt_references_and_does_not_restore_message_envelopes(self):
        self.accepted_with_receipts("unreclaimed-prefix")
        accepted = self.accepted_with_receipts()
        self.terminal(accepted)
        before, _, _ = self.page()
        requests = []
        for member in self.f.fixture["conversation"]["members"]:
            token = f"synthetic-{member['device_id']}-token"
            with self.f.store.transaction() as db:
                device = self.f.store.authenticate(db, token)
                high = db.execute("SELECT high_watermark FROM stream_watermarks WHERE account=? AND device=?",
                                  (member["account_id"], member["device_id"])).fetchone()[0]
            request = {"service_id": "S1", "conversation_id": "G1", "plan_id": "P1",
                       "stream_id": device["stream_id"], "processed_seq": str(high),
                       "acceptance_ids": [accepted["acceptance_id"]]}
            self.f.call(request, token, "confirm_reclaim")
            requests.append((request, token))
        receipts = [(self.f.call(request, token, "confirm_reclaim")["receipt"], token)
                    for request, token in requests]
        for receipt, token in receipts:
            result = self.f.call({"service_id": "S1", "conversation_id": "G1", "plan_id": "P1",
                                  "receipt": receipt}, token, "finish_reclaim")
        self.assertEqual(result["status"], "complete")
        with self.f.store.transaction() as db:
            rows = db.execute("SELECT content,compacted FROM events WHERE acceptance_id=?",
                              (accepted["acceptance_id"],)).fetchall()
            self.assertTrue(all(row["compacted"] == 1 for row in rows))
            self.assertTrue(all("envelope" not in json.loads(row["content"]) for row in rows))
        after, page, _ = self.page()
        self.assertEqual(before, after)
        self.assertEqual(self.references(page), self.expected(accepted))

    def test_reference_bytes_count_towards_page_budget_without_skipping_slots(self):
        accepted = self.accepted_with_receipts()
        self.terminal(accepted)
        _, full, _ = self.page(token="synthetic-A1-token")
        self.assertEqual(len(full["events"]), 2)
        budget = len(encode_json(full["events"][0]))
        # 降低已存在的页上限，只验证新公开引用计入预算，不声称自然容量。
        with patch("stream_pages.MAX_PAGE_BYTES", budget + 512):
            _, first, _ = self.page(token="synthetic-A1-token")
            self.assertEqual([slot["event_seq"] for slot in first["events"]], ["1"])
            self.assertTrue(first["has_more"])
            _, second, _ = self.page(token="synthetic-A1-token", request={**self.f.request,
                                      "stream_id": first["stream_id"], "after_seq": "1"})
        self.assertEqual([slot["event_seq"] for slot in second["events"]], ["2"])
        self.assertFalse(second["has_more"])
        self.assertEqual(first["events"] + second["events"], full["events"])

    def test_original_page_digest_cannot_cover_removed_or_changed_terminal_reference(self):
        accepted = self.accepted_with_receipts()
        self.terminal(accepted)
        _, page, statement = self.page(token="synthetic-A1-token")
        for field, replacement in (("type", "read"), ("acceptance_id", "different"),
                                   ("attempt_id", "different"), ("device", {"account_id": "B", "device_id": "B1"})):
            changed = deepcopy(page)
            changed["events"][0]["terminal_reference"][field] = replacement
            self.assertNotEqual(hashlib.sha256(encode_json(changed)).hexdigest(), statement["page_sha256"])
        old_projection = deepcopy(page)
        for slot in old_projection["events"]:
            slot.pop("terminal_reference")
        self.assertNotEqual(hashlib.sha256(encode_json(old_projection)).hexdigest(), statement["page_sha256"])


if __name__ == "__main__":
    unittest.main()
