"""实际原阈值的容量拒绝与事务补证；合成占额不代表自然流量、密码或生产容量。"""

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock, patch

from contract import ProtocolError
from quota_test_support import QuotaFixture
import server
from storage import Store
from test_support import envelope, key


class QuotaTests(QuotaFixture):
    def near_attempt_limit(self):
        original = self.message("original_accepted")
        accepted = self.call("submit_message", original)
        closed = self.call("close_attempt", key("original_closed"))
        rejected_request = {"envelope": envelope("original_rejected", authorization_version="0", recipients=self.members[1:])}
        rejected = self.call("submit_message", rejected_request)
        self.assertEqual(rejected["outcome"], "rejected_final")
        self.seed_attempts(9999)
        self.assertEqual(len(self.snapshot()["attempts"]), 9999)
        return original, accepted, closed, rejected_request, rejected

    def assert_full_attempts(self, originals):
        original, accepted, closed, rejected_request, rejected = originals
        before = self.snapshot()
        self.assertEqual(len(before["attempts"]), 10000)
        self.assertEqual(self.reject_unchanged("submit_message", self.message("new_at_full"),
                         "实验尝试总量已达上限").details, {"retry_after_ms": "1000"})
        self.reject_unchanged("close_attempt", key("close_at_full"), "实验尝试总量已达上限")
        self.assertEqual(self.call("submit_message", original), accepted)
        self.assertEqual(self.call("get_attempt", key("original_accepted")), accepted)
        self.assertEqual(self.call("close_attempt", key("original_accepted")), accepted)
        self.assertEqual(self.call("close_attempt", key("original_closed")), closed)
        self.assertEqual(self.call("get_attempt", key("original_closed")), closed)
        self.assertEqual(self.call("get_attempt", key("original_rejected")), rejected)
        with self.assertRaises(ProtocolError) as caught:
            self.call("submit_message", rejected_request)
        self.assertEqual((caught.exception.code, caught.exception.outcome), ("state_stale", "rejected_final"))
        self.assertEqual(caught.exception.details["closure_id"], rejected["closure_id"])
        self.assertEqual(self.snapshot(), before)

    def test_attempt_last_slot_accepts_once_and_full_keeps_original_terminals(self):
        originals = self.near_attempt_limit()
        request = self.message("last_accepted")
        accepted = self.call("submit_message", request)
        self.assertEqual(accepted["outcome"], "accepted")
        self.assert_full_attempts(originals)
        self.reopen()
        self.assertEqual(self.call("submit_message", request), accepted)
        self.assert_full_attempts(originals)

    def test_attempt_last_slot_closes_once_and_reopen_does_not_release_capacity(self):
        originals = self.near_attempt_limit()
        request = key("last_closed")
        closed = self.call("close_attempt", request)
        self.assertEqual(closed["outcome"], "cancelled_before_accept")
        self.assert_full_attempts(originals)
        self.reopen()
        self.assertEqual(self.call("close_attempt", request), closed)
        self.assert_full_attempts(originals)

    def test_full_single_stream_rolls_back_earlier_target_and_attempt(self):
        self.seed_stream("B1", 10000)
        request = self.message("stream_full")
        self.reject_unchanged("submit_message", request, "设备事件流已达实验上限", inserted_events=1)
        self.assertEqual(self.call("get_attempt", key("stream_full"))["outcome"], "not_found")
        self.reopen()
        self.reject_unchanged("submit_message", request, "设备事件流已达实验上限", inserted_events=1)

    def test_expiration_at_full_stream_preserves_original_retry_with_explicit_pending(self):
        request = self.message("expiration_blocks_original")
        with patch("messages.now_ms", return_value=1000):
            accepted = self.call("submit_message", request)
        self.seed_stream("B1", 10000)
        before = self.snapshot()
        self.assertEqual((len(before["attempts"]), len(before["events"])), (1, 10004))
        deadline = int(accepted["expires_at_unix_ms"])
        operations = (("submit_message", request),
                      ("get_attempt", key("expiration_blocks_original")),
                      ("close_attempt", key("expiration_blocks_original")))
        append_event = Store.append_event

        for reopened in (False, True):
            if reopened:
                self.reopen()
            for operation, value in operations:
                with self.subTest(operation=operation, reopened=reopened):
                    # 直接业务入口仍可精确重试；差异来自原 Handler 的到期投影顺序。
                    self.assertEqual(self.call(operation, value), accepted)
                    handler = object.__new__(server.Handler)
                    handler.server = SimpleNamespace(store=self.store, controls=self.controller)
                    handler.path = "/v1/" + operation
                    handler.request_body = Mock(return_value=("synthetic-A1-token", value))
                    handler.response = Mock()
                    dispatch = Mock(wraps=server.DISPATCH[operation])
                    with patch.dict(server.DISPATCH, {operation: dispatch}), \
                            patch("synchronization.now_ms", return_value=deadline - 1):
                        handler.do_POST()
                    self.assertEqual(dispatch.call_count, 2)
                    handler.response.assert_called_once_with(200, {"ok": True, "result": accepted})
                    self.assertEqual(self.snapshot(), before)
                    dispatch.reset_mock()
                    handler.response.reset_mock()
                    inserted = []

                    def observe(db, pair, event, acceptance_id=None):
                        append_event(db, pair, event, acceptance_id)
                        inserted.append((pair, event["type"], event["availability"]))

                    # 原 Handler/鉴权/事务/投影均实际执行；仅替换传输边界与时钟，不启动 HTTP。
                    with patch.dict(server.DISPATCH, {operation: dispatch}), \
                            patch("synchronization.now_ms", return_value=deadline), \
                            patch.object(Store, "append_event", side_effect=observe):
                        handler.do_POST()
                    dispatch.assert_called_once()
                    handler.response.assert_called_once_with(200, {"ok": True, "result": {
                        **accepted, "lifecycle_projection_pending": True}})
                    self.assertEqual(inserted, [(("A", "A2"), "message_availability", "expired")])
                    self.assertEqual(self.snapshot(), before)
                    self.assertEqual(self.call(operation, value), accepted)

    def test_global_events_full_mid_fanout_rolls_back_two_inserted_targets(self):
        self.seed_streams({"A1": 10000, "A2": 9999, "B1": 9999, "B2": 10000, "C1": 10000, "C2": 10000})
        self.assertEqual(len(self.snapshot()["events"]), 59998)
        request = self.message("global_full")
        self.reject_unchanged("submit_message", request, "实验事件总量已达上限", inserted_events=2)
        self.reopen()
        self.reject_unchanged("submit_message", request, "实验事件总量已达上限", inserted_events=2)

    def test_global_events_exact_fit_keeps_old_acceptance_retry_available(self):
        self.seed_streams({"A1": 10000, "A2": 9999, "B1": 9999, "B2": 9999, "C1": 9999, "C2": 9999})
        self.assertEqual(len(self.snapshot()["events"]), 59995)
        request = self.message("exact_fit")
        accepted = self.call("submit_message", request)
        before = self.snapshot()
        self.assertEqual(len(before["events"]), 60000)
        self.assertEqual(self.call("submit_message", request), accepted)
        self.assertEqual(self.call("get_attempt", key("exact_fit")), accepted)
        self.assertEqual(self.snapshot(), before)
        self.reject_unchanged("submit_message", self.message("past_exact_fit"), "实验事件总量已达上限")
        self.reopen()
        self.assertEqual(self.call("submit_message", request), accepted)
        self.assertEqual(self.snapshot(), before)

    def test_delivery_capacity_failure_rolls_back_receipt_and_partial_notifications(self):
        accepted = self.call("submit_message", self.message("delivery_quota"))
        request = self.delivery(accepted)
        self.seed_stream("B1", 10000)
        self.reject_unchanged("report_delivery", request, "设备事件流已达实验上限",
                              token="synthetic-B1-token", inserted_events=2)
        self.assertEqual(self.snapshot()["receipts"], ())
        self.reopen()
        self.reject_unchanged("report_delivery", request, "设备事件流已达实验上限",
                              token="synthetic-B1-token", inserted_events=2)

    def test_read_global_capacity_failure_rolls_back_implicit_delivery_and_read(self):
        accepted = self.call("submit_message", self.message("read_global_quota"))
        self.seed_streams({"A1": 9999, "A2": 9999, "B1": 9999, "B2": 9999, "C1": 9999, "C2": 10000})
        self.assertEqual(len(self.snapshot()["events"]), 59995)
        request = {"service_id": "S1", "acceptance_ids": [accepted["acceptance_id"]]}
        self.reject_unchanged("report_read", request, "实验事件总量已达上限",
                              token="synthetic-B1-token", inserted_events=5)
        self.assertEqual(self.snapshot()["receipts"], ())

    def test_read_batch_second_item_failure_rolls_back_first_complete_item(self):
        accepted = [self.call("submit_message", self.message(logical)) for logical in ("batch_one", "batch_two")]
        self.seed_stream("A1", 9997)
        request = {"service_id": "S1", "acceptance_ids": [value["acceptance_id"] for value in accepted]}
        # 第一项 12 个通知已经写入；第二项 6 个 delivery 后，首个 read 触及原单流上限。
        self.reject_unchanged("report_read", request, "设备事件流已达实验上限",
                              token="synthetic-B1-token", inserted_events=18)
        self.assertEqual(self.snapshot()["receipts"], ())
        self.reopen()
        self.reject_unchanged("report_read", request, "设备事件流已达实验上限",
                              token="synthetic-B1-token", inserted_events=18)

    def test_read_upgrade_at_full_keeps_delivered_true_and_read_false(self):
        accepted = self.call("submit_message", self.message("upgrade_quota"))
        delivery = self.delivery(accepted)
        original = self.call("report_delivery", delivery, "synthetic-B1-token")
        self.assertEqual((original["delivered"], original["read"]), (True, False))
        self.seed_stream("B1", 10000)
        request = {"service_id": "S1", "acceptance_ids": [accepted["acceptance_id"]]}
        self.reject_unchanged("report_read", request, "设备事件流已达实验上限",
                              token="synthetic-B1-token", inserted_events=2)
        before = self.snapshot()
        self.assertEqual(before["receipts"], ((accepted["acceptance_id"], "B", "B1", 1, 0),))
        self.assertEqual(self.call("report_delivery", delivery, "synthetic-B1-token"), original)
        self.assertEqual(self.snapshot(), before)

    def test_controls_last_slot_rolls_back_fanout_and_full_retries_remain_exact(self):
        for index in range(1, 128):
            self.assertEqual(self.control(self.control_request(index)), {"control_id": f"C{index}", "reused": False})
        self.seed_stream("B1", 10000)
        self.reject_unchanged("_control", self.control_request(128, append=True),
                              "设备事件流已达实验上限", inserted_events=1)
        self.assertEqual(len(self.snapshot()["controls"]), 127)
        self.assertEqual(self.control(self.control_request(128)), {"control_id": "C128", "reused": False})
        full = self.snapshot()
        self.assertEqual(len(full["controls"]), 128)
        for _ in range(2):
            self.assertEqual(self.control(self.control_request(128)), {"control_id": "C128", "reused": True})
            self.reject_unchanged("_control", self.control_request(129), "控制材料超过实验上限")
            changed = deepcopy(self.control_request(128))
            changed["control"]["payload_bytes"] = "AQ=="
            self.reject_unchanged("_control", changed, "控制记录不可修改", code="idempotency_conflict", status=409)
            self.assertEqual(self.snapshot(), full)
            self.reopen()
        ids, after = [], None
        while True:
            request = {"service_id": "S1", "conversation_id": "G1", "from_state_ref": f"{0:064x}",
                       "to_state_ref": f"{128:064x}", "limit": "32"}
            if after is not None:
                request["after_control_id"] = after
            page = self.call("get_crypto_dependencies", request, "synthetic-B1-token")
            ids.extend(item["control_id"] for item in page["controls"])
            after = page["next_after_control_id"]
            if not page["has_more"]:
                break
        self.assertEqual(ids, [f"C{index}" for index in range(1, 129)])
        self.assertEqual(self.snapshot(), full)
