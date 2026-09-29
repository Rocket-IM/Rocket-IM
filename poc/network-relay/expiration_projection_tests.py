"""原Handler的旧接受恢复通道；内存传输和时间替身，真实SQLite保存点。"""

from types import SimpleNamespace
from unittest.mock import Mock, patch

from contract import ProtocolError
from quota_test_support import QuotaFixture
import server
from test_support import envelope, key


class ExpirationProjectionTests(QuotaFixture):
    def setUp(self):
        super().setUp()
        self.original = self.message("M1")
        with patch("messages.now_ms", return_value=1000):
            self.accepted = self.call("submit_message", self.original)
        self.deadline = int(self.accepted["expires_at_unix_ms"])

    def request(self, operation, request):
        handler = object.__new__(server.Handler)
        handler.server = SimpleNamespace(store=self.store, controls=self.controller)
        handler.path = "/v1/" + operation
        handler.request_body = Mock(return_value=("synthetic-A1-token", request))
        handler.response = Mock()
        with patch("synchronization.now_ms", return_value=self.deadline):
            handler.do_POST()
        handler.response.assert_called_once()
        return handler.response.call_args.args

    def test_room_projects_terminal_and_omits_pending_marker(self):
        code, response = self.request("get_attempt", key())
        self.assertEqual(code, 200)
        self.assertEqual(response["result"], {**self.accepted, "availability": "expired"})
        self.assertEqual(self.call("get_attempt", key())["availability"], "expired")

    def test_changed_bytes_and_new_attempt_do_not_receive_preserved_acceptance(self):
        self.seed_stream("B1", 10000)
        before = self.snapshot()
        changed = {"envelope": envelope(payload=b"other", recipients=self.members[1:])}
        code, response = self.request("submit_message", changed)
        self.assertEqual((code, response["error"]["code"]), (409, "idempotency_conflict"))
        code, response = self.request("submit_message", self.message("M2"))
        self.assertEqual((code, response["error"]["code"]), (429, "resource_exhausted"))
        self.assertEqual(self.snapshot(), before)

    def test_noncapacity_projection_error_is_not_suppressed(self):
        before = self.snapshot()
        with patch("message_lifecycle.Store.append_event", side_effect=ProtocolError("state_conflict", "合成非容量错误", status=409)):
            code, response = self.request("get_attempt", key())
        self.assertEqual((code, response["error"]["code"]), (409, "state_conflict"))
        self.assertEqual(self.snapshot(), before)

    def test_full_returns_stored_acceptance_and_explicit_pending_without_projecting(self):
        self.seed_stream("B1", 10000)
        before = self.snapshot()
        code, response = self.request("get_attempt", key())
        self.assertEqual(code, 200)
        self.assertEqual(response["result"], {**self.accepted, "lifecycle_projection_pending": True})
        self.assertEqual(self.snapshot(), before)
