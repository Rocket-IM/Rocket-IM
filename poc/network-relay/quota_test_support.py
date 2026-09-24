"""原配额的模块测试装置；近限行仅为合成占额，不代表真实消息或自然容量。"""

import base64
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from contract import ProtocolError, encode_json, validate_request
from controls import TestControls
from server import DISPATCH
from storage import MAX_ATTEMPTS, MAX_EVENTS, MAX_STREAM_EVENTS, Store, logical_key
from test_support import envelope, fixture


class QuotaFixture(unittest.TestCase):
    """不含 test_ 方法；只调用原 Store/DISPATCH，不改业务或阈值。"""

    def setUp(self):
        self.assertEqual((MAX_ATTEMPTS, MAX_EVENTS, MAX_STREAM_EVENTS), (10000, 60000, 10000))
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "relay.sqlite3"
        self.fixture = fixture()
        self.fixture["devices"].extend({"account_id": "C", "device_id": device,
                                        "token": f"synthetic-{device}-token"} for device in ("C1", "C2"))
        self.members = [{name: device[name] for name in ("account_id", "device_id")}
                        for device in self.fixture["devices"]]
        self.fixture["conversation"]["members"] = self.members
        self.store = Store(self.path, self.fixture)
        self.controller = TestControls(True)

    def call(self, operation, request, token="synthetic-A1-token"):
        validate_request(operation, request)
        with self.store.transaction() as db:
            device = self.store.authenticate(db, token)
            return DISPATCH[operation](self.store, db, device, request)

    def control(self, request):
        with self.store.transaction() as db:
            return self.controller.execute(self.store, db, self.fixture["controller_token"], request)

    def message(self, logical):
        return {"envelope": envelope(logical, recipients=self.members[1:])}

    def snapshot(self):
        """同一显式只读事务比较全部表字段，不能以行数相同代替内容不变。"""
        db = sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
        try:
            db.execute("BEGIN")
            schema = tuple(db.execute("SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name"))
            state = {"__schema__": schema}
            for name, _ in schema:
                quoted = '"' + name.replace('"', '""') + '"'
                state[name] = tuple(db.execute(f"SELECT * FROM {quoted} ORDER BY rowid"))
            db.commit()
            return state
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def reopen(self):
        # 新 Store 实例重读持久数据库；这不是 HTTP 进程退出或物理断电证据。
        before = self.snapshot()
        self.store = Store(self.path, self.fixture)
        self.controller = TestControls(True)
        self.assertEqual(self.snapshot(), before)

    def seed_attempts(self, total):
        with self.store.transaction() as db:
            existing = db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]
            self.assertTrue(existing <= total <= MAX_ATTEMPTS)
            rows = []
            for index in range(total - existing):
                logical, closure = f"quota_fixture_{index}", f"quota_fixture_closure_{index}"
                value = {"outcome": "cancelled_before_accept", "logical_message_id": logical,
                         "attempt_id": "P1", "closure_id": closure}
                ident = logical_key("S1", "G1", {"account": "A", "device": "A1"}, logical)
                rows.append((ident, "P1", value["outcome"], closure, encode_json(value).decode()))
            db.executemany("INSERT INTO logical_messages(key,tail) VALUES (?,?)", [(row[0], row[1]) for row in rows])
            db.executemany("INSERT INTO attempts(logical_key,attempt_id,outcome,closure_id,result) VALUES (?,?,?,?,?)", rows)

    def seed_stream(self, device, last_seq):
        member = next(item for item in self.members if item["device_id"] == device)
        pair = (member["account_id"], device)
        with self.store.transaction() as db:
            previous = db.execute("SELECT COALESCE(MAX(seq),0) FROM events WHERE account=? AND device=?", pair).fetchone()[0]
            self.assertTrue(previous <= last_seq <= MAX_STREAM_EVENTS)
            # 非协议事件只占已有计数/序号空间，绝不作为客户端收到的合法消息。
            content = encode_json({"type": "quota_fixture", "synthetic_occupancy": True}).decode()
            db.executemany("INSERT INTO events(account,device,seq,event_id,content) VALUES (?,?,?,?,?)",
                           ((*pair, seq, f"quota_fixture_{device}_{seq}", content)
                            for seq in range(previous + 1, last_seq + 1)))

    def seed_streams(self, counts):
        for device, count in counts.items():
            self.seed_stream(device, count)

    def reject_unchanged(self, operation, request, message, *, token="synthetic-A1-token", inserted_events=0,
                         code="resource_exhausted", status=429):
        before, inserted = self.snapshot(), []
        append_event = self.store.append_event

        def observe(*args, **kwargs):
            append_event(*args, **kwargs)
            inserted.append((args[1], args[2]["type"]))

        # 仅观察实际成功的 INSERT；仍由原 append_event 执行原配额检查及写入。
        with patch.object(self.store, "append_event", side_effect=observe), self.assertRaises(ProtocolError) as caught:
            self.control(request) if operation == "_control" else self.call(operation, request, token)
        error = caught.exception
        self.assertEqual((error.code, error.status, error.outcome, error.message), (code, status, "not_recorded", message))
        self.assertEqual(len(inserted), inserted_events)
        self.assertEqual(self.snapshot(), before)
        return error

    def delivery(self, accepted, device="B1"):
        with self.store.transaction() as db:
            event_id = db.execute("SELECT event_id FROM events WHERE device=? AND acceptance_id=? AND json_extract(content,'$.type')='message'",
                                  (device, accepted["acceptance_id"])).fetchone()[0]
        return {"service_id": "S1", "acceptance_id": accepted["acceptance_id"],
                "attempt_id": accepted["attempt_id"], "event_id": event_id}

    @staticmethod
    def control_request(index, *, append=False):
        return {"action": "add_control", "control": {"control_id": f"C{index}",
            "from_state_ref": f"{index - 1:064x}", "to_state_ref": f"{index:064x}",
            "payload_bytes": base64.b64encode(b"synthetic-quota-control").decode()},
            "recipients": [{"account_id": "A", "device_id": "A2"}, {"account_id": "B", "device_id": "B1"}],
            "append_events": append}
