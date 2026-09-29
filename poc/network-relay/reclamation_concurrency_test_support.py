"""独立进程真实HTTP/SQLite屏障；复用原Handler/Store，签名和密文仅为明确合成替身。"""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import base64
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import sqlite3
import threading

from controls import TestControls
from http_test_support import RelayHTTPFixture
from receipt_test_support import ReceiptFixture, VerifiedCloseFixture, receipt_fixture
from reclamation_budget_test_support import proof_size
import server
from storage import Store
from test_support import envelope


def snapshot(db):
    """完整表定义及所有字段；哈希只用于证据输出，不以局部计数代替状态比较。"""
    schema = tuple(tuple(row) for row in db.execute("SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name"))
    values = [("__schema__", schema)]
    for name, _ in schema:
        quoted = '"' + name.replace('"', '""') + '"'
        values.append((name, tuple(tuple(row) for row in db.execute(f"SELECT * FROM {quoted} ORDER BY rowid"))))
    return tuple(values)


def digest(value):
    return hashlib.sha256(repr(value).encode()).hexdigest()


def serve(path, ready, entered, release, condition, begins, held):
    """测试子进程仅包住原事务/提交hook作观察；不替换调度、SQL或额度判断。"""
    store = Store(Path(path) / "relay.sqlite3", json.loads((Path(path) / "fixture.json").read_bytes()),
                  VerifiedCloseFixture(), ReceiptFixture())
    local = threading.local()
    original_connect, original_transaction = store.connect, store.transaction

    def trace(sql):
        if sql == "BEGIN IMMEDIATE":
            with condition:
                begins.value += 1
                condition.notify_all()

    def connect():
        db = original_connect()
        db.set_trace_callback(trace)
        return db

    @contextmanager
    def transaction():
        with original_transaction() as db:
            local.db = db
            yield db

    original_hook = server.Handler.before_commit

    def barrier(hook):
        if hook and hook["name"] == "delay_before_commit":
            held.put({"snapshot_sha256": digest(snapshot(local.db)), "pid": os.getpid()})
            entered.set()
            if not release.wait(4):
                raise TimeoutError("测试提交屏障未释放")
        original_hook(hook)

    store.connect, store.transaction = connect, transaction
    server.Handler.before_commit = staticmethod(barrier)
    relay = server.RelayServer(("127.0.0.1", 0), store, TestControls(True))
    ready.send({"url": f"http://127.0.0.1:{relay.server_port}", "pid": os.getpid()})
    ready.close()
    relay.serve_forever(poll_interval=0.01)


class ReclamationConcurrencyFixture(RelayHTTPFixture):
    """全部业务请求走原HTTP入口；只读观察和合法合成近满占额可直接访问测试SQLite。"""

    def fixture_value(self):
        value = receipt_fixture()
        members = {"A1", "A2", "B1"}
        value["devices"] = [d for d in value["devices"] if d["device_id"] in members]
        value["permission_checkpoint"]["members"] = [d for d in value["permission_checkpoint"]["members"] if d["device_id"] in members]
        value["conversation"]["members"] = [{k: d[k] for k in ("account_id", "device_id")} for d in value["permission_checkpoint"]["members"]]
        return value

    def prepare_runtime(self):
        self.context = multiprocessing.get_context("spawn")
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(self.stop)
        self.evidence = {"scope": "loopback HTTP and SQLite transactions; opaque payload and signature fixtures; no MLS evidence",
                         "processed_confirmation": "fixture clients explicitly confirm original persistent H; no Rust processing evidence",
                         "test_only_hooks": "original delay_before_commit hook plus BEGIN IMMEDIATE observation", "races": [], "pids": []}

    def start(self, **_options):
        reader, writer = self.context.Pipe(duplex=False)
        self.entered, self.release = self.context.Event(), self.context.Event()
        self.condition, self.begins, self.held = self.context.Condition(), self.context.Value("i", 0), self.context.Queue()
        self.process = self.context.Process(target=serve, args=(str(self.path), writer, self.entered, self.release,
                                                               self.condition, self.begins, self.held))
        self.process.start()
        writer.close()
        try:
            self.assertTrue(reader.poll(8), "Relay子进程没有就绪")
            ready = reader.recv()
        finally:
            reader.close()
        self.url = ready["url"]
        self.evidence["pids"].append(ready["pid"])

    def stop(self):
        if self.process is not None:
            self.release.set()
            self.process.terminate()
            self.process.join(5)
            self.assertFalse(self.process.is_alive(), "Relay子进程没有退出")
            self.process.close()
            self.process = None
            self.held.close()
            self.held.join_thread()

    def tearDown(self):
        self.stop()
        output = os.environ.get("RIM_RECLAMATION_CONCURRENCY_OUTPUT")
        if output:
            destination = Path(output)
            destination.mkdir(parents=True, exist_ok=True)
            saved = destination / (self._testMethodName + ".sqlite3")
            with self.database() as source:
                target = sqlite3.connect(saved)
                try:
                    source.backup(target)
                finally:
                    target.close()
                self.evidence["final_state_sha256"] = digest(snapshot(source))
                self.evidence["watermarks"] = [dict(row) for row in source.execute("SELECT * FROM stream_watermarks ORDER BY account,device")]
                self.evidence["rows"] = {name: source.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
                                         for name in ("attempts", "events", "reclamation_plans", "reclamation_selection", "reclamation_participants")}
            self.evidence["final_database"] = {"file": saved.name, "sha256": hashlib.sha256(saved.read_bytes()).hexdigest()}
            (destination / (self._testMethodName + ".json")).write_text(json.dumps(self.evidence, indent=2) + "\n")
        self.directory.cleanup()

    @contextmanager
    def database(self, write=False):
        uri = (self.path / "relay.sqlite3").as_uri() + ("?mode=rw" if write else "?mode=ro")
        db = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=6)
        db.row_factory = sqlite3.Row
        try:
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def state(self):
        with self.database() as db:
            return snapshot(db)

    def call(self, operation, value, device="A1"):
        status, body = self.request(operation, value, f"synthetic-{device}-token")
        self.assertEqual(status, 200, body)
        return body["result"]

    def terminal(self, logical, header_size=None):
        value = envelope(logical)
        if header_size is not None:
            raw = base64.b64decode(value["header_bytes"])
            self.assertTrue(len(raw) <= header_size <= 16384)
            value["header_bytes"] = base64.b64encode(raw + b" " * (header_size - len(raw))).decode()
        request = {"envelope": value}
        accepted = self.call("submit_message", request)
        self.control({"action": "set_availability", "acceptance_id": accepted["acceptance_id"], "availability": "deleted"})
        return request, accepted

    def confirmation(self, accepted, plan, device="A1"):
        with self.database() as db:
            row = db.execute("SELECT d.stream_id,w.high_watermark FROM devices d JOIN stream_watermarks w "
                             "ON d.account=w.account AND d.device=w.device WHERE d.device=?", (device,)).fetchone()
        ids = accepted if isinstance(accepted, list) else [accepted["acceptance_id"]]
        return {"service_id": "S1", "conversation_id": "G1", "plan_id": plan, "stream_id": row["stream_id"],
                "processed_seq": str(row["high_watermark"]), "acceptance_ids": sorted(ids)}

    def ready(self, accepted, plan):
        requests = {d: self.confirmation(accepted, plan, d) for d in ("A1", "A2", "B1")}
        for device, request in requests.items():
            self.call("confirm_reclaim", request, device)
        receipts = {d: self.call("confirm_reclaim", r, d)["receipt"] for d, r in requests.items()}
        return requests, receipts

    def reclaim(self, ids, plan):
        _, receipts = self.ready(ids, plan)
        for device, receipt in receipts.items():
            result = self.call("finish_reclaim", self.finish(plan, receipt), device)
        self.assertEqual(result["status"], "complete")

    def proof_bytes(self, ids=()):
        with self.database() as db:
            return proof_size(db, ids)

    @staticmethod
    def finish(plan, receipt):
        return {"service_id": "S1", "conversation_id": "G1", "plan_id": plan, "receipt": receipt}

    def race(self, operation, calls):
        """固定首请求持有写事务，再确认其它请求真实执行BEGIN；不靠随机启动时序。"""
        self.entered.clear()
        self.release.clear()
        self.control({"action": "hook", "hook": "delay_before_commit", "delay_ms": "1"})
        begin = self.begins.value
        before = self.state()
        with ThreadPoolExecutor(max_workers=len(calls)) as executor:
            first, *rest = calls
            futures = [executor.submit(self.request, operation, first[1], f"synthetic-{first[0]}-token")]
            try:
                self.assertTrue(self.entered.wait(3), "首请求没有进入原提交hook")
                owner = self.held.get(timeout=3)
                futures.extend(executor.submit(self.request, operation, value, f"synthetic-{device}-token") for device, value in rest)
                with self.condition:
                    self.assertTrue(self.condition.wait_for(lambda: self.begins.value >= begin + len(calls), timeout=3),
                                    "竞争请求没有到达真实SQLite写事务")
                self.assertEqual(self.state(), before, "提交屏障内的写入提前可见")
            finally:
                self.release.set()
            responses = [future.result(timeout=8) for future in futures]
        after = self.state()
        # 本装置用于『首请求唯一有效变更；其余拒绝或精确幂等』，故完整结果必须相等。
        self.assertEqual(digest(after), owner["snapshot_sha256"], "竞争者留下额外部分写入")
        self.evidence["races"].append({"operation": operation, "requests": len(calls),
            "observed_begin_count": self.begins.value - begin, "owner_pid": owner["pid"],
            "before_sha256": digest(before), "first_commit_sha256": owner["snapshot_sha256"], "after_sha256": digest(after),
            "http_statuses": [r[0] for r in responses], "errors": [r[1].get("error", {}).get("code") for r in responses]})
        return responses

    def reopen_unchanged(self):
        before, previous = self.state(), self.process.pid
        self.stop()
        self.start()
        self.assertNotEqual(self.process.pid, previous)
        self.assertEqual(self.state(), before)
