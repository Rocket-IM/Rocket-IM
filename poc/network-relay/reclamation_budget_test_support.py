"""回收原字节预算装置：原 SQLite/公开操作，真实签名；opaque 载荷不代表 MLS。"""

import base64
import hashlib
import json
import sqlite3
import subprocess
from pathlib import Path

from contract import encode_json, validate_request
from controls import TestControls
from permission_tests import VerifiedFixture
from reclamation_budget import attempt_size, event_size
from receipt_signer import ReceiptSigner
from server import DISPATCH
from storage import Store
from test_support import envelope


def digest_database(path):
    """显式只读事务覆盖 schema、全部表、字段和值；不以文件大小代替内容。"""
    digest = hashlib.sha256()
    with sqlite3.connect(Path(path).as_uri() + "?mode=ro", uri=True) as db:
        db.execute("BEGIN")
        schema = list(db.execute("SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name"))
        digest.update(encode_json(schema))
        for name, _ in schema:
            quoted = '"' + name.replace('"', '""') + '"'
            for row in db.execute(f"SELECT * FROM {quoted} ORDER BY rowid"):
                digest.update(encode_json([{"blob": base64.b64encode(v).decode()} if isinstance(v, bytes) else v for v in row]))
        db.commit()
    return digest.hexdigest()


def plan_sizes(db, reserve_completion=False):
    result = {}
    for plan in db.execute("SELECT * FROM reclamation_plans"):
        value = dict(plan)
        if reserve_completion:
            value["status"] = "complete"
        total = len(encode_json(value))
        for table in ("reclamation_participants", "reclamation_selection"):
            total += sum(len(encode_json(dict(row))) for row in db.execute(f"SELECT * FROM {table} WHERE plan_id=?", (plan["plan_id"],)))
        result[plan["plan_id"]] = total
    return result


def proof_size(db, candidate_ids=()):
    ids = set(candidate_ids) | {row[0] for row in db.execute(
        "SELECT s.acceptance_id FROM reclamation_selection s JOIN reclamation_plans p ON p.plan_id=s.plan_id WHERE p.status!='complete'")}
    keys = {db.execute("SELECT logical_key FROM attempts WHERE acceptance_id=?", (item,)).fetchone()[0] for item in ids}
    total = sum(attempt_size(row) for row in db.execute("SELECT * FROM attempts WHERE compacted=1"))
    total += sum(event_size(row) for row in db.execute("SELECT * FROM events WHERE compacted=1"))
    for key in keys:
        total += sum(attempt_size(row) for row in db.execute("SELECT * FROM attempts WHERE logical_key=? AND compacted=0", (key,)))
    for item in ids:
        total += sum(event_size(row) for row in db.execute("SELECT * FROM events WHERE acceptance_id=? AND compacted=0", (item,)))
    return total


class BudgetFixture:
    """不继承任何测试方法；预算阈值、签名输出及生产操作均不替换。"""

    def __init__(self, directory, signer_path, participants=2, long_ids=False):
        self.directory = Path(directory).absolute()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "relay.sqlite3"
        self.signer_path = Path(signer_path).absolute()
        self.key_path = self.directory / "service-receipt.key"
        init = subprocess.run([str(self.signer_path)], input=encode_json({"operation": "init", "key_path": str(self.key_path)}),
                              capture_output=True, timeout=10, check=True)
        reply = json.loads(init.stdout)
        assert reply["ok"] is True
        self.signer = ReceiptSigner(self.signer_path, self.key_path)
        self.sign_calls = 0
        self.last_plan_receipts = {}
        original_sign = self.signer.sign

        def observe_sign(statement):
            self.sign_calls += 1
            receipt = original_sign(statement)
            if statement["protocol_version"] == "rim-message-reclaim-1":
                plan = statement["plan_id"]
                if self.last_plan_receipts.get("plan_id") != plan:
                    self.last_plan_receipts = {"plan_id": plan, "receipts": {}}
                self.last_plan_receipts["receipts"][(statement["account_id"], statement["device_id"])] = receipt
            return receipt

        self.signer.sign = observe_sign
        self.service = "S" * 64 if long_ids else "S1"
        self.conversation = "G" * 64 if long_ids else "G1"
        devices = [{"account_id": str(n).zfill(64) if long_ids else f"A{n}",
                    "device_id": str(n).zfill(64) if long_ids else f"D{n}",
                    "token": f"synthetic-budget-token-{n}",
                    "signature_key": base64.b64encode(bytes([n + 1]) * 32).decode()}
                   for n in range(participants)]
        self.members = [{k: v[k] for k in ("account_id", "device_id")} for v in devices]
        self.tokens = [v["token"] for v in devices]
        self.fixture = {"service_id": self.service, "controller_token": "synthetic-budget-controller-token", "devices": devices,
                        "conversation": {"conversation_id": self.conversation, "authorization_version": "1",
                                         "crypto_state_ref": "a" * 64, "members": self.members},
                        "permission_checkpoint": {"service_id": self.service, "conversation_id": self.conversation,
                                                  "authorization_version": "1", "crypto_state_ref": "a" * 64,
                                                  "owner_account_id": devices[0]["account_id"],
                                                  "members": [{k: v[k] for k in ("account_id", "device_id", "signature_key")} for v in devices]},
                        "relay_receipt_key": reply["result"]["signature_key"]}
        self.store = Store(self.path, self.fixture, VerifiedFixture(), self.signer)
        self.controller = TestControls(True)
        self.operations = {}
        (self.directory / "fixture.json").write_bytes(encode_json(self.fixture))

    def call(self, operation, request, participant=0):
        self.operations[operation] = self.operations.get(operation, 0) + 1
        validate_request(operation, request)
        with self.store.transaction() as db:
            device = self.store.authenticate(db, self.tokens[participant])
            return DISPATCH[operation](self.store, db, device, request)

    def terminal(self, logical, header_size=None):
        value = envelope(logical, service_id=self.service, conversation_id=self.conversation,
                         sender=self.members[0], recipients=self.members[1:])
        raw = base64.b64decode(value["header_bytes"])
        if header_size is not None:
            assert len(raw) <= header_size <= 16384
            value["header_bytes"] = base64.b64encode(raw + b" " * (header_size - len(raw))).decode()
        accepted = self.call("submit_message", {"envelope": value})
        with self.store.transaction() as db:
            self.controller.execute(self.store, db, self.fixture["controller_token"],
                                    {"action": "set_availability", "acceptance_id": accepted["acceptance_id"], "availability": "deleted"})
        return accepted["acceptance_id"]

    def requests(self, plan_id, ids):
        requests = []
        with self.store.transaction() as db:
            for member in self.members:
                pair = (member["account_id"], member["device_id"])
                stream = db.execute("SELECT stream_id FROM devices WHERE account=? AND device=?", pair).fetchone()[0]
                high = db.execute("SELECT high_watermark FROM stream_watermarks WHERE account=? AND device=?", pair).fetchone()[0]
                requests.append({"service_id": self.service, "conversation_id": self.conversation, "plan_id": plan_id,
                                 "stream_id": stream, "processed_seq": str(high), "acceptance_ids": sorted(ids)})
        return requests

    def finish(self, requests):
        for n, request in enumerate(requests):
            receipt = self.call("confirm_reclaim", request, n)["receipt"]
            result = self.call("finish_reclaim", {k: request[k] for k in ("service_id", "conversation_id", "plan_id")} | {"receipt": receipt}, n)
            assert result["status"] == ("complete" if n == len(requests) - 1 else "pending")
        with self.store.transaction() as db:
            for item in requests[0]["acceptance_ids"]:
                row = db.execute("SELECT payload,compacted FROM attempts WHERE acceptance_id=?", (item,)).fetchone()
                assert tuple(row) == (None, 1)
                events = db.execute("SELECT content,compacted FROM events WHERE acceptance_id=?", (item,)).fetchall()
                assert all(row["compacted"] == 1 and "envelope" not in json.loads(row["content"]) for row in events)

    def metrics(self, candidate_ids=()):
        with self.store.transaction() as db:
            plans = plan_sizes(db)
            charged = plan_sizes(db, reserve_completion=True)
            return {"plan_bytes": sum(plans.values()), "max_plan_bytes": max(plans.values(), default=0), "plans": len(plans),
                    "charged_plan_bytes_including_finish_reservation": sum(charged.values()),
                    "proof_bytes_including_reserved_and_candidates": proof_size(db, candidate_ids),
                    "rows": {table: db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in
                             ("attempts", "events", "reclamation_plans", "reclamation_participants", "reclamation_selection")},
                    "compacted_attempts": db.execute("SELECT COUNT(*) FROM attempts WHERE compacted=1").fetchone()[0],
                    "compacted_events": db.execute("SELECT COUNT(*) FROM events WHERE compacted=1").fetchone()[0],
                    "plan_statuses": dict(db.execute("SELECT status,COUNT(*) FROM reclamation_plans GROUP BY status")),
                    "sqlite_file_bytes": self.path.stat().st_size, "real_signature_calls": self.sign_calls,
                    "operations": dict(self.operations)}

    def projected_ready_plan_bytes(self, request, participant):
        """失败事务刚生成的真实许可仍仅用于独立计费，绝不重新写入数据库。"""
        with self.store.transaction() as db:
            sizes = plan_sizes(db, reserve_completion=True)
            plan = dict(db.execute("SELECT * FROM reclamation_plans WHERE plan_id=?", (request["plan_id"],)).fetchone())
            plan["status"] = "complete"
            total = len(encode_json(plan))
            own = tuple(self.members[participant][key] for key in ("account_id", "device_id"))
            for row in db.execute("SELECT * FROM reclamation_participants WHERE plan_id=?", (request["plan_id"],)):
                value, pair = dict(row), (row["account"], row["device"])
                if pair == own:
                    value["request"] = encode_json(request).decode()
                value["receipt"] = encode_json(self.last_plan_receipts["receipts"][pair]).decode()
                total += len(encode_json(value))
            total += sum(len(encode_json(dict(row))) for row in db.execute("SELECT * FROM reclamation_selection WHERE plan_id=?", (request["plan_id"],)))
            return sum(sizes.values()) - sizes[request["plan_id"]] + total

    def reopen(self):
        before = digest_database(self.path)
        self.store = Store(self.path, self.fixture, VerifiedFixture(), self.signer)
        assert digest_database(self.path) == before
