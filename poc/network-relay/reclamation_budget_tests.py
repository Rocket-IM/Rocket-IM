"""原字节阈值：合法入口自然累积与孤立计费函数样本分别记录，不宣称 MLS/HTTP。"""

import base64
import json
import os
import sqlite3
import unittest
from pathlib import Path

from contract import ProtocolError, encode_json
from reclamation import check_plan_bytes
from reclamation_budget import attempt_size, check_proof_bytes
from reclamation_budget_test_support import BudgetFixture, digest_database, plan_sizes
from reclamation_storage import MAX_PLAN_BYTES, MAX_PLAN_TOTAL_BYTES, MAX_PROOF_BYTES


def legal_plan_upper_bound():
    """ASCII ID 无转义；生成 ID 也放宽至64，P放宽至u64，故是保守上界。"""
    ident = "x" * 64
    ids = [str(n).zfill(64) for n in range(16)]
    recipients = [{"account_id": str(n).zfill(64), "device_id": ident} for n in range(5)]
    messages = [{"acceptance_id": item, "envelope_sha256": "a" * 64, "availability": "expired", "recipients": recipients} for item in ids]
    request = {k: ident for k in ("service_id", "conversation_id", "plan_id", "stream_id")}
    request.update(processed_seq="18446744073709551615", acceptance_ids=ids)
    receipt = {"statement_bytes": "x" * (4 * ((16384 + 2) // 3)), "signature_bytes": "x" * 88}
    plan = {"plan_id": ident, "selection": encode_json(ids).decode(), "messages": encode_json(messages).decode(), "status": "complete"}
    participant = {"plan_id": ident, "account": ident, "device": ident, "request": encode_json(request).decode(),
                   "receipt": encode_json(receipt).decode(), "finished": 1}
    size = lambda value: len(encode_json(value))
    base = size(plan) + 16 * size({"acceptance_id": ident, "plan_id": ident})
    pending, ready = base + 6 * size({**participant, "receipt": None}), base + 6 * size(participant)
    return {"pending_storage_upper_bytes": pending - 1, "pending_charged_upper_bytes": pending,
            "ready_storage_upper_bytes": ready - 3, "ready_charged_upper_bytes": ready,
            "complete_storage_and_charged_upper_bytes": ready, "max_messages_json_bytes": size(messages),
            "plan_row_upper_bytes": size(plan), "participant_ready_upper_bytes": size(participant),
            "selection_row_upper_bytes": size({"acceptance_id": ident, "plan_id": ident})}


@unittest.skipUnless(os.environ.get("M12_BUDGET_EVIDENCE") and os.environ.get("M12_BUDGET_SIGNER"),
                     "原阈值长测试须显式提供独立证据目录和已归档真实签名器")
class ReclamationBudgetTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual((MAX_PLAN_BYTES, MAX_PLAN_TOTAL_BYTES, MAX_PROOF_BYTES), (262144, 8388608, 16777216))
        self.directory = Path(os.environ["M12_BUDGET_EVIDENCE"]).absolute() / self._testMethodName
        self.directory.mkdir(parents=True, exist_ok=False)
        self.evidence = {"case": self._testMethodName, "limits": {"single_plan": MAX_PLAN_BYTES, "all_plans": MAX_PLAN_TOTAL_BYTES, "proof": MAX_PROOF_BYTES},
                         "boundaries": {"transport": "原SQLite事务/validate_request/DISPATCH，无HTTP", "payload": "opaque-fixture，非MLS",
                                        "signing": "已归档build5真实Service签名器；不替换其输出", "permission": "合成初始检查点；无权限变更验签操作",
                                        "terminal": "已有TestControls set_availability；P按Relay已提交H申报，无Rust客户端"}}
        self.addCleanup(self.save)

    def save(self):
        (self.directory / "evidence.json").write_text(json.dumps(self.evidence, ensure_ascii=False, indent=2) + "\n")

    def lab(self, participants=2, long_ids=False):
        return BudgetFixture(self.directory / "lab", os.environ["M12_BUDGET_SIGNER"], participants, long_ids)

    def refuse_unchanged(self, lab, request, participant, expected):
        before = digest_database(lab.path)
        with self.assertRaises(ProtocolError) as caught:
            lab.call("confirm_reclaim", request, participant)
        error = caught.exception
        self.assertEqual((error.code, error.status, error.message), ("resource_exhausted", 429, expected))
        after = digest_database(lab.path)
        self.assertEqual(after, before)
        self.evidence["refusal"] = {"code": error.code, "status": error.status, "outcome": error.outcome, "message": error.message,
                                     "database_before_sha256": before, "database_after_sha256": after}
        lab.reopen()

    def test_maximum_legal_plan_is_below_unreachable_single_plan_limit(self):
        bound = legal_plan_upper_bound()
        self.assertEqual((bound["pending_charged_upper_bytes"], bound["ready_charged_upper_bytes"]), (31581, 163491))
        self.assertLess(bound["ready_charged_upper_bytes"], MAX_PLAN_BYTES)
        lab = self.lab(6, True)
        ids = [lab.terminal(str(n).zfill(64)) for n in range(16)]
        requests = lab.requests("P" * 64, ids)
        for n, request in enumerate(requests):
            result = lab.call("confirm_reclaim", request, n)
            self.assertEqual(result["status"], "ready" if n == 5 else "pending")
        with lab.store.transaction() as db:
            lengths = [len(base64.b64decode(json.loads(row[0])["statement_bytes"])) for row in db.execute("SELECT receipt FROM reclamation_participants")]
        self.assertLessEqual(max(lengths), 16384)
        self.evidence.update(tier="合法最大维度入口形状", mathematical_upper_bound=bound, actual_statement_bytes=lengths, ready=lab.metrics())
        lab.finish(requests)
        lab.reopen()
        self.evidence["complete"] = lab.metrics()

    def test_natural_total_plan_bytes_reaches_original_eight_mib(self):
        lab = self.lab(6, True)
        progress = []
        for plan in range(128):
            ids = [lab.terminal(f"{plan:04d}{n:04d}".zfill(64)) for n in range(16)]
            requests = lab.requests(str(plan).zfill(64), ids)
            for n, request in enumerate(requests):
                # 所有前置输入均真实提交；只在首次实际拒绝后对同一请求重试验证原错误。
                before = digest_database(lab.path) if n == 5 else None
                try:
                    result = lab.call("confirm_reclaim", request, n)
                except ProtocolError as error:
                    self.assertEqual(error.message, "回收计划字节预算已满")
                    if before is not None:
                        self.assertEqual(digest_database(lab.path), before)
                    self.refuse_unchanged(lab, request, n, error.message)
                    final = lab.metrics(ids)
                    self.assertLess(final["plans"], 128)
                    self.assertLess(final["proof_bytes_including_reserved_and_candidates"], MAX_PROOF_BYTES)
                    self.assertLessEqual(final["charged_plan_bytes_including_finish_reservation"], MAX_PLAN_TOTAL_BYTES)
                    self.evidence.update(tier="原入口合法自然累积", rejected_plan_index=plan, rejected_participant=n,
                                         final=final, progress=progress, no_database_seeding=True)
                    if n == 5:
                        self.evidence["rejected_projected_plan_bytes"] = lab.projected_ready_plan_bytes(request, n)
                        self.assertGreater(self.evidence["rejected_projected_plan_bytes"], MAX_PLAN_TOTAL_BYTES)
                    return
                self.assertEqual(result["status"], "ready" if n == 5 else "pending")
            if plan == 0:
                lab.finish(requests)
            metrics = lab.metrics()
            progress.append(metrics)
            self.evidence["progress"] = progress
            self.save()
            print(f"plan budget: {plan + 1} ready plans, {metrics['plan_bytes']} B", flush=True)
        self.fail("128计划先命中，8MiB合法可达性预期不成立")

    def test_natural_compact_proof_bytes_reaches_original_sixteen_mib(self):
        lab = self.lab()
        progress = []
        for plan in range(128):
            ids = [lab.terminal(f"M{plan:04d}_{n:02d}", 16384) for n in range(16)]
            requests = lab.requests(f"P{plan:04d}", ids)
            prospective = lab.metrics(ids)
            if prospective["proof_bytes_including_reserved_and_candidates"] > MAX_PROOF_BYTES:
                self.refuse_unchanged(lab, requests[0], 0, "回收证明总字节预算已满，保留原数据")
                final = lab.metrics()
                self.assertLess(final["plans"], 128)
                self.assertLess(final["plan_bytes"], MAX_PLAN_TOTAL_BYTES)
                self.assertLessEqual(final["proof_bytes_including_reserved_and_candidates"], MAX_PROOF_BYTES)
                self.evidence.update(tier="原入口合法自然累积", prospective_rejected=prospective, final=final,
                                     progress=progress, legal_raw_header_bytes=16384, padding="JSON尾部ASCII空格，签名绑定原始字节", no_database_seeding=True)
                return
            for n, request in enumerate(requests):
                lab.call("confirm_reclaim", request, n)
            lab.finish(requests)
            metrics = lab.metrics()
            progress.append(metrics)
            self.evidence["progress"] = progress
            self.save()
            print(f"proof budget: {plan + 1} completed plans, {metrics['proof_bytes_including_reserved_and_candidates']} B", flush=True)
        self.fail("128计划先命中，16MiB合法可达性预期不成立")

    def synthetic_plan_boundary(self, cumulative):
        """仅验证原计费函数比较符；这些任意字符串行不可由合法入口生成。"""
        with sqlite3.connect(":memory:") as db:
            db.row_factory = sqlite3.Row
            db.executescript("CREATE TABLE reclamation_plans(plan_id,selection,messages,status);"
                             "CREATE TABLE reclamation_participants(plan_id,account,device,request,receipt,finished);"
                             "CREATE TABLE reclamation_selection(acceptance_id,plan_id);")
            limit = MAX_PLAN_TOTAL_BYTES if cumulative else MAX_PLAN_BYTES
            targets = [250000] * 33 + [limit - 250000 * 33] if cumulative else [limit]
            for n, target in enumerate(targets):
                row = {"plan_id": str(n), "selection": "[]", "messages": "", "status": "complete"}
                row["messages"] = "x" * (target - len(encode_json(row)))
                db.execute("INSERT INTO reclamation_plans VALUES (?,?,?,?)", tuple(row.values()))
            self.assertEqual(sum(plan_sizes(db).values()), limit)
            db.execute("UPDATE reclamation_plans SET messages=substr(messages,1,length(messages)-1) WHERE plan_id=?", (str(len(targets) - 1),))
            check_plan_bytes(db, "0")
            db.execute("UPDATE reclamation_plans SET messages=messages||'x' WHERE plan_id=?", (str(len(targets) - 1),))
            check_plan_bytes(db, "0")
            db.execute("UPDATE reclamation_plans SET messages=messages||'x' WHERE plan_id=?", (str(len(targets) - 1),))
            with self.assertRaises(ProtocolError) as caught:
                check_plan_bytes(db, "0")
            expected = "回收计划字节预算已满" if cumulative else "回收单计划字节预算已满"
            self.assertEqual(caught.exception.message, expected)
            self.evidence.update(tier="孤立原预算函数合成精确边界；不是合法状态或端到端", accepted_bytes=[limit - 1, limit], rejected_bytes=limit + 1,
                                 plans=len(targets), error={"code": caught.exception.code, "message": expected}, signer_used=False)

    def test_synthetic_single_plan_exact_original_boundary(self):
        self.synthetic_plan_boundary(False)

    def test_synthetic_total_plans_exact_original_boundary(self):
        self.synthetic_plan_boundary(True)

    def test_ready_plan_reserves_three_finish_status_bytes(self):
        lab = self.lab()
        requests = lab.requests("real-plan", [lab.terminal("real-message")])
        for n, request in enumerate(requests):
            lab.call("confirm_reclaim", request, n)
        with lab.store.transaction() as db:
            remaining = MAX_PLAN_TOTAL_BYTES - sum(plan_sizes(db).values())
            n = 0
            while remaining:
                size = min(250000, remaining)
                row = {"plan_id": f"synthetic-filler-{n}", "selection": "[]", "messages": "", "status": "complete"}
                row["messages"] = "x" * (size - len(encode_json(row)))
                db.execute("INSERT INTO reclamation_plans VALUES (?,?,?,?)", tuple(row.values()))
                remaining -= size
                n += 1
        self.evidence.update(tier="真实ready许可加合成近满计划账本；非自然累计或端到端", before=lab.metrics(),
                             database_before_sha256=digest_database(lab.path))
        try:
            with lab.store.transaction() as db:
                check_plan_bytes(db, "real-plan")
        except ProtocolError as error:
            self.assertEqual(error.message, "回收计划字节预算已满")
            self.evidence["reserved_check_refusal"] = {"code": error.code, "message": error.message, "status": error.status}
            self.assertEqual(digest_database(lab.path), self.evidence["database_before_sha256"])
        else:
            lab.finish(requests)
            self.evidence["unreserved_finish_overflow"] = lab.metrics()
            self.evidence["database_after_sha256"] = digest_database(lab.path)
            self.fail("原8MiB账本没有预留ready→complete的3B，finish已提交越界")
        with lab.store.transaction() as db:
            db.execute("UPDATE reclamation_plans SET messages=substr(messages,1,length(messages)-3) WHERE plan_id='synthetic-filler-0'")
            check_plan_bytes(db, "real-plan")
        lab.finish(requests)
        final = lab.metrics()
        self.assertEqual(final["plan_bytes"], MAX_PLAN_TOTAL_BYTES)
        self.evidence["completed_at_original_limit"] = final
        self.evidence["database_after_sha256"] = digest_database(lab.path)

    def test_synthetic_proof_exact_original_boundary(self):
        with sqlite3.connect(":memory:") as db:
            db.row_factory = sqlite3.Row
            db.executescript("CREATE TABLE attempts(logical_key,header BLOB,compacted); CREATE TABLE events(content,compacted);")
            # 合成counter样本故意不具备原消息/签名来源；每个header仍小于16KiB。
            for n in range(2048):
                row = {"logical_key": str(n), "header": b"{}", "compacted": 1}
                padding = 8192 - attempt_size(row)
                db.execute("INSERT INTO attempts VALUES (?,?,1)", (str(n), row["header"] + b" " * padding))
            self.assertEqual(sum(attempt_size(row) for row in db.execute("SELECT * FROM attempts")), MAX_PROOF_BYTES)
            row = db.execute("SELECT header FROM attempts WHERE logical_key='0'").fetchone()
            db.execute("UPDATE attempts SET header=? WHERE logical_key='0'", (row[0][:-1],))
            check_proof_bytes(db, set(), set())
            db.execute("UPDATE attempts SET header=? WHERE logical_key='0'", (row[0],))
            check_proof_bytes(db, set(), set())
            row = db.execute("SELECT header FROM attempts WHERE logical_key='0'").fetchone()
            db.execute("UPDATE attempts SET header=? WHERE logical_key='0'", (row[0] + b" ",))
            with self.assertRaises(ProtocolError) as caught:
                check_proof_bytes(db, set(), set())
            self.assertEqual(caught.exception.message, "回收证明总字节预算已满，保留原数据")
            self.evidence.update(tier="孤立原预算函数合成精确边界；不是合法状态或端到端", accepted_bytes=[MAX_PROOF_BYTES - 1, MAX_PROOF_BYTES],
                                 rejected_bytes=MAX_PROOF_BYTES + 1, attempts=2048, signer_used=False,
                                 error={"code": caught.exception.code, "message": caught.exception.message})


if __name__ == "__main__":
    unittest.main(verbosity=2)
