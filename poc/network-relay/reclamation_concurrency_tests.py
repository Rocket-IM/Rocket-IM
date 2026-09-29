"""真实128计划边界及原请求并发幂等；新HTTP进程重启，不把opaque替身称为MLS验收。"""

from reclamation_concurrency_test_support import ReclamationConcurrencyFixture, digest
from reclamation_storage import MAX_PLANS, MAX_PROOF_BYTES
from test_support import key


class ReclamationConcurrencyTests(ReclamationConcurrencyFixture):
    def test_original_proof_byte_budget_serializes_competing_reservations(self):
        self.assertEqual(MAX_PROOF_BYTES, 16 * 1024 * 1024)
        _, first = self.terminal("proof_target_0000", header_size=16384)
        _, second = self.terminal("proof_target_0001", header_size=16384)
        ids = [first["acceptance_id"], second["acceptance_id"]]
        cost_a, cost_b = (self.proof_bytes([item]) for item in ids)
        pair_cost = cost_a + cost_b
        completed, messages = 0, 0
        # 每项均走原submit/terminal/confirm/finish；JSON尾随空格是合法头字节，未伪造已回收行。
        while MAX_PROOF_BYTES - self.proof_bytes() > pair_cost:
            remaining = MAX_PROOF_BYTES - self.proof_bytes()
            count = min(16, max(1, (remaining - pair_cost) // (cost_a + 256)))
            padding = 16384
            if count == 1:
                # 留下可承载一条但不能同时承载两条的空间；实际计费在下面重新断言。
                padding = min(16384, remaining - cost_a - cost_b // 2 - (cost_a - 16384) - 256)
                self.assertGreaterEqual(padding, 1024)
            batch = []
            for _ in range(count):
                _, accepted = self.terminal(f"proof_filler_{messages:04}", header_size=padding)
                batch.append(accepted["acceptance_id"])
                messages += 1
            self.reclaim(batch, f"proof_fill_{completed:03}")
            completed += 1
            self.assertLess(completed, MAX_PLANS - 2)
        compact_bytes = self.proof_bytes()
        self.assertLessEqual(compact_bytes + cost_a, MAX_PROOF_BYTES)
        self.assertLessEqual(compact_bytes + cost_b, MAX_PROOF_BYTES)
        self.assertGreater(compact_bytes + pair_cost, MAX_PROOF_BYTES)
        request_a, request_b = self.confirmation(first, "proof_winner"), self.confirmation(second, "proof_loser")
        responses = self.race("confirm_reclaim", [("A1", request_a), ("A1", request_b)])
        self.assertEqual(responses[0], (200, {"ok": True, "result": {"status": "pending", "plan_id": "proof_winner"}}))
        self.assertEqual((responses[1][0], responses[1][1]["error"]["code"]), (429, "resource_exhausted"))
        self.assertEqual(self.proof_bytes(), compact_bytes + cost_a)
        committed = self.state()
        self.reopen_unchanged()
        self.assertEqual(self.race("confirm_reclaim", [("A1", request_a)] * 4), [responses[0]] * 4)
        self.assertEqual(self.request("confirm_reclaim", request_b), responses[1])
        self.assertEqual(self.state(), committed)
        self.reclaim(ids[:1], "proof_winner")
        with self.database() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM reclamation_plans").fetchone()[0], completed + 1)
            self.assertIsNone(db.execute("SELECT 1 FROM reclamation_plans WHERE plan_id='proof_loser'").fetchone())
            self.assertEqual(db.execute("SELECT compacted,payload IS NULL FROM attempts WHERE acceptance_id=?", (ids[0],)).fetchone()[:], (1, 1))
            self.assertEqual(db.execute("SELECT compacted,payload IS NULL FROM attempts WHERE acceptance_id=?", (ids[1],)).fetchone()[:], (0, 0))
        self.assertEqual(self.proof_bytes(), compact_bytes + cost_a)
        completed_state = self.state()
        self.assertEqual(self.request("confirm_reclaim", request_b), responses[1])
        self.assertEqual(self.state(), completed_state, "finish不能释放永久证明额度或给败者留下记录")
        self.evidence["proof_budget"] = {"threshold_bytes": MAX_PROOF_BYTES, "compacted_before_race_bytes": compact_bytes,
            "candidate_bytes": [cost_a, cost_b], "after_reservation_bytes": self.proof_bytes(),
            "messages_compacted_via_original_http": messages, "completed_filler_plans": completed,
            "header_source": "original accepted raw JSON headers with valid trailing whitespace; opaque non-MLS payload",
            "scope": "actual 16MiB production boundary: either candidate fits individually; both exceed it"}

    def test_128th_plan_reservation_wins_once_and_retries_survive_process_restart(self):
        self.assertEqual(MAX_PLANS, 128)
        # 127项通过原HTTP提交、终态、首次confirm建立；没有降低阈值或直接伪造计划行。
        for index in range(MAX_PLANS - 1):
            _, accepted = self.terminal(f"occupied_{index:03}")
            self.assertEqual(self.call("confirm_reclaim", self.confirmation(accepted, f"occupied_{index:03}"))["status"], "pending")
        _, a = self.terminal("last_a")
        _, b = self.terminal("last_b")
        first, second = self.confirmation(a, "last_a"), self.confirmation(b, "last_b")
        before = self.state()
        responses = self.race("confirm_reclaim", [("A1", first), ("A1", second)])
        self.assertEqual(responses[0][0], 200)
        self.assertEqual(responses[0][1]["result"]["status"], "pending")
        self.assertEqual((responses[1][0], responses[1][1]["error"]["code"]), (429, "resource_exhausted"))
        with self.database() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM reclamation_plans").fetchone()[0], MAX_PLANS)
            self.assertIsNone(db.execute("SELECT 1 FROM reclamation_plans WHERE plan_id='last_b'").fetchone())
            self.assertIsNone(db.execute("SELECT 1 FROM reclamation_selection WHERE acceptance_id=?", (b["acceptance_id"],)).fetchone())
        committed = self.state()
        self.assertNotEqual(committed, before)
        for restart in (False, True):
            if restart:
                self.reopen_unchanged()
            retries = self.race("confirm_reclaim", [("A1", first)] * 4)
            self.assertTrue(all(r == responses[0] for r in retries))
            self.assertEqual(self.state(), committed)
            self.assertEqual(self.request("confirm_reclaim", second), responses[1])
            self.assertEqual(self.state(), committed)
        self.evidence["occupancy"] = {"plans_via_original_http": 127, "threshold": MAX_PLANS, "final_plans": MAX_PLANS,
                                      "ciphertext_and_signatures": "explicit fixtures; not real MLS"}

    def test_same_selection_competing_plans_and_exact_confirm_only_reserve_once(self):
        _, accepted = self.terminal("same_selection")
        first = self.confirmation(accepted, "winner")
        other = self.confirmation(accepted, "competitor")
        responses = self.race("confirm_reclaim", [("A1", first), ("A1", other), ("A1", first)])
        self.assertEqual(responses[0], responses[2])
        self.assertEqual((responses[1][0], responses[1][1]["error"]["code"]), (409, "reclamation_conflict"))
        with self.database() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM reclamation_plans").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM reclamation_selection").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM reclamation_participants WHERE request IS NOT NULL").fetchone()[0], 1)
        committed = self.state()
        self.reopen_unchanged()
        self.assertEqual(self.race("confirm_reclaim", [("A1", first)] * 4), [responses[0]] * 4)
        self.assertEqual(self.state(), committed)

    def test_concurrent_ready_confirmation_and_last_finish_reuse_proofs_and_release_once(self):
        original, accepted = self.terminal("finish_once")
        terminal_accepted = self.call("get_attempt", key("finish_once"))
        requests = {d: self.confirmation(accepted, "finish_once", d) for d in ("A1", "A2", "B1")}
        for device in ("A1", "A2"):
            self.call("confirm_reclaim", requests[device], device)
        ready = self.race("confirm_reclaim", [("B1", requests["B1"])] * 4)
        self.assertTrue(all(response == ready[0] for response in ready))
        self.assertEqual(ready[0][1]["result"]["status"], "ready")
        receipts = {d: self.call("confirm_reclaim", r, d)["receipt"] for d, r in requests.items()}
        for device in ("A1", "A2"):
            self.assertEqual(self.call("finish_reclaim", self.finish("finish_once", receipts[device]), device)["status"], "pending")
        with self.database() as db:
            marks_before = [tuple(r) for r in db.execute("SELECT * FROM stream_watermarks ORDER BY account,device")]
            self.assertEqual(db.execute("SELECT COUNT(*) FROM attempts WHERE payload IS NOT NULL").fetchone()[0], 1)
        last = self.finish("finish_once", receipts["B1"])
        responses = self.race("finish_reclaim", [("B1", last)] * 4)
        self.assertTrue(all(r == (200, {"ok": True, "result": {"status": "complete", "plan_id": "finish_once"}}) for r in responses))
        with self.database() as db:
            marks_after = [tuple(r) for r in db.execute("SELECT * FROM stream_watermarks ORDER BY account,device")]
            self.assertEqual([(r[0], r[1], r[2]) for r in marks_before], [(r[0], r[1], r[2]) for r in marks_after])
            self.assertTrue(all(r[3] == r[2] for r in marks_after))
            self.assertEqual(db.execute("SELECT COUNT(*) FROM attempts WHERE compacted=1 AND payload IS NULL").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events WHERE compacted=1").fetchone()[0], 4)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events WHERE json_extract(content,'$.envelope') IS NOT NULL").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM reclamation_participants WHERE finished=1 AND receipt IS NOT NULL").fetchone()[0], 3)
        committed = self.state()
        self.reopen_unchanged()
        self.assertEqual(self.race("finish_reclaim", [("B1", last)] * 4), responses)
        self.assertEqual(self.call("submit_message", original), terminal_accepted)
        self.assertEqual(self.call("get_attempt", key("finish_once")), terminal_accepted)
        self.assertEqual(self.state(), committed)
        self.evidence["restarted_completed_snapshot_sha256"] = digest(committed)
