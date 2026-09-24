// 新候选初始化、批准绑定与入群失败的真实浏览器验证；报告不保存认证 seed 或密码状态。
import assert from "node:assert/strict";
import { open as openCrypto } from "./crypto_support.mjs";
import { requireSnapshot as anchorSnapshot } from "./anchor_support.mjs";
import { scopeKey } from "./anchor_wire.mjs";
import {
  SERVICE, oldPair, candidateOptions, openCandidate, fixture, activate, join, diagnostic,
  openAnchored, call, close, reject, cleanup, reopen, requireSnapshot, exchange,
} from "./rebuild_support.mjs";

function errorCode(error) {
  const match = error.match(/"code":"([A-Za-z0-9_]+)"/);
  assert.ok(match, "typed failure code absent");
  return match[1];
}

function assertCandidate(view) {
  assert.equal(view.phase, "candidate");
  assert.equal(view.snapshot, null);
  assert.equal(view.status, null);
  assert.ok(view.candidate);
  return view.candidate;
}

function assertUnresolved(view, offer) {
  assert.equal(view.phase, "paused");
  assert.equal(view.snapshot, null);
  assert.deepEqual(view.candidate, offer);
  assert.equal(view.status.phase, "paused");
  assert.equal(view.status.localPending, true);
  assert.match(view.status.remotePending, /^[0-9a-f]{64}$/);
  assert.notEqual(view.status.localHead, view.status.remoteHead);
  assert.equal(view.status.remoteHead, offer.head);
  return view.status;
}

export async function runRebuildFaultCases(k) {
  const failures = {
    after_crypto: /"code":"crypto_injected_failure"/,
    after_sql: /"code":"storage_error"/,
    refuse_commit: /"code":"commit_failed"/,
    reserve_refuse: /"code":"commit_failed"/,
  };
  for (const [fault, pattern] of Object.entries(failures)) {
    await k.check("rebuild_initial_" + fault + "_cannot_regenerate_in_same_namespace", async () => {
      const p = await k.page();
      const options = candidateOptions(k, { account: "rf_initial_" + fault }, { initialFault: fault });
      const { initialFault: _initialFault, ...existing } = options;
      try {
        const requests = (await k.anchor.diagnostics()).requests;
        const initial = errorCode(await reject(() => openCandidate(p, options, "a", true), pattern));
        const reopened = [];
        for (let attempt = 0; attempt < 2; attempt++) {
          reopened.push(errorCode(await reject(() => openCandidate(p, existing), /"code":"rebuild_candidate_incomplete"/)));
          await reject(() => openCandidate(p, existing, "a", true), /"code":"rebuild_candidate_exists"/);
        }
        assert.equal((await k.anchor.diagnostics()).requests, requests, "failed candidate initialization reached the anchor");
        assert.equal(await p.evaluate(() => window.clients.a === undefined), true);
        return { fault, initial_error: initial, reopen_errors: reopened, identity_regenerated: false,
          same_namespace_recreation_rejected: true, public_candidate_returned: false };
      } finally { await cleanup(p); }
    });
  }

  await k.check("rebuild_initial_result_lost_recovers_same_committed_public_identity", async () => {
    const p = await k.page();
    const options = candidateOptions(k, { account: "rf_initial_committed" }, { initialFault: "after_commit" });
    const { initialFault: _initialFault, ...existing } = options;
    try {
      const requests = (await k.anchor.diagnostics()).requests;
      const initial = errorCode(await reject(() => openCandidate(p, options, "a", true), /"code":"rebuild_initial_result_lost"/));
      await openCandidate(p, existing);
      const first = assertCandidate(await diagnostic(p, "offer"));
      await reject(() => call(p, "inspect"), /"code":"rebuild_approval_required"/);
      await close(p);
      await reject(() => openCandidate(p, existing, "a", true), /"code":"rebuild_candidate_exists"/);
      await openCandidate(p, existing);
      assert.deepEqual(assertCandidate(await diagnostic(p, "offer")), first);
      await reject(() => call(p, "send", ["early", "early", "must remain unavailable"]), /"code":"rebuild_approval_required"/);
      assert.equal((await k.anchor.diagnostics()).requests, requests);
      return { initial_error: initial, committed_identity_stable: true, approval_required: true,
        public_offer_recovered: true, crypto_snapshot_returned: false };
    } finally { await cleanup(p); }
  });

  await k.check("rebuild_approval_signature_conversation_and_peer_binding_reject_before_link", async () => {
    const f = await fixture(k, "rf_approval");
    try {
      await openCrypto(f.p, "rf_third_peer", "third", true, SERVICE);
      const third = await call(f.p, "initialize", [], "third");
      const signature = Buffer.from(f.approval.signature_bytes, "base64"); signature[0] ^= 1;
      const mutations = [
        { plan: f.plan, approval: { ...f.approval, signature_bytes: signature.toString("base64") }, code: "anchor_signature" },
        { plan: { ...f.plan, conversation: "different_approved_group" }, approval: f.approval, code: "anchor_rebuild_binding" },
        { plan: { ...f.plan, peer: third.identity }, approval: f.approval, code: "anchor_rebuild_binding" },
      ];
      const requests = (await k.anchor.diagnostics()).requests;
      const errors = [];
      for (const mutation of mutations) {
        errors.push(errorCode(await reject(() => call(f.p, "activate", [mutation.plan, mutation.approval]),
          new RegExp('"code":"' + mutation.code + '"'))));
        assert.deepEqual(assertCandidate(await diagnostic(f.p)), f.candidate.offer);
      }
      assert.equal((await k.anchor.diagnostics()).requests, requests, "invalid approval reached the authority");
      const predecessor = await k.anchor.inspect(f.old.config.scope);
      assert.equal(predecessor.head, f.basis.oldHead);
      assert.equal(predecessor.pending.txn, f.basis.oldTxn);
      await activate(f);
      assert.equal((await diagnostic(f.p)).phase, "linked");
      return { error_codes: errors, wrong_signature_group_and_peer_rejected: true,
        rejected_plans_persisted: false, original_plan_remains_usable: true };
    } finally { await cleanup(f.p); }
  });

  await k.check("rebuild_join_admission_is_bound_to_approved_conversation_and_peer", async () => {
    const f = await fixture(k, "rf_admission");
    try {
      await activate(f);
      const grouped = anchorSnapshot(await call(f.p, "createGroup", [f.plan.conversation, f.candidate.offer.identity], "peer"));
      await openCrypto(f.p, "rf_admission_third", "third", true, SERVICE);
      const third = await call(f.p, "initialize", [], "third");
      const before = await diagnostic(f.p), requests = (await k.anchor.diagnostics()).requests;
      for (const [conversation, peer] of [["wrong_new_group", f.plan.peer], [f.plan.conversation, third.identity]]) {
        await reject(() => call(f.p, "joinGroup", [conversation, peer, grouped.welcome]), /"code":"rebuild_admission_binding"/);
      }
      assert.equal((await k.anchor.diagnostics()).requests, requests, "invalid join entered anchor reservation");
      assert.deepEqual(await diagnostic(f.p), before);
      const joined = requireSnapshot(await call(f.p, "joinGroup", [f.plan.conversation, f.plan.peer, grouped.welcome]));
      assert.equal(joined.conversation, f.plan.conversation);
      assert.equal(joined.encryptions, "0"); assert.equal(joined.decryptions, "0");
      assert.equal(joined.downloadCursor, "0"); assert.equal(joined.processingCursor, "0");
      for (const list of [joined.messages, joined.outbox, joined.events, joined.receipts]) assert.equal(list.length, 0);
      return { unapproved_group_and_peer_rejected: true, invalid_join_reserved: false,
        approved_join_completed: true, imported_old_records: 0 };
    } finally { await cleanup(f.p); }
  });

  await k.check("rebuild_completed_local_journal_is_recovered_instead_of_becoming_basis", async () => {
    const old = await oldPair(k, "rf_completed");
    try {
      await k.anchor.fault({ action: "finish", mode: "timeout" });
      await reject(() => call(old.p, "send", ["completed_uncertain", "completed_uncertain_message", "recover exact committed result"], "old"),
        /"code":"anchor_rpc_failed"/);
      const diagnostics = await k.anchor.diagnostics();
      assert.equal(diagnostics.fault, null);
      assert.ok(diagnostics.records.some(item => item.action === "finish" && item.mode === "timeout"));
      await close(old.p, "old"); await openAnchored(old.p, old.config, "old");
      const before = await call(old.p, "status", [], "old");
      assert.equal(before.snapshot, null); assert.equal(before.status.phase, "paused");
      assert.equal(before.status.localPending, true); assert.ok(before.status.remotePending);
      assert.notEqual(before.status.localHead, before.status.remoteHead);
      const requests = (await k.anchor.diagnostics()).requests;
      const error = errorCode(await reject(() => call(old.p, "rebuildBasis", [], "old"), /"code":"anchor_rebuild_basis"/));
      assert.equal((await k.anchor.diagnostics()).requests, requests, "ineligible completed journal caused an authority request");
      assert.deepEqual(await call(old.p, "status", [], "old"), before);
      const resumed = await call(old.p, "resume", [], "old");
      assert.equal(resumed.snapshot, null); assert.equal(resumed.status.phase, "ready");
      const recovered = anchorSnapshot(await call(old.p, "inspect", [], "old"));
      assert.equal(recovered.encryptions, "2"); assert.equal(recovered.decryptions, "1");
      assert.equal(recovered.outbox.filter(item => item.attemptId === "completed_uncertain").length, 1);
      assert.equal(recovered.messages.length, old.before.messages.length);
      assert.deepEqual(recovered.receipts, old.before.receipts);
      assert.equal(recovered.processingCursor, old.before.processingCursor);
      return { error_code: error, completed_journal_rejected_as_basis: true,
        original_committed_result_recovered: true, encryptions: "2", rebuild_started: false };
    } finally { await cleanup(old.p); }
  });

  for (const fault of ["after_sql", "refuse_commit"]) {
    await k.check("rebuild_join_" + fault + "_stays_paused_without_new_candidate_or_success", async () => {
      const f = await fixture(k, "rf_join_" + fault);
      try {
        await activate(f);
        // 未入群时 subscribe 的初始 inspect 本身被拒绝；只断言已发生的 Promise 和诊断行为。
        const error = errorCode(await reject(() => join(f, { fault }), failures[fault]));
        const failed = assertUnresolved(await diagnostic(f.p), f.candidate.offer);
        await reopen(k, f);
        const after = assertUnresolved(await diagnostic(f.p), f.candidate.offer);
        assert.equal(after.localHead, failed.localHead); assert.equal(after.remotePending, failed.remotePending);
        await reject(() => call(f.p, "resume"), /"code":"anchor_unresolved"/);
        await reject(() => call(f.p, "inspect"), /"code":"rebuild_join_required"/);
        await reject(() => call(f.p, "joinGroup", [f.plan.conversation, f.plan.peer, f.welcome]), /"code":"anchor_paused"/);
        await reject(() => call(f.p, "send", ["early", "early", "unconfirmed join"]), /"code":"rebuild_join_required"/);
        const remote = await k.anchor.inspect(f.candidate.offer.scope);
        assert.equal(remote.head, f.candidate.offer.head); assert.equal(remote.pending.txn, failed.remotePending);
        await close(f.p);
        await reject(() => openCandidate(f.p, f.candidate.options, "a", true), /"code":"rebuild_candidate_exists"/);
        await openCandidate(f.p, f.candidate.options);
        assertUnresolved(await diagnostic(f.p), f.candidate.offer);
        return { fault, error_code: error, admission_success_returned: false, diagnostic_snapshot: null,
          reservation_persisted: true, candidate_identity_unchanged: true, same_namespace_recreation_rejected: true };
      } finally { await cleanup(f.p); }
    });
  }
  await runRebuildMissingReservationCase(k);
}

async function runRebuildMissingReservationCase(k) {
  await k.check("rebuild_lost_reserve_reply_and_link_precommit_exit_resume_exact_plan", async () => {
    const f = await fixture(k, "rf_empty_reservation", { fault: "reserve_drop_after" });
    try {
      const old = await k.anchor.inspect(f.old.config.scope);
      const scope = scopeKey(f.old.config.scope);
      const reserveEvidence = (await k.anchor.diagnostics()).faultRecords.filter(record =>
        record.action === "reserve" && record.mode === "drop_after" && record.scopeKey === scope);
      assert.equal(reserveEvidence.length, 1, "must observe the intended lost reserve response");
      assert.equal(reserveEvidence[0].outcome, "reserved");
      assert.equal(reserveEvidence[0].txn, f.basis.oldTxn);
      assert.equal(old.closure, undefined);
      assert.ok(old.pending);
      assert.equal(f.basis.localHead, f.basis.baselineHead,
        "the lost reply must precede the durable crypto reservation and all MLS work");
      assert.equal(f.basis.localHead, f.basis.oldHead);
      assert.equal(f.basis.oldHead, old.head);
      assert.equal(f.basis.oldTxn, old.pending.txn);
      assert.equal(f.basis.oldRevision, old.revision);
      assert.equal(old.pending.base, f.basis.oldHead);
      assert.equal(old.pending.reservedRevision, f.basis.oldRevision);
      assert.equal(f.basis.oldConversation, f.old.oldConversation);
      await reject(() => call(f.p, "resume", [], "old"), /"code":"anchor_unresolved"/);
      assert.deepEqual(await call(f.p, "rebuildBasis", [], "old"), f.basis);
      assert.deepEqual(await k.anchor.inspect(f.old.config.scope), old);

      const exitCount = k.anchor.evidence.exits.length;
      await k.rebuild.fault({ action: "link", mode: "before_commit" });
      await reject(() => activate(f), /"code":"anchor_rpc_failed"/);
      await k.anchor.restart();
      assert.ok(k.anchor.evidence.exits.slice(exitCount).some(exit => exit.code === 91),
        "authority must actually exit before its Link transaction commits");
      assert.ok(k.anchor.evidence.faultRecords.some(record => record.action === "link"
        && record.mode === "before_commit" && record.scopeKey === scope && record.txn === f.plan.rebuild_id));
      assert.deepEqual(await k.anchor.inspect(f.old.config.scope), old,
        "uncommitted Link must not seal or change the old reservation");
      await assert.rejects(() => k.anchor.inspect(f.candidate.offer.scope), error => error.code === "anchor_scope");
      assert.deepEqual(await call(f.p, "rebuildBasis", [], "old"), f.basis);
      const paused = await diagnostic(f.p);
      assert.equal(paused.phase, "paused"); assert.equal(paused.status, null);
      assert.deepEqual(paused.candidate, f.candidate.offer);
      await reject(() => call(f.p, "send", ["early", "early", "no linked permission"]),
        /"code":"rebuild_approval_required"/);

      await reopen(k, f);
      assert.deepEqual(await diagnostic(f.p), paused,
        "stored intent must survive reopen even though the authority is still unlinked");
      await assert.rejects(() => k.anchor.inspect(f.candidate.offer.scope), error => error.code === "anchor_scope");
      // 只调用 resume；若实现丢失批准意图，不能靠第二次 activate 掩盖。
      const resumed = await diagnostic(f.p, "resume");
      assert.equal(resumed.phase, "linked"); assert.deepEqual(resumed.candidate, f.candidate.offer);
      const child = await k.anchor.inspect(f.candidate.offer.scope);
      assert.equal(child.head, f.candidate.offer.head); assert.equal(child.revision, "0");
      assert.equal(child.pending, null);
      const sealed = await k.anchor.inspect(f.old.config.scope);
      assert.equal(sealed.closure, "rebuilt");
      assert.equal(sealed.successorScopeKey, scopeKey(f.candidate.offer.scope));
      for (const field of ["scope", "head", "revision", "pending", "last", "rebuildApproverPublicKey"]) {
        assert.deepEqual(sealed[field], old[field], "old fact changed: " + field);
      }
      const repeated = await diagnostic(f.p, "resume");
      assert.equal(repeated.phase, "linked"); assert.deepEqual(repeated.candidate, f.candidate.offer);
      assert.deepEqual(await k.anchor.inspect(f.candidate.offer.scope), child,
        "a second resume must neither reinitialize the child nor advance its anchor revision");
      await reject(() => openAnchored(f.p, f.old.config, "closedOld"), /"code":"anchor_closed"/);

      const joined = await join(f);
      assert.equal(joined.conversation, f.plan.conversation);
      assert.equal(joined.identity.identityKey, f.candidate.offer.identity.identityKey);
      for (const field of ["encryptions", "decryptions", "downloadCursor", "processingCursor"]) {
        assert.equal(joined[field], "0");
      }
      for (const field of ["outbox", "events", "messages", "receipts"]) assert.equal(joined[field].length, 0);
      const { sent, received } = await exchange(f);
      assert.equal(sent.encryptions, "1"); assert.equal(received.decryptions, "1");
      assert.equal(received.messages.length, 1); assert.equal(received.receipts.length, 1);
      assert.equal(received.downloadCursor, "1"); assert.equal(received.processingCursor, "1");
      assert.deepEqual(await k.anchor.inspect(f.old.config.scope), sealed,
        "new traffic must leave the permanently sealed predecessor unchanged");
      return { reserve_response_lost_before_crypto_reservation: true, basis_local_head_equals_baseline: true,
        link_authority_exit: 91, uncommitted_link_created_child: false, stored_plan_resumed_without_reapproval: true,
        successor_anchor_revision_before_join: "0", original_candidate_reused: true, real_new_messages: 2 };
    } finally {
      if (!k.anchor.child) await k.anchor.restart();
      await cleanup(f.p);
    }
  });
}
