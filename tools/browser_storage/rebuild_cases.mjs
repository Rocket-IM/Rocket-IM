import assert from "node:assert/strict";
import { scopeKey } from "./anchor_wire.mjs";
import { requireSnapshot as anchorSnapshot, receive as anchorReceive } from "./anchor_support.mjs";
import { fixture, oldPair, makePending, newCandidate, newPeer, candidateOptions, openCandidate, prepare,
  activate, join, ready, reopen, diagnostic, snapshot, requireSnapshot, exchange,
  openAnchored, call, close, reject, cleanup, envelope, watch, crash, randomHex } from "./rebuild_support.mjs";

function preservedOld(before, after) {
  assert.equal(after.closure, "rebuilt");
  for (const field of ["scope", "head", "revision", "pending", "last", "rebuildApproverPublicKey"]) {
    assert.deepEqual(after[field], before[field], "old anchor fact changed: " + field);
  }
}
async function assertOldClosed(p, config) {
  await reject(() => openAnchored(p, config, "closedOld"), /anchor_closed/);
}
function deniedByAuthority(before, after, scope, action) {
  const key = scopeKey(scope);
  const matches = diagnostics => diagnostics.records.filter(record => record.action === action
    && record.scopeKey === key && record.outcome === "anchor_rebuild_denied");
  const previous = matches(before), current = matches(after);
  assert.equal(current.length, previous.length + 1, "the failing request must produce one new matching authority denial");
  assert.ok(Number.isSafeInteger(after.registryCount) && after.registryCount >= 0 && after.registryCount <= 128);
  return current.at(-1);
}
async function assertUnregistered(k, scope) {
  let rejected = false;
  try { await k.anchor.inspect(scope); }
  catch (error) { assert.equal(error.code, "anchor_scope"); rejected = true; }
  assert.equal(rejected, true, "the rejected successor must not be registered");
}

export async function runRebuildCases(k) {
  await k.check("rebuild_new_identity_and_scope_real_bidirectional_conversation", async () => {
    const f = await fixture(k, "rb_exchange");
    try {
      const old = await k.anchor.inspect(f.old.config.scope);
      const joined = await ready(f);
      for (const field of ["encryptions", "decryptions", "downloadCursor", "processingCursor"]) assert.equal(joined[field], "0");
      for (const field of ["outbox", "events", "messages", "receipts"]) assert.equal(joined[field].length, 0);
      assert.equal(f.old.before.encryptions, "1"); assert.equal(f.old.before.decryptions, "1");
      assert.equal(f.old.before.downloadCursor, "1"); assert.equal(f.old.before.processingCursor, "1");
      assert.notEqual(joined.identity.identityKey, f.old.before.identity.identityKey);
      assert.notEqual(joined.device, f.old.before.device); assert.notEqual(joined.conversation, f.old.oldConversation);
      await watch(f.p);
      const { sent, received } = await exchange(f);
      assert.equal(received.encryptions, "1"); assert.equal(received.decryptions, "1");
      assert.deepEqual(received.messages.map(message => message.text), ["new reply"]);
      const retry = requireSnapshot(await call(f.p, "send", ["new_attempt", "new_message", "new conversation"]));
      assert.equal(retry.encryptions, "1"); assert.deepEqual(retry.outbox, sent.outbox);
      assert.deepEqual(await f.p.evaluate(() => window.cryptoEvents.map(event => event.type)), ["snapshot", "committed", "committed", "committed"]);
      preservedOld(old, await k.anchor.inspect(f.old.config.scope));
      await close(f.p, "old"); await assertOldClosed(f.p, f.old.config);
      return { assurance: "synthetic_local_external_approver", new_device: joined.device,
        new_identity: f.candidate.offer.scope.identity_key, new_namespace: f.candidate.offer.storageNamespace,
        old_state_not_inherited: true, new_bidirectional_messages: 2, ciphertext_hash: sent.outbox[0].ciphertextHash };
    } finally { await cleanup(f.p); }
  });

  await k.check("rebuild_before_approval_all_communication_is_blocked", async () => {
    const f = await fixture(k, "rb_before_approval");
    try {
      // 对端先产生有效 Welcome/信封，使下面失败确实来自批准门禁而非输入格式。
      const grouped = anchorSnapshot(await call(f.p, "createGroup", [f.plan.conversation, f.candidate.offer.identity], "peer"));
      const sent = anchorSnapshot(await call(f.p, "send", ["waiting", "waiting_message", "await approval"], "peer"));
      const before = k.anchor.evidence.requests;
      await reject(() => call(f.p, "inspect"), /rebuild_approval_required/);
      await reject(() => call(f.p, "send", ["one", "one", "blocked"]), /rebuild_approval_required/);
      await reject(() => call(f.p, "download", [{ sequence: "1", eventId: "waiting_event", envelope: envelope(sent, "waiting") }]), /rebuild_approval_required/);
      await reject(() => call(f.p, "processNext"), /rebuild_approval_required/);
      await reject(() => call(f.p, "joinGroup", [f.plan.conversation, f.plan.peer, grouped.welcome]), /rebuild_approval_required/);
      const subscriptionError = await f.p.evaluate(async () => {
        try { await window.clients.a.subscribe(() => {}); return "unexpected_success"; }
        catch (error) { return error.code; }
      });
      assert.equal(subscriptionError, "rebuild_approval_required");
      assert.equal(k.anchor.evidence.requests, before);
      const view = await diagnostic(f.p, "offer"); assert.equal(view.phase, "candidate");
      assert.equal(await f.p.evaluate(() => typeof window.clients.a.initialize), "undefined");
      assert.equal(await f.p.evaluate(() => typeof window.clients.a.createGroup), "undefined");
      await activate(f);
      const joined = requireSnapshot(await call(f.p, "joinGroup", [f.plan.conversation, f.plan.peer, grouped.welcome]));
      assert.equal(joined.conversation, f.plan.conversation);
      return { valid_inputs_blocked_before_approval: 6, automatic_initialization: false, diagnostic_snapshot: null };
    } finally { await cleanup(f.p); }
  });

  await k.check("rebuild_missing_prebound_approver_is_rejected_by_authority", async () => {
    const old = await oldPair(k, "rb_no_pin", { pin: false });
    try {
      const basis = await makePending(k, old), candidate = await newCandidate(k, old), peer = await newPeer(k, old, "rb_no_pin");
      const before = await k.anchor.inspect(old.config.scope); assert.equal(before.rebuildApproverPublicKey, undefined);
      // 仅伪造控制器传给计划构造器的公开描述，真实锚登记仍没有批准者 pin。
      const plan = k.rebuild.prepare({ old: { ...before, rebuildApproverPublicKey: k.rebuild.approverPublicKey },
        oldConversation: basis.oldConversation, successor: candidate.offer, conversation: "new_rb_no_pin", peer: peer.identity });
      const approval = k.rebuild.approve(plan);
      const diagnosticsBefore = await k.anchor.diagnostics();
      const error = await reject(() => call(old.p, "activate", [plan, approval]), /"code":"anchor_rpc_failed"/);
      const afterLink = await k.anchor.diagnostics();
      const linkDenial = deniedByAuthority(diagnosticsBefore, afterLink, old.config.scope, "link");
      assert.equal(afterLink.registryCount, diagnosticsBefore.registryCount);
      assert.deepEqual(await k.anchor.inspect(old.config.scope), before);
      await assertUnregistered(k, candidate.offer.scope);
      await reject(() => call(old.p, "send", ["one", "one", "not approved"]), /rebuild_approval_required/);
      const afterBlockedSend = await k.anchor.diagnostics();
      assert.equal(afterBlockedSend.requests, afterLink.requests, "unapproved send must be blocked before another HTTP request");
      assert.equal(afterBlockedSend.registryCount, diagnosticsBefore.registryCount);
      await close(old.p); await reject(() => openCandidate(old.p, candidate.options), /"code":"anchor_rpc_failed"/);
      const afterReopen = await k.anchor.diagnostics();
      const reopenDenial = deniedByAuthority(afterBlockedSend, afterReopen, old.config.scope, "rebuild_inspect");
      assert.equal(afterReopen.registryCount, diagnosticsBefore.registryCount);
      assert.deepEqual(await k.anchor.inspect(old.config.scope), before);
      await assertUnregistered(k, candidate.offer.scope);
      return { error, signed_but_not_prebound: true, old_anchor_unchanged: true,
        registry_before: diagnosticsBefore.registryCount, registry_after: afterReopen.registryCount,
        authority_denials: [linkDenial, reopenDenial] };
    } finally { await cleanup(old.p); }
  });

  for (const mode of ["drop_after", "after_commit"]) {
    await k.check("rebuild_link_" + mode + "_reopens_and_resumes_exact_plan", async () => {
      const f = await fixture(k, "rb_link_" + mode);
      try {
        const old = await k.anchor.inspect(f.old.config.scope);
        await k.rebuild.fault({ action: "link", mode });
        const error = await reject(() => activate(f), /anchor_rpc_failed/);
        if (mode === "after_commit") await k.anchor.restart();
        const remote = await k.anchor.inspect(f.candidate.offer.scope);
        assert.equal(remote.head, f.candidate.offer.head); assert.equal(remote.revision, "0");
        preservedOld(old, await k.anchor.inspect(f.old.config.scope));
        const paused = await diagnostic(f.p); assert.equal(paused.phase, "paused");
        await reject(() => call(f.p, "send", ["one", "one", "uncertain link"]), /rebuild_approval_required/);
        await reopen(k, f); assert.equal((await diagnostic(f.p)).phase, "paused");
        const resumed = await diagnostic(f.p, "resume"); assert.equal(resumed.phase, "linked");
        assert.deepEqual(resumed.candidate, f.candidate.offer);
        assert.deepEqual(await k.anchor.inspect(f.candidate.offer.scope), remote, "link retry must not advance the successor");
        await join(f); const { sent, received } = await exchange(f);
        assert.equal(sent.encryptions, "1"); assert.equal(received.decryptions, "1");
        return { mode, error, same_plan: f.plan.rebuild_id, same_identity: resumed.candidate.scope.identity_key,
          link_revision: remote.revision, real_new_messages: 2 };
      } finally {
        if (!k.anchor.child) await k.anchor.restart();
        await cleanup(f.p);
      }
    });
  }

  await k.check("rebuild_renderer_crash_after_link_recovers_without_new_identity", async () => {
    const f = await fixture(k, "rb_link_crash");
    try {
      await f.p.evaluate(input => {
        window.phases = []; window.rebuildOperation = "pending";
        window.clients.a.test.onCheckpoint(event => window.phases.push(event.phase));
        void window.clients.a.activate(input.plan, input.approval, { anchorCheckpoint: "after_rebuild_link" })
          .then(() => { window.rebuildOperation = "success"; }, error => { window.rebuildOperation = error.code; });
      }, { plan: f.plan, approval: f.approval });
      await f.p.waitForFunction(() => window.phases.includes("after_rebuild_link"));
      assert.equal(await f.p.evaluate(() => window.rebuildOperation), "pending");
      f.p = await crash(k, f.p); await reopen(k, f);
      const paused = await diagnostic(f.p); assert.equal(paused.phase, "paused");
      assert.equal((await k.anchor.inspect(f.old.config.scope)).closure, "rebuilt");
      const resumed = await diagnostic(f.p, "resume"); assert.equal(resumed.phase, "linked");
      assert.deepEqual(resumed.candidate, f.candidate.offer);
      await join(f); const { received } = await exchange(f); assert.equal(received.decryptions, "1");
      return { interruption: "CDP Page.crash", phase: "after_rebuild_link", original_offer_reused: true, real_new_messages: 2 };
    } finally { await cleanup(f.p); }
  });

  await k.check("rebuild_old_profile_rollback_keeps_predecessor_permanently_closed", async () => {
    const f = await fixture(k, "rb_old_rollback");
    try {
      const before = await k.anchor.inspect(f.old.config.scope);
      await cleanup(f.p); await k.backupProfile("rebuild_before_link"); await reopen(k, f);
      await ready(f); const { sent } = await exchange(f);
      await cleanup(f.p); await k.backupProfile("rebuild_current");
      await k.restoreProfile("rebuild_before_link"); f.p = await k.page();
      await assertOldClosed(f.p, f.old.config); await assertOldClosed(f.p, f.old.config);
      preservedOld(before, await k.anchor.inspect(f.old.config.scope));
      // 被回滚的候选不能用旧批准把已前进的后继重置为初始化基线。
      await openCandidate(f.p, f.candidate.options);
      await reject(() => activate(f), /rebuild_successor_advanced/);
      await reject(() => call(f.p, "inspect"), /rebuild_approval_required/);
      await cleanup(f.p); await k.restoreProfile("rebuild_current"); await reopen(k, f);
      const current = await snapshot(f.p); assert.deepEqual(current.outbox, sent.outbox);
      assert.equal(current.encryptions, "1"); await assertOldClosed(f.p, f.old.config);
      return { predecessor_closed_after_full_profile_rollback: true, advanced_successor_reset_rejected: true,
        restored_ciphertext_hash: current.outbox[0].ciphertextHash };
    } finally { await cleanup(f.p); }
  });

  await k.check("rebuild_duplicate_activation_does_not_reset_advanced_successor", async () => {
    const f = await fixture(k, "rb_duplicate");
    try {
      await ready(f); const { sent } = await exchange(f); const before = await snapshot(f.p);
      const remote = await k.anchor.inspect(f.candidate.offer.scope);
      const duplicate = await activate(f); assert.equal(duplicate.phase, "ready");
      assert.deepEqual(await k.anchor.inspect(f.candidate.offer.scope), remote);
      const after = await snapshot(f.p);
      for (const field of ["revision", "identity", "providerHash", "encryptions", "decryptions", "downloadCursor", "processingCursor", "outbox", "messages", "receipts"]) {
        assert.deepEqual(after[field], before[field], "duplicate activation reset field: " + field);
      }
      assert.equal(envelope(after, "new_attempt").ciphertext, envelope(sent, "new_attempt").ciphertext);
      return { same_plan: f.plan.rebuild_id, duplicate_activation_snapshot: null, encryptions: after.encryptions, decryptions: after.decryptions };
    } finally { await cleanup(f.p); }
  });

  await k.check("rebuild_namespace_config_and_missing_candidate_fail_closed", async () => {
    const f = await fixture(k, "rb_scope");
    try {
      await reject(() => openCandidate(f.p, f.candidate.options, "same"), /IN_USE/);
      const other = await newCandidate(k, f.old, {}, "other");
      assert.notEqual(other.offer.scope.identity_key, f.candidate.offer.scope.identity_key);
      await close(f.p);
      await reject(() => openCandidate(f.p, { ...f.candidate.options, device: "wrong_device" }), /crypto_store_corrupt|crypto_state_corrupt|rebuild_context_mismatch/);
      await reject(() => openCandidate(f.p, { ...f.candidate.options, clientSeed: randomHex() }), /rebuild_context_mismatch/);
      await reject(() => openCandidate(f.p, { ...f.candidate.options, approverPublicKey: randomHex() }), /rebuild_context_mismatch|rebuild_config/);
      const absent = candidateOptions(k, f.old);
      await reject(() => openCandidate(f.p, absent), /storage_error|anchor_existing_store_required/);
      await reject(() => openCandidate(f.p, f.candidate.options, "a", true), /rebuild_candidate_exists/);
      await openCandidate(f.p, f.candidate.options); const unchanged = await diagnostic(f.p, "offer");
      assert.deepEqual(unchanged.candidate, f.candidate.offer);
      return { independent_same_account_namespaces: 2, missing_candidate_did_not_initialize: true, original_identity_unchanged: true };
    } finally { await cleanup(f.p); }
  });

  await k.check("rebuild_competing_candidates_select_exactly_one_successor", async () => {
    const f = await fixture(k, "rb_race");
    try {
      const rival = await newCandidate(k, f.old, {}, "rival");
      const second = await prepare(k, f.old, rival, f.peer, "new_rb_rival");
      const oldBefore = await k.anchor.inspect(f.old.config.scope);
      const diagnosticsBefore = await k.anchor.diagnostics();
      const results = await f.p.evaluate(async input => {
        const attempt = async (slot, plan, approval) => {
          try { return { slot, ok: true, value: await window.clients[slot].activate(plan, approval) }; }
          catch (error) { return { slot, ok: false, code: error.code, message: error.message }; }
        };
        return Promise.all([attempt("a", input.first.plan, input.first.approval), attempt("rival", input.second.plan, input.second.approval)]);
      }, { first: { plan: f.plan, approval: f.approval }, second });
      const afterRace = await k.anchor.diagnostics();
      const raceDenial = deniedByAuthority(diagnosticsBefore, afterRace, f.old.config.scope, "link");
      const winners = results.filter(result => result.ok), losers = results.filter(result => !result.ok);
      assert.equal(winners.length, 1); assert.equal(losers.length, 1);
      assert.equal(winners[0].value.phase, "linked"); assert.equal(winners[0].value.snapshot, null);
      assert.equal(losers[0].code, "anchor_rpc_failed");
      assert.equal(afterRace.registryCount, diagnosticsBefore.registryCount + 1);
      const winner = winners[0].slot === "a" ? f.candidate : rival;
      const loser = losers[0].slot === "a" ? f.candidate : rival;
      const authorization = winners[0].slot === "a" ? { plan: f.plan, approval: f.approval } : second;
      const oldAfter = await k.anchor.inspect(f.old.config.scope);
      preservedOld(oldBefore, oldAfter);
      assert.equal(oldAfter.successorScopeKey, scopeKey(winner.offer.scope));
      assert.equal((await k.anchor.inspect(winner.offer.scope)).head, winner.offer.head);
      await assertUnregistered(k, loser.offer.scope);
      await reject(() => call(f.p, "resume", [], losers[0].slot), /"code":"anchor_rpc_failed"/);
      const afterResume = await k.anchor.diagnostics();
      const resumeDenial = deniedByAuthority(afterRace, afterResume, f.old.config.scope, "link");
      assert.equal(afterResume.registryCount, diagnosticsBefore.registryCount + 1);
      await assertUnregistered(k, loser.offer.scope);
      assert.deepEqual(await k.anchor.inspect(f.old.config.scope), oldAfter);
      const grouped = anchorSnapshot(await call(f.p, "createGroup", [authorization.plan.conversation, winner.offer.identity], "peer"));
      requireSnapshot(await call(f.p, "joinGroup", [authorization.plan.conversation, authorization.plan.peer, grouped.welcome], winners[0].slot));
      const sent = requireSnapshot(await call(f.p, "send", ["winner", "winner_message", "unique successor"], winners[0].slot));
      const received = await anchorReceive(f.p, envelope(sent, "winner"), "unique successor", "1", "winner_event", "peer");
      assert.equal(received.decryptions, "1");
      return { parallel_candidates: 2, activated_successors: 1, loser_error: losers[0].code,
        winner_scope: scopeKey(winner.offer.scope), winner_encryptions: sent.encryptions,
        registry_before: diagnosticsBefore.registryCount, registry_after: afterResume.registryCount,
        loser_registered: false, authority_denials: [raceDenial, resumeDenial] };
    } finally { await cleanup(f.p); }
  });
}
