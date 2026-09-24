// 独立安装包、真实 OpenMLS、OPFS 与本机锚联合验收；不声称独立生产信任。
import assert from "node:assert/strict";
import { open as openCrypto } from "./crypto_support.mjs";
import { SERVICE, baseline, pair, openAnchored, reopenPair, call, close, reject, watch, cleanup,
  envelope, snapshot, status, assertPaused, requireSnapshot, receive, prepareCrash, crash } from "./anchor_support.mjs";

async function resumed(p) {
  const view = await call(p, "resume");
  assert.equal(view.snapshot, null);
  assert.equal(view.status.phase, "ready");
  assert.equal(view.status.localHead, view.status.remoteHead);
  assert.equal(view.status.localPending, false);
  assert.equal(view.status.remotePending, null);
  return view.status;
}

async function noSuccessEvent(p) {
  assert.deepEqual(await p.evaluate(() => window.cryptoEvents.map(event => event.type)), ["snapshot"]);
}

async function blockedBusiness(p, attempt = "attempt1", message = "message1", text = "first") {
  await reject(() => call(p, "inspect"), /anchor_paused/);
  await reject(() => call(p, "send", [attempt, message, text]), /anchor_paused/);
  await reject(() => call(p, "send", ["new_attempt", "new_message", "must remain blocked"]), /anchor_paused/);
}

export async function runAnchorCases(k) {
  await k.check("anchor_real_group_send_retry_receive_and_reply", async () => {
    const { p, a, b } = await pair(k, "anchor_exchange");
    try {
      await watch(p);
      const sent = requireSnapshot(await call(p, "send", ["attempt1", "message1", "anchored hello"]));
      assert.equal(sent.encryptions, "1"); assert.notEqual(sent.providerHash, a.providerHash);
      const retried = requireSnapshot(await call(p, "send", ["attempt1", "message1", "anchored hello"]));
      assert.equal(retried.change, "none"); assert.equal(retried.encryptions, "1");
      assert.deepEqual(retried.outbox, sent.outbox); assert.equal(retried.providerHash, sent.providerHash);
      assert.deepEqual(await p.evaluate(() => window.cryptoEvents.map(event => event.type)), ["snapshot", "committed"]);
      const received = await receive(p, envelope(sent), "anchored hello");
      assert.equal(received.decryptions, "1"); assert.notEqual(received.providerHash, b.providerHash);
      const reply = requireSnapshot(await call(p, "send", ["reply1", "reply_message", "anchored reply"], "b"));
      const replied = await receive(p, envelope(reply, "reply1"), "anchored reply", "1", "reply_event", "a");
      assert.equal(replied.decryptions, "1");
      return { assurance: "synthetic_local", real_openmls_messages: 2, retry_encryptions: retried.encryptions,
        ciphertext_hash: sent.outbox[0].ciphertextHash };
    } finally { await cleanup(p); }
  });

  await k.check("anchor_scope_lock_and_unanchored_reopen_rejected", async () => {
    const { p, config, account } = await baseline(k, "anchor_sticky");
    try {
      await reject(() => openAnchored(p, config, "other"), /IN_USE/);
      await reject(() => openCrypto(p, account, "other", true, SERVICE), /IN_USE/);
      await close(p);
      const error = await reject(() => openCrypto(p, account, "other", true, SERVICE), /anchor_required/);
      await openAnchored(p, config);
      assert.equal((await status(p)).phase, "ready");
      return { unanchored_reopen_error: error, same_scope_single_owner: true };
    } finally { await cleanup(p); }
  });

  await k.check("anchor_full_profile_rollback_blocks_cache_and_restores_current", async () => {
    let { p, configs } = await pair(k, "anchor_rollback");
    try {
      const first = requireSnapshot(await call(p, "send", ["attempt1", "message1", "first"]));
      const old = await status(p); await cleanup(p);
      await k.backupProfile("anchor_rollback_old");
      p = await reopenPair(k, configs);
      const second = requireSnapshot(await call(p, "send", ["attempt2", "message2", "second"]));
      assert.equal(second.encryptions, "2");
      const current = await status(p); assert.notEqual(current.localHead, old.localHead);
      await cleanup(p); await k.backupProfile("anchor_rollback_current");
      await k.restoreProfile("anchor_rollback_old"); p = await reopenPair(k, configs);
      const blocked = await assertPaused(p, { pending: true, reason: /anchor_head_mismatch/ });
      assert.equal(blocked.localHead, old.localHead); assert.equal(blocked.remoteHead, current.remoteHead);
      await blockedBusiness(p); await reject(() => call(p, "resume"), /anchor_unresolved/);
      await cleanup(p); await k.restoreProfile("anchor_rollback_current"); p = await reopenPair(k, configs);
      await resumed(p);
      const restored = await snapshot(p);
      assert.equal(restored.encryptions, "2"); assert.deepEqual(restored.outbox, second.outbox);
      const retry = requireSnapshot(await call(p, "send", ["attempt1", "message1", "first"]));
      assert.equal(envelope(retry).ciphertext, envelope(first).ciphertext); assert.equal(retry.encryptions, "2");
      await receive(p, envelope(first), "first");
      const received = await receive(p, envelope(second, "attempt2"), "second", "2", "event2");
      assert.equal(received.decryptions, "2");
      return { rollback_detected: true, cached_retry_blocked: true, diagnostic_snapshot: null,
        old_head: old.localHead, current_head: current.localHead, restored_encryptions: restored.encryptions };
    } finally { await cleanup(p); }
  });

  await k.check("anchor_offline_reopen_fails_then_restart_and_explicit_resume", async () => {
    const { p, configs } = await pair(k, "anchor_offline");
    let stopped = false;
    try {
      await watch(p); await k.anchor.stop(); stopped = true;
      const error = await reject(() => call(p, "send", ["attempt1", "message1", "offline"]), /anchor_rpc_failed/);
      await noSuccessEvent(p);
      await reject(() => call(p, "status"), /anchor_rpc_failed/);
      await close(p); await reject(() => openAnchored(p, configs[0]), /anchor_rpc_failed/);
      await k.anchor.restart(); stopped = false; await openAnchored(p, configs[0]);
      await assertPaused(p, { pending: true, reason: /anchor_recovery_required/ });
      await resumed(p);
      const sent = requireSnapshot(await call(p, "send", ["attempt1", "message1", "offline"]));
      assert.equal(sent.encryptions, "1"); await receive(p, envelope(sent), "offline");
      return { offline_error: error, automatic_retry: false, recovered_encryptions: sent.encryptions };
    } finally { if (stopped) await k.anchor.restart(); await cleanup(p); }
  });

  await k.check("anchor_reserve_drop_after_remains_unresolved", async () => {
    const { p, configs } = await pair(k, "anchor_reserve_drop");
    try {
      await watch(p); const before = await k.anchor.inspect(configs[0].scope);
      await k.anchor.fault({ action: "reserve", mode: "drop_after" });
      const error = await reject(() => call(p, "send", ["attempt1", "message1", "uncertain reserve"]), /anchor_rpc_failed/);
      await noSuccessEvent(p);
      const remote = await k.anchor.inspect(configs[0].scope);
      assert.ok(remote.pending); assert.equal(remote.head, before.head);
      assert.equal(BigInt(remote.revision), BigInt(before.revision) + 1n);
      await close(p); await openAnchored(p, configs[0]);
      const paused = await assertPaused(p, { pending: true, reason: /anchor_unresolved/ });
      assert.equal(paused.remotePending, remote.pending.txn);
      await blockedBusiness(p, "attempt1", "message1", "uncertain reserve");
      await reject(() => call(p, "resume"), /anchor_unresolved/);
      assert.deepEqual(await k.anchor.inspect(configs[0].scope), remote);
      return { error, unresolved_transaction: remote.pending.txn, explicit_recovery_rejected: true };
    } finally { await cleanup(p); }
  });

  await k.check("anchor_finish_drop_after_recovers_exact_committed_ciphertext", async () => {
    const { p, configs } = await pair(k, "anchor_finish_drop");
    try {
      await watch(p); await k.anchor.fault({ action: "finish", mode: "drop_after" });
      const error = await reject(() => call(p, "send", ["attempt1", "message1", "committed uncertain"]), /anchor_rpc_failed/);
      await noSuccessEvent(p);
      const remote = await k.anchor.inspect(configs[0].scope);
      assert.equal(remote.pending, null); assert.ok(remote.last);
      const paused = await assertPaused(p, { pending: true, reason: /anchor_recovery_required/ });
      assert.equal(paused.localHead, remote.head);
      await close(p); await openAnchored(p, configs[0]); await resumed(p);
      assert.deepEqual(await k.anchor.inspect(configs[0].scope), remote, "duplicate finish must not advance anchor revision");
      const recovered = await snapshot(p); assert.equal(recovered.encryptions, "1");
      const retry = requireSnapshot(await call(p, "send", ["attempt1", "message1", "committed uncertain"]));
      assert.equal(retry.encryptions, "1"); assert.equal(retry.providerHash, recovered.providerHash);
      assert.deepEqual(retry.outbox, recovered.outbox);
      await receive(p, envelope(recovered), "committed uncertain");
      return { error, recovered_transaction: remote.last.txn, ciphertext_hash: recovered.outbox[0].ciphertextHash,
        encryptions: retry.encryptions, duplicate_finish_kept_revision: remote.revision };
    } finally { await cleanup(p); }
  });

  for (const phase of ["after_candidate_commit", "after_anchor_finish"]) {
    await k.check("anchor_renderer_crash_" + phase + "_exact_resume", async () => {
      let { p, configs } = await pair(k, "anchor_crash_" + phase);
      try {
        await prepareCrash(p, "send", ["attempt1", "message1", "crash candidate"], phase);
        // 先真实崩溃再读独立锚，避免控制器 RPC 消耗有限的测试停顿窗口。
        p = await crash(k, p);
        const remote = await k.anchor.inspect(configs[0].scope);
        const transaction = phase === "after_candidate_commit" ? remote.pending : remote.last;
        assert.ok(transaction);
        if (phase === "after_anchor_finish") assert.equal(remote.pending, null);
        await openAnchored(p, configs[0]); await openAnchored(p, configs[1], "b");
        await assertPaused(p, { pending: true }); await blockedBusiness(p, "attempt1", "message1", "crash candidate");
        await resumed(p);
        const finished = await k.anchor.inspect(configs[0].scope);
        assert.equal(finished.pending, null); assert.equal(finished.last.txn, transaction.txn);
        const recovered = await snapshot(p); assert.equal(recovered.encryptions, "1"); assert.equal(recovered.outbox.length, 1);
        const retry = requireSnapshot(await call(p, "send", ["attempt1", "message1", "crash candidate"]));
        assert.deepEqual(retry.outbox, recovered.outbox); assert.equal(retry.providerHash, recovered.providerHash);
        assert.equal(retry.encryptions, "1"); await receive(p, envelope(recovered), "crash candidate");
        return { phase, interruption: "CDP Page.crash", resumed_transaction: finished.last.txn,
          encryptions: retry.encryptions, ciphertext_hash: recovered.outbox[0].ciphertextHash };
      } finally { await cleanup(p); }
    });
  }

  await k.check("anchor_missing_profile_does_not_initialize_identity", async () => {
    await k.backupProfile("anchor_before_missing_scope");
    let { p, config, head } = await baseline(k, "anchor_missing_scope");
    try {
      await cleanup(p); await k.restoreProfile("anchor_before_missing_scope"); p = await k.page();
      const remote = await k.anchor.inspect(config.scope);
      assert.equal(remote.head, head);
      const error = await reject(() => openAnchored(p, config), /storage_error|anchor_existing_store_required/);
      await reject(() => openAnchored(p, config), /storage_error|anchor_existing_store_required/);
      assert.deepEqual(await k.anchor.inspect(config.scope), remote);
      assert.equal(await p.evaluate(() => Object.keys(window.clients).length), 0);
      return { error, automatic_identity_initialization: false, anchor_unchanged: true };
    } finally { await cleanup(p); }
  });

  await k.check("anchor_prebinding_rollback_EXPECTED_UNPROTECTED_LEGACY_ENTRY", async () => {
    let p = await k.page();
    try {
      const account = "anchor_legacy_entry";
      await openCrypto(p, account, "a", true, SERVICE);
      const initial = await call(p, "initialize");
      const descriptor = await p.evaluate(() => window.clients.a.test.describeAnchor());
      assert.equal(descriptor.identity.identityKey, initial.identity.identityKey);
      await cleanup(p); await k.backupProfile("anchor_before_binding");
      const config = await k.anchor.enroll({ service: SERVICE, account, ...descriptor });
      p = await k.page(); await openAnchored(p, config);
      await openCrypto(p, "anchor_legacy_peer", "b", true, SERVICE);
      const peer = await call(p, "initialize", [], "b");
      const grouped = requireSnapshot(await call(p, "createGroup", ["anchor_legacy_group", peer.identity]));
      const current = await status(p); assert.notEqual(current.localHead, descriptor.head);
      await cleanup(p); await k.restoreProfile("anchor_before_binding"); p = await k.page();
      await openAnchored(p, config);
      const blocked = await assertPaused(p, { pending: true, reason: /anchor_head_mismatch/ });
      assert.equal(blocked.localHead, descriptor.head); assert.equal(blocked.remoteHead, current.remoteHead);
      await blockedBusiness(p); await cleanup(p);
      // 再还原未经首次绑定的完整副本，明确测试主动绕过可信锚入口的限制。
      await k.restoreProfile("anchor_before_binding"); p = await k.page();
      await openCrypto(p, account, "a", true, SERVICE);
      const legacy = await call(p, "inspect");
      assert.equal(legacy.providerHash, initial.providerHash); assert.equal(legacy.conversation, null);
      assert.equal(legacy.identity.identityKey, initial.identity.identityKey);
      const regrouped = await call(p, "createGroup", ["anchor_legacy_group", peer.identity]);
      assert.notEqual(regrouped.providerHash, grouped.providerHash);
      const sent = await call(p, "send", ["legacy_attempt", "legacy_message", "synthetic legacy entry"]);
      assert.equal(sent.encryptions, "1"); assert.equal(sent.outbox.length, 1);
      return { outcome: "EXPECTED_UNPROTECTED_LEGACY_ENTRY", assurance: "synthetic_local",
        trusted_anchor_entry_blocked: true, explicit_legacy_entry_encryptions: sent.encryptions,
        limitation: "An intentionally selected unanchored API can use a database copied before its first anchor binding; the trusted anchored entry is required." };
    } finally { await cleanup(p); }
  });

  await k.check("anchor_profile_and_authority_rollback_EXPECTED_UNDETECTABLE", async () => {
    let { p, configs } = await pair(k, "anchor_negative_control");
    try {
      const old = await status(p); const oldSnapshot = await snapshot(p);
      await cleanup(p); await k.backupProfile("anchor_negative_old"); await k.anchor.backup("anchor_negative_old");
      p = await reopenPair(k, configs);
      const sent = requireSnapshot(await call(p, "send", ["attempt1", "message1", "later erased by full rollback"]));
      assert.equal(sent.encryptions, "1"); const advanced = await status(p);
      assert.notEqual(advanced.localHead, old.localHead);
      await cleanup(p); await k.restoreProfile("anchor_negative_old"); await k.anchor.restore("anchor_negative_old");
      p = await reopenPair(k, configs);
      const undetected = await status(p);
      assert.equal(undetected.phase, "ready"); assert.equal(undetected.localHead, old.localHead);
      assert.equal(undetected.remoteHead, old.localHead);
      const reverted = await snapshot(p);
      assert.equal(reverted.encryptions, oldSnapshot.encryptions); assert.equal(reverted.outbox.length, 0);
      assert.equal(reverted.providerHash, oldSnapshot.providerHash);
      return { outcome: "EXPECTED_UNDETECTABLE", assurance: "synthetic_local", old_head: old.localHead,
        advanced_head: advanced.localHead, observed_phase: undetected.phase,
        limitation: "Both trusted anchor state and the complete browser profile were rolled back together; independent production trust is not established." };
    } finally { await cleanup(p); }
  });
}
