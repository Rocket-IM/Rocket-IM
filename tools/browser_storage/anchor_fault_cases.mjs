// 合成本地锚的真实浏览器故障矩阵；报告只包含错误码与状态摘要，不包含认证配置。
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  openAnchored, call, close, reject, watch, pair, cleanup, status, requireSnapshot,
} from "./anchor_support.mjs";

const code = error => {
  const value = error.match(/"code":"([A-Za-z0-9_]+)"/);
  assert.ok(value, "typed failure code absent");
  return value[1];
};

async function noSuccess(p) {
  assert.deepEqual(await p.evaluate(() => window.cryptoEvents.map(event => event.type)), ["snapshot"]);
}

async function reopen(p, config, slot = "a") {
  await close(p, slot);
  await openAnchored(p, config, slot);
}

function paused(value, pending) {
  assert.equal(value.phase, "paused");
  assert.equal(value.localPending, true);
  if (pending) assert.match(value.remotePending, /^[0-9a-f]{64}$/);
  else assert.equal(value.remotePending, null);
}

async function cleared(p) {
  const result = await call(p, "resume");
  assert.equal(result.snapshot, null, "recovery must not expose cached crypto output");
  assert.equal(result.status.phase, "ready");
  assert.equal(result.status.localPending, false);
  assert.equal(result.status.remotePending, null);
  assert.equal(result.status.localHead, result.status.remoteHead);
  return result.status;
}

async function observedFault(k, action, mode) {
  const diagnostic = await k.anchor.diagnostics();
  assert.equal(diagnostic.fault, null, "armed fault was not consumed");
  assert.ok(diagnostic.records.some(record => record.action === action && record.mode === mode),
    "authority did not observe the requested fault");
}

export async function runAnchorFaultCases(k) {
  const inspectErrors = {
    tamper: /"code":"anchor_signature"/,
    replay: /"code":"anchor_response_binding"/,
    oversize: /"code":"anchor_rpc_failed"/,
    timeout: /"code":"anchor_rpc_failed"/,
  };
  for (const [mode, pattern] of Object.entries(inspectErrors)) {
    await k.check("anchor_inspect_" + mode + "_keeps_gate_until_explicit_resume", async () => {
      const { p, configs } = await pair(k, "af_inspect_" + mode);
      try {
        await watch(p);
        const before = await status(p);
        await k.anchor.fault({ action: "inspect", mode });
        const error = await reject(() => call(p, "send", ["attempt1", "message1", "after verified inspect"]), pattern);
        await observedFault(k, "inspect", mode);
        await noSuccess(p);
        const failed = await status(p);
        paused(failed, false);
        assert.equal(failed.localHead, before.localHead);
        assert.equal(failed.remoteHead, before.remoteHead);
        assert.equal(failed.remoteRevision, before.remoteRevision);
        await reject(() => call(p, "send", ["attempt1", "message1", "after verified inspect"]), /"code":"anchor_paused"/);
        await reopen(p, configs[0]);
        paused(await status(p), false);
        const resumed = await cleared(p);
        assert.equal(resumed.localHead, before.localHead);
        const sent = requireSnapshot(await call(p, "send", ["attempt1", "message1", "after verified inspect"]));
        assert.equal(sent.encryptions, "1");
        assert.equal(sent.outbox.length, 1);
        assert.equal(sent.messages.length, 0);
        assert.equal(sent.receipts.length, 0);
        return { mode, error_code: code(error), gate_persisted: true, explicit_resume: true, encryptions: "1" };
      } finally { await cleanup(p); }
    });
  }

  await k.check("anchor_reserve_authority_exit_before_commit_allows_verified_retry", async () => {
    const { p, configs } = await pair(k, "af_reserve_precommit");
    try {
      await watch(p);
      const before = await status(p);
      const exits = k.anchor.evidence.exits.length;
      await k.anchor.fault({ action: "reserve", mode: "before_commit" });
      const error = await reject(() => call(p, "send", ["attempt1", "message1", "no MLS before reserve"]), /"code":"anchor_rpc_failed"/);
      await noSuccess(p);
      await k.anchor.restart();
      assert.ok(k.anchor.evidence.exits.slice(exits).some(exit => exit.code === 91),
        "authority did not exit at its pre-commit fault");
      const remote = await k.anchor.inspect(configs[0].scope);
      assert.equal(remote.pending, null);
      assert.equal(remote.head, before.remoteHead);
      assert.equal(remote.revision, before.remoteRevision);
      await reopen(p, configs[0]);
      const failed = await status(p);
      paused(failed, false);
      assert.equal(failed.localHead, before.localHead);
      await cleared(p);
      const sent = requireSnapshot(await call(p, "send", ["attempt1", "message1", "no MLS before reserve"]));
      assert.equal(sent.encryptions, "1");
      assert.equal(sent.outbox.length, 1);
      return { error_code: code(error), authority_exit: 91, anchor_reservation_committed: false, encryptions: "1" };
    } finally { await cleanup(p); }
  });

  const candidateErrors = {
    after_crypto: /"code":"crypto_injected_failure"/,
    after_sql: /"code":"storage_error"/,
    refuse_commit: /"code":"commit_failed"/,
  };
  for (const [fault, pattern] of Object.entries(candidateErrors)) {
    await k.check("anchor_candidate_" + fault + "_cannot_resume_or_replay_cached_attempt", async () => {
      const { p, configs } = await pair(k, "af_candidate_" + fault);
      try {
        const completed = requireSnapshot(await call(p, "send", ["completed", "completed_message", "already confirmed"]));
        assert.equal(completed.encryptions, "1");
        await watch(p);
        const before = await status(p);
        const error = await reject(() => call(p, "send", ["failed", "failed_message", "candidate never published", { fault }]), pattern);
        await noSuccess(p);
        const failed = await status(p);
        paused(failed, true);
        assert.equal(failed.remoteHead, before.remoteHead);
        assert.notEqual(failed.localHead, failed.remoteHead, "durable crypto reservation must change the complete commitment");
        await reopen(p, configs[0]);
        const recovered = await status(p);
        paused(recovered, true);
        assert.equal(recovered.localHead, failed.localHead);
        assert.equal(recovered.remotePending, failed.remotePending);
        await reject(() => call(p, "resume"), /"code":"anchor_unresolved"/);
        await reject(() => call(p, "inspect"), /"code":"anchor_paused"/);
        await reject(() => call(p, "send", ["completed", "completed_message", "already confirmed"]), /"code":"anchor_paused"/);
        await reject(() => call(p, "send", ["failed", "failed_message", "candidate never published"]), /"code":"anchor_paused"/);
        await noSuccess(p);
        await reopen(p, configs[0]);
        paused(await status(p), true);
        const remote = await k.anchor.inspect(configs[0].scope);
        assert.equal(remote.head, before.remoteHead);
        assert.equal(remote.pending.txn, failed.remotePending);
        return { fault, error_code: code(error), pending_persisted: true, cached_output_blocked: true, recovery_output: null };
      } finally { await cleanup(p); }
    });
  }

  await k.check("anchor_wrong_trusted_configuration_cannot_rebind_existing_database", async () => {
    const { p, configs } = await pair(k, "af_config");
    try {
      const before = await status(p);
      await close(p);
      const errors = [];
      for (const altered of [
        { ...configs[0], clientSeed: randomBytes(32).toString("hex") },
        { ...configs[0], scope: { ...configs[0].scope, store_id: randomBytes(32).toString("hex") } },
      ]) {
        const requests = (await k.anchor.diagnostics()).requests;
        errors.push(code(await reject(() => openAnchored(p, altered), /"code":"anchor_config_mismatch"/)));
        assert.equal((await k.anchor.diagnostics()).requests, requests, "wrong binding reached the anchor");
      }
      await openAnchored(p, configs[0]);
      assert.deepEqual(await status(p), before);
      const sent = requireSnapshot(await call(p, "send", ["attempt1", "message1", "original config still valid"]));
      assert.equal(sent.encryptions, "1");
      return { error_codes: errors, configuration_secrets_reported: false, original_binding_preserved: true };
    } finally { await cleanup(p); }
  });

  await k.check("anchor_public_parameter_bounds_reject_without_network_or_gate_changes", async () => {
    const { p, configs } = await pair(k, "af_bounds");
    try {
      const before = await status(p);
      await close(p);
      const rejected = [];
      const port = new URL(configs[0].endpoint).port;
      const endpoints = [
        `http://localhost:${port}/anchor`, `http://127.0.0.1:0/anchor`,
        `http://127.0.0.1:0${port}/anchor`, `${configs[0].endpoint}?redirect=1`,
        `http://user@127.0.0.1:${port}/anchor`, `http://127.0.0.1:65536/anchor`,
      ];
      for (const endpoint of endpoints) {
        const requests = (await k.anchor.diagnostics()).requests;
        rejected.push(code(await reject(() => openAnchored(p, { ...configs[0], endpoint }), /"code":"INVALID_ARGUMENT"/)));
        assert.equal((await k.anchor.diagnostics()).requests, requests);
      }
      const requests = (await k.anchor.diagnostics()).requests;
      rejected.push(code(await reject(() => openAnchored(p, { ...configs[0], clientSeed: "A".repeat(64) }), /"code":"INVALID_ARGUMENT"/)));
      assert.equal((await k.anchor.diagnostics()).requests, requests);
      await openAnchored(p, configs[0]);
      assert.deepEqual(await status(p), before);
      await close(p);
      await p.evaluate(async config => {
        window.clients.a = await window.probe.openAnchored({
          service: config.scope.service, account: config.scope.account, anchor: config, testMode: false,
        });
      }, configs[0]);
      const plain = await status(p);
      const requestCount = (await k.anchor.diagnostics()).requests;
      const testError = await reject(() => call(p, "send", ["attempt1", "message1", "no injection", { fault: "after_crypto" }]), /"code":"TEST_MODE_REQUIRED"/);
      assert.equal((await k.anchor.diagnostics()).requests, requestCount);
      assert.deepEqual(await status(p), plain);
      return { rejected_configurations: rejected.length, test_mode_error: code(testError), unintended_http_requests: 0, gate_unchanged: true };
    } finally { await cleanup(p); }
  });
}
