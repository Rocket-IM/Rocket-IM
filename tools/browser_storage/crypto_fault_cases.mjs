import assert from "node:assert/strict";
import { open, call, inspect, close, reject, watch, pair, cleanup, download, process, envelope, prepareCrash, crash, assertBlocked } from "./crypto_support.mjs";

export async function runCryptoFaultCases(k) {
  for (const fault of ["after_crypto", "after_sql", "refuse_commit"]) {
    await k.check("crypto_send_failure_" + fault + "_persists_guard", async () => {
      const { p, accounts, a } = await pair(k, "sf_" + fault); await watch(p);
      const error = await reject(() => call(p, "send", ["attempt1", "message1", "never expose", { fault }]), faultCode(fault));
      assert.equal((await inspect(p)).status, "paused");
      assert.deepEqual(await p.evaluate(() => window.cryptoEvents.map(e => e.type)), ["snapshot"]);
      await close(p); await open(p, accounts[0]); const failed = await assertBlocked(p);
      assert.equal(failed.providerHash, a.providerHash); assert.equal(failed.encryptions, "0"); assert.equal(failed.outbox.length, 0);
      await close(p); await open(p, accounts[0]); assert.equal((await inspect(p)).status, "paused");
      await cleanup(p); return { fault, error, pending: failed.pending };
    });
  }
  await k.check("crypto_reserve_commit_failure_does_not_call_mls", async () => {
    const { p, accounts, a } = await pair(k, "reserve_failure");
    const error = await reject(() => call(p, "send", ["attempt1", "message1", "no call", { fault: "reserve_refuse" }]), /commit_failed/);
    await close(p); await open(p, accounts[0]); const unchanged = await inspect(p);
    assert.equal(unchanged.status, "ready"); assert.equal(unchanged.pending, null); assert.equal(unchanged.providerHash, a.providerHash);
    assert.equal(unchanged.encryptions, "0");
    const success = await call(p, "send", ["attempt1", "message1", "no call"]); assert.equal(success.encryptions, "1");
    await cleanup(p); return { error };
  });
  for (const fault of ["after_crypto", "after_sql", "refuse_commit"]) {
    await k.check("crypto_receive_failure_" + fault + "_keeps_cursors_separate", async () => {
      const { p, accounts, b } = await pair(k, "rf_" + fault);
      const sent = await call(p, "send", ["attempt1", "message1", "pending receive"]); await download(p, envelope(sent)); await watch(p, "b");
      const error = await reject(() => process(p, { fault }), faultCode(fault));
      assert.deepEqual(await p.evaluate(() => window.cryptoEvents.map(e => e.type)), ["snapshot"]);
      await close(p, "b"); await open(p, accounts[1], "b"); const failed = await inspect(p, "b");
      assert.equal(failed.status, "paused"); assert.ok(failed.pending); assert.equal(failed.downloadCursor, "1");
      assert.equal(failed.processingCursor, "0"); assert.equal(failed.messages.length, 0); assert.equal(failed.receipts.length, 0);
      assert.equal(failed.decryptions, "0"); assert.equal(failed.providerHash, b.providerHash);
      await reject(() => process(p), /pending|paused|unresolved/); await cleanup(p); return { error, pending: failed.pending };
    });
  }
  await k.check("crypto_download_commit_failure_has_no_raw_or_cursor_partial", async () => {
    const { p, accounts, b } = await pair(k, "download_failure");
    const sent = await call(p, "send", ["attempt1", "message1", "raw"]);
    await reject(() => download(p, envelope(sent), "1", "event1", "b", { fault: "refuse_commit" }), /commit_failed/);
    await close(p, "b"); await open(p, accounts[1], "b"); const failed = await inspect(p, "b");
    assert.equal(failed.downloadCursor, "0"); assert.equal(failed.processingCursor, "0"); assert.equal(failed.events.length, 0);
    assert.equal(failed.providerHash, b.providerHash); assert.equal(failed.status, "ready");
    await download(p, envelope(sent)); assert.equal((await process(p)).messages[0].text, "raw"); await cleanup(p);
  });
  await k.check("crypto_tampered_ciphertext_never_advances_processing_cursor", async () => {
    const { p, accounts } = await pair(k, "tamper");
    const sent = await call(p, "send", ["attempt1", "message1", "auth"]); const wire = envelope(sent);
    const bytes = Buffer.from(wire.ciphertext, "base64"); bytes[bytes.length - 1] ^= 1;
    await download(p, { ...wire, ciphertext: bytes.toString("base64") });
    const error = await reject(() => process(p), /crypto|authentication|decrypt/);
    await close(p, "b"); await open(p, accounts[1], "b"); const state = await inspect(p, "b");
    assert.equal(state.status, "paused"); assert.equal(state.processingCursor, "0");
    assert.equal(state.messages.length, 0); assert.equal(state.receipts.length, 0); await cleanup(p); return { error };
  });
  for (const phase of ["after_reserve", "after_crypto", "before_commit", "after_commit"]) {
    await k.check("crypto_send_renderer_crash_" + phase, async () => {
      let { p, accounts, a } = await pair(k, "sc_" + phase);
      await prepareCrash(p, "send", ["attempt1", "message1", "crash send"], phase);
      p = await crash(k, p); await open(p, accounts[0]); await open(p, accounts[1], "b");
      const state = await inspect(p);
      if (phase === "after_commit") {
        assert.equal(state.status, "ready"); assert.equal(state.encryptions, "1"); assert.equal(state.pending, null);
        const stored = envelope(state); const retried = await call(p, "send", ["attempt1", "message1", "crash send"]);
        assert.equal(envelope(retried).ciphertext, stored.ciphertext); assert.equal(retried.providerHash, state.providerHash);
        assert.equal(retried.encryptions, "1"); await download(p, stored);
        assert.equal((await process(p)).messages[0].text, "crash send");
      } else {
        assert.equal(state.providerHash, a.providerHash); assert.equal(state.encryptions, "0"); assert.equal(state.outbox.length, 0);
        await assertBlocked(p);
      }
      await cleanup(p); return { phase, status: state.status, encryptions: state.encryptions, pending: state.pending };
    });
  }
  for (const phase of ["after_reserve", "after_crypto", "before_commit", "after_commit"]) {
    await k.check("crypto_receive_renderer_crash_" + phase, async () => {
      let { p, accounts, b } = await pair(k, "rc_" + phase);
      const sent = await call(p, "send", ["attempt1", "message1", "crash receive"]); await download(p, envelope(sent));
      await prepareCrash(p, "processNext", [], phase, "b"); p = await crash(k, p); await open(p, accounts[1], "b");
      const state = await inspect(p, "b"); assert.equal(state.downloadCursor, "1");
      if (phase === "after_commit") {
        assert.equal(state.status, "ready"); assert.equal(state.processingCursor, "1"); assert.equal(state.decryptions, "1");
        assert.equal(state.messages[0].text, "crash receive"); assert.deepEqual(state.receipts, ["event1"]);
        const repeat = await process(p); assert.equal(repeat.decryptions, "1"); assert.equal(repeat.providerHash, state.providerHash);
      } else {
        assert.equal(state.status, "paused"); assert.ok(state.pending); assert.equal(state.processingCursor, "0");
        assert.equal(state.messages.length, 0); assert.equal(state.receipts.length, 0); assert.equal(state.providerHash, b.providerHash);
        await reject(() => process(p), /pending|paused|unresolved/);
      }
      await cleanup(p); return { phase, status: state.status, download: state.downloadCursor, processing: state.processingCursor };
    });
  }
  await k.check("crypto_identity_initialization_crash_does_not_regenerate", async () => {
    let p = await k.page(); await open(p, "init_crash");
    await prepareCrash(p, "initialize", [], "after_crypto"); p = await crash(k, p); await open(p, "init_crash");
    const state = await inspect(p); assert.equal(state.status, "paused"); assert.equal(state.identity, null); assert.ok(state.pending);
    await reject(() => call(p, "initialize"), /pending|paused|unresolved/); await cleanup(p);
  });
  await k.check("crypto_site_clear_requires_explicit_new_test_identity", async () => {
    for (const page of k.context().pages()) await page.close();
    const p = await k.page(); await open(p, "clear_crypto"); const created = await call(p, "initialize"); await close(p);
    const cdp = await k.context().newCDPSession(p);
    await cdp.send("Storage.clearDataForOrigin", { origin: k.origin, storageTypes: "all" });
    await open(p, "clear_crypto"); const empty = await inspect(p); assert.equal(empty.status, "empty"); assert.equal(empty.identity, null);
    await reject(() => call(p, "send", ["one", "one", "must not recreate"]), /identity|initializ|state|group/);
    await cleanup(p); return { old_public_identity_recorded: !!created.identity, automatic_recreation: false,
      limitation: "cleared local database has no independent rollback anchor; production identity recovery is not implemented" };
  });
}

function faultCode(fault) {
  return new RegExp({ after_crypto: "crypto_injected_failure", after_sql: "storage_error", refuse_commit: "commit_failed" }[fault]);
}
