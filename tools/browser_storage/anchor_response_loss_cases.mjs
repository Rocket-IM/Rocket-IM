// 响应头前断线可能被浏览器网络栈重发；安全性不依赖一次 fetch 只到达服务器一次。
import assert from "node:assert/strict";
import { pair, call, close, openAnchored, status, watch, cleanup, requireSnapshot, receive, envelope, reject } from "./anchor_support.mjs";

export async function runAnchorResponseLossCases(k) {
  for (const action of ["reserve", "finish"]) {
    await k.check("anchor_" + action + "_response_header_loss_handles_browser_retransmission", async () => {
      const { p, configs } = await pair(k, "header_loss_" + action);
      try {
        await watch(p);
        const before = await status(p);
        const requests = (await k.anchor.diagnostics()).requests;
        await k.anchor.fault({ action, mode: "drop_before_headers" });
        let completed = null, failure = null;
        try { completed = requireSnapshot(await call(p, "send", ["attempt1", "message1", "header loss"])); }
        catch (error) { failure = String(error); }
        const diagnostic = await k.anchor.diagnostics();
        assert.equal(diagnostic.fault, null);
        assert.ok(diagnostic.records.some(record => record.action === action && record.mode === "drop_before_headers"));
        const duplicateStatus = action === "reserve" ? "reserved_duplicate" : "finished_duplicate";
        const duplicateObserved = diagnostic.records.slice(-(diagnostic.requests - requests))
          .some(record => record.action === action && record.outcome === duplicateStatus);
        const remote = await k.anchor.inspect(configs[0].scope);
        if (action === "reserve") {
          assert.equal(completed, null, "a repeated reservation must never authorize MLS");
          assert.match(failure, /anchor_rpc_failed|anchor_conflict/);
          assert.ok(remote.pending); assert.equal(remote.head, before.remoteHead);
          assert.deepEqual(await p.evaluate(() => window.cryptoEvents.map(event => event.type)), ["snapshot"]);
          await close(p); await openAnchored(p, configs[0]);
          const blocked = await status(p);
          assert.equal(blocked.phase, "paused"); assert.equal(blocked.localHead, before.localHead);
          await reject(() => call(p, "resume"), /anchor_unresolved/);
          await reject(() => call(p, "inspect"), /anchor_paused/);
        } else {
          assert.equal(remote.pending, null); assert.ok(remote.last);
          if (failure !== null) {
            assert.match(failure, /anchor_rpc_failed/);
            assert.deepEqual(await p.evaluate(() => window.cryptoEvents.map(event => event.type)), ["snapshot"]);
            await close(p); await openAnchored(p, configs[0]);
            assert.equal((await call(p, "resume")).snapshot, null);
            completed = requireSnapshot(await call(p, "inspect"));
          } else {
            assert.deepEqual(await p.evaluate(() => window.cryptoEvents.map(event => event.type)), ["snapshot", "committed"]);
          }
          assert.equal(completed.encryptions, "1"); assert.equal(completed.outbox.length, 1);
          const retried = requireSnapshot(await call(p, "send", ["attempt1", "message1", "header loss"]));
          assert.deepEqual(retried.outbox, completed.outbox); assert.equal(retried.encryptions, "1");
          await receive(p, envelope(completed), "header loss");
        }
        return { action, one_public_send_call: true, browser_duplicate_observed: duplicateObserved,
          outcome: action === "reserve" ? "paused_without_crypto" : "one_exact_committed_result",
          recovery_required: failure !== null, application_retry_loop: false };
      } finally { await cleanup(p); }
    });
  }
}
