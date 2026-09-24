import assert from "node:assert/strict";
import { open, call, inspect, close, reject, watch, pair, cleanup, download, process, envelope } from "./crypto_support.mjs";

export async function runCryptoBoundaryCases(k) {
  await k.check("crypto_test_controls_and_empty_text_rejected_before_reservation", async () => {
    const p = await k.page(); await open(p, "test_boundary", "a", false);
    await reject(() => call(p, "initialize", [{ fault: "after_crypto" }]), /TEST_MODE_REQUIRED/);
    assert.equal((await inspect(p)).status, "empty"); await call(p, "initialize");
    await reject(() => call(p, "send", ["one", "one", ""]), /INVALID_ARGUMENT/);
    const state = await inspect(p); assert.equal(state.pending, null); assert.equal(state.encryptions, "0");
    await cleanup(p);
  });
  for (const method of ["createGroup", "joinGroup"]) {
    await k.check("crypto_" + method + "_failure_preserves_identity_and_guard", async () => {
      const p = await k.page(); const account = "group_failure_" + method;
      await open(p, account); await open(p, account + "_peer", "b");
      const own = await call(p, "initialize"), peer = await call(p, "initialize", [], "b");
      const args = ["group_failure", peer.identity];
      if (method === "joinGroup") {
        const joined = await call(p, "createGroup", ["group_failure", own.identity], "b");
        args.push(joined.welcome);
      }
      await watch(p);
      await reject(() => call(p, method, [...args, { fault: "after_crypto" }]), /crypto_injected_failure/);
      assert.deepEqual(await p.evaluate(() => window.cryptoEvents.map(e => e.type)), ["snapshot"]);
      await close(p); await open(p, account); const failed = await inspect(p);
      assert.equal(failed.status, "paused"); assert.equal(failed.conversation, null); assert.equal(failed.welcome, null);
      assert.equal(failed.providerHash, own.providerHash); assert.deepEqual(failed.identity, own.identity);
      await reject(() => call(p, method, args), /crypto_pending/); await cleanup(p);
    });
  }
  await k.check("crypto_wrong_service_or_conversation_does_not_download", async () => {
    const { p, b } = await pair(k, "scope_boundary");
    const sent = await call(p, "send", ["attempt1", "message1", "scope"]);
    for (const patch of [{ service: "other-service" }, { conversation: "other-group" }]) {
      await reject(() => download(p, { ...envelope(sent), ...patch }), /crypto_event_scope/);
    }
    const state = await inspect(p, "b"); assert.equal(state.providerHash, b.providerHash);
    assert.equal(state.downloadCursor, "0"); assert.equal(state.pending, null);
    await cleanup(p);
  });
  await k.check("crypto_full_32_message_limit_and_reload_use_actual_mls", async () => {
    const { p, accounts } = await pair(k, "capacity"); const text = "\0".repeat(4096);
    const result = await p.evaluate(async text => {
      let sent, received;
      for (let n = 1; n <= 32; n++) {
        const id = `id${33 - n}`;
        sent = await window.clients.a.send(id, id, text);
        const wire = sent.outbox.find(item => item.attemptId === id).envelope;
        await window.clients.b.download({ sequence: String(n), eventId: id, envelope: wire });
        received = await window.clients.b.processNext();
      }
      return { sent, received };
    }, text);
    assert.equal(result.sent.encryptions, "32"); assert.equal(result.received.decryptions, "32");
    assert.equal(result.received.messages.length, 32); assert.ok(result.received.messages.every(m => m.text === text));
    await reject(() => call(p, "send", ["overflow", "overflow", "no room"]), /crypto_limit/);
    await reject(() => download(p, envelope(result.sent, "id1"), "33", "overflow"), /crypto_limit/);
    for (const [index, slot] of ["a", "b"].entries()) { await close(p, slot); await open(p, accounts[index], slot); }
    const a = await inspect(p), b = await inspect(p, "b");
    assert.equal(a.status, "ready"); assert.equal(b.status, "ready");
    assert.deepEqual(a.outbox, result.sent.outbox); assert.deepEqual(b.receipts, result.received.receipts);
    assert.deepEqual(b.messages, result.received.messages); assert.equal(b.processingCursor, "32");
    await cleanup(p); return { real_encryptions: 32, real_decryptions: 32, utf8_bytes_per_message: 4096 };
  });
  await k.check("crypto_missing_reservation_table_is_not_silently_recreated", async () => {
    const { p, accounts } = await pair(k, "missing_control"); await watch(p);
    await reject(() => call(p, "send", ["one", "one", "never encrypt", { fault: "lose_reservation_table" }]), /crypto_injected_failure/);
    assert.deepEqual(await p.evaluate(() => window.cryptoEvents.map(e => e.type)), ["snapshot"]);
    await close(p);
    const error = await reject(() => open(p, accounts[0]), /crypto_store_corrupt/);
    await reject(() => open(p, accounts[0]), /crypto_store_corrupt/);
    await cleanup(p); return { error, injected_damage: "only crypto_reservation table; before MLS", automatic_schema_repair: false };
  });
}
