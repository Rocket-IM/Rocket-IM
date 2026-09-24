import assert from "node:assert/strict";
import { open, call, inspect, close, reject, watch, pair, cleanup, download, process, envelope } from "./crypto_support.mjs";
import { runCryptoFaultCases } from "./crypto_fault_cases.mjs";
import { runCryptoBoundaryCases } from "./crypto_boundary_cases.mjs";
import { runCryptoAuthCases } from "./crypto_auth_cases.mjs";

export async function runCryptoCases(k) {
  await k.check("crypto_explicit_initialization_and_identity_persistence", async () => {
    const p = await k.page(); await open(p, "initialization");
    const empty = await inspect(p); assert.equal(empty.status, "empty"); assert.equal(empty.identity, null);
    await close(p); await open(p, "initialization"); assert.equal((await inspect(p)).identity, null);
    const created = await call(p, "initialize"); assert.equal(created.status, "ready");
    assert.ok(created.identity.identityKey); assert.ok(created.providerHash);
    await close(p); await open(p, "initialization"); const loaded = await inspect(p);
    assert.deepEqual(loaded.identity, created.identity); assert.equal(loaded.providerHash, created.providerHash);
    const again = await call(p, "initialize"); assert.equal(again.providerHash, created.providerHash);
    await cleanup(p); return { identity_persisted: true, provider_hash: created.providerHash };
  });
  await k.check("crypto_real_send_download_process_and_reply", async () => {
    const { p, a, b } = await pair(k, "exchange");
    const sent = await call(p, "send", ["attempt1", "message1", "synthetic hello"]);
    assert.equal(sent.encryptions, "1"); assert.notEqual(sent.providerHash, a.providerHash);
    const wire = envelope(sent); assert.ok(!wire.ciphertext.includes("synthetic hello"));
    const loaded = await download(p, wire);
    assert.equal(loaded.downloadCursor, "1"); assert.equal(loaded.processingCursor, "0");
    assert.equal(loaded.decryptions, "0");
    assert.equal(loaded.messages.length, 0); assert.equal(loaded.receipts.length, 0); assert.equal(loaded.providerHash, b.providerHash);
    const received = await process(p);
    assert.equal(received.processingCursor, "1"); assert.equal(received.decryptions, "1");
    assert.equal(received.messages[0].text, "synthetic hello"); assert.notEqual(received.providerHash, b.providerHash);
    assert.deepEqual(received.receipts, ["event1"]);
    const reply = await call(p, "send", ["reply1", "reply-message", "synthetic reply"], "b");
    await download(p, envelope(reply, "reply1"), "1", "replyevent", "a");
    const replyReceived = await process(p, undefined, "a"); assert.equal(replyReceived.messages[0].text, "synthetic reply");
    await cleanup(p); return { real_openmls_bidirectional_messages: 2 };
  });
  await k.check("crypto_send_idempotency_and_conflict_do_not_reencrypt", async () => {
    const { p } = await pair(k, "idempotent"); await watch(p);
    const sent = await call(p, "send", ["attempt1", "message1", "original"]);
    const retried = await call(p, "send", ["attempt1", "message1", "original"]);
    assert.deepEqual(retried.outbox, sent.outbox); assert.equal(retried.providerHash, sent.providerHash);
    assert.equal(retried.encryptions, "1"); assert.equal(retried.change, "none");
    await reject(() => call(p, "send", ["attempt1", "message1", "changed"]), /conflict|duplicate/);
    await reject(() => call(p, "send", ["attempt2", "message1", "original"]), /conflict|duplicate/);
    const after = await inspect(p); assert.equal(after.providerHash, sent.providerHash); assert.equal(after.encryptions, "1");
    assert.deepEqual(await p.evaluate(() => window.cryptoEvents.map(e => e.type)), ["snapshot", "committed"]);
    await cleanup(p); return { ciphertext_hash: sent.outbox[0].ciphertextHash, encryptions: after.encryptions };
  });
  await k.check("crypto_clean_restart_then_next_message_uses_new_state", async () => {
    const { p, accounts } = await pair(k, "restart");
    const first = await call(p, "send", ["attempt1", "message1", "first"]);
    await download(p, envelope(first)); await process(p); await cleanup(p);
    await k.restart(); const q = await k.page(); await open(q, accounts[0]); await open(q, accounts[1], "b");
    const retried = await call(q, "send", ["attempt1", "message1", "first"]);
    assert.equal(envelope(retried).ciphertext, envelope(first).ciphertext);
    const second = await call(q, "send", ["attempt2", "message2", "second"]);
    assert.equal(second.encryptions, "2"); assert.notEqual(envelope(second, "attempt2").ciphertext, envelope(first).ciphertext);
    await download(q, envelope(second, "attempt2"), "2", "event2"); const received = await process(q);
    assert.deepEqual(received.messages.map(m => m.text), ["first", "second"]); assert.equal(received.decryptions, "2");
    await cleanup(q);
  });
  await k.check("crypto_receive_dedup_and_contiguous_dual_cursors", async () => {
    const { p } = await pair(k, "dedup"); const sent = await call(p, "send", ["attempt1", "message1", "once"]);
    const wire = envelope(sent);
    await reject(() => download(p, wire, "2", "gap"), /sequence|cursor|gap/);
    const downloaded = await download(p, wire); const repeat = await download(p, wire);
    assert.equal(repeat.revision, downloaded.revision); assert.equal(repeat.change, "none");
    const received = await process(p); const providerHash = received.providerHash;
    await download(p, wire, "2", "duplicate2"); const duplicate = await process(p);
    assert.equal(duplicate.processingCursor, "2"); assert.equal(duplicate.downloadCursor, "2");
    assert.equal(duplicate.messages.length, 1); assert.equal(duplicate.receipts.length, 1);
    assert.equal(duplicate.decryptions, "1"); assert.equal(duplicate.providerHash, providerHash);
    assert.equal(duplicate.events[1].status, "duplicate"); await cleanup(p);
  });
  await k.check("crypto_concurrent_same_attempt_has_one_encryption", async () => {
    const { p } = await pair(k, "concurrent");
    const value = await p.evaluate(async () => {
      const results = await Promise.all([window.clients.a.send("one", "one", "same"), window.clients.a.send("one", "one", "same")]);
      return { equal: results[0].outbox[0].envelope.ciphertext === results[1].outbox[0].envelope.ciphertext,
        snapshot: await window.clients.a.inspect() };
    });
    assert.equal(value.equal, true); assert.equal(value.snapshot.encryptions, "1"); assert.equal(value.snapshot.outbox.length, 1);
    await cleanup(p);
  });
  await k.check("crypto_and_ordinary_share_scope_lock", async () => {
    const p = await k.page(); await open(p, "shared");
    const error = await p.evaluate(async () => {
      try { await window.probe.open({ service: "crypto-service", account: "shared" }); return "unexpected"; }
      catch (error) { return error.code; }
    });
    assert.equal(error, "IN_USE"); await close(p);
    await p.evaluate(async () => { window.clients.a = await window.probe.open({ service: "crypto-service", account: "shared" }); });
    await reject(() => open(p, "shared", "b"), /IN_USE/); await cleanup(p);
  });
  await k.check("crypto_subscription_callback_can_requery_after_commit", async () => {
    const { p } = await pair(k, "subscribe");
    const result = await p.evaluate(async () => {
      const seen = [], queries = [];
      const cancel = await window.clients.a.subscribe(event => { seen.push(event.type); queries.push(window.clients.a.inspect()); });
      await window.clients.a.send("one", "one", "hello"); await window.clients.a.inspect();
      await Promise.all(queries); cancel();
      await window.clients.a.send("two", "two", "world");
      return { seen, reads: queries.length };
    });
    assert.deepEqual(result, { seen: ["snapshot", "committed"], reads: 2 }); await cleanup(p);
  });
  await runCryptoBoundaryCases(k);
  await runCryptoAuthCases(k);
  await runCryptoFaultCases(k);
}
