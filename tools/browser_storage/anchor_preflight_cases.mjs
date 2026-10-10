// 普通业务拒绝必须发生在锚预约之前；只通过独立安装包访问浏览器存储。
import assert from "node:assert/strict";
import { hash } from "./anchor_wire.mjs";
import { pair, baseline, call, close, cleanup, envelope, receive, snapshot, status,
  watch, openAnchored, requireSnapshot } from "./anchor_support.mjs";

const digest = value => hash(Buffer.from(JSON.stringify(value)));

async function rejectedUnchanged(k, fixture, method, args, code, slot = "a") {
  const { p, configs } = fixture;
  const config = configs[slot === "a" ? 0 : 1];
  await watch(p, slot);
  const before = await snapshot(p, slot);
  const local = await status(p, slot);
  const remote = await k.anchor.inspect(config.scope);
  const requests = k.anchor.evidence.requests;
  const rejected = await p.evaluate(async ({ method, args, slot }) => {
    try { await window.clients[slot][method](...args); return { code: "unexpected_success" }; }
    catch (error) { return { code: error.code, paused: error.paused }; }
  }, { method, args, slot });
  assert.equal(rejected.code, code);
  const afterRemote = await k.anchor.inspect(config.scope);
  const issued = k.anchor.evidence.requests - requests;
  // 失败记录只含公开锚状态与错误码，不将正文、密文或可信配置写入报告。
  assert.equal(issued, 0, JSON.stringify({ code, anchor_requests: issued,
    remote_revision_before: remote.revision, remote_revision_after: afterRemote.revision,
    remote_pending_after: afterRemote.pending?.txn ?? null }));
  assert.equal(rejected.paused, false);
  assert.equal(digest(afterRemote), digest(remote), "业务拒绝改变了远端锚");
  assert.deepEqual(await status(p, slot), local, "业务拒绝改变了本地锚门");
  assert.equal(digest(await snapshot(p, slot)), digest(before), "业务拒绝改变了已提交业务状态");
  assert.deepEqual(await p.evaluate(() => window.cryptoEvents.map(event => event.type)), ["snapshot"]);
  await close(p, slot);
  await openAnchored(p, config, slot);
  assert.equal((await status(p, slot)).phase, "ready");
  assert.equal(digest(await snapshot(p, slot)), digest(before), "重开未保持原业务状态");
  return { code, anchor_requests: issued, state_unchanged: true, reopened_ready: true };
}

async function ready(k, name) {
  const fixture = await pair(k, name);
  const sent = requireSnapshot(await call(fixture.p, "send", ["attempt1", "message1", "first"]));
  await receive(fixture.p, envelope(sent), "first");
  return { ...fixture, sent };
}

async function continueExchange(fixture) {
  const sent = requireSnapshot(await call(fixture.p, "send", ["next", "next_message", "next"]));
  const received = await receive(fixture.p, envelope(sent, "next"), "next", "2", "event2");
  assert.equal(sent.encryptions, "2");
  assert.equal(received.decryptions, "2");
}

export async function runAnchorPreflightCases(k) {
  const cases = [
    ["attempt_content", "send", f => ["attempt1", "message1", "changed"], "crypto_attempt_conflict", "a"],
    ["attempt_message", "send", f => ["attempt1", "changed_message", "first"], "crypto_attempt_conflict", "a"],
    ["message_id", "send", f => ["another_attempt", "message1", "first"], "crypto_message_conflict", "a"],
    ["create_group", "createGroup", f => ["another_group", f.b.identity], "crypto_already_grouped", "a"],
    ["join_group", "joinGroup", f => [f.b.conversation, f.a.identity, f.a.welcome], "crypto_already_grouped", "b"],
    ["download_service", "download", f => [{ sequence: "2", eventId: "event2",
      envelope: { ...envelope(f.sent), service: "other_service" } }], "crypto_event_scope", "b"],
    ["download_group", "download", f => [{ sequence: "2", eventId: "event2",
      envelope: { ...envelope(f.sent), conversation: "other_group" } }], "crypto_event_scope", "b"],
    ["download_gap", "download", f => [{ sequence: "3", eventId: "event3", envelope: envelope(f.sent) }], "crypto_download_gap", "b"],
    ["download_slot", "download", f => [{ sequence: "1", eventId: "changed_event", envelope: envelope(f.sent) }], "crypto_event_conflict", "b"],
    ["download_event_id", "download", f => [{ sequence: "2", eventId: "event1", envelope: envelope(f.sent) }], "crypto_event_conflict", "b"],
  ];
  for (const [name, method, args, code, slot] of cases) {
    await k.check("anchor_preflight_" + name, async () => {
      const fixture = await ready(k, "preflight_" + name);
      try {
        const evidence = await rejectedUnchanged(k, fixture, method, args(fixture), code, slot);
        await continueExchange(fixture);
        return { ...evidence, continued_real_exchange: true };
      } finally { await cleanup(fixture.p); }
    });
  }
  await k.check("anchor_preflight_send_without_group", async () => {
    const left = await baseline(k, "preflight_ungrouped");
    const right = await baseline(k, "preflight_ungrouped_peer", "b", left.p);
    try {
      const fixture = { p: left.p, configs: [left.config, right.config] };
      const evidence = await rejectedUnchanged(k, fixture, "send", ["one", "one", "no group"], "crypto_no_group");
      const group = requireSnapshot(await call(left.p, "createGroup", ["preflight_group", right.identity]));
      requireSnapshot(await call(left.p, "joinGroup", ["preflight_group", left.identity, group.welcome], "b"));
      const sent = requireSnapshot(await call(left.p, "send", ["attempt1", "message1", "after group"]));
      await receive(left.p, envelope(sent), "after group");
      return { ...evidence, continued_real_exchange: true };
    } finally { await cleanup(left.p); }
  });
  for (const method of ["createGroup", "joinGroup"]) {
    for (const field of ["service", "account", "identityKey"]) {
      await k.check(`anchor_preflight_${method}_peer_${field}`, async () => {
        const name = `preflight_${method}_${field}`;
        const left = await baseline(k, name);
        const right = await baseline(k, name + "_peer", "b", left.p);
        try {
          const fixture = { p: left.p, configs: [left.config, right.config] };
          const joining = method === "joinGroup";
          let group = joining
            ? requireSnapshot(await call(left.p, "createGroup", [name, right.identity])) : null;
          const own = joining ? right.identity : left.identity;
          const peer = { ...(joining ? left.identity : right.identity),
            [field]: field === "service" ? "other_service" : own[field] };
          const args = joining ? [name, peer, group.welcome] : [name, peer];
          const evidence = await rejectedUnchanged(k, fixture, method, args,
            "crypto_identity_mismatch", joining ? "b" : "a");
          group ??= requireSnapshot(await call(left.p, "createGroup", [name, right.identity]));
          requireSnapshot(await call(left.p, "joinGroup", [name, left.identity, group.welcome], "b"));
          const sent = requireSnapshot(await call(left.p, "send", ["attempt1", "message1", "valid peer"]));
          await receive(left.p, envelope(sent), "valid peer");
          return { ...evidence, continued_real_exchange: true };
        } finally { await cleanup(left.p); }
      });
    }
  }
  for (const target of ["outbox", "download"]) {
    await k.check("anchor_preflight_capacity_" + target, async () => {
      const fixture = await ready(k, "preflight_capacity_" + target);
      const { p } = fixture;
      try {
        for (let n = 2; n <= 32; n++) {
          if (target === "outbox") requireSnapshot(await call(p, "send", [`attempt${n}`, `message${n}`, "bounded"]));
          else requireSnapshot(await call(p, "download", [{ sequence: String(n), eventId: `event${n}`, envelope: envelope(fixture.sent) }], "b"));
        }
        const slot = target === "outbox" ? "a" : "b";
        const method = target === "outbox" ? "send" : "download";
        const args = target === "outbox" ? ["overflow", "overflow", "full"]
          : [{ sequence: "33", eventId: "event33", envelope: envelope(fixture.sent) }];
        const evidence = await rejectedUnchanged(k, fixture, method, args, "crypto_limit", slot);
        const retried = requireSnapshot(await call(p, "send", ["attempt1", "message1", "first"]));
        assert.equal(envelope(retried).ciphertext, envelope(fixture.sent).ciphertext);
        assert.equal(retried.encryptions, target === "outbox" ? "32" : "1");
        if (target === "download") {
          const processed = requireSnapshot(await call(p, "processNext", [], "b"));
          assert.equal(processed.processingCursor, "2");
          assert.equal(processed.decryptions, "1");
        }
        const reply = requireSnapshot(await call(p, "send", ["reply", "reply", "still usable"], "b"));
        await receive(p, envelope(reply, "reply"), "still usable", "1", "reply_event", "a");
        return { ...evidence, cached_ciphertext_reused: true, continued_real_exchange: true };
      } finally { await cleanup(p); }
    });
  }
}
