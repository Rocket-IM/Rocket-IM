// 测试控制器只保存本轮合成可信配置；页面经公开包访问，完整数据库不导出到 JS。
import assert from "node:assert/strict";
import { open, call, close, reject, watch, cleanup, envelope, crash } from "./crypto_support.mjs";

export { call, close, reject, watch, cleanup, envelope, crash };
export const SERVICE = "anchor-service";

export async function openAnchored(p, config, slot = "a") {
  await p.evaluate(async input => {
    try {
      window.clients[input.slot] = await window.probe.openAnchored({
        service: input.config.scope.service, account: input.config.scope.account,
        testMode: true, anchor: input.config,
      });
    } catch (error) {
      // 不把可信配置、私有种子或页面入参写入失败报告。
      throw new Error(JSON.stringify({ code: error.code, cause: error.cause, message: error.message }));
    }
  }, { config, slot });
}

export function requireSnapshot(view) {
  assert.equal(view.status.assurance, "synthetic_local");
  assert.equal(view.status.phase, "ready");
  assert.ok(view.snapshot, "anchor-confirmed crypto snapshot absent");
  assert.equal(view.status.localHead, view.status.remoteHead);
  assert.equal(view.status.remotePending, null);
  assert.equal(view.status.localPending, false);
  return view.snapshot;
}

export async function snapshot(p, slot = "a") {
  return requireSnapshot(await call(p, "inspect", [], slot));
}

export async function status(p, slot = "a") {
  const value = await call(p, "status", [], slot);
  assert.equal(value.snapshot, null, "diagnostics must never expose a crypto snapshot");
  assert.equal(value.status.assurance, "synthetic_local");
  return value.status;
}

export async function assertPaused(p, options = {}, slot = "a") {
  const value = await status(p, slot);
  assert.equal(value.phase, "paused");
  if (options.pending !== undefined) assert.equal(value.localPending, options.pending);
  if (options.reason) assert.match(value.reason ?? "", options.reason);
  return value;
}

export async function baseline(k, name, slot = "a", page) {
  const p = page ?? await k.page();
  await open(p, name, slot, true, SERVICE);
  const initialized = await call(p, "initialize", [], slot);
  assert.equal(initialized.status, "ready");
  const descriptor = await p.evaluate(async slot => {
    try { return await window.clients[slot].test.describeAnchor(); }
    catch (error) { throw new Error(JSON.stringify({ code: error.code, message: error.message })); }
  }, slot);
  assert.match(descriptor.head, /^[0-9a-f]{64}$/);
  assert.deepEqual(descriptor.identity, initialized.identity);
  await close(p, slot);
  const config = await k.anchor.enroll({ service: SERVICE, account: name, ...descriptor });
  await openAnchored(p, config, slot);
  const initial = await status(p, slot);
  assert.equal(initial.phase, "ready");
  assert.equal(initial.localHead, descriptor.head);
  assert.equal(initial.remoteHead, descriptor.head);
  return { p, config, identity: descriptor.identity, head: descriptor.head,
    service: SERVICE, account: name, slot };
}

export async function pair(k, name) {
  const left = await baseline(k, "alice_" + name);
  const right = await baseline(k, "bob_" + name, "b", left.p);
  const grouped = requireSnapshot(await call(left.p, "createGroup", [name, right.identity]));
  assert.ok(grouped.welcome);
  requireSnapshot(await call(left.p, "joinGroup", [name, left.identity, grouped.welcome], "b"));
  return { p: left.p, configs: [left.config, right.config], accounts: [left.account, right.account],
    a: await snapshot(left.p), b: await snapshot(left.p, "b") };
}

export async function reopenPair(k, configs) {
  const p = await k.page();
  await openAnchored(p, configs[0]);
  await openAnchored(p, configs[1], "b");
  return p;
}

export async function receive(p, wire, text, sequence = "1", eventId = "event1", slot = "b") {
  const downloaded = requireSnapshot(await call(p, "download", [{ sequence, eventId, envelope: wire }], slot));
  assert.equal(downloaded.downloadCursor, sequence);
  const processed = requireSnapshot(await call(p, "processNext", [], slot));
  assert.equal(processed.processingCursor, sequence);
  assert.equal(processed.messages.at(-1)?.text, text);
  assert.ok(processed.receipts.includes(eventId));
  return processed;
}

export async function prepareCrash(p, method, args, phase, slot = "a") {
  await watch(p, slot);
  await p.evaluate(input => {
    window.phases = []; window.operationResult = "pending";
    window.clients[input.slot].test.onCheckpoint(event => window.phases.push(event.phase));
    void window.clients[input.slot][input.method](...input.args, { anchorCheckpoint: input.phase })
      .then(() => { window.operationResult = "success"; }, error => { window.operationResult = error.code; });
  }, { method, args, phase, slot });
  await p.waitForFunction(phase => window.phases.includes(phase), phase);
  assert.equal(await p.evaluate(() => window.operationResult), "pending");
  assert.deepEqual(await p.evaluate(() => window.cryptoEvents.map(event => event.type)), ["snapshot"]);
}
