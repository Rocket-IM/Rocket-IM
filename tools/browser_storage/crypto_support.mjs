import assert from "node:assert/strict";

export async function open(p, account, slot = "a", testMode = true, service = "crypto-service") {
  await p.evaluate(async args => {
    try { window.clients[args.slot] = await window.probe.openCrypto({ service: args.service, account: args.account, testMode: args.testMode }); }
    catch (error) { throw new Error(JSON.stringify({ code: error.code, cause: error.cause, message: error.message })); }
  }, { account, slot, testMode, service });
}
export async function call(p, method, args = [], slot = "a") {
  return p.evaluate(async input => {
    try { return await window.clients[input.slot][input.method](...input.args); }
    catch (error) { throw new Error(JSON.stringify({ code: error.code, cause: error.cause, message: error.message })); }
  }, { method, args, slot });
}
export const inspect = (p, slot = "a") => call(p, "inspect", [], slot);
export const close = (p, slot = "a") => call(p, "close", [], slot);
export async function reject(action, pattern) {
  try { await action(); } catch (error) { if (pattern) assert.match(String(error), pattern); return String(error); }
  throw new Error("operation unexpectedly succeeded");
}
export async function watch(p, slot = "a") {
  await p.evaluate(async slot => {
    window.cryptoEvents = [];
    await window.clients[slot].subscribe(event => window.cryptoEvents.push(event));
  }, slot);
}
export async function pair(k, name) {
  const p = await k.page(); const accounts = ["alice_" + name, "bob_" + name];
  await open(p, accounts[0]); await open(p, accounts[1], "b");
  const a = await call(p, "initialize"), b = await call(p, "initialize", [], "b");
  const grouped = await call(p, "createGroup", [name, b.identity]);
  await call(p, "joinGroup", [name, a.identity, grouped.welcome], "b");
  return { p, accounts, a: await inspect(p), b: await inspect(p, "b") };
}
export async function cleanup(p) {
  if (p.isClosed()) return;
  await p.evaluate(async () => { await Promise.allSettled(Object.values(window.clients).map(c => c.close())); }).catch(() => {});
  await p.close();
}
export async function download(p, envelope, sequence = "1", eventId = "event1", slot = "b", test) {
  return call(p, "download", [{ sequence, eventId, envelope }, test], slot);
}
export async function process(p, test, slot = "b") { return call(p, "processNext", [test], slot); }
export function envelope(snapshot, attemptId = "attempt1") {
  const record = snapshot.outbox.find(r => r.attemptId === attemptId);
  assert.ok(record, "committed outbox entry absent"); return record.envelope;
}
export async function prepareCrash(p, method, args, phase, slot = "a") {
  await watch(p, slot);
  await p.evaluate(input => {
    window.phases = []; window.operationResult = "pending";
    window.clients[input.slot].test.onCheckpoint(event => window.phases.push(event.phase));
    void window.clients[input.slot][input.method](...input.args, { checkpoint: input.phase })
      .then(() => { window.operationResult = "success"; }, error => { window.operationResult = error.code; });
  }, { method, args, phase, slot });
  await p.waitForFunction(phase => window.phases.includes(phase), phase);
  assert.deepEqual(await p.evaluate(() => window.cryptoEvents.map(e => e.type)), ["snapshot"]);
}
export async function crash(k, p) {
  const cdp = await k.context().newCDPSession(p), crashed = p.waitForEvent("crash");
  void cdp.send("Page.crash").catch(() => {});
  await crashed; await k.restart(); return k.page();
}
export async function assertBlocked(p) {
  const value = await inspect(p); assert.equal(value.status, "paused"); assert.ok(value.pending);
  await reject(() => call(p, "send", ["retry", "retry", "must not encrypt"]), /pending|paused|unresolved/);
  return value;
}
