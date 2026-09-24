// 只保存本轮公开材料和可信测试配置；新身份与旧状态不通过 JS 复制。
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { open as openCrypto } from "./crypto_support.mjs";
import { SERVICE, baseline, openAnchored, call, close, reject, cleanup, envelope, watch, crash,
  requireSnapshot as anchoredSnapshot, receive as anchoredReceive } from "./anchor_support.mjs";

export { SERVICE, openAnchored, call, close, reject, cleanup, envelope, watch, crash };
export const randomHex = () => randomBytes(32).toString("hex");

export async function oldPair(k, name, { pin = true } = {}) {
  const p = await k.page(), account = "old_alice_" + name, oldConversation = "old_" + name;
  await openCrypto(p, account, "old", true, SERVICE);
  const created = await call(p, "initialize", [], "old");
  const descriptor = await p.evaluate(() => window.clients.old.test.describeAnchor());
  await close(p, "old");
  const config = await k.anchor.enroll({ service: SERVICE, account, ...descriptor,
    ...(pin ? { rebuildApproverPublicKey: k.rebuild.approverPublicKey } : {}) });
  await openAnchored(p, config, "old");
  const peer = await baseline(k, "old_bob_" + name, "oldPeer", p);
  const grouped = anchoredSnapshot(await call(p, "createGroup", [oldConversation, peer.identity], "old"));
  anchoredSnapshot(await call(p, "joinGroup", [oldConversation, created.identity, grouped.welcome], "oldPeer"));
  const sent = anchoredSnapshot(await call(p, "send", ["old_attempt", "old_message", "old history"], "old"));
  await anchoredReceive(p, envelope(sent, "old_attempt"), "old history", "1", "old_event", "oldPeer");
  const reply = anchoredSnapshot(await call(p, "send", ["old_reply", "old_reply_message", "old reply"], "oldPeer"));
  const before = await anchoredReceive(p, envelope(reply, "old_reply"), "old reply", "1", "old_reply_event", "old");
  assert.equal(before.encryptions, "1"); assert.equal(before.decryptions, "1");
  return { p, config, peerConfig: peer.config, account, oldConversation, before };
}

export async function makePending(k, old, fault = "after_crypto") {
  if (fault === "reserve_drop_after") await k.anchor.fault({ action: "reserve", mode: "drop_after" });
  const control = fault === "reserve_drop_after" ? undefined : { fault };
  await reject(() => call(old.p, "send", ["old_uncertain", "old_uncertain_message", "never reuse this state", control], "old"),
    fault === "reserve_drop_after" ? /anchor_rpc_failed/ : /crypto_injected_failure|storage_error|commit_failed/);
  await close(old.p, "old"); await openAnchored(old.p, old.config, "old");
  const basis = await call(old.p, "rebuildBasis", [], "old");
  const remote = await k.anchor.inspect(old.config.scope);
  assert.ok(remote.pending); assert.equal(basis.oldHead, remote.head); assert.equal(basis.oldTxn, remote.pending.txn);
  assert.equal(basis.oldRevision, remote.revision); assert.equal(basis.oldConversation, old.oldConversation);
  assert.equal(basis.baselineHead, basis.oldHead);
  return basis;
}

export function candidateOptions(k, old, overrides = {}) {
  return { service: SERVICE, account: old.account, device: "rebuilt_" + randomHex().slice(0, 24),
    storageNamespace: randomHex(), endpoint: k.anchor.endpoint, anchorPublicKey: k.anchor.anchorPublicKey,
    approverPublicKey: k.rebuild.approverPublicKey, clientSeed: randomHex(), testMode: true, ...overrides };
}

export async function openCandidate(p, options, slot = "a", create = false) {
  await p.evaluate(async input => {
    try {
      window.clients[input.slot] = await window.probe[input.create ? "createRebuild" : "openRebuild"](input.options);
    } catch (error) {
      throw new Error(JSON.stringify({ code: error.code, cause: error.cause, message: error.message }));
    }
  }, { options, slot, create });
}

export async function diagnostic(p, method = "status", slot = "a") {
  const view = await call(p, method, [], slot);
  assert.equal(view.snapshot, null, "rebuild diagnostics must not return crypto data");
  return view;
}

export async function newCandidate(k, old, overrides = {}, slot = "a") {
  const options = candidateOptions(k, old, overrides);
  await openCandidate(old.p, options, slot, true);
  const view = await diagnostic(old.p, "offer", slot);
  assert.equal(view.phase, "candidate"); assert.ok(view.candidate);
  const offer = view.candidate;
  assert.equal(offer.scope.service, old.config.scope.service); assert.equal(offer.scope.account, old.account);
  assert.notEqual(offer.scope.device, old.config.scope.device); assert.notEqual(offer.scope.identity_key, old.config.scope.identity_key);
  assert.notEqual(offer.scope.store_id, old.config.scope.store_id); assert.equal(offer.scope.store_id, options.storageNamespace);
  return { options, offer };
}

export async function newPeer(k, old, name) {
  const peer = await baseline(k, "future_bob_" + name, "peer", old.p);
  return { config: peer.config, identity: peer.identity };
}

export async function prepare(k, old, candidate, peer, conversation) {
  const plan = k.rebuild.prepare({ old: await k.anchor.inspect(old.config.scope), oldConversation: old.oldConversation,
    successor: candidate.offer, conversation, peer: peer.identity });
  return { plan, approval: k.rebuild.approve(plan) };
}

export async function fixture(k, name, { pin = true, fault = "after_crypto" } = {}) {
  const old = await oldPair(k, name, { pin });
  const basis = await makePending(k, old, fault);
  const candidate = await newCandidate(k, old), peer = await newPeer(k, old, name);
  const authorization = await prepare(k, old, candidate, peer, "new_" + name);
  return { p: old.p, old, candidate, peer, basis, ...authorization };
}

export function requireSnapshot(view) {
  assert.equal(view.phase, "ready");
  return anchoredSnapshot(view);
}
export async function snapshot(p, slot = "a") { return requireSnapshot(await call(p, "inspect", [], slot)); }
export async function activate(f, test) {
  const view = await call(f.p, "activate", [f.plan, f.approval, test]);
  assert.equal(view.snapshot, null); assert.ok(["linked", "ready"].includes(view.phase));
  return view;
}
export async function join(f, test) {
  const grouped = anchoredSnapshot(await call(f.p, "createGroup", [f.plan.conversation, f.candidate.offer.identity], "peer"));
  f.welcome = grouped.welcome;
  return requireSnapshot(await call(f.p, "joinGroup", [f.plan.conversation, f.plan.peer, f.welcome, test]));
}
export async function ready(f) { await activate(f); return join(f); }

export async function reopen(k, f) {
  await cleanup(f.p); f.p = await k.page(); f.old.p = f.p;
  const { initialFault: _initialFault, ...options } = f.candidate.options;
  await openCandidate(f.p, options); await openAnchored(f.p, f.peer.config, "peer");
  return f.p;
}

export async function receive(p, wire, text, sequence = "1", eventId = "new_event", slot = "a") {
  const loaded = requireSnapshot(await call(p, "download", [{ sequence, eventId, envelope: wire }], slot));
  assert.equal(loaded.downloadCursor, sequence);
  const result = requireSnapshot(await call(p, "processNext", [], slot));
  assert.equal(result.processingCursor, sequence); assert.equal(result.messages.at(-1)?.text, text);
  return result;
}
export async function exchange(f, text = "new conversation") {
  const sent = requireSnapshot(await call(f.p, "send", ["new_attempt", "new_message", text]));
  await anchoredReceive(f.p, envelope(sent, "new_attempt"), text, "1", "new_event", "peer");
  const reply = anchoredSnapshot(await call(f.p, "send", ["new_reply", "new_reply_message", "new reply"], "peer"));
  const received = await receive(f.p, envelope(reply, "new_reply"), "new reply");
  return { sent, received };
}
