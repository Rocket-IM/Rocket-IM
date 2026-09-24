// 全部身份在本轮新建；只验证认证绑定与未决预约，不使用撤销设备的旧钥。
import assert from "node:assert/strict";
import {
  open, call, inspect, close, reject, watch, pair, cleanup, download, process, envelope,
} from "./crypto_support.mjs";

const identityError = /"code":"crypto_identity_mismatch"/;
const pendingError = /"code":"crypto_pending"/;

function unchangedAndPaused(value, before, operation) {
  assert.equal(value.status, "paused");
  assert.equal(value.pending?.operation, operation);
  for (const field of ["providerHash", "revision", "encryptions", "decryptions",
    "downloadCursor", "processingCursor", "conversation"]) {
    assert.equal(value[field], before[field], `${field} changed before a successful commit`);
  }
  for (const field of ["identity", "outbox", "events", "messages", "receipts"]) {
    assert.deepEqual(value[field], before[field], `${field} changed before a successful commit`);
  }
}

async function noSuccess(p) {
  assert.deepEqual(await p.evaluate(() => window.cryptoEvents.map(event => event.type)), ["snapshot"]);
}

async function identities(k, name) {
  const p = await k.page();
  const accounts = ["auth_" + name + "_alice", "auth_" + name + "_bob", "auth_" + name + "_third"];
  try {
    await open(p, accounts[0]); await open(p, accounts[1], "b"); await open(p, accounts[2], "c");
    const a = await call(p, "initialize"), b = await call(p, "initialize", [], "b");
    const third = await call(p, "initialize", [], "c");
    assert.notEqual(a.identity.identityKey, third.identity.identityKey);
    assert.notEqual(b.identity.identityKey, third.identity.identityKey);
    return { p, accounts, a, b, third };
  } catch (error) { await cleanup(p); throw error; }
}

export async function runCryptoAuthCases(k) {
  await k.check("crypto_outer_message_id_must_match_authenticated_context", async () => {
    const { p, accounts } = await pair(k, "auth_outer_id");
    try {
      const sent = await call(p, "send", ["attempt1", "message1", "authenticated content"]);
      // 密文字节完整保留，只篡改外层 ID，必须由认证绑定校验发现。
      const altered = { ...envelope(sent), messageId: "forged_message" };
      const downloaded = await download(p, altered);
      assert.equal(downloaded.downloadCursor, "1"); assert.equal(downloaded.processingCursor, "0");
      await watch(p, "b");
      const error = await reject(() => process(p), identityError);
      unchangedAndPaused(await inspect(p, "b"), downloaded, "process_next");
      await noSuccess(p);
      await close(p, "b"); await open(p, accounts[1], "b");
      unchangedAndPaused(await inspect(p, "b"), downloaded, "process_next");
      await reject(() => process(p), pendingError);
      return { error, altered_field: "messageId", ciphertext_unchanged: true, pending_persisted: true };
    } finally { await cleanup(p); }
  });

  await k.check("crypto_key_package_must_match_supplied_pinned_key", async () => {
    const { p, accounts, a, b, third } = await identities(k, "package_pin");
    try {
      const mismatched = { ...b.identity, identityKey: third.identity.identityKey };
      await watch(p);
      const error = await reject(() => call(p, "createGroup", ["auth_package_pin", mismatched]), identityError);
      unchangedAndPaused(await inspect(p), a, "create_group");
      assert.equal((await inspect(p)).welcome, null); await noSuccess(p);
      await close(p); await open(p, accounts[0]);
      unchangedAndPaused(await inspect(p), a, "create_group");
      await reject(() => call(p, "createGroup", ["auth_package_pin", b.identity]), pendingError);
      return { error, substituted_pin: "fresh third identity", pending_persisted: true };
    } finally { await cleanup(p); }
  });

  await k.check("crypto_welcome_creator_must_match_supplied_pinned_key", async () => {
    const { p, accounts, a, b, third } = await identities(k, "welcome_pin");
    try {
      const grouped = await call(p, "createGroup", ["auth_welcome_pin", b.identity]);
      const mismatched = { ...a.identity, identityKey: third.identity.identityKey };
      await watch(p, "b");
      const error = await reject(() => call(p, "joinGroup", ["auth_welcome_pin", mismatched, grouped.welcome], "b"), identityError);
      unchangedAndPaused(await inspect(p, "b"), b, "join_group");
      await noSuccess(p);
      await close(p, "b"); await open(p, accounts[1], "b");
      unchangedAndPaused(await inspect(p, "b"), b, "join_group");
      await reject(() => call(p, "joinGroup", ["auth_welcome_pin", a.identity, grouped.welcome], "b"), pendingError);
      return { error, substituted_pin: "fresh third identity", pending_persisted: true };
    } finally { await cleanup(p); }
  });

  await k.check("crypto_pending_guard_precedes_completed_attempt_cache", async () => {
    const { p, accounts } = await pair(k, "auth_cached_gate");
    try {
      const completed = await call(p, "send", ["completed_attempt", "completed_message", "already committed"]);
      assert.equal(completed.encryptions, "1"); assert.equal(completed.outbox.length, 1);
      await watch(p);
      const error = await reject(() => call(p, "send", ["failed_attempt", "failed_message", "candidate only",
        { fault: "after_crypto" }]), /"code":"crypto_injected_failure"/);
      unchangedAndPaused(await inspect(p), completed, "send"); await noSuccess(p);
      await close(p); await open(p, accounts[0]);
      unchangedAndPaused(await inspect(p), completed, "send"); await watch(p);
      // 已完成的同一尝试也必须先经过全局未决闸，不能从缓存分支绕过。
      const blocked = await reject(() => call(p, "send", ["completed_attempt", "completed_message", "already committed"]), pendingError);
      unchangedAndPaused(await inspect(p), completed, "send"); await noSuccess(p);
      await close(p); await open(p, accounts[0]);
      unchangedAndPaused(await inspect(p), completed, "send");
      return { error, blocked, committed_encryptions: "1", pending_persisted: true };
    } finally { await cleanup(p); }
  });
}
