import { PersistentDevice, SdkError } from '@rocket-im/desktop-dev';
import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
const root = resolve(process.env.ROCKET_CASE_DATA ?? './边界数据');
await mkdir(root, { recursive: true, mode: 0o700 });
const cases = [], opened = [], pids = [];
const scope = (account, service = 'test') => ({ service, account, device: 'one' });
let seq = 0;
async function open(account, opts = {}) {
  const device = await PersistentDevice.open({ path: resolve(root, `${++seq}-${account}.db`), scope: scope(account), create: true, ...opts });
  opened.push(device); pids.push(device.runtime.pid); return device;
}
async function pair() {
  const a = await open('alice'), b = await open('bob');
  await a.initialize('init'); await b.initialize('init');
  const am = await a.joiningMaterial(), bm = await b.joiningMaterial();
  const created = await a.createGroup('create', 'chat', bm.identity, bm.key_package);
  await b.joinGroup('join', 'chat', am.identity, created.value.welcome);
  return { a, b, am, bm, welcome: created.value.welcome };
}
async function rejected(fn, code) { await assert.rejects(fn, e => e instanceof SdkError && e.code === code); }
async function test(name, fn) {
  const start = opened.length;
  try { await fn(); cases.push({ name, status: 'PASS' }); }
  catch (e) { cases.push({ name, status: 'FAIL', error: String(e.stack ?? e) }); throw e; }
  finally { await Promise.allSettled(opened.slice(start).map(d => d.close())); }
}
try {
  await test('initialize-persisted-material-and-open-scope', async () => {
    const path = resolve(root, 'identity.db');
    const a = await open('alice', { path }); await a.initialize('init');
    const before = await a.joiningMaterial(); await a.close();
    const restored = await open('alice', { path, create: false });
    assert.deepEqual(await restored.joiningMaterial(), before);
    assert.equal((await restored.initialize('init')).cached, true);
    await rejected(() => open('wrong', { path, create: false }), 'scope_mismatch');
    await rejected(() => open('alice', { path, create: false, scope: scope('alice', 'other-service') }), 'scope_mismatch');
    await rejected(() => open('alice', { path, create: false, scope: { ...scope('alice'), device: 'other-device' } }), 'scope_mismatch');
    await rejected(() => open('alice', { path, create: true }), 'store_exists');
    await rejected(() => open('alice', { path: resolve(root, 'absent.db'), create: false }), 'store_missing');
  });
  await test('pin-check-before-create-and-retry-conflicts', async () => {
    const a = await open('alice'), b = await open('bob');
    await a.initialize('init'); await b.initialize('init'); const bm = await b.joiningMaterial();
    await rejected(() => a.createGroup('wrong', 'chat', { ...bm.identity, identity_key: '00'.repeat(32) }, bm.key_package), 'identity_mismatch');
    assert.equal((await a.state()).revision, '1'); assert.equal((await a.request('wrong')).status, 'failed');
    const created = await a.createGroup('create', 'chat', bm.identity, bm.key_package);
    assert.equal((await a.createGroup('create', 'chat', bm.identity, bm.key_package)).value.welcome, created.value.welcome);
    await rejected(() => a.send('create', 'x', 'x'), 'request_conflict');
  });
  await test('join-pin-failure-keeps-old-state-and-pending', async () => {
    const a = await open('alice'), b = await open('bob');
    await a.initialize('init'); await b.initialize('init');
    const am = await a.joiningMaterial(), bm = await b.joiningMaterial();
    const c = await a.createGroup('create', 'chat', bm.identity, bm.key_package);
    await rejected(() => b.joinGroup('wrong', 'chat', { ...am.identity, identity_key: '00'.repeat(32) }, c.value.welcome), 'identity_mismatch');
    assert.equal((await b.state()).revision, '1'); assert.equal((await b.request('wrong')).status, 'pending');
    assert.equal((await b.state()).conversation, null);
    await rejected(() => b.joinGroup('corrected', 'chat', am.identity, c.value.welcome), 'operation_pending');
  });
  await test('bidirectional-exact-retry-dedup-and-message-query', async () => {
    const { a, b } = await pair();
    const sent = await a.send('send', 'message', '你好 👋');
    assert.deepEqual((await a.send('send', 'message', '你好 👋')).value, sent.value);
    await rejected(() => a.send('send', 'message', 'changed'), 'request_conflict');
    await rejected(() => a.send('other', 'message', '你好 👋'), 'message_conflict');
    const received = await b.receive('receive', sent.value.envelope);
    assert.equal(received.value.message.text, '你好 👋');
    const state = await b.state(); assert.equal((await b.receive('duplicate', sent.value.envelope)).cached, true);
    assert.deepEqual(await b.state(), state);
    await rejected(() => b.receive('changed-header', { ...sent.value.envelope, message_id: 'other' }), 'message_conflict');
    await rejected(() => b.receive('changed-service', { ...sent.value.envelope, service: 'other' }), 'scope_mismatch');
    const reply = await b.send('reply', 'reply', '回复'); await a.receive('reply', reply.value.envelope);
    assert.equal((await a.message('bob', 'one', 'reply')).text, '回复');
    assert.equal(await a.message('bob', 'one', 'absent'), null);
    assert.equal((await b.request('duplicate')).status, 'complete');
  });
  await test('events-after-commit-reentrant-query-cache-failure-unsubscribe', async () => {
    const { a, b } = await pair(); const events = [], queries = [];
    const off = b.subscribe(c => { events.push(c); queries.push(b.message('alice', 'one', 'msg')); });
    const sent = await a.send('send', 'msg', 'event text');
    await b.receive('rx', sent.value.envelope);
    assert.equal((await Promise.all(queries))[0].text, 'event text');
    await b.receive('rx', sent.value.envelope); await b.receive('dup', sent.value.envelope);
    await rejected(() => b.receive('bad', { ...sent.value.envelope, service: 'no' }), 'scope_mismatch');
    assert.equal(events.length, 1); assert.equal(events[0].kind, 'local_commit');
    off(); const second = await a.send('s2', 'm2', 'two'); await b.receive('r2', second.value.envelope); assert.equal(events.length, 1);
  });
  await test('close-drains-accepted-call-suppresses-late-events', async () => {
    const { a, b } = await pair(); let events = 0; b.subscribe(() => { events++; });
    const sent = await a.send('send', 'msg', 'close'); const receive = b.receive('rx', sent.value.envelope);
    const closing = b.close(); await receive; await closing; await b.close();
    assert.equal(events, 0); await rejected(() => b.state(), 'closed');
    const back = await a.send('alive', 'alive', 'other account lives'); assert.equal(back.cached, false);
  });
  await test('pre-cancel-and-input-capture-isolation', async () => {
    const a = await open('alice'); const controller = new AbortController(); controller.abort();
    await rejected(() => a.initialize('cancelled', { signal: controller.signal }), 'cancelled');
    assert.equal((await a.request('cancelled')).status, 'missing');
    const options = { path: resolve(root, 'captured.db'), scope: scope('captured'), create: true };
    const pending = PersistentDevice.open(options); options.scope.account = 'mutated';
    const captured = await pending; opened.push(captured); pids.push(captured.runtime.pid);
    assert.equal((await captured.state()).scope.account, 'captured');
  });
  await test('inflight-cancel-is-unknown-and-only-stops-owned-process', async () => {
    const { a, b } = await pair(); let events = 0; a.subscribe(() => { events++; });
    const c = new AbortController(); const promise = a.send('abort', 'abort', 'cancel', { signal: c.signal }); c.abort();
    await rejected(() => promise, 'cancelled_unknown'); await a.close(); assert.equal(events, 0);
    assert.equal((await b.state()).conversation, 'chat');
    assert.throws(() => process.kill(a.runtime.pid, 0), { code: 'ESRCH' });
  });
  await test('timeout-kills-and-reaps-owned-native-process', async () => {
    const a = await open('timeout', { timeoutMs: 1000 });
    process.kill(a.runtime.pid, 'SIGSTOP');
    await rejected(() => a.state(), 'request_timeout_unknown');
    await a.close(); assert.throws(() => process.kill(a.runtime.pid, 0), { code: 'ESRCH' });
  });
  await test('normal-package-has-no-environment-fault-hook', async () => {
    process.env.ROCKET_IM_TEST_EXIT_PHASE = 'after_commit';
    const a = await open('normal'); delete process.env.ROCKET_IM_TEST_EXIT_PHASE;
    assert.equal((await a.initialize('init')).cached, false);
  });
  await test('new-device-no-automatic-old-history', async () => {
    const { a, b } = await pair(); const old = await a.send('old', 'old', 'old history'); await b.receive('old', old.value.envelope);
    const fresh = await open('bob'); await fresh.initialize('init');
    assert.notEqual((await fresh.state()).identity.identity_key, (await b.state()).identity.identity_key);
    assert.equal(await fresh.message('alice', 'one', 'old'), null);
    await rejected(() => fresh.receive('old', old.value.envelope), 'group_required');
  });
  await test('malformed-and-size-limits-preserve-effective-state', async () => {
    const { a, b } = await pair(); const before = await a.state();
    await rejected(() => a.send('large', 'large', 'x'.repeat(32769)), 'invalid_message');
    await rejected(() => a.send('type', 'type', null), 'invalid_request');
    assert.deepEqual(await a.state(), before);
    const maximum = await a.send('max', 'max', 'x'.repeat(32768));
    assert.equal((await b.receive('max', maximum.value.envelope)).value.message.text.length, 32768);
    const controls = await a.send('controls', 'controls', '\0'.repeat(32768));
    assert.equal((await b.receive('controls', controls.value.envelope)).value.message.text, '\0'.repeat(32768));
    await rejected(() => b.receive('bad', { ...maximum.value.envelope, ciphertext: 'nothex' }), 'invalid_encoding');
  });
  for (const pid of pids) assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
  console.log(JSON.stringify({ status: 'PASS_SCOPED', cases, process_count: pids.length, reaped: true }));
} catch (error) {
  console.log(JSON.stringify({ status: 'FAIL', cases })); throw error;
} finally { await Promise.allSettled(opened.map(d => d.close())); }
