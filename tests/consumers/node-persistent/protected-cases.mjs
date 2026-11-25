// 仓库外只安装 TGZ，系统夹具由父进程在管道另一端操作；不持有数据库钥或执行 SQL。
import { PersistentDevice, SdkError } from '@rocket-im/desktop-dev';
import assert from 'node:assert/strict';
import { createInterface } from 'node:readline';
import { resolve } from 'node:path';
import { mkdir, readFile, copyFile, writeFile, rename } from 'node:fs/promises';
import { successor } from './recovery-support.mjs';
const input = createInterface({ input: process.stdin });
const replies = input[Symbol.asyncIterator]();
const root = resolve(process.argv[2]);
const keychain = resolve(root, 'lab-consumer.keychain-db');
const secondKeychain = resolve(root, 'lab-other.keychain-db');
const cases = [], handles = [], pids = [];
async function ctl(op, options = {}) {
  process.stdout.write(JSON.stringify({ fixture: { op, keychain, ...options } }) + '\n');
  const next = await replies.next(); assert.equal(next.done, false);
  const value = JSON.parse(next.value); assert.equal(value.status, 0, JSON.stringify(value)); return value;
}
const options = (account, create = false, extra = {}) => ({ path: resolve(root, `${account}.db`), scope: { service: 'test', account, device: 'one' }, keychain, create, ...extra });
async function open(account, create = false, extra = {}) { const d = await PersistentDevice.open(options(account, create, extra)); handles.push(d); pids.push(d.runtime.pid); return d; }
async function denied(fn, code) { await assert.rejects(fn, e => e instanceof SdkError && (Array.isArray(code) ? code.includes(e.code) : e.code === code)); }
async function pass(name, fn) { await fn(); cases.push({ name, status: 'PASS' }); process.stdout.write(JSON.stringify({ progress: cases }) + '\n'); }
const fixtureOptions = o => ({ database: o.path, scope: o.scope });
async function provision(account) { await ctl('provision', fixtureOptions(options(account))); return open(account); }
try {
  await mkdir(root, { recursive: true });
  await ctl('create'); await ctl('create', { keychain: secondKeychain });
  let a = await open('alice', true), b = await open('bob', true, { keychain: secondKeychain });
  const c = await open('charlie', true); const ci = (await c.initialize('init')).value.identity;
  const ai = (await a.initialize('init')).value.identity, bi = (await b.initialize('init')).value.identity;
  const bm = await b.joiningMaterial();
  const group = await a.createGroup('create', 'chat', bi, bm.key_package);
  await b.joinGroup('join', 'chat', ai, group.value.welcome);
  async function exchange(prefix) {
    const sent = await a.send(`${prefix}-send`, `${prefix}-a`, `protected plaintext ${prefix} Alice`);
    assert.equal((await b.receive(`${prefix}-rx`, sent.value.envelope)).value.message.text, `protected plaintext ${prefix} Alice`);
    const reply = await b.send(`${prefix}-reply`, `${prefix}-b`, `protected plaintext ${prefix} Bob`);
    assert.equal((await a.receive(`${prefix}-back`, reply.value.envelope)).value.message.text, `protected plaintext ${prefix} Bob`);
  }
  await pass('protected_bidirectional', () => exchange('initial'));
  await pass('capacity_same_scope_read_only_and_lifecycle', async () => {
    const before = await a.state(), bytes = await readFile(options('alice').path);
    let count = 0; const cancel = a.subscribe(() => count++);
    const first = await a.capacity(), second = await a.capacity();
    assert.equal(first.version, 'sdk-capacity-alpha2'); assert.deepEqual(first.scope, before.scope);
    assert.equal(first.revision, before.revision); assert.notEqual(first.observation_id, second.observation_id);
    assert.deepEqual({...first,observation_id:''}, {...second,observation_id:''});
    assert.equal(first.reserve.protected_remaining, null); assert.equal(first.reserve.ordinary_available, null);
    assert.deepEqual(await a.state(), before); assert.deepEqual(await readFile(options('alice').path), bytes);
    assert.notDeepEqual((await b.capacity()).scope, first.scope); assert.equal(count, 0); cancel();
    for (const invalid of [null, false, 'scope', [], {account:'other'}, {signal:null}, {signal:{}}, {signal:new AbortController().signal,extra:true}]) {
      await denied(() => a.capacity(invalid), 'invalid_options');
    }
    assert.deepEqual(await a.state(), before); assert.deepEqual(await readFile(options('alice').path), bytes);
    const abort = new AbortController(); abort.abort(); await denied(() => a.capacity({signal:abort.signal}), 'cancelled');
    const closingDevice = await open('capacity_close', true);
    const pending = closingDevice.capacity(); const closing = closingDevice.close();
    await denied(() => pending, 'closed'); await closing; await denied(() => closingDevice.capacity(), 'closed');
  });
  await pass('actual_lock_existing_and_new_instance', async () => {
    let events = 0; a.subscribe(() => events++);
    await ctl('lock');
    for (const fn of [() => a.capacity(), () => a.state(), () => a.send('blocked', 'blocked', 'must not save'), () => a.message('bob', 'one', 'initial-b'), () => a.joiningMaterial(), () => a.recovery({ kind: 'status' })]) await denied(fn, 'keychain_locked');
    await denied(() => open('alice'), 'keychain_locked'); assert.equal(events, 0);
    await b.state();
    await ctl('unlock'); assert.equal((await a.request('blocked')).status, 'missing');
    await exchange('unlock');
  });
  await pass('close_restart_preserves_identity_history_and_exact_result', async () => {
    await a.close(); await b.close(); a = await open('alice'); b = await open('bob', false, { keychain: secondKeychain });
    assert.deepEqual((await a.state()).identity, ai); assert.deepEqual((await b.state()).identity, bi);
    assert.equal((await a.message('bob', 'one', 'initial-b')).text, 'protected plaintext initial Bob');
    assert.equal((await a.send('initial-send', 'initial-a', 'protected plaintext initial Alice')).cached, true);
    await exchange('restart');
  });
  await pass('wrong_scope_service_device_keychain_and_path', async () => {
    for (const key of ['service', 'account', 'device']) await denied(() => PersistentDevice.open({ ...options('alice'), scope: { ...options('alice').scope, [key]: 'wrong' } }), 'keychain_item_missing');
    await denied(() => open('alice', false, { keychain: secondKeychain }), 'keychain_item_missing');
    await copyFile(options('alice').path, resolve(root, 'copy.db'));
    await denied(() => open('alice', false, { path: resolve(root, 'copy.db') }), 'keychain_item_missing');
  });
  await pass('bounded_access_lock_and_missing_live_keychain', async () => {
    await ctl('hold_access', fixtureOptions(options('alice')));
    const before = Date.now(); await denied(() => a.state(), 'protection_busy'); assert.ok(Date.now() - before < 3000);
    await ctl('release_access', fixtureOptions(options('alice'))); await a.state();
    await rename(keychain, `${keychain}.unavailable`);
    try { await denied(() => a.state(), 'keychain_missing'); }
    finally { await rename(`${keychain}.unavailable`, keychain); }
    await a.state();
  });
  await pass('missing_key_refuses_active_and_reopen', async () => {
    const d = await open('missing', true); await d.initialize('init');
    await ctl('remove', fixtureOptions(options('missing')));
    await denied(() => d.state(), 'keychain_item_missing'); await denied(() => open('missing'), 'keychain_item_missing'); await d.close();
  });
  await pass('actual_acl_denial', async () => {
    const d = await provision('acl'); await d.initialize('init');
    await ctl('deny', fixtureOptions(options('acl')));
    await denied(() => d.state(), ['keychain_interaction_denied', 'keychain_auth_failed']);
    await denied(() => open('acl'), ['keychain_interaction_denied', 'keychain_auth_failed']); await d.close();
  });
  await pass('replacement_wrong_key_and_binding_refuse', async () => {
    for (const account of ['wrongkey', 'wrongbinding']) {
      const d = await provision(account); await d.initialize('init');
      await ctl('replace_random', { ...fixtureOptions(options(account)), wrongScope: account === 'wrongbinding' });
      await denied(() => d.state(), account === 'wrongkey' ? 'protection_key_replaced' : 'protection_binding_mismatch');
      await d.close();
      const before = await readFile(options(account).path);
      await denied(() => open(account), account === 'wrongkey' ? ['storage_failure', 'protected_store_invalid'] : 'protection_binding_mismatch');
      assert.deepEqual(await readFile(options(account).path), before);
    }
  });
  await pass('encrypted_page_tamper_refuses_without_rewrite', async () => {
    const d = await open('tamper', true); await d.initialize('init'); await d.close();
    const bytes = await readFile(options('tamper').path); assert.ok(bytes.length > 4200); bytes[4200] ^= 1;
    await writeFile(options('tamper').path, bytes);
    await denied(() => open('tamper'), 'protected_store_invalid');
    assert.deepEqual(await readFile(options('tamper').path), bytes);
  });
  await pass('unavailable_keychain_and_plaintext_refuse', async () => {
    await denied(() => open('alice', false, { keychain: resolve(root, 'lab-absent.keychain-db') }), 'keychain_missing');
    await ctl('plaintext', { database: resolve(root, 'legacy.db') });
    const before = await readFile(resolve(root, 'legacy.db'));
    await denied(() => open('legacy'), 'plaintext_migration_required');
    assert.deepEqual(await readFile(resolve(root, 'legacy.db')), before);
    await denied(() => open('alice', false, { upgrade: true }), 'plaintext_migration_required');
  });
  await pass('normal_runtime_ignores_fault_environment', async () => {
    process.env.ROCKET_IM_TEST_EXIT_PHASE = 'after_reserve';
    const d = await open('normal', true); await d.initialize('init'); await d.close(); delete process.env.ROCKET_IM_TEST_EXIT_PHASE;
    await ctl('normal_rejects_test_command', fixtureOptions(options('normal')));
  });
  await pass('interrupted_key_creation_never_regenerates', async () => {
    await ctl('orphan', fixtureOptions(options('orphan')));
    await denied(() => open('orphan'), 'store_missing');
    await denied(() => open('orphan', true), 'keychain_item_exists');
  });
  await pass('protected_pending_and_successor_recovery', async () => {
    // 父装置只负责真实进程中断；恢复与双方通信全部走当前安装包公开 API。
    for (const phase of ['after_reserve', 'after_crypto', 'after_candidate', 'after_commit', 'refuse_commit']) {
      const account = `fault_${phase}`;
      const t = await provision(account), p = await open(`${account}_peer`, true);
      await t.initialize('init'); await p.initialize('init');
      const tm = await t.joiningMaterial(), pm = await p.joiningMaterial();
      const welcome = (await t.createGroup('create', 'chat', pm.identity, pm.key_package)).value.welcome;
      await p.joinGroup('join', 'chat', tm.identity, welcome); await t.close();
      const action = { kind: 'send', message_id: 'target', text: `protected recovery ${phase}` };
      await ctl('fault', { ...fixtureOptions(options(account)), phase, action });
      const resumed = await open(account);
      if (phase === 'after_crypto') {
        await denied(() => resumed.recoverRequest('target', action), 'successor_required');
        await successor(resumed, p, { action });
        assert.equal((await resumed.request('target')).status, 'retired');
      } else {
        const outcome = await resumed.recoverRequest('target', action);
        assert.equal((await p.receive('receive-target', outcome.value.envelope)).value.message.text, action.text);
      }
      await resumed.close(); await p.close();
      const t2 = await open(account), p2 = await open(`${account}_peer`);
      assert.deepEqual((await t2.state()).identity, tm.identity);
      const f = await t2.send('after', 'after', 'after recovery protected'); await p2.receive('after', f.value.envelope);
      const r = await p2.send('reply', 'reply', 'reply recovery protected'); await t2.receive('reply', r.value.envelope);
      await t2.close(); await p2.close();
      await ctl('audit', fixtureOptions(options(account)));
    }
  });
  await pass('late_lock_committed_result_withheld', async () => {
    const t = await provision('late'), p = await open('late_peer', true);
    await t.initialize('init'); await p.initialize('init');
    const tm = await t.joiningMaterial(), pm = await p.joiningMaterial();
    const welcome = (await t.createGroup('create', 'chat', pm.identity, pm.key_package)).value.welcome;
    await p.joinGroup('join', 'chat', tm.identity, welcome);
    await ctl('late_lock', fixtureOptions(options('late')));
    // 测试程序已提交发送事务，结果交付前真实锁定，无成功响应。
    await ctl('unlock'); assert.deepEqual((await t.state()).identity, tm.identity);
    assert.equal((await t.request('late-send')).status, 'complete');
    const late = await t.send('late-send', 'late-message', 'late protected result'); assert.equal(late.cached, true);
    await p.receive('late-rx', late.value.envelope); await t.close(); await p.close();
  });
  await pass('capacity_after_read_lock_withholds_snapshot', async () => {
    const d = await provision('late_capacity'); await d.initialize('init');
    const before = await d.state();
    await ctl('late_capacity', fixtureOptions(options('late_capacity')));
    await denied(() => d.capacity(), 'keychain_locked'); await ctl('unlock');
    assert.deepEqual(await d.state(), before); await d.capacity(); await d.close();
  });
  await pass('logout_locked_failure_can_retry', async () => {
    const d = await open('logout_fail', true); await d.initialize('init'); await ctl('lock');
    await denied(() => d.logout(), 'keychain_locked'); await ctl('unlock');
    await PersistentDevice.logout(options('logout_fail')); await PersistentDevice.logout(options('logout_fail'));
    await denied(() => open('logout_fail'), 'logged_out');
  });
  await pass('logout_interrupted_before_and_after_tombstone', async () => {
    for (const phase of ['before_logout_replace', 'after_logout_replace']) {
      const account = `logout_${phase}`; const d = await provision(account); await d.initialize('init'); await d.close();
      await ctl('logout_fault', { ...fixtureOptions(options(account)), phase });
      await PersistentDevice.logout(options(account)); await PersistentDevice.logout(options(account));
      await denied(() => open(account), 'logged_out');
    }
  });
  await pass('logout_cancels_delivery_and_isolates_other_account', async () => {
    const same = await open('alice'); let events = 0; a.subscribe(() => events++);
    const pending = a.state(); const caught = pending.catch(e => e.code);
    const logout = a.logout(); await denied(() => a.state(), 'closed'); await logout; await a.logout();
    assert.equal(await caught, 'closed'); assert.equal(events, 0);
    await denied(() => same.state(), 'logged_out'); await same.close();
    await denied(() => open('alice'), 'logged_out');
    await PersistentDevice.logout(options('alice'));
    assert.deepEqual((await b.state()).identity, bi);
    assert.deepEqual((await c.state()).identity, ci);
    assert.equal((await b.message('alice', 'one', 'initial-a')).text, 'protected plaintext initial Alice');
    await b.close(); b = await open('bob', false, { keychain: secondKeychain }); await b.state();
    const ciphertext = await readFile(options('alice').path); assert.notEqual(ciphertext.subarray(0, 16).toString(), 'SQLite format 3\0');
  });
  process.stdout.write(JSON.stringify({ result: { status: 'PASS_SCOPED', cases, native_processes: pids } }) + '\n');
} catch (e) {
  process.stdout.write(JSON.stringify({ result: { status: 'FAIL', cases, error: String(e), stack: e.stack } }) + '\n'); process.exitCode = 1;
} finally {
  await Promise.allSettled(handles.map(h => h.close()));
  input.close(); process.stdin.pause();
}
