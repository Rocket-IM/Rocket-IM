import { PersistentDevice, SdkError } from '@rocket-im/desktop-dev';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { createInterface } from 'node:readline';

const [directory, keychain] = process.argv.slice(2), root = resolve(directory);
const lines = createInterface({ input: process.stdin })[Symbol.asyncIterator]();
async function fixture(op) {
  console.log(JSON.stringify({ fixture: { op, keychain } }));
  const line = await lines.next(); const result = JSON.parse(line.value);
  assert.equal(result.status, 0); return result;
}
const handles = [], pids = [], observations = [];
const options = (account, create = false, suffix = '') => ({ path: resolve(root, account + suffix + '.db'),
  scope: { service: 'test', account, device: 'one' }, keychain, create });
async function open(account, create = false, suffix = '') {
  const d = await PersistentDevice.open(options(account, create, suffix));
  handles.push(d); pids.push(d.runtime.pid); return d;
}
const query = (cursor = null, direction = 'forward', page_size = 3) => ({ cursor, direction, page_size });
const denied = (fn, code) => assert.rejects(fn, e => e instanceof SdkError && e.code === code);
async function walk(d, first) {
  let page = first; const items = [...page.items];
  for (let n = 0; !page.done && n < 256; n++) {
    page = await d.history(query(page.next_cursor, page.direction, page.page_size));
    assert.equal(page.upper_bound, first.upper_bound); items.push(...page.items);
  }
  assert.ok(page.done); assert.equal(page.next_cursor, null);
  assert.equal(items.length, Number(first.upper_bound));
  assert.equal(new Set(items.map(i => i.local_position)).size, items.length);
  return items;
}
let result;
try {
  let a = await open('alice', true), b = await open('bob', true);
  assert.deepEqual(await a.history(query()), { items: [], upper_bound: '0', direction: 'forward', page_size: 3, next_cursor: null, done: true });
  await a.initialize('init'); await b.initialize('init');
  const am = await a.joiningMaterial(), bm = await b.joiningMaterial();
  const group = await a.createGroup('create', 'chat', bm.identity, bm.key_package);
  await b.joinGroup('join', 'chat', am.identity, group.value.welcome);
  for (let n = 0; n < 6; n++) {
    const [from, to] = n % 2 ? [b, a] : [a, b];
    const sent = await from.send('s' + n, 'm' + n, 'message ' + n);
    await to.receive('r' + n, sent.value.envelope);
    assert.ok((await to.receive('dup' + n, sent.value.envelope)).cached);
  }
  const before = await a.state(), f = await a.history(query()), r = await a.history(query(null, 'backward', 2));
  assert.equal((await a.state()).revision, before.revision);
  const reader = await open('alice');
  const concurrent = await Promise.all([
    reader.history(query(f.next_cursor)), a.send('during-page', 'during-page', 'append during paging'),
  ]);
  assert.equal(concurrent[0].upper_bound, '6');
  await b.receive('during-page', concurrent[1].value.envelope);
  // 同一对象同时排队读取与接收，也必须保留已开始查询的上界。
  const incoming = await b.send('incoming', 'incoming', 'receive during paging');
  const overlap = await Promise.all([a.history(query(r.next_cursor, 'backward', 2)), a.receive('incoming', incoming.value.envelope)]);
  assert.equal(overlap[0].upper_bound, '6');
  await a.close(); a = await open('alice');
  const fixed = await walk(a, f);
  assert.deepEqual(fixed.map(i => i.message.message_id), ['m0','m1','m2','m3','m4','m5']);
  assert.deepEqual(await walk(a, r), [...fixed].reverse());
  observations.push({ case: 'concurrent_send_receive_restart', fixed_count: 6, fresh_count: (await walk(a, await a.history(query()))).length });
  await denied(() => b.history(query(f.next_cursor)), 'history_cursor_mismatch');
  const other = await open('alice', true, '-other'); await other.initialize('init');
  await denied(() => other.history(query(f.next_cursor)), 'history_cursor_mismatch');
  for (const q of [query(f.next_cursor, 'backward'), query(f.next_cursor, 'forward', 2), query(f.next_cursor.slice(0, -1) + (f.next_cursor.endsWith('0') ? '1' : '0'))])
    await denied(() => a.history(q), 'history_cursor_mismatch');
  for (const q of [query(''), query('h2:6:3:invalid'), query('h1:6:3:' + 'g'.repeat(64))])
    await denied(() => a.history(q), 'history_cursor_invalid');
  for (const n of [0,65]) await denied(() => a.history(query(null, 'forward', n)), 'history_page_size_invalid');
  for (const q of [null, {}, query(null, 'sideways'), query(null, 'forward', -1), query(null, 'forward', 1.5),
    query(null, 'forward', NaN), { ...query(), extra: true }, query(123)])
    await denied(() => a.history(q), 'invalid_request');
  const aborted = new AbortController(); aborted.abort();
  await denied(() => a.history(query(), { signal: aborted.signal }), 'cancelled');
  observations.push({ case: 'scope_space_cursor_parameters_cancel', status: 'PASS' });
  for (let n = 0; n < 5; n++) await a.send('control' + n, 'control' + n, '\0'.repeat(32768));
  const large = await a.history(query(null, 'backward', 64));
  assert.ok(!large.done && large.items.length < 64 && large.items.length > 0);
  const allLarge = await walk(a, large); assert.equal(allLarge.length, 13);
  observations.push({ case: 'escaped_body_short_pages', first_count: large.items.length, all_count: allLarge.length });
  await fixture('lock');
  await denied(() => a.history(query()), 'keychain_locked');
  await denied(() => reader.history(query(f.next_cursor)), 'keychain_locked');
  await fixture('unlock'); assert.deepEqual(await walk(a, f), fixed);
  observations.push({ case: 'real_keychain_lock_unlock_same_cursor', status: 'PASS' });
  // 自然积累到开发上限，不写测试快照，也不扩容/淘汰。
  for (let n = 13; n < 256; n++) await a.send('limit' + n, 'limit' + n, 'bounded ' + n);
  await denied(() => a.send('overflow', 'overflow', 'refuse capacity'), 'message_limit');
  assert.equal((await walk(a, await a.history(query(null, 'forward', 64)))).length, 256);
  assert.deepEqual(await walk(a, f), fixed);
  observations.push({ case: 'natural_256_limit_history_retained', status: 'PASS' });
  const closing = await open('alice');
  const late = closing.history(query()); const rejection = denied(() => late, 'closed');
  await closing.close(); await rejection;
  const lateLogout = a.history(query()); const logoutRejection = denied(() => lateLogout, 'closed');
  await a.logout(); await logoutRejection;
  await denied(() => a.history(query()), 'closed');
  await denied(() => reader.history(query(f.next_cursor)), 'logged_out');
  await denied(() => PersistentDevice.open(options('alice')), 'logged_out');
  assert.equal((await walk(b, await b.history(query()))).length, 8);
  observations.push({ case: 'close_logout_late_result_other_account', status: 'PASS' });
  result = { status: 'PASS_SCOPED', observations };
} finally {
  await Promise.allSettled(handles.map(d => d.close()));
  process.stdin.destroy();
}
for (const pid of pids) assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
console.log(JSON.stringify({ result: { ...result, native_processes: pids } }));
