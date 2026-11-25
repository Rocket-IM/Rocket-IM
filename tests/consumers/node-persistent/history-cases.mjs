// 新旧真实 TGZ 共用的公开 API 消费。无 SQL、密钥读取或身份重建。
import { PersistentDevice } from '@rocket-im/desktop-dev';
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const [mode, directory, keychain] = process.argv.slice(2);
const root = resolve(directory), handles = [], pids = [];
async function open(account) {
  const device = await PersistentDevice.open({ path: resolve(root, account + '.db'),
    scope: { service: 'test', account, device: 'one' }, keychain });
  handles.push(device); pids.push(device.runtime.pid); return device;
}
const query = (direction, cursor = null) => ({ direction, page_size: 1, cursor });
async function rest(device, first) {
  const items = [...first.items]; let page = first;
  for (let n = 0; !page.done && n < 256; n++) {
    const q = query(page.direction, page.next_cursor);
    page = await device.history(q);
    assert.deepEqual(page, await device.history(q), 'replaying cursor is deterministic');
    assert.equal(page.upper_bound, first.upper_bound);
    items.push(...page.items);
  }
  assert.ok(page.done); assert.equal(page.next_cursor, null);
  assert.equal(items.length, Number(first.upper_bound));
  assert.equal(new Set(items.map(i => i.local_position)).size, items.length);
  return items;
}
let observations = [];
try {
  const a = await open('alice'), b = await open('bob');
  if (mode === 'old-append') {
    const sent = await a.send('old-again-send', 'old-again-a', 'old package after new history');
    await b.receive('old-again-rx', sent.value.envelope);
    const reply = await b.send('old-again-reply', 'old-again-b', 'old package reply');
    await a.receive('old-again-back', reply.value.envelope);
  } else {
    const states = [await a.state(), await b.state()];
    const saved = mode === 'capture' ? null : JSON.parse(await readFile(resolve(root, 'history.json'), 'utf8'));
    const request = await a.request('target');
    const original = JSON.parse(await readFile(resolve(root, 'snapshot.json'), 'utf8'));
    const snapshots = [];
    for (const [n, device] of [a, b].entries()) {
      assert.deepEqual(states[n].identity, original[n === 0 ? 'alice' : 'bob'].identity);
      const forward = await device.history(query('forward'));
      const backward = await device.history(query('backward'));
      const items = await rest(device, forward);
      assert.deepEqual(await rest(device, backward), [...items].reverse());
      assert.deepEqual(items.map(i => i.local_position), items.map((_, i) => String(i + 1)));
      assert.deepEqual(items.slice(0, 2).map(i => i.message.message_id), ['old-a', 'old-b']);
      for (const item of items) {
        const m = item.message;
        assert.deepEqual(await device.message(m.sender_account, m.sender_device, m.message_id), m);
      }
      const target = items.filter(i => i.message.message_id === 'target');
      // 候选/未决/退役不能冒充已提交消息；after_commit 和精确恢复只出现一次。
      assert.equal(target.length, request.status === 'complete' && (n === 0 || mode !== 'capture') ? 1 : 0);
      assert.equal(items.length, (mode === 'capture' ? 2 : mode === 'after-old-writes' ? 6 : 4) + target.length);
      if (saved) {
        assert.deepEqual(states[n].identity, saved[n].identity);
        assert.deepEqual(items.slice(0, saved[n].items.length), saved[n].items);
        assert.deepEqual(await rest(device, saved[n].forward), saved[n].items);
        assert.deepEqual(await rest(device, saved[n].backward), [...saved[n].items].reverse());
      }
      snapshots.push({ identity: states[n].identity, forward, backward, items });
      observations.push({ account: states[n].scope.account, count: items.length,
        ids: items.map(i => i.message.message_id), request: request.status, upper: forward.upper_bound });
    }
    if (mode === 'capture') await writeFile(resolve(root, 'history.json'), JSON.stringify(snapshots), { mode: 0o600 });
  }
} finally { await Promise.allSettled(handles.map(d => d.close())); }
for (const pid of pids) assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
console.log(JSON.stringify({ status: 'PASS', mode, observations, native_processes: pids }));
