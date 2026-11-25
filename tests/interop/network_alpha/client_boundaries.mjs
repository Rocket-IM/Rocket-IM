// 使用已安装实际包验证已连接实例的取消/超时/关闭；只操作本测试拥有的SDK进程。
import { PersistentDevice, SdkError } from '@rocket-im/desktop-dev';
import assert from 'node:assert/strict';
const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
const opened = [];
const cancelled = code => e => e instanceof SdkError && e.code === code;
let count = 0;
async function open(extra = {}) {
  const device = await PersistentDevice.open({ ...input.open, ...extra, onListenerError: () => { throw new Error('listener_failure'); } });
  opened.push(device); return device;
}
try {
  let device = await open(); const identity = (await device.state()).identity;
  await device.connect(input.connect);
  const first = await device.history({ direction: 'forward', page_size: 2 });
  const off = device.subscribe(() => { count++; });
  const c = new AbortController();
  const pending = device.networkState({ signal: c.signal }); c.abort();
  await assert.rejects(pending, cancelled('cancelled_unknown'));
  const afterCancel = count; await device.close(); off(); assert.equal(count, afterCancel);
  assert.throws(() => process.kill(device.runtime.pid, 0), { code: 'ESRCH' });
  device = await open({ timeoutMs: 1000 });
  assert.deepEqual((await device.state()).identity, identity);
  const continued = first.done ? first : await device.history({ direction: 'forward', page_size: 2, cursor: first.next_cursor });
  assert.equal(continued.upper_bound, first.upper_bound);
  await device.connect(input.connect);
  process.kill(device.runtime.pid, 'SIGSTOP');
  await assert.rejects(device.state(), cancelled('request_timeout_unknown'));
  await device.close(); assert.throws(() => process.kill(device.runtime.pid, 0), { code: 'ESRCH' });
  device = await open(); await device.connect(input.connect);
  const inFlight = device.history({ direction: 'backward', page_size: 2 });
  const draining = device.close();
  await assert.rejects(inFlight, cancelled('closed')); await draining; await device.close();
  await assert.rejects(device.state(), cancelled('closed'));
  assert.throws(() => process.kill(device.runtime.pid, 0), { code: 'ESRCH' });
  console.log(JSON.stringify({ status: 'PASS', connected_cancel: true, connected_timeout: true, connected_close: true, identity_and_cursor_continuity: true, reaped: true }));
} finally { await Promise.allSettled(opened.map(d => d.close())); }
