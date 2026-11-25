// 只通过已安装的公开 SDK 操作两个持久端。夹具交换密文，不代表 Service 网络或送达。
import { PersistentDevice } from '@rocket-im/desktop-dev';
import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
const root = resolve(process.env.ROCKET_EXAMPLE_DATA ?? `./示例数据/${randomUUID()}`);
const scope = account => ({ service: 'test-service', account, device: 'device-1' });
const options = (account, create) => ({ path: resolve(root, `${account}.db`), scope: scope(account), keychain: process.env.ROCKET_EXAMPLE_KEYCHAIN, create });
async function phase(name) {
  const creating = name === 'setup';
  const a = await PersistentDevice.open(options('alice', creating));
  let b;
  try {
    b = await PersistentDevice.open(options('bob', creating));
    if (creating) {
      await a.initialize('init-a'); await b.initialize('init-b');
      const [alice, bob] = await Promise.all([a.joiningMaterial(), b.joiningMaterial()]);
      // 两个直接创建的测试端是本夹具的身份来源；固定准确公钥后再使用公开加入材料。
      // 实际业务接入需要独立身份核验流程，不能照搬此夹具建立生产信任。
      const pins = { alice: alice.identity, bob: bob.identity };
      await writeFile(resolve(root, 'test-pins.json'), JSON.stringify(pins), { flag: 'wx', mode: 0o600 });
      assert.deepEqual(bob.identity, pins.bob);
      const created = await a.createGroup('create', 'chat', pins.bob, bob.key_package);
      await b.joinGroup('join', 'chat', pins.alice, created.value.welcome);
    } else {
      const pins = JSON.parse(await readFile(resolve(root, 'test-pins.json'), 'utf8'));
      assert.deepEqual((await a.state()).identity, pins.alice);
      assert.deepEqual((await b.state()).identity, pins.bob);
      assert.equal((await b.message('alice', 'device-1', 'setup-a')).text, 'Alice setup');
      const old = await a.send('setup-send-a', 'setup-a', 'Alice setup');
      assert.equal(old.cached, true);
      assert.equal((await b.receive('setup-rx-a', old.value.envelope)).cached, true);
    }
    const eventQueries = [];
    const unsubscribe = b.subscribe(change => { eventQueries.push(b.state().then(s => assert.ok(BigInt(s.revision) >= BigInt(change.revision)))); });
    const sent = await a.send(`${name}-send-a`, `${name}-a`, `Alice ${name}`);
    const received = await b.receive(`${name}-rx-a`, sent.value.envelope);
    assert.equal(received.value.message.text, `Alice ${name}`);
    const reply = await b.send(`${name}-send-b`, `${name}-b`, `Bob ${name}`);
    assert.equal((await a.receive(`${name}-rx-b`, reply.value.envelope)).value.message.text, `Bob ${name}`);
    await Promise.all(eventQueries); unsubscribe();
    return { phase: name, alice: await a.state(), bob: await b.state(), processes: [a.runtime.pid, b.runtime.pid] };
  } finally { await Promise.allSettled([a.close(), b?.close()]); }
}
if (process.argv[2] === '--phase') {
  console.log(JSON.stringify(await phase(process.argv[3])));
} else {
  await mkdir(root, { recursive: true, mode: 0o700 });
  process.env.ROCKET_EXAMPLE_DATA = root;
  const results = [];
  for (const step of ['setup', 'resume']) {
    const result = spawnSync(process.execPath, [fileURLToPath(import.meta.url), '--phase', step], { encoding: 'utf8', timeout: 30000, env: process.env });
    if (result.status !== 0) throw new Error(`phase ${step}: ${result.stderr || result.error}`);
    results.push(JSON.parse(result.stdout));
  }
  assert.notEqual(results[0].processes[0], results[1].processes[0]);
  for (const pid of results.flatMap(r => r.processes)) assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
  console.log(JSON.stringify({ status: 'PASS_SCOPED', data_directory: root, phases: results, exchange: 'test-program ciphertext transfer' }));
}
