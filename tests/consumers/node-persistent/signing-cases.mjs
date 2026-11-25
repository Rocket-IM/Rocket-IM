// 只消费独立安装的真实 TGZ。数据库访问、身份和恢复均经公开 SDK。
import { PersistentDevice, SdkError } from '@rocket-im/desktop-dev';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { successor } from './recovery-support.mjs';

const [mode, directory, keychain, stage = 'none'] = process.argv.slice(2);
const root = resolve(directory), handles = [], pids = [];
const action = { kind: 'send', message_id: 'target', text: 'upgrade pending message' };
const options = (account, create = false) => ({ path: resolve(root, `${account}.db`),
  scope: { service: 'test', account, device: 'one' }, keychain, create });
async function open(account, create = false) {
  const d = await PersistentDevice.open(options(account, create));
  handles.push(d); pids.push(d.runtime.pid); return d;
}
async function exchange(a, b, prefix) {
  const sent = await a.send(`${prefix}-send`, `${prefix}-a`, `${prefix} Alice`);
  assert.equal((await b.receive(`${prefix}-rx`, sent.value.envelope)).value.message.text, `${prefix} Alice`);
  const reply = await b.send(`${prefix}-reply`, `${prefix}-b`, `${prefix} Bob`);
  assert.equal((await a.receive(`${prefix}-back`, reply.value.envelope)).value.message.text, `${prefix} Bob`);
}
async function snapshot(a, b) {
  return { alice: await a.state(), bob: await b.state(), request: await a.request('target'),
    recovery: [await a.recovery({ kind: 'status' }), await b.recovery({ kind: 'status' })],
    history: [await a.message('bob', 'one', 'old-b'), await b.message('alice', 'one', 'old-a')] };
}
const snapshotPath = resolve(root, 'snapshot.json');
const save = value => writeFile(snapshotPath, JSON.stringify(value), { mode: 0o600 });
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
let result;
try {
  if (mode === 'deny') {
    let code;
    await assert.rejects(() => open('alice'), error => {
      code = error.code;
      return error instanceof SdkError && stage.split(',').includes(code);
    });
    result = { status: 'PASS', mode, code };
  } else {
    await mkdir(root, { recursive: true });
    const a = await open('alice', mode === 'setup'), b = await open('bob', mode === 'setup');
    if (mode === 'setup') {
      await a.initialize('init'); await b.initialize('init');
      const am = await a.joiningMaterial(), bm = await b.joiningMaterial();
      const group = await a.createGroup('create', 'chat', bm.identity, bm.key_package);
      await b.joinGroup('join', 'chat', am.identity, group.value.welcome);
      await exchange(a, b, 'old'); await save(await snapshot(a, b));
    } else if (mode === 'prepare') {
      if (stage !== 'none') {
        const offer = await a.recovery({ kind: 'begin', request_id: 'target', action });
        if (stage !== 'offered') {
          const approval = await b.recovery({ kind: 'accept', offer: offer.packet, peer: (await a.state()).identity });
          if (stage !== 'prepared') {
            const ready = await a.recovery({ kind: 'join', approval: approval.packet });
            if (stage !== 'ready') {
              const receipt = await b.recovery({ kind: 'confirm', ready: ready.packet });
              if (stage === 'finished') await a.recovery({ kind: 'finish', receipt: receipt.packet });
            }
          }
        }
      }
      await save(await snapshot(a, b));
    } else {
      const original = JSON.parse(await readFile(snapshotPath, 'utf8'));
      const current = await snapshot(a, b);
      assert.deepEqual(current, original, 'upgrade must retain exact state, history, pending and recovery packets');
      if (mode === 'resume') {
        if (current.request.status === 'pending') {
          if (stage === 'successor') {
            await successor(a, b, { action });
            assert.equal((await a.request('target')).status, 'retired');
          } else {
            const outcome = await a.recoverRequest('target', action);
            assert.equal((await b.receive('target-rx', outcome.value.envelope)).value.message.text, action.text);
          }
        } else if (current.request.status === 'complete') {
          const outcome = await a.recoverRequest('target', action);
          assert.deepEqual(outcome.value, current.request.outcome.value);
          assert.equal((await b.receive('target-rx', outcome.value.envelope)).value.message.text, action.text);
        }
        assert.deepEqual((await a.state()).identity, original.alice.identity);
        assert.deepEqual((await b.state()).identity, original.bob.identity);
        assert.deepEqual((await snapshot(a, b)).history, original.history);
        await exchange(a, b, 'new'); await save(await snapshot(a, b));
      } else assert.equal(mode, 'verify');
      result = { status: 'PASS', mode, original_sha256: digest(original),
        observed_before_resume_sha256: digest(current), recovery_phases: current.recovery.map(x => x.phase),
        request_status: current.request.status, identity_history_packets_exact: true };
    }
    result ??= { status: 'PASS', mode, snapshot_sha256: digest(await snapshot(a, b)) };
  }
} finally {
  await Promise.allSettled(handles.map(h => h.close()));
}
for (const pid of pids) assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
console.log(JSON.stringify({ ...result, native_processes: pids }));
