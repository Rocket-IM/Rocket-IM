// 独立消费进程只使用安装后的公开SDK；不执行SQL、不传递对端密文或实现同步。
import { PersistentDevice } from '@rocket-im/desktop-dev';
import { readFile } from 'node:fs/promises';
import readline from 'node:readline';
const options = JSON.parse(await readFile(process.argv[2], 'utf8'));
const device = await PersistentDevice.open(options);
const changes = [];
let authentication;
let closed = false;
device.subscribe(change => { changes.push(change); });
const output = value => process.stdout.write(JSON.stringify(value) + '\n');
output({ ready: true, runtime: device.runtime });
for await (const line of readline.createInterface({ input: process.stdin })) {
  let request;
  try {
    request = JSON.parse(line);
    let result;
    switch (request.op) {
      case 'initialize': result = await device.initialize('init'); break;
      case 'material': result = await device.joiningMaterial(); break;
      case 'connect': result = await device.connect(request.options); break;
      case 'authSetup': {
        const { createProvider } = await import('./renewal-provider.mjs');
        authentication = await createProvider(request.config); result = null; break;
      }
      case 'authFault': authentication.fault(request.mode, request.count); result = null; break;
      case 'authStats': result = authentication.stats(); break;
      case 'authRelease': authentication.release(); result = null; break;
      case 'authExpired': result = await authentication.expiredProbe(request.endpoint); break;
      case 'authScan': result = await authentication.scan(request.paths); break;
      case 'autoConnect': result = await device.connect({ ...request.options, credentialProvider: authentication.provider }); break;
      case 'concurrentConnect': {
        const options = { ...request.options, credentialProvider: authentication.provider };
        result = await Promise.all([device.connect(options), device.connect(options), device.connect(options)].map(p => p.then(v => ({ ok: true, connection: v.connection }), e => ({ ok: false, code: e.code })))); break;
      }
      case 'concurrentSend': result = await Promise.all(request.messages.map(m => device.send(m.requestId, m.messageId, m.text))); break;
      case 'cancelInFlight': {
        const c = new AbortController(); const p = device.networkState({ signal: c.signal }); c.abort();
        result = await p; break;
      }
      case 'disconnect': result = await device.disconnect(); break;
      case 'network': result = await device.networkState(); break;
      case 'networkRecovery': result = await device.networkRecovery(request.command); break;
      case 'networkUnavailable': result = await device.networkUnavailable(request.sequence); break;
      case 'recovery': result = await device.recovery(request.command); break;
      case 'recoverRequest': result = await device.recoverRequest(request.requestId, request.action); break;
      case 'state': result = await device.state(); break;
      case 'backup': result = await device.createBackup(request.path); break;
      case 'restoreBackup': result = await PersistentDevice.restoreBackup(request.options ?? options, request.path); break;
      case 'send': result = await device.send(request.requestId, request.messageId, request.text); break;
      case 'history': result = await device.history(request.query ?? { direction: 'forward', page_size: 3 }); break;
      case 'request': result = await device.request(request.requestId); break;
      case 'message': result = await device.message(request.account, request.device, request.messageId); break;
      case 'events': result = changes.splice(0); break;
      case 'cancel': {
        const c = new AbortController(); c.abort();
        result = await device.send('cancelled', 'cancelled', 'unused', { signal: c.signal }); break;
      }
      case 'close': result = await device.close(); output({ id: request.id, ok: true, result: null }); process.exit(0); break;
      case 'closeKeep': await device.close(); closed = true; result = null; break;
      case 'logoutKeep': await device.logout(); closed = true; result = null; break;
      case 'alive': {
        let alive = true; try { process.kill(device.runtime.pid, 0); } catch { alive = false; }
        result = { alive, closed }; break;
      }
      default: throw new Error('unknown_test_command');
    }
    output({ id: request.id, ok: true, result });
  } catch (error) { output({ id: request?.id, ok: false, code: error.code ?? 'test_worker_failure' }); }
}
await device.close();
