// 仓库外实际包消费；导入和读取都走公开SDK，不读取数据库/钥匙串内容。
import { PersistentDevice } from '@rocket-im/desktop-dev';
let input = '';
for await (const chunk of process.stdin) input += chunk;
try {
  const request = JSON.parse(input);
  let result;
  if (request.mode === 'open') {
    const device = await PersistentDevice.open(request.options);
    try { result = await device.state(); } finally { await device.close(); }
  } else {
    result = await PersistentDevice.restoreBackup(request.options, request.backup);
  }
  process.stdout.write(JSON.stringify({ok: true, result}) + '\n');
} catch (error) {
  process.stdout.write(JSON.stringify({ok: false, code: error.code ?? 'test_probe_failure'}) + '\n');
}
