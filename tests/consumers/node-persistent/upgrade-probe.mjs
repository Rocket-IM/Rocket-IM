// 仅消费安装包公开入口；拒绝时不调用初始化或恢复，不自行打开数据库。
import { PersistentDevice } from '@rocket-im/desktop-dev';
import { readFile } from 'node:fs/promises';
let device;
try {
  device = await PersistentDevice.open(JSON.parse(await readFile(process.argv[2], 'utf8')));
  console.log(JSON.stringify({ ok: true, networkRecovery: typeof device.networkRecovery === 'function' }));
} catch (error) {
  console.log(JSON.stringify({ ok: false, code: error.code ?? 'unknown' }));
} finally {
  if (device) await device.close();
}
