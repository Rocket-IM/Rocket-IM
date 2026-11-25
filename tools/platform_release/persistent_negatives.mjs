// 仅在独立副本中破坏打包材料；平台分支模拟不是 Windows 运行验收。
import { cp, mkdir, readFile, writeFile, unlink } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import assert from 'node:assert/strict';
const [source, faultBinary, directory, keychain] = process.argv.slice(2);
await mkdir(directory, { recursive: true });
const cases = [];
for (const [name, code] of [
  ['missing-binary', 'artifact_binary_missing'], ['wrong-version', 'artifact_version_mismatch'],
  ['wrong-hash', 'artifact_hash_mismatch'], ['wrong-target', 'artifact_platform_mismatch'],
  ['test-runtime-refused', 'ipc_protocol_error'], ['unsupported-platform-guard-only', 'unsupported_platform']
]) {
  const root = resolve(directory, name); await cp(source, root, { recursive: true });
  const binary = resolve(root, 'bin/darwin-arm64/rocket-im-desktop-runtime');
  const manifestPath = resolve(root, 'artifact.json');
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  if (name === 'missing-binary') await unlink(binary);
  if (name === 'wrong-version') manifest.version = '999.0.0';
  if (name === 'wrong-hash') manifest.binarySha256 = '0'.repeat(64);
  if (name === 'wrong-target') manifest.target = 'win32-x64';
  if (name === 'test-runtime-refused') { await cp(faultBinary, binary); manifest.binarySha256 = createHash('sha256').update(await readFile(binary)).digest('hex'); }
  await writeFile(manifestPath, JSON.stringify(manifest));
  const url = pathToFileURL(resolve(root, 'dist/index.js')).href;
  const program = `
    import assert from 'node:assert/strict';
    ${name === 'unsupported-platform-guard-only' ? "Object.defineProperty(process, 'platform', {value:'win32'});" : ''}
    const {PersistentDevice}=await import(${JSON.stringify(url)});
    await assert.rejects(()=>PersistentDevice.open({path:${JSON.stringify(resolve(root,'test.db'))},scope:{service:'test',account:'a',device:'one'},keychain:${JSON.stringify(keychain)},create:true}), e=>e.code===${JSON.stringify(code)});
  `;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', program], { encoding: 'utf8', timeout: 15000 });
  assert.equal(result.status, 0, `${name}: ${result.stderr}`);
  cases.push({ name, status: 'PASS', error: code });
}
console.log(JSON.stringify({ status: 'PASS_SCOPED', cases, windows_runtime: 'NOT_TESTED' }));
