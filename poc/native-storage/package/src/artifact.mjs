import { readFile, stat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
export const VERSION = '0.1.0-stage0.1';
export class StorageError extends Error {
  constructor(code, paused = false) { super(code); this.name = 'StorageError'; this.code = code; this.paused = paused; }
}
export async function artifact() {
  const target = `${process.platform}-${process.arch}`;
  if (target !== 'darwin-arm64') throw new StorageError('unsupported_platform');
  const root = new URL('../', import.meta.url);
  let manifest, packageInfo;
  try {
    [manifest, packageInfo] = await Promise.all(['artifact.json', 'package.json'].map(async name => JSON.parse(await readFile(new URL(name, root), 'utf8'))));
  } catch { throw new StorageError('artifact_missing_or_invalid'); }
  if (manifest.version !== VERSION || packageInfo.version !== VERSION || manifest.protocol !== 1 ||
      packageInfo.name !== '@rocket-im/stage0-desktop-storage') throw new StorageError('artifact_version_mismatch');
  if (manifest.target !== target) throw new StorageError('artifact_platform_mismatch');
  const relative = `bin/${target}/desktop_storage`;
  let bytes, info;
  const path = fileURLToPath(new URL(relative, root));
  try { [bytes, info] = await Promise.all([readFile(path), stat(path)]); }
  catch { throw new StorageError('artifact_binary_missing'); }
  if (!info.isFile() || !(info.mode & 0o111)) throw new StorageError('artifact_not_executable');
  if (createHash('sha256').update(bytes).digest('hex') !== manifest.binarySha256) throw new StorageError('artifact_hash_mismatch');
  return path;
}
