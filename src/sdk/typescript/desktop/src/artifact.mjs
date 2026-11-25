import { readFile, stat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
export const VERSION = '0.2.0-dev.12';
export class SdkError extends Error {
  constructor(code, paused = false) { super(code); this.name = 'SdkError'; this.code = code; this.paused = paused; }
}
export async function artifact() {
  const target = `${process.platform}-${process.arch}`;
  if (target !== 'darwin-arm64') throw new SdkError('unsupported_platform');
  const root = new URL('../', import.meta.url);
  let manifest, packageInfo;
  try {
    [manifest, packageInfo] = await Promise.all(['artifact.json', 'package.json'].map(async name => JSON.parse(await readFile(new URL(name, root), 'utf8'))));
  } catch { throw new SdkError('artifact_missing_or_invalid'); }
  if (manifest.version !== VERSION || packageInfo.version !== VERSION || manifest.protocol !== 3 ||
      packageInfo.name !== '@rocket-im/desktop-dev') throw new SdkError('artifact_version_mismatch');
  if (manifest.target !== target) throw new SdkError('artifact_platform_mismatch');
  const relative = `bin/${target}/rocket-im-desktop-runtime`;
  let bytes, info;
  const path = fileURLToPath(new URL(relative, root));
  try { [bytes, info] = await Promise.all([readFile(path), stat(path)]); }
  catch { throw new SdkError('artifact_binary_missing'); }
  if (!info.isFile() || !(info.mode & 0o111)) throw new SdkError('artifact_not_executable');
  if (createHash('sha256').update(bytes).digest('hex') !== manifest.binarySha256) throw new SdkError('artifact_hash_mismatch');
  return path;
}
