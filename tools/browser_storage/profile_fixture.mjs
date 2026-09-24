// 只离线复制本轮专用 Chrome profile；调用方必须先完整关闭 Chrome context。
import fs from "node:fs/promises";
import { constants } from "node:fs";
import path from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const OUTPUT = path.resolve(process.env.ROCKET_IM_BROWSER_STORAGE_OUTPUT ?? path.join(ROOT, "dist/browser-storage"));
const RUNS = path.join(OUTPUT, "runs");
const MAX_FILES = 100000;
const MAX_BYTES = 4 * 1024 * 1024 * 1024;
function ensure(ok, message) { if (!ok) throw new Error("profile_fixture: " + message); }
function validName(value) { ensure(typeof value === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(value), "备份名称无效。"); return value; }
function digest(value) { return createHash("sha256").update(value).digest("hex"); }
function summary(inventory) {
  return { files: inventory.files.length, directories: inventory.directories.length, bytes: inventory.bytes,
    digest: digest(JSON.stringify({ directories: inventory.directories, files: inventory.files })),
    ignoredSingletons: inventory.ignoredSingletons };
}
async function plainDirectory(directory) {
  const stat = await fs.lstat(directory);
  ensure(stat.isDirectory() && !stat.isSymbolicLink(), "目录不是普通目录。");
  ensure(await fs.realpath(directory) === directory, "目录或上级路径包含符号链接。");
}
async function fileDigest(file) {
  const handle = await fs.open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat(); ensure(before.isFile() && before.size <= MAX_BYTES, "文件类型或大小不适用。");
    const hash = createHash("sha256"); const buffer = Buffer.alloc(64 * 1024); let bytes = 0;
    while (true) {
      const result = await handle.read(buffer, 0, buffer.length, null); if (result.bytesRead === 0) break;
      bytes += result.bytesRead; ensure(bytes <= MAX_BYTES, "文件超过实验容量上限。"); hash.update(buffer.subarray(0, result.bytesRead));
    }
    const after = await handle.stat();
    ensure(bytes === before.size && before.size === after.size && before.mtimeMs === after.mtimeMs, "复制期间文件发生变化，Chrome 必须先关闭。");
    return { bytes, mode: before.mode & 0o777, sha256: hash.digest("hex") };
  } finally { await handle.close(); }
}
async function inventory(directory) {
  await plainDirectory(directory);
  const result = { files: [], directories: [], ignoredSingletons: [], bytes: 0 };
  async function walk(relative, depth) {
    ensure(depth <= 32, "目录层数超过实验上限。");
    const current = path.join(directory, relative); await plainDirectory(current);
    const stat = await fs.lstat(current); result.directories.push({ path: relative, mode: stat.mode & 0o777 });
    ensure(result.directories.length <= MAX_FILES, "目录数量超过实验上限。");
    const entries = await fs.readdir(current, { withFileTypes: true }); entries.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
    for (const entry of entries) {
      const name = relative ? relative + "/" + entry.name : entry.name;
      const file = path.join(directory, name); const type = await fs.lstat(file);
      if (type.isSymbolicLink()) {
        ensure(relative === "" && /^Singleton[A-Za-z0-9_-]*$/.test(entry.name), "发现非 Singleton 符号链接，拒绝跟随或复制。");
        result.ignoredSingletons.push({ path: name, target: await fs.readlink(file) }); continue;
      }
      if (type.isDirectory()) { await walk(name, depth + 1); continue; }
      ensure(type.isFile(), "发现特殊文件，拒绝复制。");
      const info = await fileDigest(file); result.bytes += info.bytes; result.files.push({ path: name, ...info });
      ensure(result.files.length <= MAX_FILES && result.directories.length <= MAX_FILES && result.bytes <= MAX_BYTES, "profile 超过实验容量上限。");
    }
  }
  await walk("", 0); return result;
}
async function copyInventory(source, destination, manifest) {
  await fs.mkdir(destination, { mode: 0o700 });
  for (const entry of manifest.directories) {
    if (entry.path) await fs.mkdir(path.join(destination, entry.path), { mode: 0o700 });
  }
  for (const entry of manifest.files) {
    const input = path.join(source, entry.path); const output = path.join(destination, entry.path);
    // 输入重新核对且不跟随链接，输出使用排他新建；不会复制运行期 Singleton 链接。
    const from = await fs.open(input, constants.O_RDONLY | constants.O_NOFOLLOW);
    let to;
    try {
      to = await fs.open(output, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      const stat = await from.stat(); ensure(stat.isFile() && stat.size === entry.bytes, "备份源已经改变。");
      const buffer = Buffer.alloc(64 * 1024); let total = 0;
      while (true) {
        const { bytesRead } = await from.read(buffer, 0, buffer.length, null); if (!bytesRead) break;
        total += bytesRead; ensure(total <= entry.bytes, "备份源在复制时增长。");
        let offset = 0;
        while (offset < bytesRead) { const written = await to.write(buffer, offset, bytesRead - offset, null); ensure(written.bytesWritten > 0, "写入未推进。"); offset += written.bytesWritten; }
      }
      ensure(total === entry.bytes, "备份源在复制时缩短。"); await to.chmod(entry.mode);
    } finally { await from.close(); if (to) await to.close(); }
  }
  // 子目录完成后再恢复权限，避免只读目录妨碍复制。
  for (const entry of [...manifest.directories].reverse()) await fs.chmod(path.join(destination, entry.path), entry.mode);
}

export class ProfileFixture {
  constructor(output) {
    this.output = path.resolve(output);
    const outputRelative = path.relative(path.join(ROOT, "dist"), OUTPUT);
    ensure(outputRelative && !outputRelative.startsWith("..") && !path.isAbsolute(outputRelative), "验证输出必须位于本项目 dist 的独立子目录。");
    const relative = path.relative(RUNS, this.output);
    ensure(relative && !relative.startsWith("..") && !path.isAbsolute(relative) && !relative.includes(path.sep), "只允许本项目 runs 下的专用验证目录。");
    this.profile = path.join(this.output, "profile"); this.backups = path.join(this.output, "profile-backups");
    this.evidence = { scope: "closed dedicated Chrome profile only", backups: [], restores: [], clones: [] }; this.busy = false;
  }
  async run(body) {
    ensure(!this.busy, "备份和恢复不能并发。"); this.busy = true;
    try {
      await plainDirectory(this.output);
      await fs.mkdir(this.backups, { mode: 0o700 }).catch(error => { if (error.code !== "EEXIST") throw error; });
      await plainDirectory(this.backups); return await body();
    } finally { this.busy = false; }
  }
  async backup(value) {
    const name = validName(value);
    return this.run(async () => {
      const destination = path.join(this.backups, name); await fs.mkdir(destination, { mode: 0o700 });
      const source = await inventory(this.profile); const expected = summary(source);
      const data = path.join(destination, "profile"); await copyInventory(this.profile, data, source);
      const copied = summary(await inventory(data)); const sourceAfter = summary(await inventory(this.profile));
      ensure(copied.digest === expected.digest && sourceAfter.digest === expected.digest, "备份前后文件摘要不一致。");
      const manifest = { format: 1, name, ...expected, entries: source };
      const bytes = JSON.stringify(manifest, null, 2) + "\n";
      await fs.writeFile(path.join(destination, "manifest.json"), bytes, { mode: 0o600, flag: "wx" });
      const evidence = { name, path: destination, ...expected, manifestSha256: digest(bytes) };
      this.evidence.backups.push(evidence); return evidence;
    });
  }
  async verifiedBackup(name) {
    const backup = path.join(this.backups, name); await plainDirectory(backup);
    const manifestFile = path.join(backup, "manifest.json"); const stat = await fs.lstat(manifestFile);
    ensure(stat.isFile() && !stat.isSymbolicLink() && stat.size <= 32 * 1024 * 1024, "备份清单无效。");
    const raw = await fs.readFile(manifestFile); const manifest = JSON.parse(raw.toString("utf8"));
    ensure(manifest.format === 1 && manifest.name === name, "备份格式或名称不符。");
    const recorded = this.evidence.backups.find(item => item.name === name);
    ensure(recorded && digest(raw) === recorded.manifestSha256, "清单与本次控制器创建的备份记录不一致。");
    const data = path.join(backup, "profile"); const verified = await inventory(data); const expected = summary(verified);
    ensure(expected.digest === manifest.digest && expected.files === manifest.files && expected.bytes === manifest.bytes
      && expected.directories === manifest.directories && JSON.stringify(verified.files) === JSON.stringify(manifest.entries?.files)
      && JSON.stringify(verified.directories) === JSON.stringify(manifest.entries?.directories), "备份全部文件未通过清单摘要核验。");
    ensure(verified.ignoredSingletons.length === 0, "备份中不应包含符号链接。");
    return { data, verified, expected, raw };
  }
  async clone(value, cloneValue) {
    const name = validName(value); const cloneName = validName(cloneValue);
    return this.run(async () => {
      const { data, verified, expected, raw } = await this.verifiedBackup(name);
      const parent = path.join(this.output, "profile-clones");
      await fs.mkdir(parent, { mode: 0o700 }).catch(error => { if (error.code !== "EEXIST") throw error; });
      await plainDirectory(parent);
      const destination = path.join(parent, cloneName); await copyInventory(data, destination, verified);
      const copied = summary(await inventory(destination)); ensure(copied.digest === expected.digest, "克隆副本摘要不符。");
      const evidence = { name, cloneName, path: destination, ...copied, manifestSha256: digest(raw), verifiedBeforeCopy: true, verifiedAfterCopy: true };
      this.evidence.clones.push(evidence); return evidence;
    });
  }
  async restore(value) {
    const name = validName(value);
    return this.run(async () => {
      const { data, verified, expected, raw } = await this.verifiedBackup(name);
      await inventory(this.profile); // 拒绝把符号链接或意外目录当作可替换 profile。
      const suffix = randomUUID(); const staging = path.join(this.output, "profile-restore-" + suffix);
      const previous = path.join(this.output, "profile-previous-" + suffix);
      await copyInventory(data, staging, verified);
      ensure(summary(await inventory(staging)).digest === expected.digest, "恢复副本摘要不符。");
      await fs.rename(this.profile, previous);
      try {
        await fs.rename(staging, this.profile);
        const restored = summary(await inventory(this.profile)); ensure(restored.digest === expected.digest, "替换后 profile 摘要不符。");
        await fs.rm(previous, { recursive: true });
        const evidence = { name, ...restored, manifestSha256: digest(raw), verifiedBeforeReplace: true, verifiedAfterReplace: true };
        this.evidence.restores.push(evidence); return evidence;
      } catch (error) {
        // 出错保留原目录供根检查，避免用第二次删除掩盖原始失败。
        error.message += "; 原 profile 保存在 " + previous; throw error;
      }
    });
  }
}
