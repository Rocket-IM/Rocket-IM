// 便携消费验证的文件核对与进程收尾；不依赖项目源码、Python、Rust 或既有 npm cache。
import fs from "node:fs/promises";
import path from "node:path";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { release } from "node:os";

const MAX_FILES = 10000;
const MAX_BYTES = 512 * 1024 * 1024;
const HASH = /^[0-9a-f]{64}$/;

export function fail(code, message = code) {
  const error = new Error(message); error.code = code; throw error;
}
export function requireValue(value, code, message) { if (!value) fail(code, message); }
export function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
export function checkedRelative(value) {
  requireValue(typeof value === "string" && value.length > 0 && value.length <= 1024
    && !/[\\:\x00-\x1f]/.test(value) && !path.posix.isAbsolute(value), "invalid_manifest_path");
  const parts = value.split("/");
  requireValue(parts.every(part => part !== "" && part !== "." && part !== ".." && !/[. ]$/.test(part)
    && !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part)), "invalid_manifest_path");
  return value;
}
export async function plainPath(value, kind = "file") {
  const stat = await fs.lstat(value);
  requireValue(!stat.isSymbolicLink() && (kind === "directory" ? stat.isDirectory() : stat.isFile()), "invalid_file_type");
  return stat;
}
export async function resolveInput(root, relative) {
  const parts = checkedRelative(relative).split("/");
  await plainPath(root, "directory");
  let current = root;
  for (let index = 0; index < parts.length; index++) {
    current = path.join(current, parts[index]);
    await plainPath(current, index === parts.length - 1 ? "file" : "directory");
  }
  return current;
}
async function digest(file, algorithm, encoding = "hex") {
  const stat = await plainPath(file);
  requireValue(stat.size <= MAX_BYTES, "file_limit");
  const input = await fs.open(file, "r");
  try {
    const hash = createHash(algorithm), buffer = Buffer.alloc(65536); let total = 0;
    for (;;) {
      const { bytesRead } = await input.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      total += bytesRead; requireValue(total <= MAX_BYTES, "file_limit");
      hash.update(buffer.subarray(0, bytesRead));
    }
    const after = await input.stat();
    requireValue(total === stat.size && after.size === stat.size && after.mtimeMs === stat.mtimeMs, "file_changed");
    return hash.digest(encoding);
  } finally { await input.close(); }
}
export const sha = file => digest(file, "sha256");
export async function verifyIntegrity(file, integrity) {
  requireValue(typeof integrity === "string" && /^sha512-[A-Za-z0-9+/]{86}==$/.test(integrity), "invalid_compiler_integrity");
  requireValue("sha512-" + await digest(file, "sha512", "base64") === integrity, "compiler_integrity_mismatch");
}
export async function readJson(file, maxBytes = 4 * 1024 * 1024) {
  const stat = await plainPath(file);
  requireValue(stat.size <= maxBytes, "json_limit");
  return JSON.parse(await fs.readFile(file, "utf8"));
}
export async function writeJson(file, value) {
  await fs.writeFile(file, JSON.stringify(value, null, 2) + "\n", { mode: 0o600 });
}
export function validateHashes(value) {
  requireValue(plainObject(value), "invalid_hash_manifest");
  const entries = Object.entries(value);
  requireValue(entries.length > 0 && entries.length <= MAX_FILES, "hash_manifest_limit");
  const names = new Set();
  for (const [key, hash] of entries) {
    checkedRelative(key); const folded = key.toLowerCase();
    requireValue(!names.has(folded) && typeof hash === "string" && HASH.test(hash), "invalid_hash_manifest");
    names.add(folded);
  }
  return value;
}
export function equalHashes(actual, expected) {
  validateHashes(expected);
  const keys = Object.keys(actual).sort(), required = Object.keys(expected).sort();
  return keys.length === required.length && keys.every((key, index) => key === required[index] && actual[key] === expected[key]);
}
export async function fileHashes(root, excludeRoot = []) {
  await plainPath(root, "directory");
  const result = Object.create(null); let count = 0, bytes = 0;
  async function walk(directory, prefix, depth) {
    requireValue(depth <= 32, "directory_limit");
    for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
      if (!prefix && excludeRoot.includes(entry.name)) continue;
      const relative = prefix ? prefix + "/" + entry.name : entry.name;
      checkedRelative(relative); const full = path.join(directory, entry.name), stat = await fs.lstat(full);
      requireValue(!stat.isSymbolicLink(), "symbolic_link_rejected");
      if (stat.isDirectory()) await walk(full, relative, depth + 1);
      else {
        requireValue(stat.isFile(), "invalid_file_type");
        count++; bytes += stat.size;
        requireValue(count <= MAX_FILES && bytes <= MAX_BYTES, "directory_limit");
        result[relative] = await sha(full);
      }
    }
  }
  await walk(root, "", 0); validateHashes(result); return result;
}
export async function findNpmCli(override) {
  const directory = path.dirname(process.execPath);
  const candidates = override === undefined ? [
    path.join(directory, "node_modules/npm/bin/npm-cli.js"),
    path.resolve(directory, "../lib/node_modules/npm/bin/npm-cli.js"),
  ] : [override];
  if (override !== undefined) requireValue(path.isAbsolute(override), "npm_cli_absolute_path_required");
  for (const candidate of candidates) {
    try {
      // npm 的标准安装可能使用上级路径链接；固定真实 JS 文件后用当前 Node 启动，绝不执行 cmd/shell。
      const resolved = await fs.realpath(candidate);
      await plainPath(resolved);
      requireValue(path.basename(resolved) === "npm-cli.js", "invalid_npm_cli");
      return resolved;
    } catch (error) {
      if (error.code !== "ENOENT" && error.code !== "ENOTDIR") throw error;
    }
  }
  fail("npm_cli_missing", "找不到 npm-cli.js；请通过 --npm-cli 提供现有 npm 的绝对路径。");
}
export function runtimeInfo() {
  return { node: process.version, platform: process.platform, arch: process.arch, osRelease: release(), execPath: process.execPath };
}

export async function command(args, cwd, logfile, { timeoutMs = 60000, env = {}, required = true } = {}) {
  requireValue(Array.isArray(args) && args.every(value => typeof value === "string") && args.length > 0
    && timeoutMs >= 1 && timeoutMs <= 300000, "invalid_command");
  const output = await fs.open(logfile, "wx", 0o600);
  const environment = { ...process.env };
  delete environment.NODE_OPTIONS; delete environment.NODE_PATH;
  for (const key of Object.keys(environment)) if (key.toLowerCase().startsWith("npm_config_")) delete environment[key];
  Object.assign(environment, env);
  const started = Date.now();
  let child, timedOut = false, reaped = false, exitCode = null, signal = null, spawnError = null;
  let timer, forceTimer, reapTimer; const termination = [];
  try {
    child = spawn(args[0], args.slice(1), { cwd, env: environment, shell: false, windowsHide: true,
      stdio: ["ignore", output.fd, output.fd] });
    await new Promise(resolve => {
      child.once("error", error => { spawnError = error.message; });
      child.once("close", (code, reason) => { reaped = true; exitCode = code; signal = reason; resolve(); });
      const stop = requestedSignal => {
        try { termination.push({ signal: requestedSignal, accepted: child.kill(requestedSignal) }); }
        catch (error) { termination.push({ signal: requestedSignal, accepted: false, error: error.message }); }
      };
      timer = setTimeout(() => {
        timedOut = true;
        stop("SIGTERM");
        forceTimer = setTimeout(() => {
          stop("SIGKILL");
          reapTimer = setTimeout(() => {
            // 回收失败必须明确失败；不能让验证装置无限等待或把 kill 请求当成已退出。
            child.unref(); resolve();
          }, 2000);
        }, 2000);
      }, timeoutMs);
    });
  } finally {
    clearTimeout(timer); clearTimeout(forceTimer); clearTimeout(reapTimer); await output.close();
  }
  const result = { command: args, exit_code: exitCode, signal, timed_out: timedOut, reaped,
    duration_ms: Date.now() - started, termination, log: logfile, log_sha256: await sha(logfile), ...(spawnError ? { spawn_error: spawnError } : {}) };
  if (required && (spawnError || timedOut || !reaped || exitCode !== 0)) {
    const error = new Error("命令失败：" + path.basename(logfile)); error.code = "command_failed"; error.execution = result; throw error;
  }
  return result;
}
export async function consumerResult(logfile) {
  const stat = await plainPath(logfile); requireValue(stat.size <= 1024 * 1024, "consumer_result_limit");
  const lines = (await fs.readFile(logfile, "utf8")).split(/\r?\n/).filter(line => line.trim() !== "");
  requireValue(lines.length > 0, "consumer_result_missing");
  const value = JSON.parse(lines.at(-1));
  requireValue(plainObject(value) && ["PASS", "FAIL"].includes(value.status) && Array.isArray(value.checks)
    && value.checks.every(check => typeof check === "string") && new Set(value.checks).size === value.checks.length,
  "invalid_consumer_result");
  return value;
}
export function validateSuccess(result, execution, runtime, checks, version) {
  requireValue(result.status === "PASS" && execution.exit_code === 0 && !execution.timed_out && execution.reaped,
    "consumer_failed");
  requireValue(Array.isArray(result.workers) && result.workers.length === 2, "worker_result_missing");
  for (const [index, worker] of result.workers.entries()) {
    requireValue(plainObject(worker) && worker.status === "PASS" && worker.workerId === ["worker_a", "worker_b"][index]
      && worker.exitCode === 0 && worker.version === version && JSON.stringify(worker.checks) === JSON.stringify(checks),
    "worker_checks_mismatch");
    requireValue(Array.isArray(worker.identityKey) && worker.identityKey.length === 32
      && worker.identityKey.every(value => Number.isInteger(value) && value >= 0 && value <= 255), "worker_identity_invalid");
  }
  requireValue(JSON.stringify(result.workers[0].identityKey) !== JSON.stringify(result.workers[1].identityKey), "worker_identity_not_isolated");
  const expected = ["worker_a", "worker_b"].flatMap(id => checks.map(check => id + ":" + check));
  expected.push("independent_worker_identity", "two_workers_normal_exit");
  requireValue(JSON.stringify(result.checks) === JSON.stringify(expected), "consumer_checks_mismatch");
  requireValue(plainObject(result.runtime) && ["node", "platform", "arch", "osRelease"].every(key => result.runtime[key] === runtime[key]),
    "consumer_runtime_mismatch");
}
export async function validatePackage(installed, sdk) {
  const actual = await fileHashes(installed);
  requireValue(equalHashes(actual, sdk.package_files_sha256), "installed_package_hash_mismatch");
  const packageJson = await readJson(path.join(installed, "package.json"));
  requireValue(packageJson.name === sdk.name && packageJson.version === sdk.version && packageJson.private === true
    && packageJson.license === "UNLICENSED", "installed_package_identity_mismatch");
  requireValue(!["preinstall", "install", "postinstall", "prepare"].some(name => Object.hasOwn(packageJson.scripts ?? {}, name)),
    "installed_package_scripts_rejected");
  const artifact = await readJson(path.join(installed, "artifact.json"));
  requireValue(artifact.version === sdk.version && artifact.binding_target === "nodejs", "installed_artifact_mismatch");
  const { "artifact.json": _artifact, ...contents } = actual;
  requireValue(equalHashes(contents, artifact.files_sha256), "installed_artifact_hash_mismatch");
  return actual;
}
