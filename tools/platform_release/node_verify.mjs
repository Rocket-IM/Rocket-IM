// 同一冻结 TGZ 的离线消费验收；报告只描述本机实测，不重新宣称仓库源码验收。
import fs from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { checkedRelative, command, consumerResult, equalHashes, fail, fileHashes, findNpmCli,
  plainObject, plainPath, readJson, requireValue, resolveInput, runtimeInfo, sha, validateHashes,
  validatePackage, validateSuccess, verifyIntegrity, writeJson } from "./node_verify_support.mjs";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const CONSUMER = ["consumer.ts", "package-lock.json", "package.json", "run.mjs", "tsconfig.json"];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const WASM = "dist/generated/rocket_stage0_wasm_bg.wasm";
const now = () => new Date().toISOString();

function options() {
  const result = { rehearsal: false }; const args = process.argv.slice(2);
  for (let index = 0; index < args.length; index++) {
    if (args[index] === "--rehearsal" && !result.rehearsal) result.rehearsal = true;
    else if (args[index] === "--npm-cli" && result.npmCli === undefined && index + 1 < args.length) {
      result.npmCli = args[++index]; requireValue(path.isAbsolute(result.npmCli), "npm_cli_absolute_path_required");
    } else fail("invalid_arguments", "用法：node node_verify.mjs [--rehearsal] [--npm-cli 绝对路径]");
  }
  return result;
}

function validateManifest(value) {
  requireValue(plainObject(value) && value.schema_version === 1 && UUID.test(value.bundle_id)
    && value.target_os === "win32", "invalid_manifest");
  const { sdk, typescript: compiler, provenance } = value;
  requireValue(plainObject(sdk) && sdk.name === "@rocket-im/stage0-node" && sdk.version === "0.1.0-stage0.1"
    && plainObject(compiler) && compiler.version === "5.9.3", "invalid_package_contract");
  for (const item of [sdk, compiler]) {
    checkedRelative(item.archive); validateHashes({ [item.archive]: item.sha256 });
  }
  validateHashes(sdk.package_files_sha256); validateHashes(value.bundle_files_sha256);
  validateHashes(value.consumer_files_sha256);
  requireValue(Object.keys(sdk.package_files_sha256).length === 573, "sdk_file_count_mismatch");
  requireValue(value.consumer_directory === "consumer"
    && JSON.stringify(Object.keys(value.consumer_files_sha256).sort()) === JSON.stringify(CONSUMER), "invalid_consumer_files");
  requireValue(Array.isArray(value.worker_checks) && value.worker_checks.length === 51
    && value.worker_checks.every(check => typeof check === "string" && /^[a-z0-9_]+$/.test(check))
    && new Set(value.worker_checks).size === 51, "invalid_worker_checks");
  requireValue(!Object.keys(value.bundle_files_sha256).some(name => name === "manifest.json" || name.split("/")[0] === "runs"),
    "invalid_bundle_files");
  requireValue(plainObject(provenance) && UUID.test(provenance.sdk_pack_run_id) && UUID.test(provenance.sdk_verify_run_id)
    && provenance.sdk_archive_sha256 === sdk.sha256, "invalid_provenance");
  validateHashes(provenance.consumer_source_sha256);
  for (const name of CONSUMER) {
    requireValue(provenance.consumer_source_sha256["tests/consumers/node/" + name] === value.consumer_files_sha256[name]
      && value.bundle_files_sha256["consumer/" + name] === value.consumer_files_sha256[name], "consumer_provenance_mismatch");
  }
  for (const required of ["node_verify.mjs", "node_verify_support.mjs", sdk.archive, compiler.archive]) {
    requireValue(Object.hasOwn(value.bundle_files_sha256, required), "bundle_file_missing");
  }
  return value;
}

async function verifyInputs(report) {
  const manifestPath = await resolveInput(ROOT, "manifest.json");
  report.manifest_sha256 = await sha(manifestPath);
  const manifest = validateManifest(await readJson(manifestPath));
  report.bundle_id = manifest.bundle_id; report.provenance = manifest.provenance;
  const actual = await fileHashes(ROOT, ["manifest.json", "runs"]);
  requireValue(equalHashes(actual, manifest.bundle_files_sha256), "bundle_hash_mismatch");
  const sdk = await resolveInput(ROOT, manifest.sdk.archive), compiler = await resolveInput(ROOT, manifest.typescript.archive);
  report.sdk_archive_sha256 = await sha(sdk); report.compiler_archive_sha256 = await sha(compiler);
  requireValue(report.sdk_archive_sha256 === manifest.sdk.sha256, "sdk_archive_hash_mismatch");
  requireValue(report.compiler_archive_sha256 === manifest.typescript.sha256, "compiler_archive_hash_mismatch");
  await verifyIntegrity(compiler, manifest.typescript.integrity);
  report.compiler_integrity = manifest.typescript.integrity; report.bundle_files_sha256 = actual;
  const lock = await readJson(await resolveInput(ROOT, "consumer/package-lock.json"));
  const dependency = lock.packages?.["node_modules/typescript"];
  requireValue(dependency?.version === manifest.typescript.version && dependency.integrity === manifest.typescript.integrity,
    "compiler_lock_mismatch");
  return { manifest, sdk, compiler, manifestPath };
}

async function execute(report, run, name, args, cwd, opts = {}) {
  const execution = await command(args, cwd, path.join(run, name + ".log"), { ...opts, required: false });
  report.commands.push({ name, ...execution });
  if (opts.expectFailure !== true) requireValue(execution.exit_code === 0 && !execution.timed_out && execution.reaped
    && !execution.spawn_error, "command_failed", "命令失败：" + name);
  return execution;
}

async function consume(report, run, directory, name, manifest, expectedError) {
  const execution = await execute(report, run, name, [process.execPath, "run.mjs"], directory, { expectFailure: Boolean(expectedError) });
  const result = await consumerResult(execution.log);
  const record = { name, execution, result, status: "FAIL" }; report.cases.push(record);
  if (expectedError) {
    requireValue(execution.exit_code === 1 && !execution.timed_out && execution.reaped && result.status === "FAIL"
      && result.checks.length === 0 && Array.isArray(result.workers) && result.workers.length === 0
      && typeof result.error === "string" && result.error.includes(expectedError), "negative_case_failed", name);
    requireValue(plainObject(result.runtime) && ["node", "platform", "arch", "osRelease"]
      .every(key => result.runtime[key] === report.runtime[key]), "consumer_runtime_mismatch");
    record.expected_error = expectedError;
  } else validateSuccess(result, execution, report.runtime, manifest.worker_checks, manifest.sdk.version);
  record.status = "PASS";
}

async function install(report, run, inputs, npmCli) {
  const directory = path.join(run, "consumer space 中文"), cache = path.join(run, "empty npm cache");
  await fs.mkdir(directory); await fs.mkdir(cache);
  requireValue((await fs.readdir(cache)).length === 0, "cache_not_empty");
  report.install_directory = directory; report.npm_cache = { directory: cache, initially_empty: true };
  for (const name of CONSUMER) await fs.copyFile(await resolveInput(ROOT, "consumer/" + name), path.join(directory, name), fs.constants.COPYFILE_EXCL);
  report.consumer_sha256_before_install = await fileHashes(directory);
  requireValue(equalHashes(report.consumer_sha256_before_install, inputs.manifest.consumer_files_sha256), "copied_consumer_mismatch");
  const userConfig = path.join(run, "user.npmrc"), globalConfig = path.join(run, "global.npmrc");
  await fs.writeFile(userConfig, "", { flag: "wx" }); await fs.writeFile(globalConfig, "", { flag: "wx" });
  await execute(report, run, "offline_install", [process.execPath, npmCli, "install", "--offline", "--include=dev", "--ignore-scripts",
    "--no-audit", "--no-fund", "--save-exact", "--bin-links=false", inputs.sdk, inputs.compiler], directory,
  { timeoutMs: 120000, env: { npm_config_cache: cache, npm_config_userconfig: userConfig, npm_config_globalconfig: globalConfig,
    npm_config_update_notifier: "false" } });
  const modules = path.join(directory, "node_modules"), installed = path.join(modules, "@rocket-im/stage0-node");
  report.package_sha256 = await validatePackage(installed, inputs.manifest.sdk);
  report.installed_files_sha256 = await fileHashes(modules);
  const compiler = await readJson(await resolveInput(modules, "typescript/package.json"));
  requireValue(compiler.name === "typescript" && compiler.version === inputs.manifest.typescript.version, "installed_compiler_mismatch");
  const installedLock = await readJson(path.join(directory, "package-lock.json"));
  requireValue(installedLock.packages?.["node_modules/typescript"]?.integrity === inputs.manifest.typescript.integrity,
    "installed_compiler_integrity_mismatch");
  report.installed_lock_sha256 = await sha(path.join(directory, "package-lock.json"));
  await execute(report, run, "compile", [process.execPath, await resolveInput(modules, "typescript/bin/tsc"), "-p", "tsconfig.json"], directory);
  report.compiled_files_sha256 = await fileHashes(path.join(directory, "dist"));
  return { directory, modules, installed };
}

async function faults(report, run, installation, manifest) {
  const { directory, installed } = installation;
  await consume(report, run, directory, "public_api", manifest);
  const wasm = await resolveInput(installed, WASM), absent = wasm + ".absent-test";
  await fs.rename(wasm, absent);
  try { await consume(report, run, directory, "missing_wasm", manifest, "node_initialization_failed"); }
  finally { await fs.rename(absent, wasm); }
  const entry = await resolveInput(installed, "dist/index.js"), original = await fs.readFile(entry);
  const source = original.toString("utf8"), target = 'SDK_VERSION = "' + manifest.sdk.version + '"';
  requireValue(source.split(target).length === 2, "version_fixture_missing");
  try {
    await fs.writeFile(entry, source.replace(target, 'SDK_VERSION = "0.0.0-invalid"'));
    await consume(report, run, directory, "mismatched_version", manifest, "sdk_version_mismatch");
  } finally { await fs.writeFile(entry, original); }
  report.package_sha256_after_restore = await validatePackage(installed, manifest.sdk);
  report.package_restored = equalHashes(report.package_sha256_after_restore, report.package_sha256);
  requireValue(report.package_restored, "package_restore_failed");
  await consume(report, run, directory, "restored_public_api", manifest);
  const execution = await execute(report, run, "harness_timeout", [process.execPath, "-e", "setInterval(() => {}, 1000)"], directory,
    { expectFailure: true, timeoutMs: 1000 });
  const record = { name: "harness_timeout", execution, scope: "test harness process termination; not SDK operation cancellation", status: "FAIL" };
  report.cases.push(record);
  requireValue(execution.timed_out && execution.reaped && execution.exit_code !== 0 && !execution.spawn_error, "timeout_cleanup_failed");
  record.status = "PASS";
}

async function start() {
  const runId = randomUUID(), report = { schema_version: 1, run_id: runId, status: "RUNNING", started_at: now(),
    windows_acceptance: "NOT_TESTED", runtime: runtimeInfo(), commands: [], cases: [],
    trust_boundary: "Bundle hashes detect changed inputs. They do not independently attest the host OS or reproduce repository source verification." };
  let run, reportPath, inputs, installation;
  try {
    await plainPath(ROOT, "directory");
    const runs = path.join(ROOT, "runs");
    try { await fs.mkdir(runs); } catch (error) { if (error.code !== "EEXIST") throw error; }
    await plainPath(runs, "directory"); run = path.join(runs, runId); await fs.mkdir(run);
    reportPath = path.join(run, "report.json"); await writeJson(reportPath, report);
    const opts = options(); report.mode = opts.rehearsal ? "rehearsal" : "windows_acceptance";
    inputs = await verifyInputs(report);
    if (!opts.rehearsal && process.platform !== "win32") {
      report.status = "NOT_TESTED"; report.reason = "windows_runtime_required";
    } else {
      const npmCli = await findNpmCli(opts.npmCli); report.npm_cli = { path: npmCli, sha256: await sha(npmCli) };
      const version = await execute(report, run, "npm_version", [process.execPath, npmCli, "--version"], run);
      report.runtime.npm = (await fs.readFile(version.log, "utf8")).trim();
      requireValue(/^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(report.runtime.npm), "invalid_npm_version");
      installation = await install(report, run, inputs, npmCli);
      await faults(report, run, installation, inputs.manifest);
      report.status = "PASS";
    }
  } catch (error) {
    report.status = "FAIL"; report.error = { code: typeof error.code === "string" ? error.code : "verification_failed", message: String(error.message ?? error) };
  } finally {
    try {
      if (inputs) {
        report.inputs_stable = await sha(inputs.manifestPath) === report.manifest_sha256
          && equalHashes(await fileHashes(ROOT, ["manifest.json", "runs"]), inputs.manifest.bundle_files_sha256);
        requireValue(report.inputs_stable, "bundle_changed_during_run");
      }
      if (installation) {
        report.installed_files_sha256_after_restore = await fileHashes(installation.modules);
        requireValue(equalHashes(report.installed_files_sha256_after_restore, report.installed_files_sha256), "installed_files_changed");
        report.package_restored = equalHashes(await validatePackage(installation.installed, inputs.manifest.sdk), report.package_sha256);
      }
    } catch (error) {
      report.status = "FAIL"; report.finalization_error = { code: error.code ?? "finalization_failed", message: String(error.message ?? error) };
    }
    report.windows_acceptance = report.status === "PASS" && report.mode === "windows_acceptance" && process.platform === "win32" ? "PASS" : "NOT_TESTED";
    report.finished_at = now();
    if (reportPath) {
      try { await writeJson(reportPath, report); }
      catch (error) { report.status = "FAIL"; report.windows_acceptance = "NOT_TESTED"; report.error = { code: "report_write_failed", message: String(error.message ?? error) }; }
    }
    console.log(JSON.stringify({ status: report.status, run_id: runId, report: reportPath ?? null,
      windows_acceptance: report.windows_acceptance, ...(report.reason ? { reason: report.reason } : {}),
      ...(report.error ? { error: report.error } : {}), ...(report.finalization_error ? { finalization_error: report.finalization_error } : {}) }));
    process.exitCode = report.status === "PASS" ? 0 : report.status === "NOT_TESTED" ? 2 : 1;
  }
}

await start();
