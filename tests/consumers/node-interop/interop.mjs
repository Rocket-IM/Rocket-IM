// 主线程仅启动和回收 Worker；SDK 导入、设备状态与同步调用全部留在 Worker。
import { Worker, isMainThread, parentPort, workerData, threadId } from "node:worker_threads";
import { release } from "node:os";

const runtime = { node: process.version, platform: process.platform, arch: process.arch, osRelease: release() };
const timeoutMilliseconds = 180000;

function runWorker(configuration) {
  return new Promise(resolve => {
    const worker = new Worker(new URL(import.meta.url), {
      workerData: configuration, env: {}, execArgv: [], stdout: true, stderr: true,
    });
    const expectedThreadId = worker.threadId;
    let result, error, finished = false;
    const failed = code => {
      error ??= code;
      void worker.terminate().catch(() => { error = "worker_termination_failed"; });
    };
    // 留出五秒回收时间；硬上限覆盖原生/WASM 阻塞导致 terminate 无法及时完成的情况。
    const timer = setTimeout(() => failed("worker_timeout"), timeoutMilliseconds - 5000);
    const hardTimer = setTimeout(() => {
      if (finished) return;
      finished = true;
      console.log(JSON.stringify({ status: "FAIL", runtime, error: "worker_reap_timeout",
        worker: { threadId: expectedThreadId, shutdown: false, exitCode: null } }));
      process.exit(1);
    }, timeoutMilliseconds);
    for (const stream of [worker.stdout, worker.stderr]) {
      stream.on("data", () => failed("unexpected_worker_output"));
    }
    worker.on("message", value => {
      if (result !== undefined) { failed("multiple_worker_results"); return; }
      result = value;
      if (value === null || typeof value !== "object" || value.status !== "PASS" || value.shutdown !== true ||
          value.threadId !== expectedThreadId || Object.keys(value).sort().join(",") !== "shutdown,status,threadId") {
        failed("worker_failed_or_invalid_result");
      }
    });
    worker.once("error", () => failed("worker_error"));
    worker.once("exit", exitCode => {
      if (finished) return;
      finished = true;
      clearTimeout(timer); clearTimeout(hardTimer);
      if (error === undefined && (exitCode !== 0 || result === undefined)) error = "worker_failed_or_missing_result";
      const shutdown = error === undefined && result?.shutdown === true;
      resolve({ status: shutdown ? "PASS" : "FAIL", runtime,
        worker: { threadId: expectedThreadId, exitCode, shutdown }, ...(error ? { error } : {}) });
    });
  });
}

if (isMainThread) {
  let result;
  try {
    if (process.platform !== "darwin") throw new Error("runtime_not_macos");
    result = await runWorker({ url: process.env.ROCKETS_INTEROP_URL,
      runId: process.env.ROCKETS_INTEROP_RUN_ID, endpointId: process.env.ROCKETS_INTEROP_ENDPOINT_ID });
  } catch { result = { status: "FAIL", runtime, error: "runtime_or_worker_start_failed" }; }
  console.log(JSON.stringify(result));
  if (result.status !== "PASS") process.exitCode = 1;
} else {
  if (parentPort === null) throw new Error("worker_port_missing");
  try {
    const { runInterop } = await import("./dist/interop.js");
    const result = await runInterop(workerData);
    if (result?.shutdown !== true) throw new Error("shutdown_not_confirmed");
    parentPort.postMessage({ status: "PASS", threadId, shutdown: true });
  } catch {
    parentPort.postMessage({ status: "FAIL", threadId, error: "worker_execution_failed" });
    process.exitCode = 1;
  } finally { parentPort.close(); }
}
