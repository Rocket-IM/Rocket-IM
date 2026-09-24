// 独立 Node 消费装置：密码 API 仅在 Worker 内同步调用，主线程负责有界等待和运行证据。
import { Worker, isMainThread, parentPort, workerData } from "node:worker_threads";
import { release } from "node:os";

const WORKER_IDS = ["worker_a", "worker_b"];
const TIMEOUT_MS = 30000;
const message = error => error instanceof Error ? error.message : String(error);

async function runWorker(workerId) {
  const worker = new Worker(new URL(import.meta.url), { workerData: { workerId } });
  return new Promise((resolve, reject) => {
    let result, failure, timedOut = false;
    const timer = setTimeout(async () => {
      timedOut = true;
      try { await worker.terminate(); } catch (error) { failure = error; }
      reject(new Error(workerId + ": worker_timeout" + (failure ? ": " + message(failure) : "")));
    }, TIMEOUT_MS);
    worker.on("message", value => {
      if (result !== undefined) { failure = new Error("multiple_worker_results"); return; }
      result = value;
    });
    worker.once("error", error => { failure = error; });
    worker.once("exit", exitCode => {
      clearTimeout(timer);
      if (timedOut) return;
      const valid = result !== null && typeof result === "object" && result.workerId === workerId;
      if (failure || exitCode !== 0 || !valid || result.status !== "PASS") {
        reject(new Error(workerId + ": " + (failure ? message(failure) : valid && typeof result.error === "string"
          ? result.error : "worker_failed_or_missing_result: exit=" + exitCode)));
        return;
      }
      if (!Array.isArray(result.checks) || result.checks.length === 0
          || result.checks.some(value => typeof value !== "string")
          || new Set(result.checks).size !== result.checks.length
          || result.version !== "0.1.0-stage0.1" || !Array.isArray(result.identityKey)
          || result.identityKey.length !== 32 || result.identityKey.some(value => !Number.isInteger(value) || value < 0 || value > 255)) {
        reject(new Error(workerId + ": invalid_worker_result")); return;
      }
      resolve({ ...result, exitCode });
    });
  });
}

if (isMainThread) {
  const runtime = { node: process.version, platform: process.platform, arch: process.arch, osRelease: release() };
  const settled = await Promise.allSettled(WORKER_IDS.map(runWorker));
  const workers = settled.filter(item => item.status === "fulfilled").map(item => item.value);
  const errors = settled.filter(item => item.status === "rejected").map(item => message(item.reason));
  const checks = workers.flatMap(worker => worker.checks.map(check => worker.workerId + ":" + check));
  if (errors.length === 0 && workers.length === 2) {
    if (workers[0].identityKey.join(",") === workers[1].identityKey.join(",")) errors.push("worker_identity_not_isolated");
    else checks.push("independent_worker_identity");
    checks.push("two_workers_normal_exit");
  }
  const status = errors.length ? "FAIL" : "PASS";
  console.log(JSON.stringify({ status, checks, workers, runtime, ...(errors.length ? { error: errors.join("; ") } : {}) }));
  if (errors.length) process.exitCode = 1;
} else {
  if (parentPort === null) throw new Error("missing_worker_port");
  try {
    const { runConsumer } = await import("./dist/consumer.js");
    const result = await runConsumer();
    parentPort.postMessage({ ...result, workerId: workerData.workerId });
  } catch (error) {
    parentPort.postMessage({ status: "FAIL", checks: [], workerId: workerData.workerId, error: message(error) });
    process.exitCode = 1;
  } finally { parentPort.close(); }
}
