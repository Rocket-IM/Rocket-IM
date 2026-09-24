import assert from "node:assert/strict";
import { boundaryCases } from "./boundary_cases.mjs";

const open = (p, account, options = {}, slot = "a", service = "service") => p.evaluate(async args => {
  try { window.clients[args.slot] = await window.probe.open({ service: args.service, account: args.account, testMode: true, ...args.options }); }
  catch (error) { throw new Error(`${error.code}: ${error.message}; cause=${JSON.stringify(error.cause)}`); }
}, { account, options, slot, service });
const snapshot = (p, slot = "a") => p.evaluate(async slot => {
  try { return await window.clients[slot].snapshot(); }
  catch (error) { throw new Error(`${error.code}: ${error.message}; cause=${JSON.stringify(error.cause)}`); }
}, slot);
const put = (p, key, value, revision, test, slot = "a") => p.evaluate(async a => {
  try { return await window.clients[a.slot].put(a.key, a.value, a.revision, a.test); }
  catch (error) { throw new Error(`${error.code}: ${error.message}; cause=${JSON.stringify(error.cause)}`); }
}, { slot, key, value, revision, test });
const close = (p, slot = "a") => p.evaluate(slot => window.clients[slot].close(), slot);
const revision = (value, expected) => assert.equal(value.revision, String(expected));
const record = (value, key, expected) => assert.equal(value.records.find(r => r.key === key)?.value, expected);
async function rejects(fn, pattern) {
  try { await fn(); } catch (error) { if (pattern) assert.match(String(error), pattern); return String(error); }
  throw new Error("expected rejection, got success");
}
async function observe(p) {
  await p.evaluate(async () => {
    window.events = [];
    window.cancel = await window.clients.a.subscribe(event => window.events.push(event));
  });
}
async function reopen(p, account) {
  // 这里只重试明确的临时占用，既不吞掉其他存储错误，也不在生产门面自动重试。
  const failures = [];
  for (let i = 0; i < 80; i++) {
    try { await open(p, account); return { retries: i, last_temporary_error: failures.at(-1) }; }
    catch (error) {
      if (!String(error).match(/IN_USE|in_use|NoModificationAllowedError/)) throw error;
      failures.push(String(error));
      await new Promise(r => setTimeout(r, 50));
    }
  }
  throw new Error("old owner did not release within 80 retries: " + failures.at(-1));
}

export async function runCases(k) {
  let p = await k.page();
  await k.check("secure_worker_opfs_environment", async () => {
    const value = await p.evaluate(() => ({ secure: isSecureContext, worker: typeof Worker,
      locks: !!navigator.locks, opfs: typeof navigator.storage?.getDirectory, isolated: crossOriginIsolated }));
    assert.equal(value.secure, true); assert.equal(value.worker, "function");
    assert.equal(value.locks, true); assert.equal(value.opfs, "function"); assert.equal(value.isolated, false);
    return value;
  });
  await k.check("explicit_migration_empty_read_write_reopen", async () => {
    await open(p, "ordinary"); const empty = await snapshot(p);
    revision(empty, 0); assert.equal(empty.schemaVersion, 2); assert.deepEqual(empty.records, []);
    revision(await put(p, "hello", "persisted", "0"), 1);
    await close(p); await open(p, "ordinary"); const loaded = await snapshot(p);
    record(loaded, "hello", "persisted"); revision(loaded, 1); await close(p);
    return { sqliteVersion: loaded.sqliteVersion, schemaVersion: loaded.schemaVersion };
  });
  await k.check("same_scope_second_tab_rejected_and_takeover", async () => {
    const other = await k.page();
    try {
      await open(p, "single");
      const error = await rejects(() => open(other, "single"), /IN_USE|in_use/);
      await put(p, "owner", "first", "0"); await close(p);
      await open(other, "single"); record(await snapshot(other), "owner", "first"); await close(other);
      return { error };
    } finally { await other.close(); }
  });
  await k.check("service_and_account_spaces_isolated", async () => {
    await open(p, "userA"); await open(p, "userB", {}, "b"); await open(p, "userA", {}, "c", "secondService");
    await put(p, "data", "A", "0"); await put(p, "data", "B", "0", undefined, "b");
    assert.deepEqual((await snapshot(p, "c")).records, []);
    await close(p); record(await snapshot(p, "b"), "data", "B");
    await close(p, "b"); await close(p, "c");
  });
  await k.check("input_conflict_and_fault_gate", async () => {
    await open(p, "inputs", { testMode: false });
    await rejects(() => put(p, "../bad", "x", "0"));
    await rejects(() => put(p, "valid", "x", "9007199254740993"));
    await rejects(() => put(p, "valid", "x", "00"));
    await rejects(() => put(p, "valid", "x".repeat(4097), "0"));
    await rejects(() => put(p, "valid", "x", "0", { fault: "refuse_commit" }));
    revision(await snapshot(p), 0); await close(p);
  });
  await k.check("maximum_json_escaping_records_remain_readable", async () => {
    await open(p, "escaping");
    const written = await p.evaluate(async () => {
      let value = await window.clients.a.snapshot();
      for (let i = 0; i < 128; i++) value = await window.clients.a.put("key" + i, "\0".repeat(4096), value.revision);
      return { revision: value.revision, count: value.records.length };
    });
    assert.deepEqual(written, { revision: "128", count: 128 }); await close(p); await open(p, "escaping");
    const read = await p.evaluate(async () => {
      const value = await window.clients.a.snapshot();
      return { revision: value.revision, count: value.records.length,
        valid: value.records.every(r => r.value === "\0".repeat(4096)) };
    });
    assert.deepEqual(read, { revision: "128", count: 128, valid: true });
    await close(p); return read;
  });
  await k.check("subscription_handoff_and_reentrant_query", async () => {
    await open(p, "subscribe");
    const value = await p.evaluate(async () => {
      const observed = []; const queries = [];
      const subscription = window.clients.a.subscribe(event => {
        observed.push({ type: event.type, revision: event.snapshot.revision });
        queries.push(window.clients.a.snapshot());
      });
      const writing = window.clients.a.put("one", "1", "0");
      const cancel = await subscription; await writing;
      await window.clients.a.put("two", "2", "1");
      // 回调已经同步入队；snapshot作串行屏障，再等待回调中的查询。
      await window.clients.a.snapshot(); await Promise.all(queries);
      cancel(); await window.clients.a.put("three", "3", "2");
      return { observed, queried: queries.length };
    });
    assert.deepEqual(value.observed.map(x => x.revision), ["0", "1", "2"]);
    assert.equal(value.queried, 3); await close(p); return value;
  });
  await k.check("write_rollback_emits_no_success", async () => {
    await open(p, "rollback"); await observe(p);
    const error = await rejects(() => put(p, "bad", "uncommitted", "0", { fault: "write_then_rollback" }), /injected_rollback/);
    revision(await snapshot(p), 0);
    assert.deepEqual(await p.evaluate(() => window.events.map(e => e.type)), ["snapshot"]);
    revision(await put(p, "good", "ok", "0"), 1); await close(p);
    return { injection: "explicit rollback after SQL write", error };
  });
  await k.check("sqlite_commit_hook_refusal_pauses_and_recovers", async () => {
    await open(p, "commit"); await observe(p);
    const error = await rejects(() => put(p, "bad", "uncommitted", "0", { fault: "refuse_commit" }), /commit_failed/);
    assert.match(error, /"source":"sqlite"/);
    await rejects(() => snapshot(p), /storage_paused|PAUSED/);
    assert.deepEqual(await p.evaluate(() => window.events.map(e => e.type)), ["snapshot"]);
    await close(p); await open(p, "commit"); revision(await snapshot(p), 0); await close(p);
    return { injection: "SQLite commit hook returns refusal", error };
  });
  await k.check("migration_failure_rollback_then_upgrade", async () => {
    await open(p, "migration", { seedV1: true }); let value = await snapshot(p);
    assert.equal(value.schemaVersion, 1); record(value, "seed", "from-v1"); await close(p);
    const error = await rejects(() => open(p, "migration", { failMigration: true }), /migration_failed/);
    await open(p, "migration", { seedV1: true }); value = await snapshot(p);
    assert.equal(value.schemaVersion, 1); revision(value, 1); record(value, "seed", "from-v1"); await close(p);
    await open(p, "migration"); value = await snapshot(p);
    assert.equal(value.schemaVersion, 2); revision(value, 1); record(value, "seed", "from-v1"); await close(p);
    return { error };
  });
  await k.check("page_refresh_preserves_committed_rows", async () => {
    await open(p, "refresh"); await put(p, "row", "survived", "0");
    await p.reload(); await k.attach(p); await reopen(p, "refresh");
    record(await snapshot(p), "row", "survived"); await close(p);
  });
  await k.check("worker_termination_preserves_committed_rows", async () => {
    await open(p, "worker"); await put(p, "row", "survived", "0");
    await p.evaluate(() => window.clients.a.test.terminate());
    await reopen(p, "worker"); record(await snapshot(p), "row", "survived"); await close(p);
  });
  await k.check("tab_close_reopen_preserves_rows", async () => {
    await open(p, "tab"); await put(p, "row", "survived", "0"); await p.close();
    p = await k.page(); await reopen(p, "tab"); record(await snapshot(p), "row", "survived"); await close(p);
  });
  await k.check("browser_process_close_relaunch_same_origin_profile", async () => {
    await open(p, "browser"); await put(p, "row", "survived", "0");
    await k.restart(); p = await k.page(); await open(p, "browser");
    record(await snapshot(p), "row", "survived"); await close(p);
    return { actual_browser_relaunch: true, origin: k.origin };
  });
  for (const phase of ["before_commit", "after_commit"]) {
    await k.check("terminate_at_" + phase, async () => {
      await open(p, phase); await observe(p);
      await p.evaluate(phase => {
        window.phases = []; window.pending = "pending";
        window.clients.a.test.onCheckpoint(value => window.phases.push(value));
        void window.clients.a.put("interrupted", "value", "0", { checkpoint: phase })
          .then(() => { window.pending = "success"; }, () => { window.pending = "rejected"; });
      }, phase);
      await p.waitForFunction(() => window.phases.length > 0);
      await p.evaluate(() => window.clients.a.test.terminate());
      await p.waitForFunction(() => window.pending === "rejected");
      assert.deepEqual(await p.evaluate(() => window.events.map(e => e.type)), ["snapshot"]);
      const recovery = await reopen(p, phase); const value = await snapshot(p);
      // terminate是取消请求；Chrome可让同步WASM继续到提交。本例验证原子结果及无成功回调。
      assert.ok(phase === "before_commit" ? ["0", "1"].includes(value.revision) : value.revision === "1");
      record(value, "interrupted", value.revision === "0" ? undefined : "value"); await close(p);
      return { injection: "bounded checkpoint delay", interruption: "Worker.terminate request; not a guaranteed pre-commit kill",
        recovered_revision: value.revision, recovery };
    });
  }
  for (const phase of ["before_commit", "after_commit"]) {
    await k.check("renderer_crash_at_" + phase, async () => {
      const account = "crash_" + phase;
      await open(p, account); await observe(p);
      await p.evaluate(phase => {
        window.phases = [];
        window.clients.a.test.onCheckpoint(value => window.phases.push(value.phase));
        void window.clients.a.put("row", "atomic", "0", { checkpoint: phase }).catch(() => {});
      }, phase);
      await p.waitForFunction(phase => window.phases.includes(phase), phase);
      assert.deepEqual(await p.evaluate(() => window.events.map(e => e.type)), ["snapshot"]);
      const cdp = await k.context().newCDPSession(p);
      const crashed = p.waitForEvent("crash");
      // CDP Page.crash在renderer的IO线程触发真实崩溃，可中断同步WASM调用。
      void cdp.send("Page.crash").catch(() => {});
      await crashed; await k.restart(); p = await k.page();
      const recovery = await reopen(p, account); const value = await snapshot(p);
      revision(value, phase === "before_commit" ? 0 : 1);
      record(value, "row", phase === "before_commit" ? undefined : "atomic"); await close(p);
      return { interruption: "real renderer crash (CDP Page.crash), then Chrome relaunch",
        recovered_revision: value.revision, recovery };
    });
  }
  await k.check("late_requests_do_not_reach_other_account", async () => {
    await open(p, "oldAccount"); await open(p, "newAccount", {}, "b");
    const result = await p.evaluate(async () => {
      const pending = Array.from({ length: 8 }, () => window.clients.a.snapshot());
      window.clients.a.test.terminate();
      return Promise.allSettled(pending).then(values => values.map(x => x.status));
    });
    assert.ok(result.includes("rejected")); revision(await snapshot(p, "b"), 0);
    await put(p, "new", "safe", "0", undefined, "b"); await close(p, "b"); return result;
  });
  await k.check("real_browser_opaque_origin_storage_rejected", async () => {
    const frame = await p.evaluateHandle(origin => {
      const frame = document.createElement("iframe"); frame.sandbox = "allow-scripts";
      frame.src = origin + "/index.html"; document.body.append(frame); return frame;
    }, k.origin);
    const element = frame.asElement(); const target = await element.contentFrame(); await target.waitForLoadState();
    const result = await target.evaluate(async () => {
      let storageError; try { await navigator.storage.getDirectory(); } catch (error) { storageError = String(error); }
      let openError; try { const api = (await import("/dist/main.js")).probe; await api.open({ service: "service", account: "opaque" }); }
      catch (error) { openError = String(error); }
      return { storageError, openError };
    });
    assert.match(result.storageError, /SecurityError|not allowed|denied/i); assert.ok(result.openError);
    await element.evaluate(el => el.remove()); return result;
  });
  await k.check("missing_worker_explicit_unsupported_synthetic", async () => {
    const result = await p.evaluate(async () => {
      const WorkerBefore = window.Worker;
      try { window.Worker = undefined; await window.probe.open({ service: "service", account: "unsupported" }); return "unexpected success"; }
      catch (error) { return `${error.code}: ${error.message}`; } finally { window.Worker = WorkerBefore; }
    });
    assert.match(result, /unsupported/i); return { injection: "remove Worker capability", error: result };
  });
  await k.check("missing_precompiled_wasm_explicit_failure", async () => {
    const rule = "**/*_bg.wasm";
    let aborted = 0;
    await k.context().route(rule, route => { aborted++; return route.abort("failed"); });
    let error;
    try {
      error = await rejects(() => open(p, "missingWasm"), /WORKER_ENVIRONMENT_ERROR.*fetch/i);
      assert.ok(aborted > 0);
    } finally { await k.context().unroute(rule); }
    await open(p, "missingWasm"); revision(await snapshot(p), 0); await close(p);
    return { injection: "browser request aborted for packaged WASM", aborted, error };
  });
  await boundaryCases(k, { open, close, snapshot, put, observe, rejects });
  await k.check("browser_quota_enforced_write_failure", async () => {
    const q = await k.page(); const cdp = await k.context().newCDPSession(q);
    // 独立 origin 下既有其它测试库；在当前 usage 上给一个小增长窗口。
    await open(q, "quota"); await observe(q); const usage = await cdp.send("Storage.getUsageAndQuota", { origin: k.origin });
    await cdp.send("Storage.overrideQuotaForOrigin", { origin: k.origin, quotaSize: usage.usage + 16384 });
    try {
      const result = await q.evaluate(async () => {
        let last = await window.clients.a.snapshot(); let error; let cause; let paused;
        for (let i = 0; i < 128; i++) {
          try { last = await window.clients.a.put("row" + i, "x".repeat(4096), last.revision); }
          catch (failure) { error = `${failure.code}: ${failure.message}`; cause = failure.cause; paused = failure.paused; break; }
        }
        return { error, cause, paused, last, eventCount: window.events.length };
      });
      assert.match(result.error ?? "", /storage_error|commit_failed|transaction_cleanup_failed/, "quota must cause a real SQLite write failure");
      assert.equal(result.cause?.source, "sqlite"); assert.equal(result.paused, true);
      assert.equal(result.eventCount, Number(result.last.revision) + 1);
      await close(q);
      await cdp.send("Storage.overrideQuotaForOrigin", { origin: k.origin });
      await open(q, "quota"); const recovered = await snapshot(q);
      revision(recovered, result.last.revision); assert.deepEqual(recovered.records, result.last.records);
      await close(q); return { error: result.error, cause: result.cause, last_committed_revision: recovered.revision, quota_injection: "CDP quota override; real OPFS write" };
    } finally { await cdp.send("Storage.overrideQuotaForOrigin", { origin: k.origin }); await q.close(); }
  });
  await k.check("explicit_site_data_clear_returns_empty_store", async () => {
    // 所有页面关闭，清理仅属于本次随机本机origin及专用profile。
    for (const page of k.context().pages()) await page.close();
    p = await k.page(); const cdp = await k.context().newCDPSession(p);
    await cdp.send("Storage.clearDataForOrigin", { origin: k.origin, storageTypes: "all" });
    await open(p, "browser"); const value = await snapshot(p); revision(value, 0); assert.deepEqual(value.records, []);
    await close(p);
    return { meaning: "cleared browser storage has no old rows; this POC does not recreate crypto identity or old state" };
  });
}
