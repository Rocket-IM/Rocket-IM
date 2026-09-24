import assert from "node:assert/strict";

export async function boundaryCases(k, api) {
  const { open, close, snapshot, observe, rejects } = api;
  const p = await k.page();
  await k.check("sql_read_failure_rolls_back_and_pauses", async () => {
    await open(p, "readFailure"); await p.evaluate(() => window.clients.a.put("good", "saved", "0"));
    await observe(p);
    const result = await p.evaluate(async () => {
      try { await window.clients.a.test.failRead(); return { unexpectedSuccess: true }; }
      catch (error) { return { code: error.code, paused: error.paused, cause: error.cause, events: window.events.map(e => e.type) }; }
    });
    assert.equal(result.code, "storage_error"); assert.equal(result.paused, true);
    assert.equal(result.cause?.source, "sqlite"); assert.equal(result.cause?.code, 1);
    assert.deepEqual(result.events, ["snapshot"]);
    await rejects(() => snapshot(p), /storage_paused|PAUSED/);
    await close(p); await open(p, "readFailure"); const recovered = await snapshot(p);
    assert.equal(recovered.revision, "1"); assert.deepEqual(recovered.records, [{ key: "good", value: "saved" }]);
    await close(p); return { injection: "real missing-table SELECT inside explicit Rust read transaction", ...result };
  });
  await k.check("concurrent_expected_revision_has_one_winner", async () => {
    await open(p, "concurrent"); await observe(p);
    const result = await p.evaluate(async () => {
      const values = await Promise.allSettled([
        window.clients.a.put("first", "a", "0"), window.clients.a.put("second", "b", "0"),
      ]);
      return { results: values.map(v => v.status === "fulfilled" ? "ok" : v.reason.code),
        events: window.events.map(e => e.type) };
    });
    assert.deepEqual(result.results, ["ok", "revision_conflict"]);
    assert.deepEqual(result.events, ["snapshot", "committed"]);
    const value = await snapshot(p); assert.equal(value.revision, "1"); assert.equal(value.records.length, 1);
    await close(p); return result;
  });
  await k.check("close_during_committed_response_suppresses_events", async () => {
    await open(p, "closing"); await observe(p);
    await p.evaluate(() => {
      window.phases = []; window.resultCodes = [];
      window.clients.a.test.onCheckpoint(e => window.phases.push(e.phase));
      void window.clients.a.put("row", "committed", "0", { checkpoint: "after_commit" })
        .then(() => window.resultCodes.push("unexpected_success"), error => window.resultCodes.push(error.code));
      void window.clients.a.snapshot().then(() => window.resultCodes.push("unexpected_read"), error => window.resultCodes.push(error.code));
    });
    await p.waitForFunction(() => window.phases.includes("after_commit"));
    await close(p);
    const result = await p.evaluate(() => ({ codes: window.resultCodes, events: window.events.map(e => e.type) }));
    assert.deepEqual(result.codes.sort(), ["CLOSED", "CLOSED"]); assert.deepEqual(result.events, ["snapshot"]);
    await open(p, "closing"); assert.equal((await snapshot(p)).revision, "1"); await close(p); return result;
  });
  await k.check("queue_is_bounded_without_losing_accepted_queries", async () => {
    await open(p, "bounded");
    const result = await p.evaluate(async () => {
      const values = await Promise.allSettled(Array.from({ length: 70 }, () => window.clients.a.snapshot()));
      return values.reduce((counts, result) => {
        const key = result.status === "fulfilled" ? "ok" : result.reason.code;
        counts[key] = (counts[key] ?? 0) + 1; return counts;
      }, {});
    });
    assert.deepEqual(result, { ok: 64, QUEUE_FULL: 6 }); await close(p); return result;
  });
  await k.check("wasm_version_mismatch_explicit_rejection", async () => {
    const rule = "**/generated/rockets_browser_storage_probe.js";
    await k.context().route(rule, async route => {
      const response = await route.fetch();
      await route.fulfill({ response, body: (await response.text()) + '\nprobe_version = () => "incompatible-test-version";\n' });
    });
    let error;
    try { error = await rejects(() => open(p, "wrongVersion"), /VERSION_MISMATCH/); }
    finally { await k.context().unroute(rule); }
    await open(p, "wrongVersion"); assert.equal((await snapshot(p)).revision, "0"); await close(p);
    return { injection: "replace generated glue version response", error };
  });
  await p.close();
}
