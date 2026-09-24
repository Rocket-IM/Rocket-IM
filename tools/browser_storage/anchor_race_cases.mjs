// 两个独立 Chrome profile 持有同一已提交密码库；唯一执行许可必须由外部锚 CAS 决定。
import assert from "node:assert/strict";
import { pair, openAnchored, call, snapshot, status, requireSnapshot, cleanup } from "./anchor_support.mjs";
import { scopeKey } from "./anchor_wire.mjs";

export async function runAnchorRaceCases(kit) {
  await kit.check("anchor_two_independent_profile_clones_have_one_send_winner", async () => {
    const contexts = []; const pages = []; let initial;
    try {
      initial = await pair(kit, "profile_clone_race");
      const config = initial.configs[0]; const original = initial.a;
      assert.equal(original.encryptions, "0");
      const backup = await kit.backupProfile("anchor-clone-race");
      // 克隆源是已关闭主 Chrome 时保存的完整 profile；克隆过程不访问或改变主 profile。
      for (const name of ["anchor-race-left", "anchor-race-right"]) {
        const context = await kit.cloneProfile("anchor-clone-race", name); contexts.push(context);
        const page = await kit.page(context); pages.push(page); await openAnchored(page, config);
      }
      assert.notEqual(contexts[0], contexts[1]);
      const localBefore = await Promise.all(pages.map(page => status(page)));
      assert.ok(localBefore.every(value => value.phase === "ready"));
      assert.equal(localBefore[0].localHead, localBefore[1].localHead);
      const before = await kit.anchor.inspect(config.scope);
      const diagnosticsBefore = await kit.anchor.diagnostics();
      assert.equal(before.pending, null);
      const attempts = ["race_left", "race_right"];
      const results = await Promise.allSettled(pages.map((page, index) => call(page, "send", [
        attempts[index], "message_" + attempts[index], "synthetic independent profile " + index,
      ])));
      const winners = results.flatMap((result, index) => result.status === "fulfilled" ? [index] : []);
      assert.equal(winners.length, 1, "two cloned providers must never both receive permission to encrypt");
      const winner = winners[0]; const loser = 1 - winner;
      assert.match(String(results[loser].reason), /anchor_conflict/);
      const completed = requireSnapshot(results[winner].value);
      assert.equal(completed.encryptions, "1"); assert.equal(completed.outbox.length, 1);
      assert.equal(completed.outbox[0].attemptId, attempts[winner]);
      assert.notEqual(completed.providerHash, original.providerHash);
      const after = await kit.anchor.inspect(config.scope);
      const diagnosticsAfter = await kit.anchor.diagnostics();
      assert.equal(after.pending, null); assert.equal(BigInt(after.revision), BigInt(before.revision) + 2n);
      const count = diagnosticsAfter.requests - diagnosticsBefore.requests;
      assert.ok(count > 0 && count <= 128, "race diagnostic window must fit the bounded journal");
      const records = diagnosticsAfter.records.slice(-count).filter(record => record.scopeKey === scopeKey(config.scope));
      assert.equal(records.filter(record => record.action === "reserve" && record.outcome === "reserved").length, 1);
      assert.equal(records.filter(record => record.action === "finish" && record.outcome === "finished").length, 1);
      assert.equal(records.filter(record => record.action === "reserve" && record.outcome === "conflict").length, 1);
      const observed = await snapshot(pages[winner]);
      assert.equal(observed.encryptions, "1"); assert.equal(observed.providerHash, completed.providerHash);
      assert.deepEqual(observed.outbox, completed.outbox);
      const blocked = await status(pages[loser]);
      assert.equal(blocked.phase, "paused"); assert.equal(blocked.localPending, true);
      assert.equal(blocked.localHead, before.head); assert.equal(blocked.remoteHead, after.head);
      return { profiles: 2, winner: winner === 0 ? "left" : "right", encryptionCount: observed.encryptions,
        raceAnchorRevisionBefore: before.revision, raceAnchorRevisionAfter: after.revision,
        firstReservations: 1, completedFinishes: 1, rejectedReservations: 1, raceRequests: count,
        loserError: "anchor_conflict", loserPaused: true, backupFiles: backup.files, backupDigest: backup.digest };
    } finally {
      await Promise.allSettled(pages.map(page => cleanup(page)));
      await Promise.allSettled(contexts.map(context => context.close()));
      if (initial?.p) await cleanup(initial.p);
    }
  });
}
