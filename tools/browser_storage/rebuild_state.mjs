// 封存事实与唯一后继在同一显式事务登记；原预约与原密码承诺永不释放。
import { scopeKey, hex, requestDigest, requireValue } from "./anchor_wire.mjs";
import { REBUILD_PROTOCOL, canonicalPlan, planHash, verifyApproval, verifyRebuildRequest, signRebuildResponse } from "./rebuild_wire.mjs";

export function createRebuildTables(db) {
  db.exec(`CREATE TABLE rebuild_approvers (scope_key TEXT PRIMARY KEY NOT NULL REFERENCES registry(scope_key), public_key TEXT NOT NULL);
    CREATE TABLE rebuild_links (old_scope_key TEXT PRIMARY KEY NOT NULL REFERENCES registry(scope_key),
    successor_scope_key TEXT NOT NULL UNIQUE REFERENCES registry(scope_key), rebuild_id TEXT NOT NULL UNIQUE,
    plan_hash TEXT NOT NULL UNIQUE, plan_json TEXT NOT NULL, approval_digest TEXT NOT NULL, client_proof_digest TEXT NOT NULL);`);
}
export function validateRebuildTables(state) {
  const pins = state.db.prepare("SELECT scope_key, public_key FROM rebuild_approvers LIMIT 129").all();
  requireValue(pins.length <= 128, "anchor_capacity");
  for (const row of pins) { hex(row.public_key); requireValue(state.db.prepare("SELECT scope_key FROM registry WHERE scope_key=?").get(row.scope_key), "anchor_corrupt"); }
  const links = state.db.prepare("SELECT old_scope_key,successor_scope_key,rebuild_id,plan_hash,plan_json,approval_digest,client_proof_digest FROM rebuild_links LIMIT 129").all();
  requireValue(links.length <= 128, "anchor_capacity");
  for (const link of links) {
    const plan = canonicalPlan(JSON.parse(link.plan_json)); const old = state.row(plan.old_scope); const child = state.row(plan.successor_scope);
    requireValue(link.old_scope_key === scopeKey(plan.old_scope) && link.successor_scope_key === scopeKey(plan.successor_scope)
      && link.rebuild_id === plan.rebuild_id && link.plan_hash === planHash(plan) && child.clientKey === plan.successor_client_public_key,
    "anchor_corrupt"); hex(link.approval_digest); hex(link.client_proof_digest); validateBase(state, old, plan);
    requireValue(!findLink(state, plan.successor_scope), "anchor_corrupt");
  }
}
export function findLink(state, value) {
  return state.db.prepare("SELECT plan_hash,plan_json,successor_scope_key FROM rebuild_links WHERE old_scope_key=?").get(scopeKey(value));
}
function validateBase(state, old, plan) {
  const pin = state.db.prepare("SELECT public_key FROM rebuild_approvers WHERE scope_key=?").get(scopeKey(plan.old_scope));
  requireValue(pin?.public_key === plan.approver_public_key && plan.anchor_public_key === state.publicKey
    && old.head === plan.old_head && old.revision.toString() === plan.old_revision && old.pending
    && old.pending.txn === plan.old_txn && old.pending.base === plan.old_head && old.pending.reservedRevision === plan.old_revision
    && old.clientKey !== plan.successor_client_public_key, "anchor_rebuild_denied");
  requireValue(!state.db.prepare("SELECT old_scope_key FROM rebuild_links WHERE successor_scope_key=?").get(scopeKey(plan.old_scope)), "anchor_rebuild_denied");
  return pin.public_key;
}
export function rebuild(state, input, failpoint) {
  const plan = canonicalPlan(input.plan); const digest = planHash(plan);
  const response = state.tx(() => {
    const old = state.row(plan.old_scope); const pin = validateBase(state, old, plan);
    verifyApproval(plan, input.approval, pin); const request = verifyRebuildRequest(plan, input.request);
    const link = findLink(state, plan.old_scope);
    if (link) requireValue(link.plan_hash === digest && JSON.stringify(canonicalPlan(JSON.parse(link.plan_json))) === JSON.stringify(plan), "anchor_rebuild_denied");
    const nextKey = scopeKey(plan.successor_scope); let status;
    if (link) status = request.action === "link" ? "duplicate" : "linked";
    else {
      requireValue(!state.db.prepare("SELECT scope_key FROM registry WHERE scope_key=?").get(nextKey), "anchor_rebuild_denied");
      requireValue(!state.db.prepare("SELECT old_scope_key FROM rebuild_links WHERE rebuild_id=? OR successor_scope_key=?").get(plan.rebuild_id, nextKey), "anchor_rebuild_denied");
      status = "unlinked";
      if (request.action === "link") {
        requireValue(state.db.prepare("SELECT COUNT(*) AS count FROM registry").get().count < 128, "anchor_capacity");
        state.db.prepare("INSERT INTO registry VALUES (?, ?, ?, ?, '0', NULL, NULL)").run(nextKey, JSON.stringify(plan.successor_scope), plan.successor_client_public_key, plan.successor_head);
        state.db.prepare("INSERT INTO rebuild_links VALUES (?, ?, ?, ?, ?, ?, ?)").run(scopeKey(plan.old_scope), nextKey,
          plan.rebuild_id, digest, JSON.stringify(plan), requestDigest(input.approval), requestDigest(input.request));
        status = "linked";
      }
    }
    const current = status === "unlinked" ? null : state.row(plan.successor_scope);
    return { protocol_version: REBUILD_PROTOCOL, plan_sha256: digest, request_sha256: requestDigest(input.request),
      challenge: request.challenge, action: request.action, status, old_scope: plan.old_scope, old_head: plan.old_head,
      old_txn: plan.old_txn, old_revision: plan.old_revision, successor_scope: plan.successor_scope,
      successor_head: plan.successor_head, successor_revision: "0", current_head: current?.head ?? "absent",
      current_revision: current?.revision.toString() ?? "0", active_txn: current?.pending?.txn ?? null };
  }, "IMMEDIATE", failpoint);
  return { ok: true, response: signRebuildResponse(response, state.seed) };
}
