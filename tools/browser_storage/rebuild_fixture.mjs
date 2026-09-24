// 独立批准者仅属于本机测试控制器；批准私钥不在浏览器、anchor-trust 或锚备份中。
import fs from "node:fs/promises";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { LIMIT, AnchorError, base64, hex, hash, publicKey, scopeKey, requireValue } from "./anchor_wire.mjs";
import { REBUILD_PROTOCOL, canonicalPlan, planHash, signApproval, signRebuildRequest } from "./rebuild_wire.mjs";

const randomHex = () => randomBytes(32).toString("hex");
export class RebuildFixture {
  #seed;
  constructor(anchor, seed) {
    this.anchor = anchor; this.#seed = hex(seed); this.approverPublicKey = publicKey(seed);
    this.directory = path.join(anchor.output, "rebuild-trust");
    this.evidence = { assurance: "synthetic_local_external_approver", approvals: [], requests: [] };
  }
  static async attach(anchor) {
    const directory = path.join(anchor.output, "rebuild-trust"); let created = false;
    try { await fs.mkdir(directory, { mode: 0o700 }); created = true; }
    catch (error) { if (error.code !== "EEXIST") throw error; }
    const stat = await fs.lstat(directory);
    requireValue(stat.isDirectory() && !stat.isSymbolicLink() && (stat.mode & 0o777) === 0o700, "rebuild_trust_invalid");
    const file = path.join(directory, "approver.json");
    if (created) await fs.writeFile(file, JSON.stringify({ format: 1, seed: randomHex() }) + "\n", { mode: 0o600, flag: "wx" });
    const fileStat = await fs.lstat(file);
    requireValue(fileStat.isFile() && !fileStat.isSymbolicLink() && fileStat.size <= 1024 && (fileStat.mode & 0o777) === 0o600, "rebuild_trust_invalid");
    const value = JSON.parse(await fs.readFile(file, "utf8"));
    requireValue(value.format === 1 && Object.keys(value).sort().join(",") === "format,seed", "rebuild_trust_invalid");
    return new RebuildFixture(anchor, value.seed);
  }
  prepare({ old, oldConversation, successor, conversation, peer, rebuildId = randomHex() }) {
    requireValue(old.pending && old.rebuildApproverPublicKey === this.approverPublicKey, "anchor_rebuild_denied");
    const nextKey = successor.clientPublicKey ?? publicKey(successor.clientSeed);
    if (successor.clientSeed !== undefined) requireValue(publicKey(successor.clientSeed) === nextKey, "anchor_rebuild_denied");
    if (successor.storageNamespace !== undefined) requireValue(successor.storageNamespace === successor.scope.store_id, "anchor_rebuild_denied");
    const keyPackageHash = successor.keyPackageSha256 ?? hash(base64(successor.identity?.keyPackage, 64 * 1024));
    return canonicalPlan({ protocol_version: REBUILD_PROTOCOL, rebuild_id: rebuildId,
      anchor_public_key: this.anchor.anchorPublicKey, approver_public_key: this.approverPublicKey,
      old_scope: old.scope, old_head: old.head, old_txn: old.pending.txn, old_revision: old.revision,
      old_conversation: oldConversation, successor_scope: successor.scope, successor_head: successor.head,
      successor_client_public_key: nextKey, successor_key_package_sha256: keyPackageHash, conversation, peer });
  }
  approve(plan) {
    const fixed = canonicalPlan(plan);
    requireValue(fixed.approver_public_key === this.approverPublicKey && fixed.anchor_public_key === this.anchor.anchorPublicKey, "anchor_rebuild_denied");
    const approved = signApproval(fixed, this.#seed);
    this.evidence.approvals.push({ rebuildId: fixed.rebuild_id, planHash: planHash(fixed), oldScopeKey: scopeKey(fixed.old_scope), successorScopeKey: scopeKey(fixed.successor_scope) });
    if (this.evidence.approvals.length > 128) this.evidence.approvals.shift(); return approved;
  }
  request(plan, clientSeed, action = "link", challenge = randomHex()) {
    requireValue(publicKey(clientSeed) === canonicalPlan(plan).successor_client_public_key, "anchor_rebuild_denied");
    return signRebuildRequest(plan, clientSeed, action, challenge);
  }
  async submit(plan, approval, clientSeed, action = "link") {
    const request = this.request(plan, clientSeed, action);
    const body = JSON.stringify({ rebuild: { plan: canonicalPlan(plan), approval, request } });
    requireValue(Buffer.byteLength(body) <= LIMIT, "anchor_limit");
    const response = await fetch(this.anchor.endpoint, { method: "POST", redirect: "error", signal: AbortSignal.timeout(4000),
      headers: { Origin: this.anchor.origin, "Content-Type": "application/json" }, body });
    const chunks = []; let bytes = 0;
    for await (const chunk of response.body) { bytes += chunk.length; requireValue(bytes <= LIMIT, "anchor_limit"); chunks.push(chunk); }
    let value;
    try { value = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { throw new AnchorError("anchor_response"); }
    this.evidence.requests.push({ action, planHash: planHash(plan), httpStatus: response.status, ok: value.ok === true });
    if (this.evidence.requests.length > 128) this.evidence.requests.shift(); return value;
  }
  async fault(value) {
    requireValue(["link", "rebuild_inspect"].includes(value.action)); return this.anchor.fault(value);
  }
  async fileHashes() {
    const file = path.join(this.directory, "approver.json"); return { [path.relative(this.anchor.output, file)]: hash(await fs.readFile(file)) };
  }
}
