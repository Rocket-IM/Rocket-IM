// 浏览器实验重建协议：独立批准 + 新客户端持有证明，不使用旧设备私钥。
import { createPublicKey, verify, sign } from "node:crypto";
import { AnchorError, exact, scope, hex, revision, base64, signed, hash, privateKey, requireValue } from "./anchor_wire.mjs";

export const REBUILD_PROTOCOL = "rim-browser-rebuild-1";
export const APPROVAL_DOMAIN = Buffer.from("Rocket-IM/browser-rebuild-approval/v1\0");
const REQUEST_DOMAIN = Buffer.from("Rocket-IM/browser-rebuild-request/v1\0");
const RESPONSE_DOMAIN = Buffer.from("Rocket-IM/browser-rebuild-response/v1\0");
const FIELDS = ["protocol_version", "rebuild_id", "anchor_public_key", "approver_public_key", "old_scope", "old_head",
  "old_txn", "old_revision", "old_conversation", "successor_scope", "successor_head", "successor_client_public_key",
  "successor_key_package_sha256", "conversation", "peer"];
function id(value) { requireValue(typeof value === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(value)); return value; }
function identity(value) {
  exact(value, ["service", "account", "device", "identityKey", "keyPackage"]);
  requireValue(base64(value.identityKey, 32).length === 32); base64(value.keyPackage, 64 * 1024);
  return { service: id(value.service), account: id(value.account), device: id(value.device), identityKey: value.identityKey, keyPackage: value.keyPackage };
}
export function canonicalPlan(value) {
  exact(value, FIELDS); requireValue(value.protocol_version === REBUILD_PROTOCOL);
  const old = scope(value.old_scope); const next = scope(value.successor_scope); const peer = identity(value.peer);
  const peerKey = base64(peer.identityKey, 32).toString("hex");
  requireValue(![value.anchor_public_key, old.identity_key, next.identity_key, value.successor_client_public_key].includes(value.approver_public_key)
    && peerKey !== old.identity_key && peerKey !== next.identity_key, "anchor_rebuild_denied");
  requireValue(revision(value.old_revision) > 0n);
  requireValue(old.service === next.service && old.account === next.account && old.device !== next.device
    && old.identity_key !== next.identity_key && old.store_id !== next.store_id && value.old_head !== value.successor_head,
  "anchor_rebuild_denied");
  requireValue(id(value.old_conversation) !== id(value.conversation) && peer.service === next.service && peer.account !== next.account,
    "anchor_rebuild_denied");
  return { protocol_version: REBUILD_PROTOCOL, rebuild_id: hex(value.rebuild_id), anchor_public_key: hex(value.anchor_public_key),
    approver_public_key: hex(value.approver_public_key), old_scope: old, old_head: hex(value.old_head), old_txn: hex(value.old_txn),
    old_revision: value.old_revision, old_conversation: value.old_conversation, successor_scope: next,
    successor_head: hex(value.successor_head), successor_client_public_key: hex(value.successor_client_public_key),
    successor_key_package_sha256: hex(value.successor_key_package_sha256), conversation: value.conversation, peer };
}
export function planHash(value) {
  const bytes = Buffer.from(JSON.stringify(canonicalPlan(value))); requireValue(bytes.length <= 8 * 1024); return hash(bytes);
}
function signValue(value, seed, domain) {
  const raw = Buffer.from(JSON.stringify(value)); requireValue(raw.length <= 8 * 1024);
  return { statement_bytes: raw.toString("base64"), signature_bytes: sign(null, Buffer.concat([domain, raw]), privateKey(seed)).toString("base64") };
}
function verifyValue(value, key, domain) {
  const { bytes, signature } = signed(value);
  try {
    const publicKey = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(hex(key), "hex")]), format: "der", type: "spki" });
    requireValue(verify(null, Buffer.concat([domain, bytes]), publicKey, signature), "anchor_rebuild_signature");
    requireValue(Buffer.from(bytes.toString("utf8")).equals(bytes)); return JSON.parse(bytes.toString("utf8"));
  } catch { throw new AnchorError("anchor_rebuild_signature"); }
}
export function signApproval(plan, seed) { const value = canonicalPlan(plan); planHash(value); return signValue(value, seed, APPROVAL_DOMAIN); }
export function verifyApproval(plan, approval, key) {
  const value = canonicalPlan(plan); requireValue(value.approver_public_key === hex(key), "anchor_rebuild_denied");
  const approved = canonicalPlan(verifyValue(approval, key, APPROVAL_DOMAIN));
  requireValue(JSON.stringify(approved) === JSON.stringify(value), "anchor_rebuild_denied");
}
export function parseRebuildRequest(value) {
  const { bytes } = signed(value); let result;
  try { result = JSON.parse(bytes.toString("utf8")); } catch { throw new AnchorError("anchor_invalid"); }
  exact(result, ["protocol_version", "plan_sha256", "challenge", "action"]);
  requireValue(result.protocol_version === REBUILD_PROTOCOL && ["link", "inspect"].includes(result.action));
  hex(result.plan_sha256); hex(result.challenge); return result;
}
export function signRebuildRequest(plan, seed, action, challenge) {
  requireValue(["link", "inspect"].includes(action));
  return signValue({ protocol_version: REBUILD_PROTOCOL, plan_sha256: planHash(plan), challenge: hex(challenge), action }, seed, REQUEST_DOMAIN);
}
export function verifyRebuildRequest(plan, request) {
  const parsed = parseRebuildRequest(request); const verified = verifyValue(request, canonicalPlan(plan).successor_client_public_key, REQUEST_DOMAIN);
  requireValue(JSON.stringify(parsed) === JSON.stringify(verified) && parsed.plan_sha256 === planHash(plan), "anchor_rebuild_denied"); return parsed;
}
export function signRebuildResponse(value, seed) { return signValue(value, seed, RESPONSE_DOMAIN); }
