// 只解析公开值与声明形状；签名、授权及范围转换均由 Rust 验证。
import { StorageError, identifier, object, revision } from "./protocol.js";
import { identity } from "./crypto_protocol.js";
import type { AnchorScope } from "./anchor_types.js";
import type { RebuildBasis, RebuildOffer, RebuildPlan, RebuildSigned } from "./rebuild_types.js";

function invalid(message: string): StorageError { return new StorageError("INVALID_ARGUMENT", message); }
export function rebuildHex(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) throw invalid("Expected 32-byte lowercase hexadecimal data.");
  return value;
}
export function rebuildScope(value: unknown): AnchorScope {
  const raw = object(value);
  return Object.freeze({ service: identifier(raw.service, "service"), account: identifier(raw.account, "account"),
    device: identifier(raw.device, "device"), identity_key: rebuildHex(raw.identity_key), store_id: rebuildHex(raw.store_id) });
}
export function rebuildBasis(value: unknown, service: string, account: string): RebuildBasis {
  const raw = object(value), oldScope = rebuildScope(raw.oldScope), oldRevision = revision(raw.oldRevision);
  if (oldScope.service !== service || oldScope.account !== account || oldRevision === "0") throw invalid("Invalid predecessor basis scope or revision.");
  if (raw.baselineHead !== raw.oldHead) throw invalid("Predecessor basis does not match its anchor baseline.");
  return Object.freeze({ oldScope, oldHead: rebuildHex(raw.oldHead), oldTxn: rebuildHex(raw.oldTxn), oldRevision,
    oldConversation: identifier(raw.oldConversation, "oldConversation"), localHead: rebuildHex(raw.localHead), baselineHead: rebuildHex(raw.baselineHead) });
}
export function rebuildOffer(value: unknown): RebuildOffer {
  const raw = object(value), scope = rebuildScope(raw.scope), owner = identity(raw.identity);
  if (scope.service !== owner.service || scope.account !== owner.account || scope.device !== owner.device) {
    throw invalid("Candidate identity and scope do not match.");
  }
  const publicKey = Array.from(atob(owner.identityKey), byte => byte.charCodeAt(0).toString(16).padStart(2, "0")).join("");
  if (scope.identity_key !== publicKey) throw invalid("Candidate public identity does not match its anchor scope.");
  return Object.freeze({ scope, head: rebuildHex(raw.head), identity: owner,
    clientPublicKey: rebuildHex(raw.clientPublicKey), storageNamespace: rebuildHex(raw.storageNamespace) });
}
export function rebuildPlan(value: unknown): RebuildPlan {
  const raw = object(value), oldRevision = revision(raw.old_revision);
  if (raw.protocol_version !== "rim-browser-rebuild-1" || oldRevision === "0") throw invalid("Invalid rebuild plan version or revision.");
  // 字段顺序与 Rust/Node 的已签名合同保持一致；签名内容仍以 statement_bytes 为准。
  const plan: RebuildPlan = Object.freeze({ protocol_version: "rim-browser-rebuild-1", rebuild_id: rebuildHex(raw.rebuild_id),
    anchor_public_key: rebuildHex(raw.anchor_public_key), approver_public_key: rebuildHex(raw.approver_public_key),
    old_scope: rebuildScope(raw.old_scope), old_head: rebuildHex(raw.old_head), old_txn: rebuildHex(raw.old_txn),
    old_revision: oldRevision, old_conversation: identifier(raw.old_conversation, "old_conversation"),
    successor_scope: rebuildScope(raw.successor_scope), successor_head: rebuildHex(raw.successor_head),
    successor_client_public_key: rebuildHex(raw.successor_client_public_key),
    successor_key_package_sha256: rebuildHex(raw.successor_key_package_sha256),
    conversation: identifier(raw.conversation, "conversation"), peer: identity(raw.peer) });
  if (new TextEncoder().encode(JSON.stringify(plan)).length > 8192) throw invalid("Rebuild plan exceeds 8 KiB.");
  return plan;
}
function encoded(value: unknown, limit: number, exact?: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > Math.ceil(limit / 3) * 4
      || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw invalid("Invalid bounded rebuild statement encoding.");
  }
  const decoded = atob(value);
  if (decoded.length > limit || (exact !== undefined && decoded.length !== exact) || btoa(decoded) !== value) {
    throw invalid("Invalid rebuild statement size or canonical encoding.");
  }
  return value;
}
export function rebuildSigned(value: unknown): RebuildSigned {
  const raw = object(value);
  return Object.freeze({ statement_bytes: encoded(raw.statement_bytes, 8192), signature_bytes: encoded(raw.signature_bytes, 64, 64) });
}
