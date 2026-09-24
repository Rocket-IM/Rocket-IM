import { StorageError, identifier, member, object, parseJsonResult, revision, wireError } from "./protocol.js";
import type { ResultOutcome } from "./protocol.js";
import type { CryptoSnapshot } from "./crypto_types.js";
import { cryptoOutcome, cryptoRequest } from "./crypto_protocol.js";
import { anchorEndpoint } from "./anchor_rpc.js";
import { rebuildBasis } from "./rebuild_values.js";
import type { AnchorOptions, AnchorRequest, AnchorStatus, AnchorView, AnchorWindow } from "./anchor_types.js";

const WINDOWS = ["after_anchor_reserve", "after_candidate_commit", "after_anchor_finish"] as const;
function invalid(message: string): StorageError { return new StorageError("INVALID_ARGUMENT", message); }
function hex(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) throw invalid("Expected a 32-byte lowercase hexadecimal value.");
  return value;
}
export function anchorOptions(value: unknown): Required<AnchorOptions> {
  const raw = object(value), config = object(raw.anchor), scope = object(config.scope);
  const service = identifier(raw.service, "service"), account = identifier(raw.account, "account");
  if (raw.testMode !== undefined && typeof raw.testMode !== "boolean") throw invalid("testMode must be a boolean.");
  if (scope.service !== service || scope.account !== account || scope.device !== "probe-device") {
    throw invalid("Anchor scope must match the service, account and isolated probe device.");
  }
  return Object.freeze({ service, account, testMode: raw.testMode === true, anchor: Object.freeze({
    endpoint: anchorEndpoint(config.endpoint),
    scope: Object.freeze({ service, account, device: "probe-device", identity_key: hex(scope.identity_key), store_id: hex(scope.store_id) }),
    anchorPublicKey: hex(config.anchorPublicKey), clientSeed: hex(config.clientSeed),
  }) });
}
function anchorTest(value: unknown, testMode: boolean): { checkpoint: AnchorWindow } | undefined {
  if (value === undefined) return undefined;
  if (!testMode) throw new StorageError("TEST_MODE_REQUIRED", "Anchor checkpoints require testMode.");
  const raw = object(value);
  if (Object.keys(raw).some(key => key !== "checkpoint") || !member(raw.checkpoint, WINDOWS)) {
    throw invalid("Invalid anchor checkpoint.");
  }
  return Object.freeze({ checkpoint: raw.checkpoint });
}
/** Worker 线协议：只验证公开形状，锚签名与业务门禁由 Rust 判断。 */
export function anchorRequest(value: unknown, testMode: boolean): AnchorRequest {
  const raw = object(value), control = anchorTest(raw.anchorTest, testMode);
  if (raw.op === "initialize") throw invalid("Initialize the isolated test baseline before opening its anchored scope.");
  let parsed: AnchorRequest;
  if (raw.op === "status" || raw.op === "resume" || raw.op === "rebuild_basis") {
    if (raw.test !== undefined) throw invalid("Anchor diagnostics do not accept crypto fault controls.");
    if (control !== undefined) throw invalid("Anchor diagnostics do not accept checkpoints.");
    parsed = { op: raw.op };
  } else {
    const crypto = cryptoRequest(raw, testMode);
    if (crypto.op === "initialize") throw invalid("Anchored initialization is not supported.");
    if (control !== undefined && crypto.op !== "inspect" && crypto.test !== undefined) {
      throw invalid("Use crypto fault controls or an anchor checkpoint in separate operations.");
    }
    parsed = crypto;
  }
  if (control !== undefined) parsed = { ...parsed, anchorTest: control };
  if (new TextEncoder().encode(JSON.stringify(parsed)).length > 256 * 1024) throw invalid("Anchor command exceeds 256 KiB.");
  return parsed;
}
/** 对外最后一个 test 参数映射为两个已声明的 Rust 测试字段。 */
export function anchorCommand(value: unknown, test: unknown, testMode: boolean): AnchorRequest {
  if (test === undefined) return anchorRequest(value, testMode);
  if (!testMode) throw new StorageError("TEST_MODE_REQUIRED", "Anchor fault controls require testMode.");
  const raw = object(test);
  if (Object.keys(raw).some(key => !["fault", "checkpoint", "anchorCheckpoint"].includes(key))) {
    throw invalid("Unknown anchor test control.");
  }
  const crypto = raw.fault === undefined && raw.checkpoint === undefined ? undefined
    : { fault: raw.fault, checkpoint: raw.checkpoint };
  const control = raw.anchorCheckpoint === undefined ? undefined : { checkpoint: raw.anchorCheckpoint };
  return anchorRequest({ ...object(value), test: crypto, anchorTest: control }, testMode);
}
export function anchorStatus(value: unknown): AnchorStatus {
  const raw = object(value);
  if (raw.assurance !== "synthetic_local" || !member(raw.phase, ["ready", "paused"])
      || typeof raw.localPending !== "boolean"
      || (raw.reason !== null && (typeof raw.reason !== "string" || !/^anchor_[A-Za-z0-9_]{1,121}$/.test(raw.reason)))) {
    throw invalid("Invalid anchor status.");
  }
  return Object.freeze({ assurance: "synthetic_local", phase: raw.phase, localHead: hex(raw.localHead),
    remoteHead: hex(raw.remoteHead), remoteRevision: revision(raw.remoteRevision),
    remotePending: raw.remotePending === null ? null : hex(raw.remotePending), localPending: raw.localPending, reason: raw.reason });
}
export function anchorOutcome(value: unknown, service: string, account: string): ResultOutcome<AnchorView> {
  const raw = object(value);
  if (raw.ok === false && raw.result === undefined) return { ok: false, error: wireError(raw.error) };
  if (raw.ok !== true || raw.error !== undefined) throw new StorageError("INVALID_RESPONSE", "Invalid anchor outcome.", true);
  try {
    const view = object(raw.result);
    let snapshot: CryptoSnapshot | null = null;
    if (view.snapshot !== null) {
      const result = cryptoOutcome({ ok: true, result: view.snapshot }, service, account);
      if (!result.ok) throw invalid("Invalid confirmed crypto snapshot.");
      snapshot = result.result;
    }
    return { ok: true, result: Object.freeze({ snapshot, status: anchorStatus(view.status),
      ...(view.rebuildBasis === undefined ? {} : { rebuildBasis: rebuildBasis(view.rebuildBasis, service, account) }) }) };
  } catch (error) {
    throw new StorageError("INVALID_RESPONSE", error instanceof Error ? error.message : "Invalid anchor view.", true);
  }
}
export function parseAnchorOutcome(value: unknown, service: string, account: string, op: AnchorRequest["op"]): ResultOutcome<AnchorView> {
  const result = anchorOutcome(parseJsonResult(value), service, account);
  if (result.ok && (op === "status" || op === "resume" || op === "rebuild_basis") && result.result.snapshot !== null) {
    throw new StorageError("INVALID_RESPONSE", "Anchor diagnostics must not expose crypto snapshots.", true);
  }
  if (result.ok && op === "rebuild_basis" && result.result.rebuildBasis === undefined) {
    throw new StorageError("INVALID_RESPONSE", "The predecessor basis is absent.", true);
  }
  return result;
}
