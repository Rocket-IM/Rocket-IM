import { StorageError, identifier, member, object, parseJsonResult, wireError } from "./protocol.js";
import type { ResultOutcome } from "./protocol.js";
import { cryptoOutcome, cryptoRequest } from "./crypto_protocol.js";
import { anchorStatus } from "./anchor_protocol.js";
import { anchorEndpoint } from "./anchor_rpc.js";
import { rebuildHex, rebuildOffer, rebuildPlan, rebuildSigned } from "./rebuild_values.js";
import type { ParsedRebuildOptions, RebuildOptions, RebuildRequest, RebuildView, RebuildWindow } from "./rebuild_types.js";

const WINDOWS = ["after_anchor_reserve", "after_candidate_commit", "after_anchor_finish", "after_rebuild_link"] as const;
function invalid(message: string): StorageError { return new StorageError("INVALID_ARGUMENT", message); }
export function rebuildOptions(value: unknown): ParsedRebuildOptions {
  const raw = object(value), device = identifier(raw.device, "device");
  if (device === "probe-device") throw invalid("Rebuild requires a new explicit device identifier.");
  if (raw.testMode !== undefined && typeof raw.testMode !== "boolean") throw invalid("testMode must be a boolean.");
  if (raw.initialFault !== undefined && !member(raw.initialFault, ["after_crypto", "after_sql", "refuse_commit", "reserve_refuse", "after_commit"])) {
    throw invalid("Invalid rebuild identity initialization fault.");
  }
  return Object.freeze({ service: identifier(raw.service, "service"), account: identifier(raw.account, "account"), device,
    storageNamespace: rebuildHex(raw.storageNamespace), endpoint: anchorEndpoint(raw.endpoint),
    anchorPublicKey: rebuildHex(raw.anchorPublicKey), approverPublicKey: rebuildHex(raw.approverPublicKey),
    clientSeed: rebuildHex(raw.clientSeed), testMode: raw.testMode === true,
    ...(raw.initialFault === undefined ? {} : { initialFault: raw.initialFault }) });
}
/** WASM 配置不包含由独立参数传递的 create/testMode。 */
export function rebuildConfiguration(options: ParsedRebuildOptions): Omit<RebuildOptions, "testMode"> {
  const { testMode: _testMode, ...config } = options;
  return config;
}
function anchorTest(value: unknown, testMode: boolean): { checkpoint: RebuildWindow } | undefined {
  if (value === undefined) return undefined;
  if (!testMode) throw new StorageError("TEST_MODE_REQUIRED", "Rebuild checkpoints require testMode.");
  const raw = object(value);
  if (Object.keys(raw).some(key => key !== "checkpoint") || !member(raw.checkpoint, WINDOWS)) throw invalid("Invalid rebuild checkpoint.");
  return Object.freeze({ checkpoint: raw.checkpoint });
}
export function rebuildRequest(value: unknown, testMode: boolean): RebuildRequest {
  const raw = object(value), control = anchorTest(raw.anchorTest, testMode);
  let parsed: RebuildRequest;
  if (raw.op === "status" || raw.op === "offer" || raw.op === "resume") {
    if (raw.test !== undefined || control !== undefined) throw invalid("Rebuild diagnostics do not accept test controls.");
    parsed = { op: raw.op };
  } else if (raw.op === "activate") {
    if (raw.test !== undefined || (control !== undefined && control.checkpoint !== "after_rebuild_link")) {
      throw invalid("Activation only accepts the rebuild link checkpoint.");
    }
    parsed = { op: "activate", plan: rebuildPlan(raw.plan), approval: rebuildSigned(raw.approval) };
  } else {
    if (raw.op === "initialize" || raw.op === "create_group") throw invalid("The successor cannot initialize or create a group through this entry.");
    if (control?.checkpoint === "after_rebuild_link") throw invalid("The rebuild link checkpoint only applies to activation.");
    const crypto = cryptoRequest(raw, testMode);
    if (crypto.op === "initialize" || crypto.op === "create_group") throw invalid("Unsupported successor operation.");
    if (control !== undefined && crypto.op !== "inspect" && crypto.test !== undefined) {
      throw invalid("Use one crypto fault or anchor checkpoint at a time.");
    }
    parsed = crypto;
  }
  if (control !== undefined) parsed = { ...parsed, anchorTest: control };
  if (new TextEncoder().encode(JSON.stringify(parsed)).length > 256 * 1024) throw invalid("Rebuild command exceeds 256 KiB.");
  return parsed;
}
export function rebuildCommand(value: unknown, test: unknown, testMode: boolean): RebuildRequest {
  if (test === undefined) return rebuildRequest(value, testMode);
  if (!testMode) throw new StorageError("TEST_MODE_REQUIRED", "Rebuild test controls require testMode.");
  const raw = object(test);
  if (Object.keys(raw).some(key => !["fault", "checkpoint", "anchorCheckpoint"].includes(key))) throw invalid("Unknown rebuild test control.");
  const crypto = raw.fault === undefined && raw.checkpoint === undefined ? undefined : { fault: raw.fault, checkpoint: raw.checkpoint };
  const control = raw.anchorCheckpoint === undefined ? undefined : { checkpoint: raw.anchorCheckpoint };
  return rebuildRequest({ ...object(value), test: crypto, anchorTest: control }, testMode);
}
export function rebuildOutcome(value: unknown, options: ParsedRebuildOptions): ResultOutcome<RebuildView> {
  const raw = object(value);
  if (raw.ok === false && raw.result === undefined) return { ok: false, error: wireError(raw.error) };
  if (raw.ok !== true || raw.error !== undefined) throw new StorageError("INVALID_RESPONSE", "Invalid rebuild outcome.", true);
  try {
    const view = object(raw.result);
    if (!member(view.phase, ["candidate", "linked", "ready", "paused"])) throw invalid("Invalid rebuild phase.");
    const candidate = view.candidate === null ? null : rebuildOffer(view.candidate);
    if (candidate !== null && (candidate.scope.service !== options.service || candidate.scope.account !== options.account
        || candidate.scope.device !== options.device || candidate.storageNamespace !== options.storageNamespace
        || candidate.scope.store_id !== options.storageNamespace)) throw invalid("Rebuild candidate scope is invalid.");
    let snapshot = null;
    if (view.snapshot !== null) {
      if (view.phase !== "ready") throw invalid("Unready successor cannot return a crypto snapshot.");
      const result = cryptoOutcome({ ok: true, result: view.snapshot }, options.service, options.account);
      if (!result.ok) throw invalid("Invalid successor crypto snapshot.");
      if (result.result.device !== options.device || result.result.identity?.device !== options.device
          || result.result.outbox.some(record => record.envelope.senderDevice !== options.device)) {
        throw invalid("Successor snapshot device does not match its storage owner.");
      }
      snapshot = result.result;
    }
    const status = view.status === null ? null : anchorStatus(view.status);
    if (snapshot !== null && (status === null || status.phase !== "ready")) throw invalid("Successor snapshot requires confirmed anchor status.");
    return { ok: true, result: Object.freeze({ phase: view.phase, candidate, snapshot, status }) };
  } catch (error) {
    throw new StorageError("INVALID_RESPONSE", error instanceof Error ? error.message : "Invalid rebuild result.", true);
  }
}
export function parseRebuildOutcome(value: unknown, options: ParsedRebuildOptions, op: RebuildRequest["op"]): ResultOutcome<RebuildView> {
  const result = rebuildOutcome(parseJsonResult(value), options);
  if (result.ok && ["status", "offer", "activate", "resume"].includes(op) && result.result.snapshot !== null) {
    throw new StorageError("INVALID_RESPONSE", "Rebuild diagnostics and activation cannot expose crypto snapshots.", true);
  }
  return result;
}
