/** 仅描述跨 Worker 的公开值；不含数据库或 SQL 实现。 */
export const VERSION = "0.1.0-q05.4";
export const MAX_PENDING = 64;
export const COMMAND_TIMEOUT_MS = 20000;
const MAX_REVISION = 18446744073709551615n;

export interface RecordValue { readonly key: string; readonly value: string; }
export interface Snapshot {
  readonly service: string;
  readonly account: string;
  readonly schemaVersion: 1 | 2;
  readonly revision: string;
  readonly records: readonly RecordValue[];
  readonly sqliteVersion: string;
}
export interface OpenOptions {
  service: string;
  account: string;
  testMode?: boolean;
  seedV1?: boolean;
  failMigration?: boolean;
}
export interface PutTestOptions {
  fault?: "write_then_rollback" | "refuse_commit";
  checkpoint?: "before_commit" | "after_commit";
}
const BROWSER_ERROR_NAMES = ["QuotaExceededError", "NotAllowedError", "InvalidStateError", "NotFoundError",
  "NotSupportedError", "NoModificationAllowedError", "SecurityError", "AbortError", "DataError",
  "InvalidModificationError", "TypeMismatchError", "UnknownError", "TypeError", "RangeError",
  "UnclassifiedBrowserError"] as const;
const OPFS_OPERATIONS = ["get_directory", "get_file", "create_sync_access_handle", "iterate_directory",
  "get_path", "remove_entity", "get_size", "read", "write", "flush", "truncate", "reflect",
  "dedicated_worker_required", "vfs_registration", "import_database", "pool_state"] as const;
const BINDING_ERROR_NAMES = ["query_returned_no_rows", "invalid_column_type", "value_conversion_failed", "binding_error"] as const;
type BrowserErrorName = typeof BROWSER_ERROR_NAMES[number];
export type StorageCause =
  | { readonly source: "sqlite"; readonly code: number; readonly extendedCode: number }
  | { readonly source: "sqlite_binding"; readonly name: typeof BINDING_ERROR_NAMES[number] }
  | { readonly source: "opfs"; readonly operation: typeof OPFS_OPERATIONS[number]; readonly name: BrowserErrorName | "OpfsError" }
  | { readonly source: "browser"; readonly name: BrowserErrorName };
export interface WireError { code: string; message: string; paused: boolean; cause?: StorageCause; }
export type ResultOutcome<T> = { ok: true; result: T } | { ok: false; error: WireError };
export type Outcome = ResultOutcome<Snapshot>;
export type Checkpoint = "before_commit" | "after_commit";
export type Request = { op: "snapshot" } | { op: "read_fault" } | {
  op: "put"; key: string; value: string; expectedRevision: string;
  fault?: PutTestOptions["fault"]; checkpoint?: PutTestOptions["checkpoint"];
};

export class StorageError extends Error {
  constructor(readonly code: string, message: string, readonly paused = false, readonly cause?: StorageCause) {
    super(message);
    this.name = "StorageError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
export function object(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new StorageError("INVALID_RESPONSE", "Expected an object.", true);
  }
  return value;
}
export function identifier(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(value)) {
    throw new StorageError("INVALID_ARGUMENT", `${label} must contain 1–64 safe ASCII characters.`);
  }
  return value;
}
export function revision(value: unknown): string {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,19})$/.test(value) || BigInt(value) > MAX_REVISION) {
    throw new StorageError("INVALID_ARGUMENT", "Revision must be an unsigned 64-bit decimal string.");
  }
  return value;
}
export function recordText(value: unknown): string {
  if (typeof value !== "string" || new TextEncoder().encode(value).length > 4096) {
    throw new StorageError("INVALID_ARGUMENT", "Value must contain at most 4096 UTF-8 bytes.");
  }
  return value;
}
export function openOptions(value: unknown): Required<OpenOptions> {
  const raw = object(value);
  for (const name of ["testMode", "seedV1", "failMigration"]) {
    if (raw[name] !== undefined && typeof raw[name] !== "boolean") {
      throw new StorageError("INVALID_ARGUMENT", `${name} must be a boolean.`);
    }
  }
  const testMode = raw.testMode === true;
  if (!testMode && (raw.seedV1 === true || raw.failMigration === true)) {
    throw new StorageError("TEST_MODE_REQUIRED", "Migration fault controls require testMode.");
  }
  return { service: identifier(raw.service, "service"), account: identifier(raw.account, "account"),
    testMode, seedV1: raw.seedV1 === true, failMigration: raw.failMigration === true };
}
export function request(value: unknown, testMode: boolean): Request {
  const raw = object(value);
  if (raw.op === "snapshot") return { op: "snapshot" };
  if (raw.op === "read_fault") {
    if (!testMode) throw new StorageError("TEST_MODE_REQUIRED", "Read fault controls require testMode.");
    return { op: "read_fault" };
  }
  if (raw.op !== "put") throw new StorageError("INVALID_ARGUMENT", "Unknown operation.");
  const parsed: Request = { op: "put", key: identifier(raw.key, "key"), value: recordText(raw.value),
    expectedRevision: revision(raw.expectedRevision) };
  if (raw.fault !== undefined) {
    if (!testMode) throw new StorageError("TEST_MODE_REQUIRED", "Fault controls require testMode.");
    if (raw.fault !== "write_then_rollback" && raw.fault !== "refuse_commit") {
      throw new StorageError("INVALID_ARGUMENT", "Unknown test fault.");
    }
    parsed.fault = raw.fault;
  }
  if (raw.checkpoint !== undefined) {
    if (!testMode) throw new StorageError("TEST_MODE_REQUIRED", "Checkpoints require testMode.");
    if (raw.checkpoint !== "before_commit" && raw.checkpoint !== "after_commit") {
      throw new StorageError("INVALID_ARGUMENT", "Unknown test checkpoint.");
    }
    parsed.checkpoint = raw.checkpoint;
  }
  return parsed;
}
export function member<T extends string>(value: unknown, choices: readonly T[]): value is T {
  return typeof value === "string" && choices.some(choice => choice === value);
}
function storageCause(value: unknown): StorageCause {
  const raw = object(value);
  if (raw.source === "sqlite" && typeof raw.code === "number" && Number.isInteger(raw.code)
      && raw.code >= 0 && raw.code <= 255 && typeof raw.extendedCode === "number"
      && Number.isInteger(raw.extendedCode) && raw.extendedCode >= -2147483648 && raw.extendedCode <= 2147483647) {
    return Object.freeze({ source: "sqlite", code: raw.code, extendedCode: raw.extendedCode });
  }
  if (raw.source === "sqlite_binding" && member(raw.name, BINDING_ERROR_NAMES)) {
    return Object.freeze({ source: "sqlite_binding", name: raw.name });
  }
  if (raw.source === "opfs" && member(raw.operation, OPFS_OPERATIONS)
      && (raw.name === "OpfsError" || member(raw.name, BROWSER_ERROR_NAMES))) {
    return Object.freeze({ source: "opfs", operation: raw.operation, name: raw.name });
  }
  if (raw.source === "browser" && member(raw.name, BROWSER_ERROR_NAMES)) {
    return Object.freeze({ source: "browser", name: raw.name });
  }
  throw new StorageError("INVALID_RESPONSE", "Invalid structured storage diagnostic.", true);
}
export function wireError(value: unknown): WireError {
  const raw = object(value);
  if (typeof raw.code !== "string" || !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(raw.code)
      || typeof raw.message !== "string" || raw.message.length > 2048 || typeof raw.paused !== "boolean") {
    throw new StorageError("INVALID_RESPONSE", "Invalid storage error envelope.", true);
  }
  return { code: raw.code, message: raw.message, paused: raw.paused,
    ...(raw.cause === undefined ? {} : { cause: storageCause(raw.cause) }) };
}
export function outcome(value: unknown, service: string, account: string): Outcome {
  const raw = object(value);
  if (raw.ok === false && raw.result === undefined) return { ok: false, error: wireError(raw.error) };
  if (raw.ok !== true || raw.error !== undefined) throw new StorageError("INVALID_RESPONSE", "Invalid storage outcome.", true);
  const data = object(raw.result);
  if (data.service !== service || data.account !== account || (data.schemaVersion !== 1 && data.schemaVersion !== 2)
      || !Array.isArray(data.records) || data.records.length > 128
      || typeof data.sqliteVersion !== "string" || data.sqliteVersion.length > 64) {
    throw new StorageError("INVALID_RESPONSE", "Snapshot scope or shape is invalid.", true);
  }
  const keys = new Set<string>();
  const records = data.records.map((entry: unknown) => {
    const item = object(entry), key = identifier(item.key, "record key"), value = recordText(item.value);
    if (keys.has(key)) throw new StorageError("INVALID_RESPONSE", "Duplicate snapshot key.", true);
    keys.add(key);
    return Object.freeze({ key, value });
  });
  return { ok: true, result: Object.freeze({ service, account, schemaVersion: data.schemaVersion,
    revision: revision(data.revision), records: Object.freeze(records), sqliteVersion: data.sqliteVersion }) };
}
export function parseOutcome(text: unknown, service: string, account: string): Outcome {
  return outcome(parseJsonResult(text), service, account);
}
export function parseJsonResult(text: unknown): unknown {
  // 128 条 4096 字节 NUL 值经 JSON 转义可超过 3 MiB，必须容纳全部合法快照。
  if (typeof text !== "string" || text.length > 4 * 1024 * 1024) {
    throw new StorageError("INVALID_RESPONSE", "Rust result is absent or oversized.", true);
  }
  let parsed: unknown;
  try { parsed = JSON.parse(text); }
  catch (error) {
    throw new StorageError("INVALID_RESPONSE", error instanceof Error ? error.message : "Rust result is not JSON.", true);
  }
  return parsed;
}
