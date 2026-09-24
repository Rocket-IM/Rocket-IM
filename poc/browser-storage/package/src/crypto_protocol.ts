import { StorageError, identifier, member, object, parseJsonResult, recordText, revision, wireError } from "./protocol.js";
import type { ResultOutcome } from "./protocol.js";
import type { CryptoOpenOptions, CryptoRequest, CryptoSnapshot, CryptoTestOptions, DownloadEvent,
  Envelope, Identity, CryptoOperation } from "./crypto_types.js";

const OPERATIONS = ["initialize", "create_group", "join_group", "send", "process_next"] as const;
const FAULTS = ["after_crypto", "after_sql", "refuse_commit", "reserve_refuse", "lose_reservation_table"] as const;
const CHECKPOINTS = ["after_reserve", "after_crypto", "before_commit", "after_commit"] as const;
const CHANGES = ["none", "initialized", "grouped", "outbox_ready", "downloaded", "processed"] as const;
const MAX_BLOB_BYTES = 65536;

function invalid(message: string): StorageError { return new StorageError("INVALID_ARGUMENT", message); }
function device(value: unknown): string { return identifier(value, "device"); }
function digest(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) throw invalid("Expected a lowercase SHA-256 digest.");
  return value;
}
function base64(value: unknown, allowEmpty = false, exactBytes?: number): string {
  if (typeof value !== "string" || value.length > 87384 || (!allowEmpty && value.length === 0)
      || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw invalid("Expected bounded canonical base64.");
  }
  const decoded = atob(value);
  if (decoded.length > MAX_BLOB_BYTES || (exactBytes !== undefined && decoded.length !== exactBytes)
      || btoa(decoded) !== value) throw invalid("Base64 size or canonical encoding is invalid.");
  return value;
}
function text(value: unknown): string {
  const parsed = recordText(value);
  if (parsed.length === 0) throw invalid("Message text must not be empty.");
  return parsed;
}
export function identity(value: unknown): Identity {
  const raw = object(value);
  return Object.freeze({ service: identifier(raw.service, "service"), account: identifier(raw.account, "account"),
    device: device(raw.device), identityKey: base64(raw.identityKey, false, 32), keyPackage: base64(raw.keyPackage, true) });
}
export function envelope(value: unknown): Envelope {
  const raw = object(value);
  return Object.freeze({ service: identifier(raw.service, "service"), conversation: identifier(raw.conversation, "conversation"),
    senderAccount: identifier(raw.senderAccount, "senderAccount"), senderDevice: device(raw.senderDevice),
    messageId: identifier(raw.messageId, "messageId"), ciphertext: base64(raw.ciphertext) });
}
export function downloadEvent(value: unknown): DownloadEvent {
  const raw = object(value);
  return Object.freeze({ sequence: revision(raw.sequence), eventId: identifier(raw.eventId, "eventId"), envelope: envelope(raw.envelope) });
}
export function cryptoOpenOptions(value: unknown): Required<CryptoOpenOptions> {
  const raw = object(value);
  if (raw.testMode !== undefined && typeof raw.testMode !== "boolean") throw invalid("testMode must be a boolean.");
  return { service: identifier(raw.service, "service"), account: identifier(raw.account, "account"), testMode: raw.testMode === true };
}
function testOptions(value: unknown, testMode: boolean): CryptoTestOptions | undefined {
  if (value === undefined) return undefined;
  if (!testMode) throw new StorageError("TEST_MODE_REQUIRED", "Crypto fault controls require testMode.");
  const raw = object(value), result: CryptoTestOptions = {};
  if (Object.keys(raw).some(key => key !== "fault" && key !== "checkpoint")) throw invalid("Unknown crypto test control.");
  if (raw.fault !== undefined) {
    if (!member(raw.fault, FAULTS)) throw invalid("Unknown crypto test fault.");
    result.fault = raw.fault;
  }
  if (raw.checkpoint !== undefined) {
    if (!member(raw.checkpoint, CHECKPOINTS)) throw invalid("Unknown crypto checkpoint.");
    result.checkpoint = raw.checkpoint;
  }
  if (result.fault !== undefined && result.checkpoint !== undefined) throw invalid("Use one crypto fault or checkpoint at a time.");
  return result;
}
export function cryptoRequest(value: unknown, testMode: boolean): CryptoRequest {
  const raw = object(value), test = testOptions(raw.test, testMode);
  if (test?.fault === "lose_reservation_table" && raw.op !== "send") {
    throw invalid("Reservation table loss is only available for the send experiment.");
  }
  let parsed: CryptoRequest;
  switch (raw.op) {
    case "inspect":
      if (test !== undefined) throw invalid("Inspect does not accept fault controls.");
      parsed = { op: "inspect" }; break;
    case "initialize": case "process_next": parsed = { op: raw.op, test }; break;
    case "create_group": parsed = { op: raw.op, conversation: identifier(raw.conversation, "conversation"), peer: identity(raw.peer), test }; break;
    case "join_group": parsed = { op: raw.op, conversation: identifier(raw.conversation, "conversation"),
      peer: identity(raw.peer), welcome: base64(raw.welcome), test }; break;
    case "send": parsed = { op: raw.op, attemptId: identifier(raw.attemptId, "attemptId"),
      messageId: identifier(raw.messageId, "messageId"), text: text(raw.text), test }; break;
    case "download":
      if (test?.fault === "after_crypto" || test?.fault === "reserve_refuse"
          || test?.checkpoint === "after_reserve" || test?.checkpoint === "after_crypto") {
        throw invalid("Download has no crypto reservation or encryption checkpoint.");
      }
      parsed = { op: raw.op, event: downloadEvent(raw.event), test }; break;
    default: throw invalid("Unknown crypto operation.");
  }
  if (new TextEncoder().encode(JSON.stringify(parsed)).length > 256 * 1024) throw invalid("Crypto request exceeds 256 KiB.");
  return parsed;
}
function array<T>(value: unknown, parse: (value: unknown) => T): readonly T[] {
  if (!Array.isArray(value) || value.length > 32) throw invalid("Crypto snapshot arrays are limited to 32 entries.");
  return Object.freeze(value.map((entry: unknown) => parse(entry)));
}
function pending(value: unknown): CryptoSnapshot["pending"] {
  if (value === null) return null;
  const raw = object(value);
  if (!member(raw.operation, OPERATIONS)) throw invalid("Invalid pending crypto operation.");
  const operation: CryptoOperation = raw.operation;
  return Object.freeze({ operation, attemptId: identifier(raw.attemptId, "attemptId") });
}
function snapshot(value: unknown, service: string, account: string): CryptoSnapshot {
  const raw = object(value);
  if (raw.service !== service || raw.account !== account || !member(raw.status, ["empty", "ready", "paused"])
      || !member(raw.change, CHANGES)) throw invalid("Crypto snapshot scope or status is invalid.");
  const owner = raw.identity === null ? null : identity(raw.identity);
  if (owner !== null && (owner.service !== service || owner.account !== account)) throw invalid("Crypto identity scope is invalid.");
  return Object.freeze({ service, account, device: device(raw.device), status: raw.status, revision: revision(raw.revision),
    identity: owner, conversation: raw.conversation === null ? null : identifier(raw.conversation, "conversation"),
    providerHash: raw.providerHash === null ? null : digest(raw.providerHash), pending: pending(raw.pending),
    encryptions: revision(raw.encryptions), decryptions: revision(raw.decryptions), downloadCursor: revision(raw.downloadCursor),
    processingCursor: revision(raw.processingCursor), welcome: raw.welcome === null ? null : base64(raw.welcome), change: raw.change,
    ...(raw.commitment === undefined ? {} : { commitment: digest(raw.commitment) }),
    outbox: array(raw.outbox, value => {
      const row = object(value), encoded = envelope(row.envelope);
      if (encoded.service !== service || encoded.senderAccount !== account) throw invalid("Outbox scope is invalid.");
      return Object.freeze({ attemptId: identifier(row.attemptId, "attemptId"), messageId: identifier(row.messageId, "messageId"),
        plaintextHash: digest(row.plaintextHash), ciphertextHash: digest(row.ciphertextHash), envelope: encoded });
    }),
    events: array(raw.events, value => {
      const row = object(value);
      if (!member(row.status, ["pending", "processed", "duplicate"])) throw invalid("Invalid crypto event status.");
      return Object.freeze({ sequence: revision(row.sequence), eventId: identifier(row.eventId, "eventId"),
        ciphertextHash: digest(row.ciphertextHash), status: row.status });
    }),
    messages: array(raw.messages, value => {
      const row = object(value);
      return Object.freeze({ sequence: revision(row.sequence), eventId: identifier(row.eventId, "eventId"),
        messageId: identifier(row.messageId, "messageId"), senderAccount: identifier(row.senderAccount, "senderAccount"), text: text(row.text) });
    }),
    receipts: array(raw.receipts, value => identifier(value, "receipt eventId")),
  });
}
export function cryptoOutcome(value: unknown, service: string, account: string): ResultOutcome<CryptoSnapshot> {
  const raw = object(value);
  if (raw.ok === false && raw.result === undefined) return { ok: false, error: wireError(raw.error) };
  if (raw.ok !== true || raw.error !== undefined) throw new StorageError("INVALID_RESPONSE", "Invalid crypto outcome.", true);
  try { return { ok: true, result: snapshot(raw.result, service, account) }; }
  catch (error) {
    throw new StorageError("INVALID_RESPONSE", error instanceof Error ? error.message : "Invalid crypto snapshot.", true);
  }
}
export function parseCryptoOutcome(value: unknown, service: string, account: string): ResultOutcome<CryptoSnapshot> {
  return cryptoOutcome(parseJsonResult(value), service, account);
}
