import type { Scope, Identity, Envelope, Received, Outcome, State, DownloadOutcome, Change, Runtime } from './types.js';
export function object(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('invalid_response');
  return value as Record<string, unknown>;
}
export function string(value: unknown): string {
  if (typeof value !== 'string') throw new Error('invalid_response');
  return value;
}
function boolean(value: unknown): boolean {
  if (typeof value !== 'boolean') throw new Error('invalid_response');
  return value;
}
function number(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) throw new Error('invalid_response');
  return value;
}
function decimal(value: unknown): string {
  const result = string(value);
  if (!/^(0|[1-9][0-9]*)$/.test(result) || BigInt(result) > 18446744073709551615n) throw new Error('invalid_response');
  return result;
}
export function array(value: unknown): unknown[] {
  if (!Array.isArray(value)) throw new Error('invalid_response');
  return value;
}
export function scope(value: unknown): Scope {
  const v = object(value);
  return { service: string(v.service), account: string(v.account), device: string(v.device) };
}
export function identity(value: unknown): Identity {
  const v = object(value);
  return { ...scope(v), identityKey: string(v.identityKey), keyPackage: string(v.keyPackage) };
}
export function envelope(value: unknown): Envelope {
  const v = object(value);
  return { service: string(v.service), conversation: string(v.conversation), senderAccount: string(v.senderAccount),
    senderDevice: string(v.senderDevice), messageId: string(v.messageId), ciphertext: string(v.ciphertext) };
}
export function received(value: unknown): Received {
  const v = object(value), m = object(v.message);
  return { sequence: decimal(v.sequence), duplicate: boolean(v.duplicate),
    message: { messageId: string(m.messageId), senderAccount: string(m.senderAccount), text: string(m.text) } };
}
export function outcome<T>(value: unknown, kind: string, parse: (value: unknown) => T): Outcome<T> {
  const v = object(value);
  if (v.kind !== kind) throw new Error('invalid_response');
  return { revision: decimal(v.revision), kind, cached: boolean(v.cached), value: parse(v.value) };
}
export function state(value: unknown): State {
  const v = object(value);
  return { scope: scope(v.scope), revision: decimal(v.revision), identity: v.identity === null ? null : identity(v.identity),
    conversation: v.conversation === null ? null : string(v.conversation), pending: boolean(v.pending),
    outbox: array(v.outbox).map(item => { const o = object(item); return {
      attemptId: string(o.attempt_id), messageId: string(o.message_id), ciphertextHash: string(o.ciphertext_hash) }; }),
    processedCursor: decimal(v.processed_cursor), downloadCursor: decimal(v.download_cursor), receivedCount: number(v.received_count) };
}
export function download(value: unknown): DownloadOutcome {
  const v = object(value);
  return { downloadCursor: decimal(v.download_cursor), processedCursor: decimal(v.processed_cursor), added: number(v.added), cached: boolean(v.cached) };
}
export function change(value: unknown): Change {
  const v = object(value), base = { scope: scope(v.scope), kind: string(v.kind) };
  return v.kind === 'download' ? { ...base, downloadCursor: decimal(v.download_cursor), processedCursor: decimal(v.processed_cursor) }
    : { ...base, revision: decimal(v.revision) };
}
export function runtime(value: unknown): Runtime {
  const v = object(value);
  if (v.databaseThread === v.coordinatorThread) throw new Error('invalid_response');
  return { pid: number(v.pid), os: string(v.os), arch: string(v.arch), databaseThread: string(v.databaseThread), coordinatorThread: string(v.coordinatorThread) };
}
export function sameScope(a: Scope, b: Scope): boolean {
  return a.service === b.service && a.account === b.account && a.device === b.device;
}
