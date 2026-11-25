import { SdkError } from './transport.mjs';
import type * as T from './types.js';
function bad(): never { throw new SdkError('ipc_protocol_error', true); }
export function object(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return bad();
  return value as Record<string, unknown>;
}
export function string(value: unknown): string { if (typeof value !== 'string') return bad(); return value; }
export function bool(value: unknown): boolean { if (typeof value !== 'boolean') return bad(); return value; }
function id(v: unknown): string { const s = string(v); if (!/^[A-Za-z0-9_-]{1,64}$/.test(s)) return bad(); return s; }
function hex(v: unknown): string { const s = string(v); if (!/^(?:[0-9a-f]{2})+$/.test(s)) return bad(); return s; }
export function count(v: unknown): string {
  const s = string(v); if (!/^(0|[1-9][0-9]{0,19})$/.test(s) || BigInt(s) > 18446744073709551615n) return bad(); return s;
}
function nullable<T>(v: unknown, parser: (v: unknown) => T): T | null { return v === null ? null : parser(v); }
export function scope(value: unknown): T.Scope { const v = object(value); return { service: id(v.service), account: id(v.account), device: id(v.device) }; }
export function sameScope(a: T.Scope, b: T.Scope): boolean { return a.service === b.service && a.account === b.account && a.device === b.device; }
export function backupInfo(value: unknown): T.BackupInfo {
  const v = object(value), backup = hex(v.backup_id), snapshot = hex(v.snapshot);
  if ((v.format !== 1 && v.format !== 2) || backup.length !== 64 || snapshot.length !== 64) return bad();
  return {format: v.format, backup_id: backup, scope: scope(v.scope), revision: count(v.revision), snapshot};
}
export function identity(value: unknown): T.Identity { const v = object(value); const key = hex(v.identity_key); if (key.length !== 64) return bad(); return { scope: scope(v.scope), identity_key: key }; }
export function joining(value: unknown): T.JoiningMaterial { const v = object(value); return { identity: identity(v.identity), key_package: hex(v.key_package) }; }
export function envelope(value: unknown): T.Envelope {
  const v = object(value); return { service: id(v.service), conversation: id(v.conversation), sender_account: id(v.sender_account), sender_device: id(v.sender_device), message_id: id(v.message_id), ciphertext: hex(v.ciphertext), context: id(v.context) };
}
export function message(value: unknown): T.Message {
  const v = object(value); return { service: id(v.service), conversation: id(v.conversation), sender_account: id(v.sender_account), sender_device: id(v.sender_device), message_id: id(v.message_id), text: string(v.text), context: id(v.context) };
}
export function history(data: unknown): T.HistoryPage {
  const v = object(data);
  if (!Array.isArray(v.items) || (v.direction !== 'forward' && v.direction !== 'backward') ||
      typeof v.page_size !== 'number' || !Number.isInteger(v.page_size) || v.page_size < 1 || v.page_size > 64 ||
      v.items.length > v.page_size) return bad();
  const items = v.items.map(raw => { const item = object(raw); return { local_position: count(item.local_position), message: message(item.message), ...(item.rejection === undefined ? {} : {rejection: rejection(item.rejection)}) }; });
  const upper = count(v.upper_bound), done = bool(v.done), cursor = nullable(v.next_cursor, string);
  if (done !== (cursor === null) || (!done && (!items.length || !/^h1:[0-9]+:[0-9]+:[0-9a-f]{64}$/.test(cursor ?? ''))) ||
      items.some(i => BigInt(i.local_position) < 1n || BigInt(i.local_position) > BigInt(upper))) return bad();
  return { items, upper_bound: upper, direction: v.direction, page_size: v.page_size, next_cursor: cursor, done };
}
export function value(data: unknown): T.Value {
  const v = object(data);
  switch (v.kind) {
    case 'initialized': return { kind: v.kind, identity: identity(v.identity) };
    case 'created': return { kind: v.kind, welcome: hex(v.welcome) };
    case 'joined': return { kind: v.kind };
    case 'sent': return { kind: v.kind, envelope: envelope(v.envelope) };
    case 'received': return { kind: v.kind, message: message(v.message), position: count(v.position) };
    default: return bad();
  }
}
export function outcome(data: unknown): T.Outcome { const v = object(data); return { revision: count(v.revision), cached: bool(v.cached), value: value(v.value) }; }
export function state(data: unknown): T.State {
  const v = object(data); return { scope: scope(v.scope), revision: count(v.revision), context: id(v.context), identity: nullable(v.identity, identity), conversation: nullable(v.conversation, id), peer: nullable(v.peer, identity), received_count: count(v.received_count), pending_request: nullable(v.pending_request, id) };
}
export function request(data: unknown): T.RequestState {
  const v = object(data);
  if (v.status === 'missing' || v.status === 'pending') return { status: v.status };
  if (v.status === 'retired') return { status: v.status, context: id(v.context) };
  if (v.status === 'complete') return { status: v.status, outcome: outcome(v.outcome) };
  if (v.status === 'failed') { const e = object(v.error); return { status: v.status, error: { code: string(e.code), paused: bool(e.paused) } }; }
  return bad();
}
export function change(data: unknown): T.LocalChange {
  const v = object(data); if (v.kind !== 'local_commit' && v.kind !== 'context_changed') return bad();
  return { scope: scope(v.scope), request_id: id(v.request_id), revision: count(v.revision), kind: v.kind };
}
export function runtime(data: unknown): T.Runtime {
  const v = object(data); if (typeof v.pid !== 'number' || !Number.isSafeInteger(v.pid) || v.pid <= 0 || v.os !== 'macos' || v.arch !== 'aarch64') return bad();
  return { pid: v.pid, os: v.os, arch: v.arch };
}

export function recovery(data: unknown): T.RecoveryResult {
  const v = object(data); const phases = ['offered','building','prepared','joining','ready','committed','finished','closing','closed'] as const;
  const phase = phases.find(p => p === v.phase);
  if (v.phase !== null && phase === undefined) return bad();
  const commit = v.commit === null ? null : { revision: count(object(v.commit).revision), context: id(object(v.commit).context) };
  return { phase: phase ?? null, context: nullable(v.context,id), packet: nullable(v.packet,hex), commit };
}

function sdkError(data: unknown): { code: string; paused: boolean } { const e = object(data); return { code: string(e.code), paused: bool(e.paused) }; }
function acceptance(data: unknown): T.Acceptance { const a = object(data); return { request_id: id(a.request_id), message_id: id(a.message_id), sequence: count(a.sequence), envelope_hash: hex(a.envelope_hash) }; }
function rejection(data: unknown): T.SendRejection {
  const r = object(data);
  if (r.source !== 'service_send' || r.code !== 'message_limit' || Object.keys(r).length !== 2) return bad();
  return { source: r.source, code: r.code };
}
export function network(data: unknown): T.NetworkState {
  const v = object(data);
  if (v.connection !== 'offline' && v.connection !== 'authenticating' && v.connection !== 'connecting' && v.connection !== 'online' && v.connection !== 'recovering' && v.connection !== 'blocked') return bad();
  // 终态从同一1024条请求账本投影；256个普通消息槽与此界限分别校验。
  if (!Array.isArray(v.sending) || v.sending.length > 1024) return bad();
  const sending: T.SendingState[] = v.sending.map(item => {
    const s = object(item);
    const ack = nullable(s.acceptance, acceptance);
    const ids = { message_id: id(s.message_id), request_id: id(s.request_id) };
    if (s.status === 'rejected') {
      if (ack !== null) return bad();
      return {...ids, status: s.status, acceptance: null, rejection: rejection(s.rejection)};
    }
    if (s.rejection !== undefined) return bad();
    if (s.status === 'local_saved' || s.status === 'not_accepted') {
      if (ack !== null) return bad();
      return {...ids, status: s.status, acceptance: null};
    }
    if (s.status !== 'accepted' && s.status !== 'delivered' && s.status !== 'context_retired') return bad();
    if (ack === null) return bad();
    return { ...ids, status: s.status, acceptance: ack };
  });
  const downloaded = count(v.downloaded), processed = count(v.processed), reported = count(v.reported);
  if (BigInt(reported) > BigInt(processed) || BigInt(processed) > BigInt(downloaded)) return bad();
  if (!Array.isArray(v.unavailable_history) || v.unavailable_history.length > 256) return bad();
  const unavailable_history: T.UnavailableRecord[] = v.unavailable_history.map(raw => {
    const r = object(raw); if (r.reason !== 'context_retired') return bad();
    return { sequence: count(r.sequence), reason: r.reason, acceptance: acceptance(r.acceptance) };
  });
  return { connection: v.connection, error: nullable(v.error, sdkError), downloaded, processed, reported, sending,
    recovery: nullable(v.recovery, networkRecovery), unavailable_history };
}
export function networkRecovery(data: unknown): T.NetworkRecoveryState {
  const v = object(data); if (v.role !== 'target' && v.role !== 'peer') return bad();
  return {round_id: id(v.round_id), context: nullable(v.context,id), role:v.role, phase:string(v.phase), requires_action:bool(v.requires_action), request_id:id(v.request_id), request_hash:hex(v.request_hash), deadline:count(v.deadline)};
}
export function unavailableMessage(data: unknown): T.UnavailableMessage {
  const r=object(data); if(r.reason!=='context_retired') return bad();
  return {sequence:count(r.sequence), reason:r.reason, acceptance:acceptance(r.acceptance), envelope:envelope(r.envelope)};
}
export function networkChange(data: unknown): T.Change {
  const v = object(data), own = scope(v.scope);
  if (v.kind === 'network_state') return { kind: v.kind, scope: own, state: network(v.state) };
  if (v.kind === 'network_error') return { kind: v.kind, scope: own, error: sdkError(v.error) };
  return bad();
}
