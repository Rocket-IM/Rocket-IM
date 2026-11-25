import { SdkError } from './transport.mjs';
import { object, string, bool, scope, count } from './validation.js';
import type { Scope } from './types.js';

export interface CapacityBudget {
  readonly category: string; readonly unit: 'items' | 'bytes';
  readonly used: string; readonly limit: string; readonly hard_remaining: string;
}
export interface CapacityOperation {
  readonly operation: string; readonly state: 'requires_input' | 'not_reserved' | 'blocked' | 'bounded_ready';
  readonly blockers: readonly string[];
}
export interface CapacityBlocker {
  readonly code: string; readonly resource: string | null; readonly operations: readonly string[];
}
/** 单库逻辑快照。数字均为u64十进制字符串；观察ID不是执行许可。 */
export interface Capacity {
  readonly version: 'sdk-capacity-alpha2'; readonly owner: 'sdk'; readonly scope: Scope;
  readonly observation_id: string; readonly consistency: 'single_sqlite_read'; readonly revision: string;
  readonly cursors: { readonly downloaded: string; readonly processed: string; readonly reported: string } | null;
  readonly recovery: {
    readonly pending: string; readonly phase: string | null; readonly candidate: boolean;
    readonly locally_authorized: boolean; readonly network_phase: string | null;
  };
  readonly budgets: readonly CapacityBudget[];
  readonly components: readonly { readonly category: string; readonly included_in: 'meta_bytes'; readonly bytes: string }[];
  readonly reserve: { readonly state: 'not_enabled' | 'bounded_ready'; readonly protected_remaining: null; readonly ordinary_available: null; readonly resources: readonly { readonly category: string; readonly protected_remaining: string; readonly ordinary_available: string }[]; readonly work: readonly { readonly kind: string; readonly count: string }[] };
  readonly operations: readonly CapacityOperation[]; readonly blockers: readonly CapacityBlocker[];
  readonly physical: { readonly state: 'unavailable'; readonly reserved: false };
  readonly remote: { readonly state: 'unavailable'; readonly reserved: false };
}
const categories = ['requests','ordinary_messages','events','data_bytes','crypto_bytes','meta_bytes','history','archives','transitions'];
const operationNames = ['new_send','new_receive','retry_request','recover_pending','retry_send','download','process','report','install_candidate','new_recovery','authorized_recovery','first_backup','export','import'];
const reasons = ['request_limit','message_limit','data_preflight_limit','meta_preflight_limit','initialize_required','group_required','operation_pending','successor_required','recovery_active','candidate_missing','network_unbound','event_limit','recovery_limit','recovery_preflight_limit','backup_guard_limit'];
const phases = ['offered','building','prepared','joining','ready','committed','finished','closing','closed'];
function bad(): never { throw new SdkError('ipc_protocol_error', true); }
function exact(value: unknown, keys: readonly string[]): Record<string, unknown> {
  const v = object(value);
  if (Object.keys(v).length !== keys.length || keys.some(k => !Object.hasOwn(v, k))) return bad();
  return v;
}
function choice(value: unknown, values: readonly string[]): string {
  const v = string(value); if (!values.includes(v)) return bad(); return v;
}
function list<T>(value: unknown, max: number, parser: (v: unknown) => T): T[] {
  if (!Array.isArray(value) || value.length > max) return bad(); return value.map(parser);
}
function unique(values: readonly string[]): void { if (new Set(values).size !== values.length) bad(); }
function unavailable(value: unknown): Capacity['physical'] {
  const v = exact(value, ['state','reserved']);
  if (v.state !== 'unavailable' || v.reserved !== false) return bad();
  return { state: v.state, reserved: v.reserved };
}
export function capacity(value: unknown): Capacity {
  const v = exact(value, ['version','owner','scope','observation_id','consistency','revision','cursors','recovery','budgets','components','reserve','operations','blockers','physical','remote']);
  if (v.version !== 'sdk-capacity-alpha2' || v.owner !== 'sdk' || v.consistency !== 'single_sqlite_read') return bad();
  const observation = string(v.observation_id); if (!/^[0-9a-f]{64}$/.test(observation)) return bad();
  const own = scope(exact(v.scope, ['service','account','device']));
  let cursors: Capacity['cursors'] = null;
  if (v.cursors !== null) {
    const c = exact(v.cursors, ['downloaded','processed','reported']);
    cursors = { downloaded: count(c.downloaded), processed: count(c.processed), reported: count(c.reported) };
    if (BigInt(cursors.reported) > BigInt(cursors.processed) || BigInt(cursors.processed) > BigInt(cursors.downloaded)) return bad();
  }
  const r = exact(v.recovery, ['pending','phase','candidate','locally_authorized','network_phase']);
  const pending = choice(r.pending, ['none','reserved','initialization_retry','executing_unknown','legacy_unknown','complete_candidate']);
  const recovery = { pending, phase: r.phase === null ? null : choice(r.phase, phases), candidate: bool(r.candidate), locally_authorized: bool(r.locally_authorized),
    network_phase: r.network_phase === null ? null : choice(r.network_phase, [...phases,'complete','approval_required','reserving']) };
  if (recovery.candidate !== (pending === 'complete_candidate')) return bad();
  const budgets = list<CapacityBudget>(v.budgets, categories.length, raw => {
    const b = exact(raw, ['category','unit','used','limit','hard_remaining']);
    const category = choice(b.category, categories), used = count(b.used), limit = count(b.limit), remaining = count(b.hard_remaining);
    if ((b.unit !== 'bytes' && b.unit !== 'items') || (category.endsWith('_bytes') !== (b.unit === 'bytes')) || BigInt(used) > BigInt(limit) || BigInt(limit) - BigInt(used) !== BigInt(remaining)) return bad();
    return { category, unit: b.unit, used, limit, hard_remaining: remaining };
  });
  unique(budgets.map(b => b.category)); if (budgets.length !== categories.length) return bad();
  const components = list<Capacity['components'][number]>(v.components, 4, raw => {
    const c = exact(raw, ['category','included_in','bytes']);
    const category = choice(c.category, ['candidate_bytes','session_bytes','archives_bytes','legacy_bytes']);
    if (c.included_in !== 'meta_bytes') return bad();
    return { category, included_in: c.included_in, bytes: count(c.bytes) };
  });
  unique(components.map(c => c.category)); if (components.length !== 4) return bad();
  const reserve = exact(v.reserve, ['state','protected_remaining','ordinary_available','resources','work']);
  if ((reserve.state !== 'not_enabled' && reserve.state !== 'bounded_ready') || reserve.protected_remaining !== null || reserve.ordinary_available !== null) return bad();
  const resources = list<Capacity['reserve']['resources'][number]>(reserve.resources, categories.length, raw => {
    const r = exact(raw, ['category','protected_remaining','ordinary_available']);
    const category = choice(r.category, categories), protectedRemaining = count(r.protected_remaining), available = count(r.ordinary_available);
    const budget = budgets.find(b => b.category === category); if (!budget) return bad();
    if (BigInt(protectedRemaining) + BigInt(available) !== BigInt(budget.hard_remaining)) return bad();
    return { category, protected_remaining: protectedRemaining, ordinary_available: available };
  });
  unique(resources.map(r => r.category));
  const kinds = ['candidate_install','send_settlement','known_control','known_report','target_install','backup_guard'];
  const work = list<Capacity['reserve']['work'][number]>(reserve.work, kinds.length, raw => {
    const w = exact(raw, ['kind','count']); const kind = choice(w.kind, kinds), total = count(w.count);
    const max = ['candidate_install','target_install','backup_guard'].includes(kind) ? 1n : kind === 'send_settlement' ? 256n : 512n;
    if (BigInt(total) > max) return bad(); return { kind, count: total };
  });
  unique(work.map(w => w.kind));
  if (reserve.state === 'not_enabled' ? (resources.length !== 0 || work.length !== 0) : (resources.length !== categories.length || work.length !== kinds.length)) return bad();
  const blockers = list(v.blockers, 32, raw => {
    const b = exact(raw, ['code','resource','operations']);
    const operations = list(b.operations, operationNames.length, v => choice(v, operationNames)); unique(operations);
    if (!operations.length) return bad();
    return { code: choice(b.code, reasons), resource: b.resource === null ? null : choice(b.resource, categories), operations };
  });
  const operations = list<CapacityOperation>(v.operations, operationNames.length, raw => {
    const o = exact(raw, ['operation','state','blockers']), operation = choice(o.operation, operationNames);
    if (o.state !== 'requires_input' && o.state !== 'not_reserved' && o.state !== 'blocked' && o.state !== 'bounded_ready') return bad();
    const codes = list(o.blockers, reasons.length, v => choice(v, reasons)); unique(codes);
    const expected = new Set(blockers.filter(b => b.operations.includes(operation)).map(b => b.code));
    if ((o.state === 'blocked') !== (codes.length > 0) || codes.length !== expected.size || codes.some(c => !expected.has(c))) return bad();
    if (o.state === 'bounded_ready') {
      const kinds: Record<string,string> = {install_candidate:'candidate_install',retry_send:'send_settlement',process:'known_control',report:'known_report',authorized_recovery:'target_install'};
      if (reserve.state !== 'bounded_ready' || !work.some(w => w.kind === kinds[operation] && BigInt(w.count) > 0n)) return bad();
    }
    return { operation, state: o.state, blockers: codes };
  });
  unique(operations.map(o => o.operation)); if (operations.length !== operationNames.length) return bad();
  return { version: v.version, owner: v.owner, scope: own, observation_id: observation, consistency: v.consistency, revision: count(v.revision), cursors, recovery, budgets, components,
    reserve: { state: reserve.state, protected_remaining: null, ordinary_available: null, resources, work }, operations, blockers, physical: unavailable(v.physical), remote: unavailable(v.remote) };
}
