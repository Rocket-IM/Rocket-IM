import { SdkError } from './transport.mjs';
import { object, identity, count, string } from './validation.js';
import type { Identity } from './types.js';

interface CapacityWorksetFields {
  readonly id: string;
  readonly owner: Identity;
  readonly sdk_instance: string;
  readonly conversation: string;
  readonly context: string;
  readonly first: string;
  readonly last: string;
  readonly originals_hash: string;
}
export type CapacityWorkset = CapacityWorksetFields & (
  { readonly version: 'control-workset-v1'; readonly previous?: never } |
  { readonly version: 'control-workset-v2'; readonly previous: string }
);
export interface CapacityWorksetState {
  readonly workset: CapacityWorkset;
  readonly phase: 'prepared' | 'confirmed' | 'active' | 'settled';
}
function bad(): never { throw new SdkError('ipc_protocol_error', true); }
function exact(v: Record<string, unknown>, keys: string[]): void {
  if (Object.keys(v).length !== keys.length || keys.some(k => !(k in v))) bad();
}
function digest(v: unknown): string { const s = string(v); return /^[0-9a-f]{64}$/.test(s) ? s : bad(); }
export function worksetState(value: unknown): CapacityWorksetState | null {
  if (value === null) return null;
  const s = object(value); exact(s, ['workset', 'phase']);
  if (s.phase !== 'prepared' && s.phase !== 'confirmed' && s.phase !== 'active' && s.phase !== 'settled') return bad();
  const w = object(s.workset);
  const keys = ['version', 'id', 'owner', 'sdk_instance', 'conversation', 'context', 'first', 'last', 'originals_hash'];
  if (w.version === 'control-workset-v2') keys.push('previous');
  else if (w.version !== 'control-workset-v1') return bad();
  exact(w, keys);
  const owner = object(w.owner); exact(owner, ['scope', 'identity_key']);
  exact(object(owner.scope), ['service', 'account', 'device']);
  const first = count(w.first), last = count(w.last), conversation = string(w.conversation), context = string(w.context);
  if (BigInt(first) < 1n || BigInt(first) > BigInt(last) || BigInt(last) > 512n ||
      !/^[A-Za-z0-9_-]{1,64}$/.test(conversation) || (context !== 'initial' && !/^[0-9a-f]{64}$/.test(context))) return bad();
  const fields = {id: digest(w.id), owner: identity(owner), sdk_instance: digest(w.sdk_instance),
    conversation, context, first, last, originals_hash: digest(w.originals_hash)};
  return {phase:s.phase, workset:w.version === 'control-workset-v2'
    ? {...fields,version:w.version,previous:digest(w.previous)} : {...fields,version:w.version}};
}
