import { SdkError, Transport } from './transport.mjs';
import * as v from './validation.js';
import type { CredentialProvider, CredentialResult, Scope } from './types.js';

/** 仅桥接宿主认证与取消。请求/期限/重试由Rust决定，不创建消息或连接状态机。 */
export class AuthenticationBridge {
  #provider: CredentialProvider | undefined;
  readonly #pending = new Map<string, AbortController>();
  constructor(readonly transport: Transport, readonly scope: Scope) {}
  start(provider: CredentialProvider | undefined): void { this.stop(); this.#provider = provider; }
  stop(): void {
    this.#provider = undefined;
    for (const controller of this.#pending.values()) controller.abort();
    this.#pending.clear();
  }
  handle(data: unknown): boolean {
    const event = v.object(data);
    if (event.kind !== 'credential_request' && event.kind !== 'credential_cancel') return false;
    const scope = v.scope(event.scope), id = v.string(event.request_id);
    if (!v.sameScope(scope, this.scope) || !/^auth-[0-9a-f]{32}-[1-9][0-9]*$/.test(id)) throw new SdkError('ipc_protocol_error', true);
    if (event.kind === 'credential_cancel') {
      this.#pending.get(id)?.abort(); this.#pending.delete(id); return true;
    }
    if (event.reason !== 'initial' && event.reason !== 'expired' ||
        typeof event.attempt !== 'number' || !Number.isInteger(event.attempt) || event.attempt < 1 || event.attempt > 3 ||
        typeof event.timeout_ms !== 'number' || !Number.isInteger(event.timeout_ms) || event.timeout_ms < 100 || event.timeout_ms > 30000)
      throw new SdkError('ipc_protocol_error', true);
    const provider = this.#provider;
    if (!provider) return true; // disconnect已发出，原Rust事件可以仍在管道中。
    if (this.#pending.size) throw new SdkError('ipc_protocol_error', true);
    const controller = new AbortController(); this.#pending.set(id, controller);
    const request = Object.freeze({ scope: Object.freeze(scope), request_id: id, reason: event.reason,
      attempt: event.attempt, timeout_ms: event.timeout_ms, signal: controller.signal });
    // 不await宿主Promise；close有界，忽略signal的宿主迟到成功/失败均不可应用。
    Promise.resolve().then(() => provider(request)).then(
      result => this.#respond(id, controller, result),
      () => this.#respond(id, controller, { kind: 'failure', code: 'provider_failed' }),
    ).catch(() => this.transport.stop(new SdkError('authentication_bridge_failed', true)));
    return true;
  }
  async #respond(id: string, controller: AbortController, value: unknown): Promise<void> {
    if (this.#pending.get(id) !== controller || controller.signal.aborted) return;
    let result: CredentialResult;
    try { result = parseResult(value); }
    catch { result = { kind: 'failure', code: 'invalid_credential' }; }
    this.#pending.delete(id);
    try { await this.transport.control({ op: 'authentication_result', request_id: id, result }); }
    catch (error) {
      if (!(error instanceof SdkError) || !['stale_authentication', 'closed'].includes(error.code)) throw error;
    }
  }
}
function parseResult(data: unknown): CredentialResult {
  const r = v.object(data);
  if (r.kind === 'credential') {
    const c = v.object(r.credential);
    return { kind: r.kind, credential: { scope: v.scope(c.scope), token: v.string(c.token), expires_at_unix_ms: v.string(c.expires_at_unix_ms) } };
  }
  if (r.kind === 'failure' && (r.code === 'unavailable' || r.code === 'login_required' || r.code === 'forbidden' ||
      r.code === 'cancelled' || r.code === 'invalid_credential' || r.code === 'provider_failed')) return { kind: r.kind, code: r.code };
  throw new SdkError('invalid_credential');
}
