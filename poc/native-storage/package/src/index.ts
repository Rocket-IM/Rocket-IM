import { Transport, StorageError, VERSION } from './transport.mjs';
import * as v from './validation.js';
import type { OpenOptions, Scope, Runtime, Change, CallOptions, Identity, Envelope, DownloadRecord } from './types.js';
export { StorageError, VERSION };
export type * from './types.js';

/** 单实例绑定单库和服务/账号/设备。所有 I/O 异步；不向宿主暴露数据库句柄或 provider。 */
export class DesktopStorage {
  readonly #transport: Transport;
  readonly #scope: Scope;
  readonly runtime: Runtime;
  readonly #listeners = new Set<(change: Change) => void | Promise<void>>();
  readonly #onListenerError: (error: unknown) => void;
  #closing = false;
  private constructor(transport: Transport, options: OpenOptions, handshake: unknown) {
    const ready = v.object(handshake);
    this.#scope = Object.freeze(v.scope(options.scope));
    if (!v.sameScope(v.scope(ready.scope), this.#scope)) throw new StorageError('scope_mismatch', true);
    this.#transport = transport;
    this.runtime = Object.freeze(v.runtime(ready.runtime));
    this.#onListenerError = options.onListenerError ?? (error => { queueMicrotask(() => { throw error; }); });
  }
  static async open(options: OpenOptions): Promise<DesktopStorage> {
    // 在首个 await 前复制宿主输入，避免迟到开库使用被修改的账号或路径。
    const captured = { ...options, scope: { ...options.scope } };
    const transport = await Transport.open(captured);
    try { return new DesktopStorage(transport, captured, await transport.ready); }
    catch (error) { transport.stop(error); await transport.close(); throw error; }
  }
  /** 返回取消订阅函数；事件仅代表本地事务提交，不代表 Service 接受、送达或已读。 */
  subscribe(listener: (change: Change) => void | Promise<void>): () => void {
    if (this.#closing) throw new StorageError('closed');
    this.#listeners.add(listener);
    return () => { this.#listeners.delete(listener); };
  }
  async #call<T>(operation: Record<string, unknown>, parse: (value: unknown) => T, options?: CallOptions): Promise<T> {
    if (this.#closing) throw new StorageError('closed');
    const reply = v.object(await this.#transport.request(operation, options));
    let result: T;
    let changes: Change[];
    try {
      result = parse(reply.result);
      changes = v.array(reply.events).map(v.change);
      if (changes.some(change => !v.sameScope(change.scope, this.#scope))) throw new StorageError('scope_mismatch', true);
    } catch (error) {
      this.#transport.stop(new StorageError('ipc_protocol_error', true)); throw error;
    }
    for (const change of changes) {
      for (const listener of [...this.#listeners]) {
        if (this.#closing || !this.#listeners.has(listener)) continue;
        try { Promise.resolve(listener(structuredClone(change))).catch(this.#onListenerError); }
        catch (error) { this.#onListenerError(error); }
      }
    }
    return result;
  }
  initialize(requestId: string, options?: CallOptions) {
    return this.#call({ op: 'initialize', request_id: requestId }, value => v.outcome(value, 'initialize', v.identity), options);
  }
  createGroup(requestId: string, conversation: string, peer: Identity, options?: CallOptions) {
    return this.#call({ op: 'create_group', request_id: requestId, conversation, peer },
      value => v.outcome(value, 'create_group', data => ({ welcome: v.string(v.object(data).welcome) })), options);
  }
  send(requestId: string, attemptId: string, messageId: string, text: string, options?: CallOptions) {
    return this.#call({ op: 'send', request_id: requestId, attempt_id: attemptId, message_id: messageId, text },
      value => v.outcome(value, 'send', v.envelope), options);
  }
  receive(requestId: string, sequence: string, envelope: Envelope, options?: CallOptions) {
    return this.#call({ op: 'receive', request_id: requestId, sequence, envelope },
      value => v.outcome(value, 'receive', v.received), options);
  }
  download(records: readonly DownloadRecord[], options?: CallOptions) {
    return this.#call({ op: 'download', records }, v.download, options);
  }
  process(requestId: string, sequence: string, options?: CallOptions) {
    return this.#call({ op: 'process', request_id: requestId, sequence }, value => v.outcome(value, 'receive', v.received), options);
  }
  received(sequence: string, options?: CallOptions) {
    return this.#call({ op: 'received', sequence }, v.received, options);
  }
  state(options?: CallOptions) {
    return this.#call({ op: 'state' }, value => {
      const state = v.state(value);
      if (!v.sameScope(state.scope, this.#scope)) throw new StorageError('scope_mismatch', true);
      return state;
    }, options);
  }
  /** 停止新请求与回调；等待已接受请求和 Rust 线程正常结束。调用可重复；未知提交须重开查询。 */
  close(): Promise<void> {
    this.#closing = true;
    this.#listeners.clear();
    return this.#transport.close();
  }
}
