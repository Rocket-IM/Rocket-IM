import { Transport, SdkError, VERSION } from './transport.mjs';
import * as v from './validation.js';
import type * as T from './types.js';
import { capacity } from './capacity.js';
import type { Capacity } from './capacity.js';
import { worksetState } from './workset.js';
import type { CapacityWorksetState } from './workset.js';
export type { CapacityWorkset, CapacityWorksetState } from './workset.js';
export type { Capacity, CapacityBudget, CapacityOperation, CapacityBlocker } from './capacity.js';
import { AuthenticationBridge } from './authentication.js';
export { SdkError, VERSION };
export type * from './types.js';

/** 单库、单服务/账号/设备。预编译 Rust 拥有密码、SQLite、请求账本与消息。测试身份专用。 */
export class PersistentDevice {
  readonly #transport: Transport;
  readonly #scope: T.Scope;
  readonly runtime: T.Runtime;
  readonly #listeners = new Set<(change: T.Change) => void | Promise<void>>();
  readonly #listenerError: (error: unknown) => void;
  #closing = false;
  #logout?: Promise<void>;
  readonly #authentication: AuthenticationBridge;
  #networkActive = false;
  private constructor(transport: Transport, options: T.OpenOptions, handshake: unknown) {
    const ready = v.object(handshake);
    this.#scope = Object.freeze(v.scope(options.scope));
    if (!v.sameScope(v.scope(ready.scope), this.#scope)) throw new SdkError('scope_mismatch', true);
    this.#transport = transport; this.runtime = Object.freeze(v.runtime(ready.runtime));
    this.#authentication = new AuthenticationBridge(transport, this.#scope);
    transport.onStop(() => this.#authentication.stop());
    this.#listenerError = options.onListenerError ?? (error => { queueMicrotask(() => { throw error; }); });
    transport.onEvent(data => {
      if (this.#authentication.handle(data)) return;
      const change = v.networkChange(data);
      if (!v.sameScope(change.scope, this.#scope)) throw new SdkError('scope_mismatch', true);
      if (change.kind === 'network_error') { this.#authentication.stop(); this.#networkActive = false; }
      this.#notify(change);
    });
  }
  static async open(options: T.OpenOptions): Promise<PersistentDevice> {
    const captured = { ...options, scope: { ...options.scope } };
    const transport = await Transport.open(captured);
    try { return new PersistentDevice(transport, captured, await transport.ready); }
    catch (error) { transport.stop(error); await transport.close(); throw error; }
  }
  /** 中断后重试该空间退出。只会确认/销毁已绑定的密钥，不重新创建身份。 */
  static async logout(options: T.OpenOptions): Promise<void> {
    const transport = await Transport.open({ ...options, scope: { ...options.scope }, create: false }, 'logout');
    await transport.logout();
  }
  /** 关闭原空间全部实例后，只安装与原钥匙串最新进度一致的完整备份。成功后重新open/connect。 */
  static async restoreBackup(options: T.OpenOptions, backupPath: string): Promise<T.BackupInfo> {
    if (options.create || options.upgrade) throw new SdkError('invalid_options');
    const captured = { ...options, scope: { ...options.scope }, create: false };
    const transport = await Transport.open(captured, 'restore');
    try {
      const ready = v.object(await transport.ready);
      if (!v.sameScope(v.scope(ready.scope), captured.scope)) throw new SdkError('scope_mismatch', true);
      const reply = v.object(await transport.request({op: 'restore_backup', path: backupPath}, options));
      const info = v.backupInfo(reply.result);
      if (!Array.isArray(reply.events) || reply.events.length || !v.sameScope(info.scope, captured.scope)) throw new SdkError('ipc_protocol_error', true);
      return info;
    } finally { await transport.close(); }
  }
  /** 先disconnect。首次备份显式启用v4进度保护，旧包随后拒绝此库；目标必须为绝对.rimbackup路径。 */
  createBackup(path: string, options?: T.CallOptions): Promise<T.BackupInfo> {
    return this.#call({op: 'create_backup', path}, data => {
      const info = v.backupInfo(data);
      if (!v.sameScope(info.scope, this.#scope)) throw new SdkError('scope_mismatch', true);
      return info;
    }, options);
  }
  /** 本地提交后通知；允许重入查询。缓存命中、失败、关闭后的迟到结果不发事件。 */
  subscribe(listener: (change: T.Change) => void | Promise<void>): () => void {
    if (this.#closing) throw new SdkError('closed'); this.#listeners.add(listener);
    return () => { this.#listeners.delete(listener); };
  }
  async #call<R>(operation: Record<string, unknown>, parse: (value: unknown) => R, options?: T.CallOptions): Promise<R> {
    if (this.#closing) throw new SdkError('closed');
    const reply = v.object(await this.#transport.request(operation, options));
    if (this.#closing) throw new SdkError('closed');
    let result: R; let changes: T.LocalChange[];
    try {
      result = parse(reply.result);
      if (!Array.isArray(reply.events)) throw new SdkError('ipc_protocol_error', true);
      changes = reply.events.map(v.change);
      const resultObject = operation.op === 'execute' || operation.op === 'recover_request' ? v.object(reply.result) : null;
      const commit = operation.op === 'recovery' ? v.recovery(reply.result).commit : null;
      const expected = resultObject ? (!v.bool(resultObject.cached) ? 1 : 0) : commit ? 1 : 0;
      const requestId = commit?.context ?? operation.request_id;
      const revision = commit?.revision ?? resultObject?.revision;
      const kind = commit ? 'context_changed' : 'local_commit';
      if (changes.length !== expected || changes.some(c => !v.sameScope(c.scope, this.#scope) || c.request_id !== requestId || c.revision !== revision || c.kind !== kind)) throw new SdkError('ipc_protocol_error', true);
    } catch (error) { this.#transport.stop(new SdkError('ipc_protocol_error', true)); throw error; }
    for (const change of changes) this.#notify(change);
    return result;
  }
  #notify(change: T.Change): void {
    for (const listener of [...this.#listeners]) {
      if (this.#closing || !this.#listeners.has(listener)) continue;
      try { Promise.resolve(listener(structuredClone(change))).catch(this.#listenerError); }
      catch (error) { this.#listenerError(error); }
    }
  }
  /** 自动模式先返回authenticating；订阅状态等待Rust完成认证、TLS及固定双方身份核验。 */
  async connect(options: T.NetworkOptions, call?: T.CallOptions): Promise<T.NetworkState> {
    if (this.#closing) throw new SdkError('closed');
    if (call?.signal?.aborted) throw new SdkError('cancelled');
    if (this.#networkActive) throw new SdkError('already_connected');
    const { credentialProvider, authentication, ...endpoint } = options;
    if ((credentialProvider !== undefined && (typeof credentialProvider !== 'function' || options.token !== undefined)) ||
        (credentialProvider === undefined && authentication !== undefined)) throw new SdkError('invalid_authentication_options');
    this.#networkActive = true; this.#authentication.start(credentialProvider);
    try {
      return await this.#call({ op: 'connect', options: credentialProvider ? {
        ...endpoint, authentication: authentication ?? { timeout_ms: 5000, max_attempts: 3 },
      } : endpoint }, v.network, call);
    } catch (error) { this.#networkActive = false; this.#authentication.stop(); throw error; }
  }
  /** 停止连接；保留已保存发送和游标，再次connect继续。 */
  async disconnect(options?: T.CallOptions): Promise<T.NetworkState> {
    if (options?.signal?.aborted) throw new SdkError('cancelled');
    this.#authentication.stop();
    const state = await this.#call({ op: 'disconnect' }, v.network, options);
    this.#networkActive = false; return state;
  }
  networkState(options?: T.CallOptions): Promise<T.NetworkState> { return this.#call({ op: 'network_state' }, v.network, options); }
  /** 明确发起/批准/拒绝/封存。签名材料和续接由Rust拥有；关闭只中断传输，不撤回已持久授权。 */
  networkRecovery(command: T.NetworkRecoveryCommand, options?: T.CallOptions): Promise<T.NetworkRecoveryState | null> {
    return this.#call({ op: 'network_recovery', command }, data => data === null ? null : v.networkRecovery(data), options);
  }
  /** 单份读取未能解密的旧密文；networkState只返回有界摘要列表。 */
  networkUnavailable(sequence: string, options?: T.CallOptions): Promise<T.UnavailableMessage | null> {
    return this.#call({op:'network_unavailable', sequence}, data => data === null ? null : v.unavailableMessage(data), options);
  }
  #execute<K extends T.Value['kind']>(requestId: string, action: Record<string, unknown>, kind: K, options?: T.CallOptions): Promise<T.Outcome<Extract<T.Value, { kind: K }>>> {
    return this.#call({ op: 'execute', request_id: requestId, action }, data => {
      const outcome = v.outcome(data); if (outcome.value.kind !== kind) throw new SdkError('ipc_protocol_error', true);
      // 运行时已经核验判别字段；此处只把判别联合映射为对应方法的返回类型。
      return outcome as T.Outcome<Extract<T.Value, { kind: K }>>;
    }, options);
  }
  initialize(requestId: string, options?: T.CallOptions) { return this.#execute(requestId, { kind: 'initialize' }, 'initialized', options); }
  joiningMaterial(options?: T.CallOptions) { return this.#call({ op: 'joining_material' }, v.joining, options); }
  createGroup(requestId: string, conversation: string, peer: T.Identity, keyPackage: string, options?: T.CallOptions) {
    return this.#execute(requestId, { kind: 'create_group', conversation, peer, key_package: keyPackage }, 'created', options);
  }
  joinGroup(requestId: string, conversation: string, peer: T.Identity, welcome: string, options?: T.CallOptions) {
    return this.#execute(requestId, { kind: 'join_group', conversation, peer, welcome }, 'joined', options);
  }
  /** 返回本地保存结果；连接后由Rust自动发送。接受/送达见networkState及subscribe。重试使用原requestId/messageId/text。 */
  send(requestId: string, messageId: string, text: string, options?: T.CallOptions) {
    return this.#execute(requestId, { kind: 'send', message_id: messageId, text }, 'sent', options);
  }
  receive(requestId: string, envelope: T.Envelope, options?: T.CallOptions) {
    return this.#execute(requestId, { kind: 'receive', envelope }, 'received', options);
  }
  /** 原输入精确恢复；已执行但无候选时返回 successor_required，随后显式协商后继。 */
  recoverRequest(requestId: string, action: T.PendingAction, options?: T.CallOptions) {
    return this.#call({ op: 'recover_request', request_id: requestId, action }, v.outcome, options);
  }
  /** 签名材料是不可修改的公开原件。accept 必须传入已独立核验的对端 Identity。 */
  recovery(command: T.RecoveryCommand, options?: T.CallOptions) {
    return this.#call({ op: 'recovery', command }, v.recovery, options);
  }
  message(senderAccount: string, senderDevice: string, messageId: string, options?: T.CallOptions) {
    return this.#call({ op: 'message', sender_account: senderAccount, sender_device: senderDevice, message_id: messageId }, value => value === null ? null : v.message(value), options);
  }
  request(requestId: string, options?: T.CallOptions) { return this.#call({ op: 'request', request_id: requestId }, v.request, options); }
  /** 已提交收发消息按本地追加顺序分页。原样续传游标；新查询才包含后续提交。 */
  history(query: T.HistoryQuery, options?: T.CallOptions): Promise<T.HistoryPage> {
    return this.#call({ op: 'history', query }, v.history, options);
  }
  /** 同一SQLite读事务观察；容量状态不授予操作权限。 */
  async capacity(options?: T.CallOptions): Promise<Capacity> {
    if (this.#closing) throw new SdkError('closed');
    if (options !== undefined && (options === null || typeof options !== 'object' || Array.isArray(options) ||
        Object.keys(options).some(key => key !== 'signal') ||
        (options.signal !== undefined && !(options.signal instanceof AbortSignal)))) throw new SdkError('invalid_options');
    return this.#call({ op: 'capacity' }, data => {
      const result = capacity(data);
      if (!v.sameScope(result.scope, this.#scope)) throw new SdkError('scope_mismatch', true);
      return result;
    }, options);
  }
  /** 显式启用known-v1本地有限预留并升级v6；旧包拒载。取消不撤销已提交的启用。 */
  async reserveCapacity(options?: T.CallOptions): Promise<Capacity> {
    if (this.#closing) throw new SdkError('closed');
    if (options !== undefined && (options === null || typeof options !== 'object' || Array.isArray(options) ||
        Object.keys(options).some(key => key !== 'signal') ||
        (options.signal !== undefined && !(options.signal instanceof AbortSignal)))) throw new SdkError('invalid_options');
    return this.#call({ op: 'reserve_capacity' }, data => {
      const result = capacity(data);
      if (!v.sameScope(result.scope, this.#scope)) throw new SdkError('scope_mismatch', true);
      return result;
    }, options);
  }
  /** 固定已下载控制原件，启用原进度保护并升级v7。Prepared仅为本地；取消不解除承诺。 */
  async prepareCapacityWorkset(options?: T.CallOptions): Promise<CapacityWorksetState> {
    const result = await this.#workset('prepare_capacity_workset', options);
    if (result === null) throw new SdkError('ipc_protocol_error', true);
    return result;
  }
  /** 本机持久观察；active才包含Service确认。null表示本机尚未准备，不能推断远端。 */
  capacityWorkset(options?: T.CallOptions): Promise<CapacityWorksetState | null> {
    return this.#workset('capacity_workset', options);
  }
  #workset(op: string, options?: T.CallOptions): Promise<CapacityWorksetState | null> {
    if (options !== undefined && (options === null || typeof options !== 'object' || Array.isArray(options) ||
        Object.keys(options).some(key => key !== 'signal') ||
        (options.signal !== undefined && !(options.signal instanceof AbortSignal)))) return Promise.reject(new SdkError('invalid_options'));
    return this.#call({op}, data => {
      const result = worksetState(data);
      if (result !== null && !v.sameScope(result.workset.owner.scope, this.#scope)) throw new SdkError('scope_mismatch', true);
      return result;
    }, options);
  }
  state(options?: T.CallOptions) { return this.#call({ op: 'state' }, data => {
    const result = v.state(data); if (!v.sameScope(result.scope, this.#scope)) throw new SdkError('scope_mismatch', true); return result;
  }, options); }
  /** 停止新调用/事件，等待已受理操作并回收 Rust 进程；重复关闭安全。 */
  close(): Promise<void> { this.#closing = true; this.#listeners.clear(); this.#authentication.stop(); return this.#transport.close(); }
  /** 本地销毁解密钥并关闭；保留加密文件及无密钥墓碑，不撤销远端设备。 */
  logout(): Promise<void> {
    if (this.#logout) return this.#logout;
    if (this.#closing) return Promise.reject(new SdkError('closed'));
    this.#closing = true; this.#listeners.clear(); this.#authentication.stop();
    this.#logout = this.#transport.logout(); return this.#logout;
  }
}
