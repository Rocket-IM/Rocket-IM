import { VERSION, MAX_PENDING, COMMAND_TIMEOUT_MS, StorageError, object, wireError } from "./protocol.js";
import type { ResultOutcome } from "./protocol.js";
import type { AnchorConfiguration } from "./anchor_types.js";
import type { ParsedRebuildOptions } from "./rebuild_types.js";

export type Phase = "after_reserve" | "after_crypto" | "before_commit" | "after_commit"
  | "after_anchor_reserve" | "after_candidate_commit" | "after_anchor_finish" | "after_rebuild_link";
export interface CheckpointEvent<P extends Phase> { readonly phase: P; readonly testOnly: true; }
export type StateEvent<S> = { readonly type: "snapshot" | "committed"; readonly snapshot: S };
export type StateListener<S> = (event: StateEvent<S>) => void | Promise<void>;
export interface TransportOptions {
  mode: "ordinary" | "crypto" | "anchor" | "rebuild";
  service: string;
  account: string;
  testMode: boolean;
  seedV1?: boolean;
  failMigration?: boolean;
  anchor?: AnchorConfiguration;
  rebuild?: { readonly options: ParsedRebuildOptions; readonly create: boolean };
}
export interface Codec<Q, S, P extends Phase> {
  readonly read: Q;
  outcome(value: unknown, service: string, account: string): ResultOutcome<S>;
  checkpoint(request: Q): P | undefined;
  changed(request: Q, snapshot: S): boolean;
  validateInitial(snapshot: S): void;
  allowWhenPaused(request: Q): boolean;
}
interface Lease { release(): Promise<void>; }
interface Command<Q, S> {
  id: string;
  kind: "open" | "execute" | "close";
  request?: Q;
  options?: TransportOptions;
  resolve: (snapshot: S) => void;
  reject: (error: StorageError) => void;
  accept?: (snapshot: S) => void;
}
export function unavailable(code: string, message: string): StorageError { return new StorageError(code, message, true); }
export function caught(value: unknown): StorageError {
  if (value instanceof StorageError) return value;
  return unavailable("ENVIRONMENT_ERROR", value instanceof Error ? `${value.name}: ${value.message}` : String(value));
}
function checkEnvironment(): void {
  if (!globalThis.isSecureContext || typeof Worker === "undefined" || typeof navigator === "undefined"
      || !navigator.locks || typeof navigator.storage?.getDirectory !== "function") {
    throw unavailable("UNSUPPORTED_ENVIRONMENT", "Secure context, Web Locks, dedicated Worker and OPFS are required.");
  }
}
async function acquire(options: TransportOptions): Promise<Lease> {
  const { service, account } = options;
  const namespace = options.mode === "rebuild" ? options.rebuild?.options.storageNamespace : undefined;
  if (options.mode === "rebuild" && namespace === undefined) throw new StorageError("INVALID_ARGUMENT", "Missing rebuild storage namespace.");
  const key = `rockets-q05:${service}:${account}` + (namespace === undefined ? "" : `-rebuild-${namespace}`);
  let releaseLock: () => void = () => {};
  const lifetime = new Promise<void>(resolve => { releaseLock = resolve; });
  let grant: (lease: Lease) => void = () => {};
  let reject: (error: StorageError) => void = () => {};
  const ready = new Promise<Lease>((resolve, fail) => { grant = resolve; reject = fail; });
  // 旧入口保持原锁；重建命名空间对应不同物理库，同一命名空间仍只允许一个所有者。
  const held = navigator.locks.request(key,
    { mode: "exclusive", ifAvailable: true }, async lock => {
      if (!lock) { reject(new StorageError("IN_USE", "This service/account is already open in another instance.")); return; }
      grant({ release: async () => { releaseLock(); await held; } });
      await lifetime;
    });
  void held.catch(error => { reject(caught(error)); });
  return ready;
}

/** 唯一的有界队列和 Worker 生命周期；业务快照与事务只归 Rust。 */
export class Transport<Q, S, P extends Phase> {
  private state: "opening" | "open" | "paused" | "closing" | "closed" | "failed" = "opening";
  private readonly queue: Command<Q, S>[] = [];
  private pending: Command<Q, S> | undefined;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private nextID = 1;
  private readonly listeners = new Set<StateListener<S>>();
  private readonly checkpoints = new Set<(event: CheckpointEvent<P>) => void>();
  private closing: Promise<void> | undefined;
  private resolveClose: () => void = () => {};
  private rejectClose: (error: StorageError) => void = () => {};
  private teardown: Promise<void> | undefined;

  private constructor(private readonly options: TransportOptions, private readonly codec: Codec<Q, S, P>,
    private readonly worker: Worker, private readonly lease: Lease) {
    worker.onmessage = (event: MessageEvent<unknown>) => { this.receive(event.data); };
    worker.onerror = event => {
      event.preventDefault();
      this.abort(unavailable("WORKER_ERROR", event.message || "Storage Worker failed."));
    };
    worker.onmessageerror = () => { this.abort(unavailable("WORKER_MESSAGE_ERROR", "Storage Worker message could not be decoded.")); };
  }
  static async open<Q, S, P extends Phase>(options: TransportOptions, codec: Codec<Q, S, P>): Promise<Transport<Q, S, P>> {
    checkEnvironment();
    const lease = await acquire(options);
    let client: Transport<Q, S, P> | undefined;
    try {
      const worker = new Worker(new URL("./worker.js", import.meta.url), { type: "module", name: "rockets-q05-storage" });
      client = new Transport(options, codec, worker, lease);
      codec.validateInitial(await client.enqueue("open", undefined, undefined, options));
      return client;
    } catch (error) {
      // VFS 初始化失败可能遗留同步访问句柄；整个 Worker 终止后才释放范围锁。
      if (client) { client.abort(caught(error)); await client.teardown; }
      else await lease.release();
      throw caught(error);
    }
  }
  execute(command: Q, accept?: (snapshot: S) => void): Promise<S> {
    if (this.state !== "open" && !(this.state === "paused" && this.codec.allowWhenPaused(command))) {
      return Promise.reject(new StorageError(this.state === "paused" ? "storage_paused" : "CLOSED",
        "Storage is not available; close and open a new instance.", this.state === "paused"));
    }
    return this.enqueue("execute", command, accept);
  }
  /** 快照与注册在同一串行队列完成；回调可重入查询，调度器不等待回调。 */
  async subscribe(listener: StateListener<S>): Promise<() => void> {
    if (typeof listener !== "function") throw new StorageError("INVALID_ARGUMENT", "Listener must be a function.");
    const subscription: StateListener<S> = event => listener(event);
    await this.execute(this.codec.read, snapshot => {
      this.listeners.add(subscription);
      this.notify(subscription, { type: "snapshot", snapshot });
    });
    return () => { this.listeners.delete(subscription); };
  }
  /** 拒绝未交付结果，等待活动调用结束，Rust 关闭后终止 Worker 并释放范围锁。 */
  close(): Promise<void> {
    if (this.closing) return this.closing;
    if (this.state === "closed" || this.state === "failed") return this.teardown ?? Promise.resolve();
    this.state = "closing";
    this.listeners.clear(); this.checkpoints.clear();
    const error = new StorageError("CLOSED", "Storage closed before the result was delivered.");
    for (const command of this.queue.splice(0)) command.reject(error);
    this.pending?.reject(error);
    this.closing = new Promise<void>((resolve, reject) => { this.resolveClose = resolve; this.rejectClose = reject; });
    this.queue.push({ id: this.id(), kind: "close", resolve: () => {}, reject: this.rejectClose });
    this.pump();
    return this.closing;
  }
  get test(): {
    onCheckpoint: (listener: (event: CheckpointEvent<P>) => void) => () => void;
    terminate: () => Promise<void>;
  } {
    if (!this.options.testMode) throw new StorageError("TEST_MODE_REQUIRED", "Test controls require testMode.");
    return {
      onCheckpoint: listener => {
        if (typeof listener !== "function") throw new StorageError("INVALID_ARGUMENT", "Checkpoint listener must be a function.");
        if (this.state !== "open" && this.state !== "paused") throw new StorageError("CLOSED", "Storage is not open.");
        this.checkpoints.add(listener);
        return () => { this.checkpoints.delete(listener); };
      },
      terminate: async () => {
        this.abort(unavailable("TEST_TERMINATED", "Worker termination requested; the pending write outcome is unknown until reopened."));
        await this.teardown;
      },
    };
  }
  private id(): string { return `r${this.nextID++}`; }
  private enqueue(kind: "open" | "execute", request?: Q,
    accept?: (snapshot: S) => void, options?: TransportOptions): Promise<S> {
    if (this.queue.length + (this.pending ? 1 : 0) >= MAX_PENDING) {
      return Promise.reject(new StorageError("QUEUE_FULL", `At most ${MAX_PENDING} storage commands may be pending.`));
    }
    return new Promise<S>((resolve, reject) => {
      this.queue.push({ id: this.id(), kind, request, options, resolve, reject, accept });
      this.pump();
    });
  }
  private pump(): void {
    if (this.pending || this.state === "closed" || this.state === "failed") return;
    const command = this.queue.shift();
    if (!command) return;
    this.pending = command;
    this.timer = setTimeout(() => { this.abort(unavailable("WORKER_TIMEOUT", "Storage Worker command exceeded 20 seconds.")); }, COMMAND_TIMEOUT_MS);
    try { this.worker.postMessage({ id: command.id, kind: command.kind, request: command.request, options: command.options }); }
    catch (error) { this.abort(caught(error)); }
  }
  private receive(value: unknown): void {
    if (this.state === "failed" || this.state === "closed") return;
    try {
      const message = object(value), command = this.pending;
      if (!command || message.id !== command.id) throw unavailable("INVALID_RESPONSE", "Worker response does not match the active command.");
      if (message.kind === "checkpoint") {
        const phase = command.request === undefined ? undefined : this.codec.checkpoint(command.request);
        if (!this.options.testMode || message.testOnly !== true || phase === undefined || phase !== message.phase) {
          throw unavailable("INVALID_RESPONSE", "Unexpected storage checkpoint.");
        }
        if (this.state === "open") for (const listener of this.checkpoints) {
          try { listener(Object.freeze({ phase, testOnly: true })); }
          catch (error) { queueMicrotask(() => { throw error; }); }
        }
        return;
      }
      if (message.version !== VERSION) throw unavailable("VERSION_MISMATCH", "Worker and package versions do not match.");
      if (message.kind === "closed" && command.kind === "close") {
        clearTimeout(this.timer); this.timer = undefined; this.pending = undefined;
        this.state = "closed";
        this.stop();
        void this.teardown?.then(this.resolveClose, error => { this.rejectClose(caught(error)); });
        return;
      }
      const result = message.kind === "error" ? { ok: false as const, error: wireError(message.error) }
        : message.kind === "result" && command.kind !== "close"
          ? this.codec.outcome(message.outcome, this.options.service, this.options.account) : undefined;
      if (!result) throw unavailable("INVALID_RESPONSE", "Unexpected Worker result kind.");
      clearTimeout(this.timer); this.timer = undefined; this.pending = undefined;
      if (!result.ok) {
        const error = new StorageError(result.error.code, result.error.message, result.error.paused, result.error.cause);
        command.reject(error);
        if (command.kind === "open" || command.kind === "close" || message.kind === "error") this.abort(error);
        else if (result.error.paused && this.state !== "closing") {
          this.state = "paused";
          for (const queued of this.queue.splice(0)) queued.reject(error);
        }
      } else if (this.state !== "closing") {
        if (command.kind === "open") this.state = "open";
        command.accept?.(result.result);
        command.resolve(result.result);
        if (command.request !== undefined && this.codec.changed(command.request, result.result) && this.state === "open") {
          for (const listener of this.listeners) this.notify(listener, { type: "committed", snapshot: result.result });
        }
      }
      this.pump();
    } catch (error) { this.abort(caught(error)); }
  }
  private notify(listener: StateListener<S>, event: StateEvent<S>): void {
    try {
      const result = listener(Object.freeze(event));
      if (result instanceof Promise) void result.catch(error => { queueMicrotask(() => { throw error; }); });
    } catch (error) { queueMicrotask(() => { throw error; }); }
  }
  private abort(error: StorageError): void {
    if (this.state === "failed" || this.state === "closed") return;
    this.state = "failed";
    clearTimeout(this.timer); this.timer = undefined;
    this.pending?.reject(error); this.pending = undefined;
    for (const command of this.queue.splice(0)) command.reject(error);
    this.listeners.clear(); this.checkpoints.clear();
    this.rejectClose(error);
    this.stop();
  }
  private stop(): void {
    if (this.teardown) return;
    this.worker.onmessage = null; this.worker.onerror = null; this.worker.onmessageerror = null;
    this.worker.terminate();
    this.teardown = this.lease.release();
  }
}
