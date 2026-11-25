import { spawn } from 'node:child_process';
import { artifact, VERSION, SdkError } from './artifact.mjs';
export { SdkError, VERSION };
const LIMIT = 1024 * 1024;

// 只承载有界 IPC，不包含业务队列、SQL、密码状态或重试逻辑。
export class Transport {
  #child; #pending = new Map(); #sequence = 0; #buffer = Buffer.alloc(0);
  #stopped = false; #closing; #exit; #readyResolve; #readyReject; #readyTimer;
  #timeout; #handshake = false; #stderrBytes = 0;
  ready; #eventListener; #stopListener;
  onEvent(listener) { this.#eventListener = listener; }
  onStop(listener) { this.#stopListener = listener; }
  constructor(binary, options, mode) {
    this.#timeout = options.timeoutMs ?? 10000;
    this.ready = new Promise((resolve, reject) => { this.#readyResolve = resolve; this.#readyReject = reject; });
    this.#child = spawn(binary, [options.path, options.scope.service, options.scope.account, options.scope.device,
      mode ?? (options.create ? 'create' : 'open'), options.keychain], { shell: false, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    this.#exit = new Promise(resolve => this.#child.once('close', (code, signal) => {
      if (!this.#stopped && (!this.#closing || code !== 0 || signal || this.#pending.size))
        this.stop(new SdkError('process_exit_unknown', true));
      this.#stopped = true;
      resolve();
    }));
    this.#readyTimer = setTimeout(() => this.stop(new SdkError('open_timeout', true)), this.#timeout);
    this.#child.on('error', () => this.stop(new SdkError('process_start_failed', true)));
    this.#child.stdin.on('error', () => this.stop(new SdkError('ipc_write_failed', true)));
    this.#child.stdout.on('data', chunk => this.#read(chunk));
    this.#child.stderr.on('data', chunk => {
      this.#stderrBytes += chunk.length;
      // 不将子进程错误正文转入应用日志，仍明确报告异常或过量输出。
      if (this.#stderrBytes > 65536) this.stop(new SdkError('process_output_limit', true));
    });
  }
  static async open(options, mode) {
    if (!options || typeof options.path !== 'string' || !options.path || options.path.includes('\0') || !options.path.startsWith('/') ||
        !options.scope || ['service', 'account', 'device'].some(k => typeof options.scope[k] !== 'string' || !options.scope[k] ||
          Buffer.byteLength(options.scope[k]) > 64 || options.scope[k].includes('\0')) ||
        (options.create !== undefined && typeof options.create !== 'boolean') ||
        (options.upgrade !== undefined && typeof options.upgrade !== 'boolean') || (options.create && options.upgrade) ||
        (options.timeoutMs !== undefined && (!Number.isInteger(options.timeoutMs) || options.timeoutMs < 100 || options.timeoutMs > 60000)))
      throw new SdkError('invalid_options');
    if (options.upgrade) throw new SdkError('plaintext_migration_required');
    if (typeof options.keychain !== 'string' || !options.keychain.startsWith('/') || options.keychain.includes('\0')) throw new SdkError('keychain_required');
    if (options.signal?.aborted) throw new SdkError('cancelled');
    const binary = await artifact();
    if (options.signal?.aborted) throw new SdkError('cancelled');
    const transport = new Transport(binary, options, mode);
    const abort = () => transport.stop(new SdkError('cancelled_unknown', true));
    options.signal?.addEventListener('abort', abort, { once: true });
    try { await transport.ready; return transport; }
    catch (error) { transport.stop(error); await transport.#exit; throw error; }
    finally { options.signal?.removeEventListener('abort', abort); }
  }
  #read(chunk) {
    if (this.#stopped) return;
    this.#buffer = Buffer.concat([this.#buffer, chunk]);
    if (this.#buffer.length > 2 * 1024 * 1024) return this.stop(new SdkError('ipc_output_limit', true));
    let end;
    while ((end = this.#buffer.indexOf(10)) !== -1) {
      const line = this.#buffer.subarray(0, end);
      this.#buffer = this.#buffer.subarray(end + 1);
      try {
        if (line.length > 1024 * 1024) throw new Error('limit');
        const reply = JSON.parse(line.toString('utf8'));
        if (!reply || typeof reply !== 'object') throw new Error('shape');
        if (!this.#handshake) {
          if (reply.ready === false && typeof reply.error?.code === 'string') {
            this.stop(new SdkError(reply.error.code, reply.error.paused === true)); return;
          }
          if (reply.test_hooks !== false || reply.ready !== true || reply.protocol !== 3 || reply.version !== VERSION ||
              reply.runtime?.pid !== this.#child.pid || reply.runtime?.os !== 'macos' || reply.runtime?.arch !== 'aarch64')
            throw new Error('handshake');
          this.#handshake = true; clearTimeout(this.#readyTimer); this.#readyResolve(reply);
        } else if ('event' in reply) {
          if (this.#closing) continue;
          if (!this.#eventListener || 'id' in reply) throw new Error('event');
          this.#eventListener(reply.event);
        } else {
          const pending = this.#pending.get(reply.id);
          if (!pending || typeof reply.ok !== 'boolean' || !Array.isArray(reply.events)) throw new Error('response');
          if (!reply.ok && (reply.result !== null || reply.events.length !== 0 || typeof reply.error?.code !== 'string' ||
              typeof reply.error.paused !== 'boolean')) throw new Error('error');
          if (reply.ok && reply.error !== null) throw new Error('success');
          this.#pending.delete(reply.id); pending.cleanup();
          if (reply.ok) pending.resolve(reply);
          else pending.reject(new SdkError(reply.error.code, reply.error.paused));
        }
      } catch { this.stop(new SdkError('ipc_protocol_error', true)); return; }
    }
    if (this.#buffer.length > 1024 * 1024) this.stop(new SdkError('ipc_output_limit', true));
  }
  control(operation) { return this.request(operation, {}, false, true); }
  request(operation, options = {}, closing = false, control = false) {
    if (this.#stopped || (this.#closing && !closing)) return Promise.reject(new SdkError('closed'));
    if (options.signal?.aborted) return Promise.reject(new SdkError('cancelled'));
    if (!closing && this.#pending.size >= (control ? 10 : 8)) return Promise.reject(new SdkError('queue_full'));
    const id = String(++this.#sequence);
    let bytes;
    try { bytes = Buffer.from(JSON.stringify({ id, operation }) + '\n'); }
    catch { return Promise.reject(new SdkError('invalid_request')); }
    if (bytes.length > LIMIT) return Promise.reject(new SdkError('request_too_large'));
    return new Promise((resolve, reject) => {
      const abort = () => this.stop(new SdkError('cancelled_unknown', true));
      const timer = setTimeout(() => this.stop(new SdkError('request_timeout_unknown', true)), this.#timeout);
      const cleanup = () => { clearTimeout(timer); options.signal?.removeEventListener('abort', abort); };
      this.#pending.set(id, { resolve, reject, cleanup });
      options.signal?.addEventListener('abort', abort, { once: true });
      this.#child.stdin.write(bytes, error => { if (error) this.stop(new SdkError('ipc_write_failed', true)); });
    });
  }
  stop(error) {
    if (this.#stopped) return;
    this.#stopped = true; clearTimeout(this.#readyTimer);
    this.#stopListener?.();
    this.#readyReject(error);
    for (const pending of this.#pending.values()) { pending.cleanup(); pending.reject(error); }
    this.#pending.clear(); this.#buffer = Buffer.alloc(0);
    this.#child.kill('SIGKILL');
  }
  logout() { return this.#finish('logout'); }
  close() { return this.#finish('close'); }
  #finish(operation) {
    if (this.#closing) return this.#closing;
    if (this.#stopped) return this.#exit;
    this.#closing = (async () => {
      try { await this.request({ op: operation }, {}, true); }
      finally { this.#child.stdin.end(); await this.#exit; }
    })();
    return this.#closing;
  }
}
