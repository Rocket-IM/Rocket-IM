/** 所有序号均为十进制字符串；仅合成身份，不是稳定产品 API。 */
export interface Scope { readonly service: string; readonly account: string; readonly device: string }
export interface Identity extends Scope { readonly identityKey: string; readonly keyPackage: string }
export interface Envelope {
  readonly service: string; readonly conversation: string; readonly senderAccount: string;
  readonly senderDevice: string; readonly messageId: string; readonly ciphertext: string;
}
export interface PlainMessage { readonly messageId: string; readonly senderAccount: string; readonly text: string }
export interface Received { readonly sequence: string; readonly duplicate: boolean; readonly message: PlainMessage }
export interface Outcome<T> { readonly revision: string; readonly kind: string; readonly cached: boolean; readonly value: T }
export interface DownloadRecord { readonly sequence: string; readonly envelope: Envelope }
export interface DownloadOutcome {
  readonly downloadCursor: string; readonly processedCursor: string; readonly added: number; readonly cached: boolean;
}
export interface State {
  readonly scope: Scope; readonly revision: string; readonly identity: Identity | null;
  readonly conversation: string | null; readonly pending: boolean;
  readonly outbox: ReadonlyArray<{ readonly attemptId: string; readonly messageId: string; readonly ciphertextHash: string }>;
  readonly processedCursor: string; readonly downloadCursor: string; readonly receivedCount: number;
}
export interface Change {
  readonly scope: Scope; readonly kind: string; readonly revision?: string;
  readonly downloadCursor?: string; readonly processedCursor?: string;
}
export interface Runtime {
  readonly pid: number; readonly os: string; readonly arch: string;
  readonly databaseThread: string; readonly coordinatorThread: string;
}
/** signal 在发送前取消不写入；发送后取消会终止该实例，结果可能已提交，须重开并用原请求 ID 查询/重试。 */
export interface CallOptions { readonly signal?: AbortSignal }
export interface OpenOptions extends CallOptions {
  readonly path: string; readonly scope: Scope; readonly create?: boolean;
  /** 每次请求含排队时间，默认 10 秒，范围 100—60000 毫秒；超时终止实例。 */
  readonly timeoutMs?: number;
  /** 监听器异常明确转交；未提供时通过微任务抛出，不吞错。 */
  readonly onListenerError?: (error: unknown) => void;
}
