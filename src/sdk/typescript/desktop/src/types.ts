export interface Scope { readonly service: string; readonly account: string; readonly device: string }
/** 端侧快照完成回执，不表示Service同步或送达完成；不含系统秘密。 */
export interface BackupInfo {
  readonly format: 1; readonly backup_id: string; readonly scope: Scope;
  readonly revision: string; readonly snapshot: string;
}
/** 公钥和协议材料均为小写十六进制字符串。Identity 必须经测试接入方独立核验。 */
export interface Identity { readonly scope: Scope; readonly identity_key: string }
export interface JoiningMaterial { readonly identity: Identity; readonly key_package: string }
export interface Envelope {
  readonly service: string; readonly conversation: string; readonly sender_account: string;
  readonly sender_device: string; readonly message_id: string; readonly ciphertext: string; readonly context: string;
}
export interface Message {
  readonly service: string; readonly conversation: string; readonly sender_account: string;
  readonly sender_device: string; readonly message_id: string; readonly text: string; readonly context: string;
}
export type HistoryDirection = 'forward' | 'backward';
export interface HistoryQuery {
  /** 1..64；编码预算可能提前结束一页，以 done 为结束依据。 */
  readonly page_size: number;
  readonly direction: HistoryDirection;
  /** 首次省略或 null；续页必须原样传回并保持方向和页大小。 */
  readonly cursor?: string | null;
}
export interface SendRejection { readonly source: 'service_send'; readonly code: 'message_limit' }
export interface HistoryItem { readonly local_position: string; readonly message: Message; readonly rejection?: SendRejection }
export interface HistoryPage {
  readonly items: readonly HistoryItem[];
  /** 本次查询固定的本地位置包含式上界；不是网络游标或时间。 */
  readonly upper_bound: string;
  readonly direction: HistoryDirection;
  readonly page_size: number;
  readonly next_cursor: string | null;
  readonly done: boolean;
}
export interface Initialized { readonly kind: 'initialized'; readonly identity: Identity }
export interface Created { readonly kind: 'created'; readonly welcome: string }
export interface Joined { readonly kind: 'joined' }
export interface Sent { readonly kind: 'sent'; readonly envelope: Envelope }
export interface Received { readonly kind: 'received'; readonly message: Message; readonly position: string }
export type Value = Initialized | Created | Joined | Sent | Received;
export interface Outcome<T extends Value = Value> { readonly revision: string; readonly cached: boolean; readonly value: T }
export interface State {
  readonly scope: Scope; readonly revision: string; readonly context: string; readonly identity: Identity | null;
  readonly conversation: string | null; readonly peer: Identity | null;
  /** 本地成功接收计数，不是网络游标或送达状态。 */
  readonly received_count: string; readonly pending_request: string | null;
}
export type RequestState = { readonly status: 'missing' | 'pending' }
  | { readonly status: 'retired'; readonly context: string }
  | { readonly status: 'failed'; readonly error: { readonly code: string; readonly paused: boolean } }
  | { readonly status: 'complete'; readonly outcome: Outcome };
export interface LocalChange { readonly scope: Scope; readonly request_id: string; readonly revision: string; readonly kind: 'local_commit' | 'context_changed' }
export interface Runtime { readonly pid: number; readonly os: 'macos'; readonly arch: 'aarch64' }
export interface CallOptions { readonly signal?: AbortSignal }
export interface OpenOptions extends CallOptions {
  readonly path: string; readonly scope: Scope; readonly create?: boolean;
  /** 明确的专用 macOS 文件钥匙串绝对路径；须由宿主事先创建并解锁。SDK 不接收密码。 */
  readonly keychain: string;
  /** dev.3 拒绝明文旧格式；保留字段仅使旧调用得到明确迁移拒绝。 */
  readonly upgrade?: boolean;
  /** 单次 IPC 最长等待毫秒数，100–60000，默认10000。超时会终止所属进程；用原请求查询结果。 */
  readonly timeoutMs?: number;
  readonly onListenerError?: (error: unknown) => void;
}

export type PendingAction = { readonly kind: 'initialize' }
  | { readonly kind: 'create_group'; readonly conversation: string; readonly peer: Identity; readonly key_package: string }
  | { readonly kind: 'join_group'; readonly conversation: string; readonly peer: Identity; readonly welcome: string }
  | { readonly kind: 'send'; readonly message_id: string; readonly text: string }
  | { readonly kind: 'receive'; readonly envelope: Envelope };
export type RecoveryCommand = { readonly kind: 'begin'; readonly request_id: string; readonly action: PendingAction }
  | { readonly kind: 'accept'; readonly offer: string; readonly peer: Identity }
  | { readonly kind: 'reject'; readonly offer: string; readonly peer: Identity }
  | { readonly kind: 'join'; readonly approval: string }
  | { readonly kind: 'confirm'; readonly ready: string }
  | { readonly kind: 'finish'; readonly receipt: string }
  | { readonly kind: 'close'; readonly peer_close: string | null }
  | { readonly kind: 'status' }
  | { readonly kind: 'inspect'; readonly context: string };
export type RecoveryPhase = 'offered' | 'building' | 'prepared' | 'joining' | 'ready' | 'committed' | 'finished' | 'closing' | 'closed';
export interface RecoveryResult {
  readonly phase: RecoveryPhase | null; readonly context: string | null; readonly packet: string | null;
  readonly commit: { readonly revision: string; readonly context: string } | null;
}

/** 字面IP的wss URL；凭证只在本次连接内存持有，重新打开需再次传入。 */
interface NetworkEndpoint {
  readonly url: string; readonly ca_certificate: string;
  readonly conversation: string; readonly peer: Identity; readonly creator: boolean;
}
export interface DeviceCredential {
  readonly scope: Scope;
  readonly token: string;
  /** UTC Unix毫秒十进制字符串，由业务后台真实expires_at转换；不在本地持久保存。 */
  readonly expires_at_unix_ms: string;
}
export interface CredentialRequest {
  readonly scope: Scope;
  readonly request_id: string;
  readonly reason: 'initial' | 'expired';
  readonly attempt: number;
  readonly timeout_ms: number;
  /** 超时、断开、关闭或退出即abort。宿主负责把signal传给自己的I/O并释放资源。 */
  readonly signal: AbortSignal;
}
export type CredentialResult = { readonly kind: 'credential'; readonly credential: DeviceCredential }
  | { readonly kind: 'failure'; readonly code: 'unavailable' | 'login_required' | 'forbidden' | 'cancelled' | 'invalid_credential' | 'provider_failed' };
/** 只向已认证业务后台取访问凭证；禁止回调中阻塞JS事件循环。异常按provider_failed永久失败处理。 */
export type CredentialProvider = (request: CredentialRequest) => Promise<CredentialResult>;
export type NetworkOptions = NetworkEndpoint & (
  { readonly token: string; readonly credentialProvider?: never; readonly authentication?: never }
  | { readonly token?: never; readonly credentialProvider: CredentialProvider;
      /** 默认每次5000毫秒、共3次。上限30000毫秒/3次；耗尽后需显式disconnect/connect。 */
      readonly authentication?: { readonly timeout_ms: number; readonly max_attempts: number } }
);
export interface Acceptance { readonly request_id: string; readonly message_id: string; readonly sequence: string; readonly envelope_hash: string }
export type SendingState = { readonly message_id: string; readonly request_id: string } & (
  { readonly status: 'rejected'; readonly acceptance: null; readonly rejection: SendRejection }
  | { readonly status: 'local_saved' | 'not_accepted'; readonly acceptance: null; readonly rejection?: never }
  | { readonly status: 'accepted' | 'delivered' | 'context_retired'; readonly acceptance: Acceptance; readonly rejection?: never }
);
export type NetworkRecoveryCommand = {readonly kind: 'begin'; readonly request_id: string; readonly action: PendingAction}
  | {readonly kind: 'approve' | 'reject' | 'seal'; readonly round_id: string}
  | {readonly kind: 'status'};
export interface NetworkRecoveryState {
  readonly round_id: string; readonly context: string | null; readonly role: 'target' | 'peer';
  readonly phase: string; readonly requires_action: boolean; readonly request_id: string;
  readonly request_hash: string; readonly deadline: string;
}
/** 已接受但旧上下文已退休的密文历史原件；没有解密成功或送达含义。 */
export interface UnavailableRecord {readonly sequence: string; readonly reason: 'context_retired'; readonly acceptance: Acceptance}
export interface UnavailableMessage extends UnavailableRecord {readonly envelope: Envelope}
export interface NetworkState {
  readonly connection: 'offline' | 'authenticating' | 'connecting' | 'online' | 'recovering' | 'blocked';
  readonly error: { readonly code: string; readonly paused: boolean } | null;
  readonly downloaded: string; readonly processed: string; readonly reported: string;
  readonly sending: readonly SendingState[];
  readonly recovery: NetworkRecoveryState | null;
  readonly unavailable_history: readonly UnavailableRecord[];
}
export type Change = LocalChange
  | { readonly kind: 'network_state'; readonly scope: Scope; readonly state: NetworkState }
  | { readonly kind: 'network_error'; readonly scope: Scope; readonly error: { readonly code: string; readonly paused: boolean } };
