/** 隔离密码持久化探针的公开值；不暴露 OpenMLS 类型、私钥或 provider BLOB。 */
export interface CryptoOpenOptions { service: string; account: string; testMode?: boolean; }
export interface Identity {
  readonly service: string;
  readonly account: string;
  readonly device: string;
  readonly identityKey: string;
  /** 初始化后可用于建群；建群或入群后为空字符串。 */
  readonly keyPackage: string;
}
export interface Envelope {
  readonly service: string;
  readonly conversation: string;
  readonly senderAccount: string;
  readonly senderDevice: string;
  readonly messageId: string;
  readonly ciphertext: string;
}
export interface DownloadEvent { readonly sequence: string; readonly eventId: string; readonly envelope: Envelope; }
export type CryptoCheckpoint = "after_reserve" | "after_crypto" | "before_commit" | "after_commit";
export interface CryptoTestOptions {
  /** lose_reservation_table 仅用于 send：预约提交后模拟控制表丢失，重开必须拒绝。 */
  fault?: "after_crypto" | "after_sql" | "refuse_commit" | "reserve_refuse" | "lose_reservation_table";
  checkpoint?: CryptoCheckpoint;
}
export type CryptoChange = "none" | "initialized" | "grouped" | "outbox_ready" | "downloaded" | "processed";
export type CryptoOperation = "initialize" | "create_group" | "join_group" | "send" | "process_next";
export interface CryptoOutbox {
  readonly attemptId: string;
  readonly messageId: string;
  readonly plaintextHash: string;
  readonly ciphertextHash: string;
  readonly envelope: Envelope;
}
export interface CryptoStoredEvent {
  readonly sequence: string;
  readonly eventId: string;
  readonly ciphertextHash: string;
  readonly status: "pending" | "processed" | "duplicate";
}
export interface CryptoMessage {
  readonly sequence: string;
  readonly eventId: string;
  readonly messageId: string;
  readonly senderAccount: string;
  readonly text: string;
}
export interface CryptoSnapshot {
  readonly service: string;
  readonly account: string;
  readonly device: string;
  readonly status: "empty" | "ready" | "paused";
  readonly revision: string;
  readonly identity: Identity | null;
  readonly conversation: string | null;
  readonly providerHash: string | null;
  readonly pending: { readonly operation: CryptoOperation; readonly attemptId: string } | null;
  readonly encryptions: string;
  readonly decryptions: string;
  readonly downloadCursor: string;
  readonly processingCursor: string;
  readonly outbox: readonly CryptoOutbox[];
  readonly events: readonly CryptoStoredEvent[];
  readonly messages: readonly CryptoMessage[];
  readonly receipts: readonly string[];
  readonly welcome: string | null;
  readonly change: CryptoChange;
  /** 仅 testMode 的未锚定探针提供，用于选择本轮实验基线；不是数据库内容。 */
  readonly commitment?: string;
}
export type CryptoRequest = { op: "inspect" } | ({ test?: CryptoTestOptions } & (
  | { op: "initialize" }
  | { op: "create_group"; conversation: string; peer: Identity }
  | { op: "join_group"; conversation: string; peer: Identity; welcome: string }
  | { op: "send"; attemptId: string; messageId: string; text: string }
  | { op: "download"; event: DownloadEvent }
  | { op: "process_next" }
));
