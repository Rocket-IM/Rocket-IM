import type { AnchorScope, AnchorStatus, AnchorWindow } from "./anchor_types.js";
import type { CryptoCheckpoint, CryptoRequest, CryptoSnapshot, CryptoTestOptions, Identity } from "./crypto_types.js";

/** 新实验身份的独立存储范围；不以此配置重新授权旧数据库或旧未决操作。 */
export interface RebuildOptions {
  service: string;
  account: string;
  device: string;
  storageNamespace: string;
  endpoint: string;
  anchorPublicKey: string;
  approverPublicKey: string;
  /** 合成认证种子来自浏览器备份之外的可信配置，不进入公开结果。 */
  clientSeed: string;
  testMode?: boolean;
  /** 仅显式测试创建：验证新身份初始化失败与已提交身份的 offer 补全。 */
  initialFault?: "after_crypto" | "after_sql" | "refuse_commit" | "reserve_refuse" | "after_commit";
}
export type ParsedRebuildOptions = Omit<Required<RebuildOptions>, "initialFault"> & Pick<RebuildOptions, "initialFault">;
export interface RebuildBasis {
  readonly oldScope: AnchorScope;
  readonly oldHead: string;
  readonly oldTxn: string;
  readonly oldRevision: string;
  readonly oldConversation: string;
  readonly localHead: string;
  readonly baselineHead: string;
}
export interface RebuildOffer {
  readonly scope: AnchorScope;
  readonly head: string;
  readonly identity: Identity;
  readonly clientPublicKey: string;
  readonly storageNamespace: string;
}
/** 与已签名计划使用同一 snake_case 线格式，门面不改写声明原文。 */
export interface RebuildPlan {
  readonly protocol_version: "rim-browser-rebuild-1";
  readonly rebuild_id: string;
  readonly anchor_public_key: string;
  readonly approver_public_key: string;
  readonly old_scope: AnchorScope;
  readonly old_head: string;
  readonly old_txn: string;
  readonly old_revision: string;
  readonly old_conversation: string;
  readonly successor_scope: AnchorScope;
  readonly successor_head: string;
  readonly successor_client_public_key: string;
  readonly successor_key_package_sha256: string;
  readonly conversation: string;
  readonly peer: Identity;
}
export interface RebuildSigned {
  readonly statement_bytes: string;
  readonly signature_bytes: string;
}
export type RebuildWindow = AnchorWindow | "after_rebuild_link";
export type RebuildCheckpoint = CryptoCheckpoint | RebuildWindow;
export interface RebuildTestOptions extends CryptoTestOptions { anchorCheckpoint?: RebuildWindow; }
export interface RebuildView {
  readonly phase: "candidate" | "linked" | "ready" | "paused";
  readonly candidate: RebuildOffer | null;
  /** 仅完成批准及真实入群后交付业务快照，诊断与激活结果为 null。 */
  readonly snapshot: CryptoSnapshot | null;
  readonly status: AnchorStatus | null;
}
export type RebuildRequest = (
  | Exclude<CryptoRequest, { op: "initialize" } | { op: "create_group" }>
  | { op: "offer" } | { op: "status" } | { op: "resume" }
  | { op: "activate"; plan: RebuildPlan; approval: RebuildSigned }
) & { anchorTest?: { checkpoint: RebuildWindow }; };
