import type { CryptoCheckpoint, CryptoRequest, CryptoSnapshot, CryptoTestOptions } from "./crypto_types.js";
import type { RebuildBasis } from "./rebuild_types.js";

/** 固定实验范围；输入来自本轮独立配置，不能从锚响应中重新信任。 */
export interface AnchorScope {
  readonly service: string;
  readonly account: string;
  readonly device: string;
  readonly identity_key: string;
  readonly store_id: string;
}
export interface AnchorConfiguration {
  readonly endpoint: string;
  readonly scope: AnchorScope;
  readonly anchorPublicKey: string;
  /** 本轮合成客户端的签名种子；不写入日志或返回值。 */
  readonly clientSeed: string;
}
export interface AnchorOptions {
  service: string;
  account: string;
  testMode?: boolean;
  anchor: AnchorConfiguration;
}
export type AnchorWindow = "after_anchor_reserve" | "after_candidate_commit" | "after_anchor_finish";
export type AnchorCheckpoint = CryptoCheckpoint | AnchorWindow;
export interface AnchorTestOptions extends CryptoTestOptions { anchorCheckpoint?: AnchorWindow; }
export interface AnchorStatus {
  readonly assurance: "synthetic_local";
  readonly phase: "ready" | "paused";
  readonly localHead: string;
  readonly remoteHead: string;
  readonly remoteRevision: string;
  readonly remotePending: string | null;
  readonly localPending: boolean;
  readonly reason: string | null;
}
export interface AnchorView {
  /** 只有 Rust 完成锚确认才返回公开密码快照；status/resume 的诊断结果为 null。 */
  readonly snapshot: CryptoSnapshot | null;
  readonly status: AnchorStatus;
  /** 仅 rebuildBasis 诊断返回；不含密码快照或旧 provider。 */
  readonly rebuildBasis?: RebuildBasis;
}
export type AnchorRequest = (Exclude<CryptoRequest, { op: "initialize" }> | { op: "status" } | { op: "resume" } | { op: "rebuild_basis" }) & {
  anchorTest?: { checkpoint: AnchorWindow };
};
