import { VERSION, object, openOptions, outcome, request } from "./protocol.js";
import type { Checkpoint, OpenOptions, PutTestOptions, Request, Snapshot } from "./protocol.js";
import { Transport, caught, unavailable } from "./transport.js";
import type { CheckpointEvent as TransportCheckpointEvent, StateEvent, StateListener } from "./transport.js";

export { StorageError } from "./protocol.js";
export type { OpenOptions, PutTestOptions, Snapshot, RecordValue, StorageCause } from "./protocol.js";
export { CryptoClient, openCrypto } from "./crypto_client.js";
export { AnchorClient, openAnchored } from "./anchor_client.js";
export { RebuildClient, createRebuild, openRebuild } from "./rebuild_client.js";
export type { RebuildEvent, RebuildListener, RebuildCheckpointEvent } from "./rebuild_client.js";
export type { RebuildOptions, RebuildBasis, RebuildOffer, RebuildPlan, RebuildSigned,
  RebuildTestOptions, RebuildWindow, RebuildCheckpoint, RebuildView } from "./rebuild_types.js";
export type { AnchorEvent, AnchorListener, AnchorCheckpointEvent } from "./anchor_client.js";
export type { AnchorOptions, AnchorConfiguration, AnchorScope, AnchorView, AnchorStatus,
  AnchorTestOptions, AnchorWindow, AnchorCheckpoint } from "./anchor_types.js";
export type { CryptoListener, CryptoEvent, CryptoCheckpointEvent } from "./crypto_client.js";
export type { CryptoOpenOptions, CryptoTestOptions, CryptoSnapshot, Identity, Envelope, DownloadEvent,
  CryptoCheckpoint, CryptoChange, CryptoOperation, CryptoOutbox, CryptoStoredEvent, CryptoMessage } from "./crypto_types.js";
export const PACKAGE_VERSION = VERSION;
export type StorageEvent = StateEvent<Snapshot>;
export type Listener = StateListener<Snapshot>;
export type CheckpointEvent = TransportCheckpointEvent<Checkpoint>;

/** 一个实例独占服务/账号范围；普通记录与密码门面不能同时占用相同范围。 */
export class StorageClient {
  private constructor(private readonly transport: Transport<Request, Snapshot, Checkpoint>, private readonly testMode: boolean) {}

  static async open(input: OpenOptions): Promise<StorageClient> {
    const options = openOptions(input);
    const transport = await Transport.open<Request, Snapshot, Checkpoint>({ ...options, mode: "ordinary" }, {
      read: { op: "snapshot" }, outcome,
      checkpoint: command => command.op === "put" ? command.checkpoint : undefined,
      changed: command => command.op === "put",
      allowWhenPaused: () => false,
      validateInitial: snapshot => {
        if (!options.seedV1 && snapshot.schemaVersion !== 2) {
          throw unavailable("SCHEMA_MISMATCH", "Normal open requires schema version 2.");
        }
      },
    });
    return new StorageClient(transport, options.testMode);
  }
  snapshot(): Promise<Snapshot> { return this.transport.execute({ op: "snapshot" }); }
  put(key: string, value: string, expectedRevision: string, test: PutTestOptions = {}): Promise<Snapshot> {
    try {
      const control = object(test);
      return this.transport.execute(request({ op: "put", key, value, expectedRevision,
        fault: control.fault, checkpoint: control.checkpoint }, this.testMode));
    } catch (error) { return Promise.reject(caught(error)); }
  }
  /** 首次快照与后续提交无缝交接；回调可重新查询，SDK 不等待回调。 */
  subscribe(listener: Listener): Promise<() => void> { return this.transport.subscribe(listener); }
  /** 关闭会拒绝未交付命令并停止事件，Rust 释放数据库后才释放范围锁。 */
  close(): Promise<void> { return this.transport.close(); }
  /** 明确标记的实验控制，不属于正式 SDK 接口。 */
  get test(): {
    onCheckpoint: (listener: (event: CheckpointEvent) => void) => () => void;
    terminate: () => Promise<void>;
    failRead: () => Promise<Snapshot>;
  } {
    return { ...this.transport.test, failRead: () => this.transport.execute({ op: "read_fault" }) };
  }
}
export async function open(options: OpenOptions): Promise<StorageClient> { return StorageClient.open(options); }
