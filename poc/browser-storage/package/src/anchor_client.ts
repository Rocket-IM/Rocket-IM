import { StorageError } from "./protocol.js";
import { Transport, caught } from "./transport.js";
import type { CheckpointEvent, StateEvent, StateListener } from "./transport.js";
import { anchorCommand, anchorOptions, anchorOutcome } from "./anchor_protocol.js";
import type { DownloadEvent, Identity } from "./crypto_types.js";
import type { AnchorCheckpoint, AnchorOptions, AnchorRequest, AnchorTestOptions, AnchorView } from "./anchor_types.js";
import type { RebuildBasis } from "./rebuild_types.js";

export type AnchorEvent = StateEvent<AnchorView>;
export type AnchorListener = StateListener<AnchorView>;
export type AnchorCheckpointEvent = CheckpointEvent<AnchorCheckpoint>;

/** 本机合成独立锚实验。公开快照仅由 Rust 完成锚确认后返回，不在宿主层恢复密码状态。 */
export class AnchorClient {
  private constructor(private readonly transport: Transport<AnchorRequest, AnchorView, AnchorCheckpoint>, private readonly testMode: boolean) {}

  static async open(input: AnchorOptions): Promise<AnchorClient> {
    const options = anchorOptions(input);
    const transport = await Transport.open<AnchorRequest, AnchorView, AnchorCheckpoint>({ ...options, mode: "anchor" }, {
      read: { op: "inspect" }, outcome: anchorOutcome,
      checkpoint: command => command.anchorTest?.checkpoint
        ?? (command.op === "status" || command.op === "resume" || command.op === "rebuild_basis" || command.op === "inspect" ? undefined : command.test?.checkpoint),
      changed: (command, view) => command.op !== "status" && command.op !== "resume" && command.op !== "rebuild_basis"
        && view.snapshot !== null && view.snapshot.change !== "none",
      allowWhenPaused: command => command.op === "status" || command.op === "resume" || command.op === "rebuild_basis",
      validateInitial: view => {
        if (view.snapshot !== null) throw new StorageError("INVALID_RESPONSE", "Anchor open must return status without a crypto snapshot.", true);
      },
    });
    return new AnchorClient(transport, options.testMode);
  }
  /** 只读取诊断，不开放密文缓存、消息或密码快照，也不解除暂停。 */
  status(): Promise<AnchorView> { return this.execute({ op: "status" }); }
  /** 只读旧未决范围的公开批准依据，不恢复旧密码状态。 */
  async rebuildBasis(): Promise<RebuildBasis> {
    const view = await this.execute({ op: "rebuild_basis" });
    if (view.snapshot !== null || view.rebuildBasis === undefined) {
      throw new StorageError("INVALID_RESPONSE", "A diagnostic predecessor basis is required.", true);
    }
    return view.rebuildBasis;
  }
  /** 只由 Rust 恢复可验证的已提交结果；真实存储故障须先关闭重开。 */
  resume(): Promise<AnchorView> { return this.execute({ op: "resume" }); }
  inspect(): Promise<AnchorView> { return this.execute({ op: "inspect" }); }
  createGroup(conversation: string, peer: Identity, test?: AnchorTestOptions): Promise<AnchorView> {
    return this.execute({ op: "create_group", conversation, peer }, test);
  }
  joinGroup(conversation: string, peer: Identity, welcome: string, test?: AnchorTestOptions): Promise<AnchorView> {
    return this.execute({ op: "join_group", conversation, peer, welcome }, test);
  }
  send(attemptId: string, messageId: string, text: string, test?: AnchorTestOptions): Promise<AnchorView> {
    return this.execute({ op: "send", attemptId, messageId, text }, test);
  }
  download(event: DownloadEvent, test?: AnchorTestOptions): Promise<AnchorView> {
    return this.execute({ op: "download", event }, test);
  }
  processNext(test?: AnchorTestOptions): Promise<AnchorView> { return this.execute({ op: "process_next" }, test); }
  /** 事件的 snapshot 字段为完整 AnchorView；首个 inspect 与后续提交在同一队列衔接。 */
  subscribe(listener: AnchorListener): Promise<() => void> { return this.transport.subscribe(listener); }
  close(): Promise<void> { return this.transport.close(); }
  get test(): {
    onCheckpoint: (listener: (event: AnchorCheckpointEvent) => void) => () => void;
    terminate: () => Promise<void>;
  } { return this.transport.test; }
  private execute(value: unknown, test?: AnchorTestOptions): Promise<AnchorView> {
    try { return this.transport.execute(anchorCommand(value, test, this.testMode)); }
    catch (error) { return Promise.reject(caught(error)); }
  }
}
export async function openAnchored(options: AnchorOptions): Promise<AnchorClient> { return AnchorClient.open(options); }
