import { StorageError } from "./protocol.js";
import { Transport, caught } from "./transport.js";
import type { CheckpointEvent, StateEvent, StateListener } from "./transport.js";
import { rebuildCommand, rebuildOptions, rebuildOutcome } from "./rebuild_protocol.js";
import type { DownloadEvent, Identity } from "./crypto_types.js";
import type { RebuildCheckpoint, RebuildOptions, RebuildPlan, RebuildRequest, RebuildSigned, RebuildTestOptions, RebuildView } from "./rebuild_types.js";

export type RebuildEvent = StateEvent<RebuildView>;
export type RebuildListener = StateListener<RebuildView>;
export type RebuildCheckpointEvent = CheckpointEvent<RebuildCheckpoint>;

/** 新身份和独立存储的实验入口；批准、旧范围封存及真实入群只由 Rust 与锚协议处理。 */
export class RebuildClient {
  private constructor(private readonly transport: Transport<RebuildRequest, RebuildView, RebuildCheckpoint>, private readonly testMode: boolean) {}

  static async open(input: RebuildOptions, create = false): Promise<RebuildClient> {
    const options = rebuildOptions(input);
    if (!create && options.initialFault !== undefined) throw new StorageError("INVALID_ARGUMENT", "Identity initialization faults only apply to createRebuild.");
    if (create && !options.testMode) throw new StorageError("TEST_MODE_REQUIRED", "Creating a synthetic rebuild identity requires testMode.");
    const transport = await Transport.open<RebuildRequest, RebuildView, RebuildCheckpoint>({
      service: options.service, account: options.account, testMode: options.testMode,
      mode: "rebuild", rebuild: { options, create },
    }, {
      read: { op: "inspect" }, outcome: value => rebuildOutcome(value, options),
      checkpoint: command => command.anchorTest?.checkpoint
        ?? (command.op === "inspect" || command.op === "status" || command.op === "offer" || command.op === "resume"
          || command.op === "activate" ? undefined : command.test?.checkpoint),
      changed: (command, view) => command.op !== "status" && command.op !== "offer" && command.op !== "resume"
        && command.op !== "activate" && view.snapshot !== null && view.snapshot.change !== "none",
      allowWhenPaused: command => command.op === "status" || command.op === "offer" || command.op === "resume",
      validateInitial: view => {
        if (view.snapshot !== null) throw new StorageError("INVALID_RESPONSE", "Rebuild open requires diagnostics without a crypto snapshot.", true);
      },
    });
    return new RebuildClient(transport, options.testMode);
  }
  offer(): Promise<RebuildView> { return this.execute({ op: "offer" }); }
  status(): Promise<RebuildView> { return this.execute({ op: "status" }); }
  /** 提交事前可信批准；不隐式更换计划或重试不确定的链接。 */
  activate(plan: RebuildPlan, approval: RebuildSigned, test?: RebuildTestOptions): Promise<RebuildView> {
    return this.execute({ op: "activate", plan, approval }, test);
  }
  /** 只恢复原计划的确定结果，不能重新执行旧 MLS 操作。 */
  resume(): Promise<RebuildView> { return this.execute({ op: "resume" }); }
  inspect(): Promise<RebuildView> { return this.execute({ op: "inspect" }); }
  joinGroup(conversation: string, peer: Identity, welcome: string, test?: RebuildTestOptions): Promise<RebuildView> {
    return this.execute({ op: "join_group", conversation, peer, welcome }, test);
  }
  send(attemptId: string, messageId: string, text: string, test?: RebuildTestOptions): Promise<RebuildView> {
    return this.execute({ op: "send", attemptId, messageId, text }, test);
  }
  download(event: DownloadEvent, test?: RebuildTestOptions): Promise<RebuildView> { return this.execute({ op: "download", event }, test); }
  processNext(test?: RebuildTestOptions): Promise<RebuildView> { return this.execute({ op: "process_next" }, test); }
  subscribe(listener: RebuildListener): Promise<() => void> { return this.transport.subscribe(listener); }
  close(): Promise<void> { return this.transport.close(); }
  get test(): {
    onCheckpoint: (listener: (event: RebuildCheckpointEvent) => void) => () => void;
    terminate: () => Promise<void>;
  } { return this.transport.test; }
  private execute(value: unknown, test?: RebuildTestOptions): Promise<RebuildView> {
    try { return this.transport.execute(rebuildCommand(value, test, this.testMode)); }
    catch (error) { return Promise.reject(caught(error)); }
  }
}
/** 只用于明确创建本轮合成新身份；已存在的命名空间不得被覆盖。 */
export async function createRebuild(options: RebuildOptions): Promise<RebuildClient> { return RebuildClient.open(options, true); }
/** 只重开既有候选；数据库缺失时必须失败，不自动生成替代身份。 */
export async function openRebuild(options: RebuildOptions): Promise<RebuildClient> { return RebuildClient.open(options, false); }
