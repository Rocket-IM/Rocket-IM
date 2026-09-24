import { cryptoOpenOptions, cryptoOutcome, cryptoRequest } from "./crypto_protocol.js";
import { Transport, caught } from "./transport.js";
import { StorageError } from "./protocol.js";
import type { CheckpointEvent, StateEvent, StateListener } from "./transport.js";
import type { CryptoCheckpoint, CryptoOpenOptions, CryptoRequest, CryptoSnapshot, CryptoTestOptions,
  DownloadEvent, Identity } from "./crypto_types.js";

export type CryptoListener = StateListener<CryptoSnapshot>;
export type CryptoEvent = StateEvent<CryptoSnapshot>;
export type CryptoCheckpointEvent = CheckpointEvent<CryptoCheckpoint>;

/** 隔离 OpenMLS + SQLite 实验门面；所有密码状态与成功判断均由 Rust 持有。 */
export class CryptoClient {
  private constructor(private readonly transport: Transport<CryptoRequest, CryptoSnapshot, CryptoCheckpoint>, private readonly testMode: boolean) {}

  static async open(input: CryptoOpenOptions): Promise<CryptoClient> {
    const options = cryptoOpenOptions(input);
    const transport = await Transport.open<CryptoRequest, CryptoSnapshot, CryptoCheckpoint>({ ...options, mode: "crypto" }, {
      read: { op: "inspect" }, outcome: cryptoOutcome,
      checkpoint: command => command.op === "inspect" ? undefined : command.test?.checkpoint,
      changed: (_command, snapshot) => snapshot.change !== "none",
      allowWhenPaused: command => command.op === "inspect",
      // 持久 paused 是可查询的业务状态；不能在宿主层伪造恢复或阻断核验。
      validateInitial: () => {},
    });
    return new CryptoClient(transport, options.testMode);
  }
  /** 显式读事务快照；持久状态为 paused 时仍允许检查，不代表恢复密码操作。 */
  inspect(): Promise<CryptoSnapshot> { return this.execute({ op: "inspect" }); }
  initialize(test?: CryptoTestOptions): Promise<CryptoSnapshot> { return this.execute({ op: "initialize", test }); }
  createGroup(conversation: string, peer: Identity, test?: CryptoTestOptions): Promise<CryptoSnapshot> {
    return this.execute({ op: "create_group", conversation, peer, test });
  }
  joinGroup(conversation: string, peer: Identity, welcome: string, test?: CryptoTestOptions): Promise<CryptoSnapshot> {
    return this.execute({ op: "join_group", conversation, peer, welcome, test });
  }
  /** 同一 attemptId 的重试由 Rust 复用已提交密文；未决预约不会在宿主层重试。 */
  send(attemptId: string, messageId: string, text: string, test?: CryptoTestOptions): Promise<CryptoSnapshot> {
    return this.execute({ op: "send", attemptId, messageId, text, test });
  }
  download(event: DownloadEvent, test?: CryptoTestOptions): Promise<CryptoSnapshot> {
    return this.execute({ op: "download", event, test });
  }
  processNext(test?: CryptoTestOptions): Promise<CryptoSnapshot> { return this.execute({ op: "process_next", test }); }
  /** 首次 inspect 快照后，仅真实提交且 change 非 none 的结果派发 committed。 */
  subscribe(listener: CryptoListener): Promise<() => void> { return this.transport.subscribe(listener); }
  close(): Promise<void> { return this.transport.close(); }
  /** 检查点只是测试诊断；terminate 后必须重新打开并读取实际持久结果。 */
  get test(): {
    onCheckpoint: (listener: (event: CryptoCheckpointEvent) => void) => () => void;
    terminate: () => Promise<void>;
    describeAnchor: () => Promise<{ readonly head: string; readonly identity: Identity }>;
  } {
    return { ...this.transport.test, describeAnchor: async () => {
      const snapshot = await this.inspect();
      if (snapshot.commitment === undefined || snapshot.identity === null) {
        throw new StorageError("ANCHOR_BASELINE_UNAVAILABLE", "An initialized test identity and commitment are required.");
      }
      return Object.freeze({ head: snapshot.commitment, identity: snapshot.identity });
    } };
  }
  private execute(value: unknown): Promise<CryptoSnapshot> {
    try { return this.transport.execute(cryptoRequest(value, this.testMode)); }
    catch (error) { return Promise.reject(caught(error)); }
  }
}
export async function openCrypto(options: CryptoOpenOptions): Promise<CryptoClient> { return CryptoClient.open(options); }
