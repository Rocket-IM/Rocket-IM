import initialize, { StorageProbe, CryptoProbe, AnchorProbe, RebuildProbe, probe_version } from "../generated/rocket_browser_storage_probe.js";
import { VERSION, StorageError, object, openOptions, parseJsonResult, parseOutcome, request, wireError } from "./protocol.js";
import { cryptoOpenOptions, cryptoRequest, parseCryptoOutcome } from "./crypto_protocol.js";
import { anchorOptions, anchorRequest, parseAnchorOutcome } from "./anchor_protocol.js";
import { anchorRpc } from "./anchor_rpc.js";
import { rebuildConfiguration, rebuildOptions, rebuildRequest, parseRebuildOutcome } from "./rebuild_protocol.js";
import type { ResultOutcome, Snapshot, WireError } from "./protocol.js";
import type { CryptoSnapshot } from "./crypto_types.js";
import type { AnchorView } from "./anchor_types.js";
import type { ParsedRebuildOptions, RebuildView } from "./rebuild_types.js";

// 此入口仅在 dedicated Worker 内运行；结构声明只适配消息端口，不转换外部数据。
declare const self: { postMessage(value: unknown): void; onmessage: ((event: MessageEvent<unknown>) => void) | null };
type Session = { mode: "ordinary"; probe: StorageProbe } | { mode: "crypto"; probe: CryptoProbe }
  | { mode: "anchor"; probe: AnchorProbe } | { mode: "rebuild"; probe: RebuildProbe; options: ParsedRebuildOptions };
let session: Session | undefined;
let service = "", account = "", testMode = false;
let activeID: string | undefined;
let busy = false;

function failure(error: unknown): WireError {
  if (typeof error === "string") {
    try {
      const parsed = object(parseJsonResult(error));
      if (parsed.ok === false && parsed.result === undefined) return wireError(parsed.error);
    } catch { /* 非 Rust 错误按实际环境异常回报。 */ }
  }
  if (error instanceof StorageError) return { code: error.code, message: error.message, paused: error.paused,
    ...(error.cause === undefined ? {} : { cause: error.cause }) };
  const message = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
  return { code: "WORKER_ENVIRONMENT_ERROR", message: message.slice(0, 2048), paused: true };
}
async function execute(value: unknown): Promise<ResultOutcome<Snapshot> | ResultOutcome<CryptoSnapshot> | ResultOutcome<AnchorView> | ResultOutcome<RebuildView>> {
  if (!session) throw new StorageError("CLOSED", "Worker has no open storage.", true);
  if (session.mode === "ordinary") {
    const parsed = request(value, testMode);
    return parseOutcome(session.probe.execute(JSON.stringify(parsed)), service, account);
  }
  if (session.mode === "anchor") {
    const parsed = anchorRequest(value, testMode);
    return parseAnchorOutcome(await session.probe.execute(JSON.stringify(parsed)), service, account, parsed.op);
  }
  if (session.mode === "rebuild") {
    const parsed = rebuildRequest(value, testMode);
    return parseRebuildOutcome(await session.probe.execute(JSON.stringify(parsed)), session.options, parsed.op);
  }
  const parsed = cryptoRequest(value, testMode);
  return parseCryptoOutcome(session.probe.execute(JSON.stringify(parsed)), service, account);
}
async function open(value: unknown): Promise<void> {
  if (session) throw new StorageError("ALREADY_OPEN", "Worker already owns a storage scope.", true);
  const raw = object(value);
  if (raw.mode !== "ordinary" && raw.mode !== "crypto" && raw.mode !== "anchor" && raw.mode !== "rebuild") {
    throw new StorageError("INVALID_REQUEST", "Unknown storage mode.", true);
  }
  const options = raw.mode === "ordinary" ? openOptions(raw) : raw.mode === "rebuild" ? rebuildOptions(object(raw.rebuild).options)
    : raw.mode === "anchor" ? anchorOptions(raw) : cryptoOpenOptions(raw);
  service = options.service; account = options.account; testMode = options.testMode;
  await initialize();
  if (probe_version() !== VERSION) throw new StorageError("VERSION_MISMATCH", "WASM and package versions do not match.", true);
  if (raw.mode === "ordinary") {
    const ordinary = openOptions(raw);
    session = { mode: "ordinary", probe: await StorageProbe.open(service, account, testMode, ordinary.seedV1, ordinary.failMigration) };
  } else if (raw.mode === "anchor") {
    const config = anchorOptions(raw).anchor;
    session = { mode: "anchor", probe: await AnchorProbe.open(service, account, testMode, JSON.stringify(config), anchorRpc(config.endpoint)) };
  } else if (raw.mode === "rebuild") {
    const input = object(raw.rebuild), fixed = rebuildOptions(input.options);
    if (typeof input.create !== "boolean" || raw.service !== service || raw.account !== account || raw.testMode !== testMode) {
      throw new StorageError("INVALID_REQUEST", "Invalid rebuild ownership or creation mode.", true);
    }
    if (!input.create && fixed.initialFault !== undefined) throw new StorageError("INVALID_ARGUMENT", "Initialization faults require explicit creation.");
    if (input.create && !testMode) throw new StorageError("TEST_MODE_REQUIRED", "Synthetic identity creation requires testMode.");
    session = { mode: "rebuild", options: fixed, probe: await RebuildProbe.open(
      JSON.stringify(rebuildConfiguration(fixed)), input.create, testMode, anchorRpc(fixed.endpoint)) };
  } else session = { mode: "crypto", probe: await CryptoProbe.open(service, account, testMode) };
  const current = session;
  if (testMode) current.probe.setCheckpointHook((phase: unknown) => {
    if (!activeID || (phase !== "before_commit" && phase !== "after_commit"
        && !(current.mode !== "ordinary" && (phase === "after_reserve" || phase === "after_crypto"))
        && !((current.mode === "anchor" || current.mode === "rebuild") && (phase === "after_anchor_reserve" || phase === "after_candidate_commit" || phase === "after_anchor_finish"))
        && !(current.mode === "rebuild" && phase === "after_rebuild_link"))) {
      throw new StorageError("INVALID_CHECKPOINT", "Invalid Rust test checkpoint.", true);
    }
    // 仅测试诊断；事务可能仍活动，不能在这里派发数据成功事件。
    self.postMessage({ id: activeID, kind: "checkpoint", phase, testOnly: true });
  });
}
async function handle(value: unknown): Promise<void> {
  let id: string | undefined;
  let ownsCommand = false;
  try {
    const command = object(value);
    if (typeof command.id !== "string" || !/^r[1-9][0-9]{0,15}$/.test(command.id)) {
      throw new StorageError("INVALID_REQUEST", "Invalid worker command ID.", true);
    }
    id = command.id;
    if (busy) throw new StorageError("WORKER_BUSY", "Only one worker command may execute.", true);
    busy = true; ownsCommand = true; activeID = id;
    if (command.kind === "open") {
      await open(command.options);
      const mode = object(command.options).mode;
      const result = await execute({ op: mode === "ordinary" ? "snapshot" : mode === "anchor" || mode === "rebuild" ? "status" : "inspect" });
      self.postMessage({ id, kind: "result", version: VERSION, outcome: result });
    } else if (command.kind === "execute") {
      // execute 成功结果已完成 Rust 事务；JS 不维护第二份业务状态。
      self.postMessage({ id, kind: "result", version: VERSION, outcome: await execute(command.request) });
    } else if (command.kind === "close") {
      if (session) { session.probe.close(); session.probe.free(); session = undefined; }
      self.postMessage({ id, kind: "closed", version: VERSION });
    } else throw new StorageError("INVALID_REQUEST", "Unknown worker command.", true);
  } catch (error) {
    self.postMessage({ id, kind: "error", error: failure(error), version: VERSION });
  } finally {
    if (ownsCommand) { activeID = undefined; busy = false; }
  }
}
self.onmessage = (event: MessageEvent<unknown>) => { void handle(event.data); };
