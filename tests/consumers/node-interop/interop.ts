// 独立安装 Node 包的互通端；仅由 interop.mjs 的 Worker 调用，不实现密码算法。
import { initialize, SDK_VERSION, Stage0Device } from "@rocket-im/stage0-node";

type JsonObject = { [name: string]: unknown };
interface Command { run_id: string; command_id: string; op: string; handle: string; args: Record<string, string>; }
interface Failure { origin: "sdk" | "harness"; code: string; device_poisoned: boolean; message: string; }
type Result = { run_id: string; endpoint_id: string; command_id: string } &
  ({ ok: true; value: string | null } | { ok: false; error: Failure });

class HarnessError extends Error {}
class SdkFailure extends Error {
  constructor(readonly failure: Failure) { super(failure.code); }
}
const maximumBytes = 1024 * 1024;
const codes = new Set(["invalid_argument", "invalid_encoding", "identity_mismatch", "scope_mismatch",
  "already_grouped", "group_required", "closed", "poisoned", "crypto_failure", "limit_exceeded"]);
const argumentsByOperation: Readonly<Record<string, readonly string[]>> = {
  new: ["service_id", "account_id", "device_id"], identity: [], key_package: [],
  create_group: ["conversation_id", "peer_account_id", "peer_device_id", "peer_identity_key", "key_package"],
  join_group: ["conversation_id", "creator_account_id", "creator_device_id", "creator_identity_key", "welcome"],
  encrypt: ["plaintext"], decrypt: ["ciphertext"], close: [], drop: [], shutdown: [],
};

function object(value: unknown): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new HarnessError("object_expected");
  return Object.fromEntries(Object.entries(value));
}
function text(value: unknown): string {
  if (typeof value !== "string") throw new HarnessError("string_expected");
  return value;
}
function exactKeys(value: JsonObject, names: readonly string[]): boolean {
  return Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name));
}
function validID(value: string): boolean { return /^[A-Za-z0-9_-]{1,96}$/.test(value); }
function command(value: unknown, runID: string): Command {
  const item = object(value);
  if (!exactKeys(item, ["run_id", "command_id", "op", "handle", "args"])) throw new HarnessError("command_shape");
  const run_id = text(item.run_id), command_id = text(item.command_id), op = text(item.op), handle = text(item.handle);
  if (run_id !== runID || !validID(command_id) || (op === "shutdown" ? handle !== "" : !validID(handle))) {
    throw new HarnessError("command_binding");
  }
  if (!Object.hasOwn(argumentsByOperation, op)) throw new HarnessError("operation_unknown");
  const rawArgs = object(item.args);
  if (!exactKeys(rawArgs, argumentsByOperation[op])) throw new HarnessError("argument_shape");
  const args: Record<string, string> = {};
  for (const [key, value] of Object.entries(rawArgs)) args[key] = text(value);
  return { run_id, command_id, op, handle, args };
}
function argument(item: Command, name: string): string {
  const value = item.args[name];
  if (typeof value !== "string") throw new HarnessError("argument_missing");
  return value;
}
function base64(bytes: Uint8Array): string {
  let encoded = "";
  for (let offset = 0; offset < bytes.length; offset += 8192) {
    encoded += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
  }
  return btoa(encoded);
}
function bytes(item: Command, name: string): Uint8Array {
  const value = argument(item, name);
  let raw: string;
  try { raw = atob(value); } catch { throw new HarnessError("argument_base64"); }
  const output = Uint8Array.from(raw, character => character.charCodeAt(0));
  if (base64(output) !== value) throw new HarnessError("argument_base64");
  return output;
}
function sdk<T>(action: () => T): T {
  try { return action(); } catch (error) {
    if (error instanceof HarnessError) throw error;
    // 仅解析本次公开 SDK 调用直接抛出的固定错误格式；HTTP、加载或装置异常不冒充密码拒绝。
    const match = error instanceof Error ? /^([a-z_]+); device_poisoned=(true|false)$/.exec(error.message) : null;
    if (match && codes.has(match[1])) {
      throw new SdkFailure({ origin: "sdk", code: match[1], device_poisoned: match[2] === "true", message: "" });
    }
    throw new HarnessError("unexpected_sdk_error");
  }
}
function failure(error: unknown): Failure {
  if (error instanceof SdkFailure) return error.failure;
  return { origin: "harness", code: error instanceof HarnessError ? error.message : "unexpected_error",
    device_poisoned: false, message: "" };
}

class Endpoint {
  private readonly devices = new Map<string, Stage0Device>();
  private readonly seen = new Set<string>();
  constructor(private readonly base: URL, private readonly runID: string, private readonly endpointID: string) {}

  private async request(path: string, body?: unknown): Promise<unknown> {
    const encoded = body === undefined ? undefined : JSON.stringify(body);
    if (encoded !== undefined && new TextEncoder().encode(encoded).length > maximumBytes) throw new HarnessError("request_size");
    const response = await fetch(new URL(path, this.base), {
      method: body === undefined ? "GET" : "POST", body: encoded,
      headers: body === undefined ? {} : { "Content-Type": "application/json" },
      signal: AbortSignal.timeout(20000), redirect: "error", credentials: "omit", cache: "no-store",
    });
    if (body === undefined && response.status === 204) return undefined;
    if (response.status !== 200 || response.body === null) {
      await response.body?.cancel();
      throw new HarnessError("http_response");
    }
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = []; let length = 0;
    try {
      while (true) {
        const item = await reader.read();
        if (item.done) break;
        length += item.value.length;
        if (length > maximumBytes) { await reader.cancel(); throw new HarnessError("response_size"); }
        chunks.push(item.value);
      }
    } finally { reader.releaseLock(); }
    const data = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { data.set(chunk, offset); offset += chunk.length; }
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(data));
  }

  private async post(path: string, body: unknown): Promise<void> {
    const reply = object(await this.request(path, body));
    if (!exactKeys(reply, ["ok"]) || reply.ok !== true) throw new HarnessError("http_ack");
  }

  private perform(item: Command): string | null {
    if (item.op === "new") {
      if (this.devices.has(item.handle) || this.devices.size >= 32) throw new HarnessError("handle_limit_or_duplicate");
      const device = sdk(() => new Stage0Device(argument(item, "service_id"), argument(item, "account_id"), argument(item, "device_id")));
      this.devices.set(item.handle, device);
      return null;
    }
    if (item.op === "shutdown") { this.clear(); return null; }
    const device = this.devices.get(item.handle);
    if (device === undefined) throw new HarnessError("handle_missing");
    switch (item.op) {
      case "identity": return base64(sdk(() => device.identityKey()));
      case "key_package": return base64(sdk(() => device.keyPackage()));
      case "create_group": return base64(sdk(() => device.createGroup(argument(item, "conversation_id"),
        argument(item, "peer_account_id"), argument(item, "peer_device_id"), bytes(item, "peer_identity_key"), bytes(item, "key_package"))));
      case "join_group": sdk(() => device.joinGroup(argument(item, "conversation_id"), argument(item, "creator_account_id"),
        argument(item, "creator_device_id"), bytes(item, "creator_identity_key"), bytes(item, "welcome"))); return null;
      case "encrypt": return base64(sdk(() => device.encrypt(bytes(item, "plaintext"))));
      case "decrypt": return base64(sdk(() => device.decrypt(bytes(item, "ciphertext"))));
      case "close": sdk(() => device.close()); return null;
      case "drop": sdk(() => device.close()); this.devices.delete(item.handle); return null;
      default: throw new HarnessError("operation_unknown");
    }
  }

  private clear(): void {
    let failed = false;
    for (const device of this.devices.values()) {
      try { device.close(); } catch { failed = true; }
    }
    this.devices.clear();
    if (failed) throw new HarnessError("cleanup_failed");
  }

  async run(): Promise<{ shutdown: true }> {
    try {
      await initialize();
      await this.post("ready", { run_id: this.runID, endpoint_id: this.endpointID, sdk_version: SDK_VERSION, platform: "node-macos" });
      while (true) {
        const next = await this.request("next");
        if (next === undefined) continue;
        const item = command(next, this.runID);
        if (this.seen.has(item.command_id) || this.seen.size >= 4096) throw new HarnessError("command_duplicate_or_limit");
        this.seen.add(item.command_id);
        const binding = { run_id: this.runID, endpoint_id: this.endpointID, command_id: item.command_id };
        let result: Result;
        try { result = { ...binding, ok: true, value: this.perform(item) }; }
        catch (error) { result = { ...binding, ok: false, error: failure(error) }; }
        // 命令只执行一次、结果只提交一次；连接失败即终止，不重做有状态密码调用。
        await this.post("result", result);
        if (!result.ok && result.error.origin === "harness") throw new HarnessError("command_harness_failure");
        if (item.op === "shutdown") {
          if (!result.ok) throw new HarnessError("shutdown_failed");
          return { shutdown: true };
        }
      }
    } finally { this.clear(); }
  }
}

export async function runInterop(configuration: unknown): Promise<{ shutdown: true }> {
  const config = object(configuration);
  if (!exactKeys(config, ["url", "runId", "endpointId"])) throw new HarnessError("configuration_shape");
  const base = new URL(text(config.url)), runID = text(config.runId), endpointID = text(config.endpointId);
  if (base.protocol !== "http:" || base.hostname !== "127.0.0.1" || base.port === "" || base.username || base.password ||
      base.pathname !== "/" || base.search || base.hash || !validID(runID) || endpointID !== "node-macos") {
    throw new HarnessError("configuration_invalid");
  }
  base.pathname = `/interop/${runID}/${endpointID}/`;
  return new Endpoint(base, runID, endpointID).run();
}
