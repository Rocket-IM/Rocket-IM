import { initialize, SDK_VERSION, Stage0Device } from "@rocket-im/stage0";

type JsonObject = { [name: string]: unknown };
interface Command { run_id: string; command_id: string; op: string; handle: string; args: Record<string, string>; }
interface Failure { origin: "sdk" | "harness"; code: string; device_poisoned: boolean; message: string; }
interface Result { run_id: string; endpoint_id: string; command_id: string; ok: boolean; value?: string | null; error?: Failure; }
interface State { status: "RUNNING" | "READY" | "STOPPED" | "FAIL"; error?: Failure; }
declare global { interface Window { __interopState?: State; } }

class HarnessError extends Error {}
const maximumBytes = 1024 * 1024;
const codes = new Set(["invalid_argument", "invalid_encoding", "identity_mismatch", "scope_mismatch",
  "already_grouped", "group_required", "closed", "poisoned", "crypto_failure", "limit_exceeded"]);

function object(value: unknown): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new HarnessError("object_expected");
  return Object.fromEntries(Object.entries(value));
}
function text(value: unknown): string {
  if (typeof value !== "string") throw new HarnessError("string_expected");
  return value;
}
function validID(value: string): boolean { return /^[A-Za-z0-9_-]{1,96}$/.test(value); }
function command(value: unknown, runID: string): Command {
  const item = object(value);
  const run_id = text(item.run_id), command_id = text(item.command_id), op = text(item.op), handle = text(item.handle);
  if (run_id !== runID || !validID(command_id) || (op !== "shutdown" && !validID(handle))) throw new HarnessError("command_binding");
  const args: Record<string, string> = {};
  for (const [key, value] of Object.entries(object(item.args))) args[key] = text(value);
  return { run_id, command_id, op, handle, args };
}
function argument(item: Command, name: string): string {
  const value = item.args[name];
  if (typeof value !== "string") throw new HarnessError("argument_missing");
  return value;
}
function base64(bytes: Uint8Array): string {
  // 分块避免大消息超出函数参数栈，但始终编码原始字节。
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
function failure(error: unknown): Failure {
  const message = error instanceof Error ? error.message : String(error);
  if (!(error instanceof HarnessError)) {
    const match = /^([a-z_]+); device_poisoned=(true|false)$/.exec(message);
    if (match && codes.has(match[1])) {
      return { origin: "sdk", code: match[1], device_poisoned: match[2] === "true", message: message.slice(0, 256) };
    }
  }
  return { origin: "harness", code: error instanceof HarnessError ? message : "unexpected_error",
    device_poisoned: false, message: message.slice(0, 256) };
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
    if (response.status !== 200 || response.body === null) throw new HarnessError("http_response");
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = []; let length = 0;
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      length += item.value.length;
      if (length > maximumBytes) { await reader.cancel(); throw new HarnessError("response_size"); }
      chunks.push(item.value);
    }
    const data = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { data.set(chunk, offset); offset += chunk.length; }
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(data));
  }

  private async post(path: string, body: unknown): Promise<void> {
    if (object(await this.request(path, body)).ok !== true) throw new HarnessError("http_ack");
  }

  private perform(item: Command): string | null {
    if (item.op === "new") {
      if (this.devices.has(item.handle) || this.devices.size >= 32) throw new HarnessError("handle_limit_or_duplicate");
      const device = new Stage0Device(argument(item, "service_id"), argument(item, "account_id"), argument(item, "device_id"));
      this.devices.set(item.handle, device);
      return null;
    }
    if (item.op === "shutdown") { this.clear(); return null; }
    const device = this.devices.get(item.handle);
    if (device === undefined) throw new HarnessError("handle_missing");
    switch (item.op) {
      case "identity": return base64(device.identityKey());
      case "key_package": return base64(device.keyPackage());
      case "create_group": return base64(device.createGroup(argument(item, "conversation_id"),
        argument(item, "peer_account_id"), argument(item, "peer_device_id"), bytes(item, "peer_identity_key"), bytes(item, "key_package")));
      case "join_group": device.joinGroup(argument(item, "conversation_id"), argument(item, "creator_account_id"),
        argument(item, "creator_device_id"), bytes(item, "creator_identity_key"), bytes(item, "welcome")); return null;
      case "encrypt": return base64(device.encrypt(bytes(item, "plaintext")));
      case "decrypt": return base64(device.decrypt(bytes(item, "ciphertext")));
      case "close": device.close(); return null;
      case "drop": device.close(); this.devices.delete(item.handle); return null;
      default: throw new HarnessError("operation_unknown");
    }
  }

  private clear(): void {
    for (const device of this.devices.values()) device.close();
    this.devices.clear();
  }

  async run(): Promise<void> {
    try {
      await initialize();
      await this.post("ready", { run_id: this.runID, endpoint_id: this.endpointID, sdk_version: SDK_VERSION, platform: "browser" });
      window.__interopState = { status: "READY" };
      while (true) {
        const next = await this.request("next");
        if (next === undefined) continue;
        const item = command(next, this.runID);
        if (this.seen.has(item.command_id) || this.seen.size >= 4096) throw new HarnessError("command_duplicate_or_limit");
        this.seen.add(item.command_id);
        let result: Result;
        try {
          result = { run_id: this.runID, endpoint_id: this.endpointID, command_id: item.command_id, ok: true, value: this.perform(item) };
        } catch (error) {
          result = { run_id: this.runID, endpoint_id: this.endpointID, command_id: item.command_id, ok: false, error: failure(error) };
        }
        // 一次执行只提交一次；HTTP失败终止，不重做有状态密码命令。
        await this.post("result", result);
        if (item.op === "shutdown") {
          if (!result.ok) throw new HarnessError("shutdown_failed");
          window.__interopState = { status: "STOPPED" };
          return;
        }
      }
    } finally { this.clear(); }
  }
}

export async function runInterop(): Promise<void> {
  window.__interopState = { status: "RUNNING" };
  try {
    const params = new URL(location.href).searchParams;
    const base = new URL(text(params.get("interop_url")));
    const runID = text(params.get("interop_run_id")), endpointID = text(params.get("interop_endpoint_id"));
    if (base.protocol !== "http:" || base.hostname !== "127.0.0.1" || base.port === "" || base.username || base.password || base.search || base.hash ||
        !validID(runID) || !validID(endpointID)) throw new HarnessError("configuration_invalid");
    base.pathname = base.pathname.replace(/\/$/, "") + `/interop/${runID}/${endpointID}/`;
    await new Endpoint(base, runID, endpointID).run();
  } catch (error) { window.__interopState = { status: "FAIL", error: failure(error) }; }
  const output = document.querySelector("#result");
  if (output instanceof HTMLElement) output.textContent = JSON.stringify(window.__interopState);
}
