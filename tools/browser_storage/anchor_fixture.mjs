// 独立子进程控制器；可信配置和锚备份均在浏览器 profile 外，仍只证明 synthetic_local。
import fs from "node:fs/promises";
import path from "node:path";
import { fork } from "node:child_process";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { AnchorError, base64, hex, head, publicKey, scope, scopeKey, hash, requireValue } from "./anchor_wire.mjs";

const serverPath = fileURLToPath(new URL("./anchor_server.mjs", import.meta.url));
const randomHex = () => randomBytes(32).toString("hex");
function name(value) { requireValue(typeof value === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(value)); return value; }

export class AnchorFixture {
  constructor(output, origin) {
    this.output = path.resolve(output); this.origin = origin; this.directory = path.join(this.output, "anchor");
    this.trustDirectory = path.join(this.output, "anchor-trust"); this.backupsDirectory = path.join(this.output, "anchor-backups");
    this.child = null; this.pending = new Map(); this.nextId = 0; this.port = 0;
    this.evidence = { assurance: "synthetic_local", requests: 0, processStarts: 0, exits: [], records: [], faultRecords: [], scopes: 0 };
  }
  static async start(output, origin) {
    const fixture = new AnchorFixture(output, origin);
    await fs.mkdir(fixture.output, { recursive: true });
    await fs.mkdir(fixture.directory, { mode: 0o700 });
    await fs.mkdir(fixture.trustDirectory, { mode: 0o700 });
    await fs.mkdir(fixture.backupsDirectory, { mode: 0o700 });
    await fs.writeFile(path.join(fixture.directory, "authority.json"), JSON.stringify({ format: 1, seed: randomHex() }) + "\n", { mode: 0o600, flag: "wx" });
    await fixture.launch(true); return fixture;
  }
  async launch(initialize = false) {
    requireValue(!this.child, "anchor_running");
    const child = fork(serverPath, [this.directory, this.origin, String(this.port), initialize ? "new" : "existing"],
      { stdio: ["ignore", "ignore", "pipe", "ipc"], serialization: "json", execArgv: [] });
    this.child = child; this.evidence.processStarts += 1;
    // stderr 不采集输入/私钥；仅记录字节数，避免意外诊断泄露合成秘密。
    child.stderr.on("data", chunk => { this.evidence.stderrBytes = (this.evidence.stderrBytes ?? 0) + chunk.length; });
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new AnchorError("anchor_start_timeout")); }, 5000);
      let ready = false;
      child.on("message", message => {
        if (message.event === "ready") {
          ready = true; clearTimeout(timer); this.endpoint = message.endpoint; this.anchorPublicKey = hex(message.anchorPublicKey);
          this.port = Number(new URL(this.endpoint).port); resolve();
        } else if (message.event === "failed") { clearTimeout(timer); reject(new AnchorError(message.error.code, message.error.message)); }
        else if (message.event === "http_request") this.evidence.requests += 1;
        else if (message.event === "fault_evidence") {
          this.evidence.faultRecords.push(message);
          if (this.evidence.faultRecords.length > 128) this.evidence.faultRecords.shift();
        }
        else if (message.event === "request") {
          this.evidence.records.push(message);
          if (this.evidence.records.length > 128) this.evidence.records.shift();
        } else if (message.id && this.pending.has(message.id)) {
          const waiting = this.pending.get(message.id); this.pending.delete(message.id); clearTimeout(waiting.timer);
          if (message.ok) waiting.resolve(message.value); else waiting.reject(new AnchorError(message.error.code, message.error.message));
        }
      });
      child.once("error", error => { clearTimeout(timer); reject(error); });
      child.once("exit", (code, signal) => {
        clearTimeout(timer); if (this.child === child) this.child = null;
        this.evidence.exits.push({ code, signal }); if (this.evidence.exits.length > 128) this.evidence.exits.shift();
        for (const waiting of this.pending.values()) { clearTimeout(waiting.timer); waiting.reject(new AnchorError("anchor_process_exit")); }
        this.pending.clear(); if (!ready) reject(new AnchorError("anchor_start_failed"));
      });
    });
  }
  async command(op, value) {
    requireValue(this.child?.connected, "anchor_unavailable");
    const child = this.child; const id = String(++this.nextId);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new AnchorError("anchor_ipc_timeout")); }, 5000);
      this.pending.set(id, { resolve, reject, timer });
      child.send({ id, op, value }, error => {
        if (error) { clearTimeout(timer); this.pending.delete(id); reject(new AnchorError("anchor_ipc_failed")); }
      });
    });
  }
  async enroll({ service, account, identity, head: commitment, rebuildApproverPublicKey }) {
    requireValue(identity && identity.service === service && identity.account === account);
    const identityKey = base64(identity.identityKey, 32); requireValue(identityKey.length === 32);
    const fixed = scope({ service, account, device: identity.device, identity_key: identityKey.toString("hex"), store_id: randomHex() });
    const clientSeed = randomHex();
    const enrolled = await this.command("enroll", { scope: fixed, clientPublicKey: publicKey(clientSeed), head: head(commitment),
      ...(rebuildApproverPublicKey === undefined ? {} : { rebuildApproverPublicKey }) });
    const config = { endpoint: this.endpoint, scope: fixed, anchorPublicKey: enrolled.anchorPublicKey, clientSeed };
    await fs.writeFile(path.join(this.trustDirectory, scopeKey(fixed) + ".json"), JSON.stringify(config) + "\n", { mode: 0o600, flag: "wx" });
    this.evidence.scopes += 1; return config;
  }
  async fault(value) { return this.command("fault", value); }
  async inspect(value) { return this.command("inspect", value); }
  async diagnostics() { return this.command("diagnostics"); }
  async stop() {
    const child = this.child; if (!child) return;
    const exited = new Promise(resolve => child.once("exit", resolve));
    try { await this.command("stop"); } catch { child.kill("SIGKILL"); }
    const timer = setTimeout(() => child.kill("SIGKILL"), 2000);
    await exited; clearTimeout(timer);
  }
  async restart() { await this.stop(); await this.launch(false); return { endpoint: this.endpoint, anchorPublicKey: this.anchorPublicKey }; }
  async backup(value) {
    const destination = path.join(this.backupsDirectory, name(value));
    await this.stop();
    try { await fs.cp(this.directory, destination, { recursive: true, force: false, errorOnExist: true }); }
    finally { await this.launch(false); }
    return destination;
  }
  async restore(value) {
    const source = path.join(this.backupsDirectory, name(value));
    const stat = await fs.stat(source); requireValue(stat.isDirectory(), "anchor_backup_missing");
    await this.stop();
    await fs.rm(this.directory, { recursive: true });
    await fs.cp(source, this.directory, { recursive: true, force: false, errorOnExist: true });
    await this.launch(false);
  }
  async fileHashes() {
    const result = {};
    for (const directory of [this.directory, this.trustDirectory]) {
      for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
        if (!entry.isFile()) continue;
        const file = path.join(directory, entry.name); result[path.relative(this.output, file)] = hash(await fs.readFile(file));
      }
    }
    return result;
  }
}
