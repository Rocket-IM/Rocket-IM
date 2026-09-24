// 只监听本机的测试锚子进程；私有 IPC 引导，HTTP 不提供登记、重置或故障入口。
import http from "node:http";
import { AnchorState } from "./anchor_state.mjs";
import { AnchorError, LIMIT, parseRequest, scopeKey, requestDigest, errorReply, requireValue, exact } from "./anchor_wire.mjs";
import { canonicalPlan, planHash, parseRebuildRequest } from "./rebuild_wire.mjs";
import { rebuild } from "./rebuild_state.mjs";

const [directory, origin, portText, initialize] = process.argv.slice(2);
let state;
let fault = null;
let requestCount = 0;
const history = new Map();
const records = [];
const faultRecords = [];
const sockets = new Set();
const timers = new Set();
let stopping = null;
function ipc(value) { if (process.connected) process.send(value); }
function record(value, details = {}) {
  records.push(value); if (records.length > 128) records.shift();
  ipc({ event: "request", ...value });
  if (value.mode || value.outcome === "duplicate" || value.outcome.endsWith("_duplicate")) {
    const evidence = { ...value, ...details };
    faultRecords.push(evidence); if (faultRecords.length > 128) faultRecords.shift();
    ipc({ event: "fault_evidence", ...evidence });
  }
}
function json(response, status, value) {
  const body = JSON.stringify(value);
  requireValue(Buffer.byteLength(body) <= LIMIT, "anchor_limit");
  response.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": origin, Vary: "Origin" });
  response.end(body);
}
async function body(request) {
  const chunks = []; let size = 0;
  requireValue(!request.headers["content-encoding"], "anchor_invalid");
  requireValue(request.headers["content-type"]?.split(";")[0].trim() === "application/json", "anchor_invalid");
  if (request.headers["content-length"]) requireValue(/^[0-9]+$/.test(request.headers["content-length"])
    && Number(request.headers["content-length"]) <= LIMIT, "anchor_limit");
  for await (const chunk of request) { size += chunk.length; requireValue(size <= LIMIT, "anchor_limit"); chunks.push(chunk); }
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { throw new AnchorError("anchor_invalid"); }
}
const server = http.createServer(async (request, response) => {
  let action = "invalid"; let chosen = null; let key = null; let details = {};
  if (request.method !== "OPTIONS") { requestCount += 1; ipc({ event: "http_request" }); }
  try {
    requireValue(request.headers.origin === origin, "anchor_origin");
    requireValue(request.url === "/anchor", "anchor_route");
    if (request.method === "OPTIONS") {
      response.writeHead(204, { "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Methods": "POST",
        "Access-Control-Allow-Headers": "content-type", "Access-Control-Max-Age": "0", Vary: "Origin" });
      response.end(); return;
    }
    requireValue(request.method === "POST", "anchor_method");
    const payload = await body(request); let dispatch;
    if (payload && Object.hasOwn(payload, "rebuild")) {
      exact(payload, ["rebuild"]); exact(payload.rebuild, ["plan", "approval", "request"]);
      const plan = canonicalPlan(payload.rebuild.plan); const parsed = parseRebuildRequest(payload.rebuild.request);
      action = parsed.action === "link" ? "link" : "rebuild_inspect"; key = scopeKey(plan.old_scope);
      details = { txn: plan.rebuild_id, planHash: planHash(plan), requestDigest: requestDigest(payload.rebuild.request) };
      dispatch = () => rebuild(state, payload.rebuild, chosen);
    } else {
      const parsed = parseRequest(payload); action = parsed.action; key = scopeKey(parsed.scope);
      details = { txn: parsed.txn, requestDigest: requestDigest(payload) };
      dispatch = () => state.request(payload, chosen);
    }
    if (fault?.action === action) { chosen = fault.mode; fault = null; }
    if (chosen === "drop_before") { record({ action, mode: chosen, outcome: "not_applied", scopeKey: key }, details); request.socket.destroy(); return; }
    if (chosen === "timeout") {
      record({ action, mode: chosen, outcome: "not_applied", scopeKey: key }, details);
      const timer = setTimeout(() => { timers.delete(timer); request.socket.destroy(); }, 10000); timers.add(timer);
      response.once("close", () => { clearTimeout(timer); timers.delete(timer); }); return;
    }
    if (chosen === "replay") {
      requireValue(history.has(action), "anchor_no_replay");
      record({ action, mode: chosen, outcome: "old_response", scopeKey: key }, details);
      json(response, 200, history.get(action)); return;
    }
    if (chosen === "oversize") {
      record({ action, mode: chosen, outcome: "not_applied", scopeKey: key }, details);
      response.writeHead(200, { "Content-Type": "application/json", "Access-Control-Allow-Origin": origin, "Cache-Control": "no-store" });
      response.end(" ".repeat(LIMIT + 1)); return;
    }
    if (chosen === "before_commit" || chosen === "after_commit") record({ action, mode: chosen, outcome: "authority_exit_requested", scopeKey: key }, details);
    const result = dispatch();
    history.set(action, result);
    const statement = JSON.parse(Buffer.from(result.response.statement_bytes, "base64").toString("utf8"));
    record({ action, mode: chosen, outcome: statement.status, scopeKey: key }, details);
    if (chosen === "drop_before_headers") { request.socket.destroy(); return; }
    if (chosen === "drop_after") {
      // 先交付头和不完整 JSON，固定为响应体读取失败；头之前断连可能被浏览器透明重发。
      const bytes = Buffer.from(JSON.stringify(result));
      response.writeHead(200, { "Content-Type": "application/json", "Content-Length": bytes.length,
        "Access-Control-Allow-Origin": origin, "Cache-Control": "no-store", Vary: "Origin" });
      response.flushHeaders(); response.write(bytes.subarray(0, 1));
      const timer = setTimeout(() => { timers.delete(timer); response.destroy(); }, 10); timers.add(timer);
      response.once("close", () => { clearTimeout(timer); timers.delete(timer); }); return;
    }
    if (chosen === "tamper") {
      const altered = structuredClone(result); const signature = Buffer.from(altered.response.signature_bytes, "base64");
      signature[0] ^= 1; altered.response.signature_bytes = signature.toString("base64"); json(response, 200, altered); return;
    }
    json(response, 200, result);
  } catch (error) {
    const result = errorReply(error); record({ action, mode: chosen, outcome: result.error.code, scopeKey: key }, details);
    if (!response.headersSent && !response.destroyed) json(response, 400, result); else response.destroy();
  }
});
server.maxConnections = 32;
server.requestTimeout = 5000;
server.headersTimeout = 5000;
server.keepAliveTimeout = 1000;
server.on("connection", socket => { sockets.add(socket); socket.on("close", () => sockets.delete(socket)); socket.setTimeout(15000, () => socket.destroy()); });
async function stop() {
  if (stopping) return stopping;
  stopping = stopOnce(); return stopping;
}
async function stopOnce() {
  for (const timer of timers) clearTimeout(timer);
  for (const socket of sockets) socket.destroy();
  await new Promise(resolve => server.close(resolve)); state?.close();
}
process.on("message", async message => {
  try {
    let value;
    if (message.op === "enroll") value = state.enroll(message.value);
    else if (message.op === "fault") {
      requireValue(["inspect", "reserve", "finish", "link", "rebuild_inspect"].includes(message.value.action));
      requireValue(["drop_before", "drop_after", "drop_before_headers", "tamper", "replay", "timeout", "oversize", "before_commit", "after_commit"].includes(message.value.mode));
      fault = { ...message.value }; value = { armed: true };
    } else if (message.op === "inspect") value = state.inspect(message.value);
    else if (message.op === "diagnostics") {
      const registryCount = state.tx(() => state.db.prepare("SELECT COUNT(*) AS count FROM registry").get().count, "DEFERRED");
      value = { requests: requestCount, records: [...records], faultRecords: [...faultRecords], fault: fault && { ...fault }, registryCount };
    }
    else if (message.op === "stop") { await stop(); ipc({ id: message.id, ok: true, value: { stopped: true } }); process.disconnect(); return; }
    else throw new AnchorError("anchor_invalid");
    ipc({ id: message.id, ok: true, value });
  } catch (error) { ipc({ id: message.id, ...errorReply(error) }); }
});
process.on("disconnect", () => { stop().finally(() => process.exit(process.exitCode ?? 0)); });
try {
  const parsedOrigin = new URL(origin); requireValue(parsedOrigin.origin === origin && parsedOrigin.hostname === "127.0.0.1" && parsedOrigin.protocol === "http:");
  state = new AnchorState(directory, initialize === "new");
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(Number(portText), "127.0.0.1", resolve); });
  ipc({ event: "ready", endpoint: `http://127.0.0.1:${server.address().port}/anchor`, anchorPublicKey: state.publicKey });
} catch (error) { ipc({ event: "failed", ...errorReply(error) }); process.exitCode = 1; if (process.connected) process.disconnect(); }
