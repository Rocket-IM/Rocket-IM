// 与 rim-rollback-anchor-1 一致的原文签名；仅供本机合成锚装置。
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";

export const PROTOCOL = "rim-rollback-anchor-1";
export const LIMIT = 32 * 1024;
const STATEMENT_LIMIT = 8 * 1024;
const REQUEST_DOMAIN = Buffer.from("Rockets-IM/POC/rollback-anchor-request/v1\0");
const RESPONSE_DOMAIN = Buffer.from("Rockets-IM/POC/rollback-anchor-response/v1\0");
const PRIVATE_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const PUBLIC_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export class AnchorError extends Error {
  constructor(code, message = "合成锚请求、状态或权限不匹配。") { super(message); this.code = code; }
}
export function requireValue(ok, code = "anchor_invalid") { if (!ok) throw new AnchorError(code); }
export function exact(value, keys) {
  requireValue(value !== null && typeof value === "object" && !Array.isArray(value));
  requireValue(Object.keys(value).sort().join("|") === [...keys].sort().join("|"));
}
export function hex(value) { requireValue(typeof value === "string" && /^[0-9a-f]{64}$/.test(value)); return value; }
export function revision(value) {
  requireValue(typeof value === "string" && /^(0|[1-9][0-9]{0,19})$/.test(value));
  const result = BigInt(value); requireValue(result <= 18446744073709551615n); return result;
}
export function head(value) { if (value !== "absent") hex(value); return value; }
export function scope(value) {
  exact(value, ["service", "account", "device", "identity_key", "store_id"]);
  for (const field of ["service", "account", "device"]) requireValue(typeof value[field] === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(value[field]));
  return { service: value.service, account: value.account, device: value.device,
    identity_key: hex(value.identity_key), store_id: hex(value.store_id) };
}
export function scopeKey(value) { return hash(Buffer.from(JSON.stringify(scope(value)))); }
export function hash(value) { return createHash("sha256").update(value).digest("hex"); }
export function base64(value, limit) {
  requireValue(typeof value === "string" && value.length <= Math.ceil(limit / 3) * 4);
  const bytes = Buffer.from(value, "base64");
  requireValue(bytes.length <= limit && bytes.toString("base64") === value); return bytes;
}
export function privateKey(seed) {
  return createPrivateKey({ key: Buffer.concat([PRIVATE_PREFIX, Buffer.from(hex(seed), "hex")]), format: "der", type: "pkcs8" });
}
export function publicKey(seed) {
  return createPublicKey(privateKey(seed)).export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
}
export function signed(value) {
  exact(value, ["statement_bytes", "signature_bytes"]);
  const bytes = base64(value.statement_bytes, STATEMENT_LIMIT);
  const signature = base64(value.signature_bytes, 64); requireValue(signature.length === 64);
  return { bytes, signature };
}
export function parseRequest(value) {
  const { bytes } = signed(value);
  let request;
  try { request = JSON.parse(bytes.toString("utf8")); } catch { throw new AnchorError("anchor_invalid"); }
  requireValue(Buffer.from(bytes.toString("utf8")).equals(bytes));
  exact(request, ["protocol_version", "scope", "challenge", "action", "expected_revision", "txn", "head", "target"]);
  requireValue(request.protocol_version === PROTOCOL && ["inspect", "reserve", "finish"].includes(request.action));
  scope(request.scope); hex(request.challenge); hex(request.txn); revision(request.expected_revision); head(request.head);
  if (request.action === "finish") hex(request.target); else requireValue(request.target === "absent");
  return request;
}
export function verifyRequest(value, key) {
  const request = parseRequest(value); const { bytes, signature } = signed(value);
  try {
    const publicValue = createPublicKey({ key: Buffer.concat([PUBLIC_PREFIX, Buffer.from(hex(key), "hex")]), format: "der", type: "spki" });
    requireValue(verify(null, Buffer.concat([REQUEST_DOMAIN, bytes]), publicValue, signature), "anchor_signature");
  } catch { throw new AnchorError("anchor_signature"); }
  return request;
}
export function requestDigest(value) {
  signed(value);
  return hash(Buffer.from(JSON.stringify({ statement_bytes: value.statement_bytes, signature_bytes: value.signature_bytes })));
}
function signValue(value, seed, domain) {
  const bytes = Buffer.from(JSON.stringify(value)); requireValue(bytes.length <= STATEMENT_LIMIT);
  return { statement_bytes: bytes.toString("base64"), signature_bytes: sign(null, Buffer.concat([domain, bytes]), privateKey(seed)).toString("base64") };
}
export function signResponse(value, seed) { return signValue(value, seed, RESPONSE_DOMAIN); }
export function signRequest(value, seed) { const result = signValue(value, seed, REQUEST_DOMAIN); parseRequest(result); return result; }
export function errorReply(error) {
  return { ok: false, error: { code: error instanceof AnchorError ? error.code : "anchor_storage", message: error instanceof AnchorError ? error.message : "合成锚存储不可用。" } };
}
