import { StorageError } from "./protocol.js";

const MAX_BYTES = 32 * 1024;
const TIMEOUT_MS = 3000;

/** 固定本机实验地址，不接受重定向、DNS 名称或夹带凭证的 URL。 */
export function anchorEndpoint(value: unknown): string {
  if (typeof value !== "string") throw new StorageError("INVALID_ARGUMENT", "A loopback anchor endpoint is required.");
  const match = /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})\/anchor$/.exec(value);
  if (!match || Number(match[1]) > 65535) {
    throw new StorageError("INVALID_ARGUMENT", "Anchor endpoint must be http://127.0.0.1:<port>/anchor with a canonical port.");
  }
  return value;
}

/** 只传递 Rust 签名的有界 JSON；不解析签名、锚状态或数据库内容，不重试。 */
export function anchorRpc(endpoint: string): (signedRequest: unknown) => Promise<string> {
  const fixedEndpoint = anchorEndpoint(endpoint);
  return async signedRequest => {
    if (typeof signedRequest !== "string" || new TextEncoder().encode(signedRequest).length > MAX_BYTES) {
      throw new StorageError("ANCHOR_REQUEST_LIMIT", "Anchor request is absent or exceeds 32 KiB.");
    }
    const controller = new AbortController();
    const timer = setTimeout(() => { controller.abort(); }, TIMEOUT_MS);
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    try {
      const response = await fetch(fixedEndpoint, { method: "POST", body: signedRequest,
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        credentials: "omit", redirect: "error", cache: "no-store", signal: controller.signal });
      if (!response.ok) throw new StorageError("ANCHOR_HTTP_ERROR", `Anchor HTTP request failed with status ${response.status}.`);
      const length = response.headers.get("Content-Length");
      if (length !== null && (!/^[0-9]+$/.test(length) || Number(length) > MAX_BYTES)) {
        controller.abort();
        throw new StorageError("ANCHOR_RESPONSE_LIMIT", "Anchor response exceeds 32 KiB or has an invalid length.");
      }
      if (!response.body) throw new StorageError("ANCHOR_RESPONSE_EMPTY", "Anchor response has no body.");
      reader = response.body.getReader();
      const decoder = new TextDecoder("utf-8", { fatal: true });
      let bytes = 0, text = "";
      while (true) {
        const part = await reader.read();
        if (part.done) break;
        bytes += part.value.byteLength;
        if (bytes > MAX_BYTES) {
          controller.abort();
          throw new StorageError("ANCHOR_RESPONSE_LIMIT", "Anchor response exceeds 32 KiB.");
        }
        text += decoder.decode(part.value, { stream: true });
      }
      text += decoder.decode();
      if (bytes === 0) throw new StorageError("ANCHOR_RESPONSE_EMPTY", "Anchor response is empty.");
      return text;
    } catch (error) {
      if (error instanceof StorageError) throw error;
      if (controller.signal.aborted) throw new StorageError("ANCHOR_RPC_TIMEOUT", "Anchor request exceeded 3 seconds; its outcome is unknown.");
      const detail = error instanceof Error ? `${error.name}: ${error.message}` : "Unknown fetch failure.";
      throw new StorageError("ANCHOR_RPC_FAILED", detail.slice(0, 2048));
    } finally {
      controller.abort();
      clearTimeout(timer);
      if (reader) {
        try { await reader.cancel(); } catch { /* 已失败或关闭的流不改变主错误。 */ }
        reader.releaseLock();
      }
    }
  };
}
