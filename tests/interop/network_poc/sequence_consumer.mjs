/** M12.c 独立 JavaScript HTTP 消费装置；签名与消息业务仍由 Rust 验证。 */
import { createHash } from 'node:crypto';
import http from 'node:http';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const MAX_INPUT_BYTES = 1024 * 1024;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_U64 = (1n << 64n) - 1n;

class ConsumerError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function requireValue(condition, code, message) {
  if (!condition) throw new ConsumerError(code, message);
}

function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function identifier(value) {
  requireValue(typeof value === 'string' && value.length > 0 && value.length <= 256,
    'invalid_envelope', '标识必须为有界非空字符串');
}

function decimal(value) {
  requireValue(typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value),
    'invalid_envelope', '序号或游标必须为规范无符号十进制字符串');
  const parsed = BigInt(value);
  requireValue(parsed <= MAX_U64, 'invalid_envelope', '序号或游标超过 u64 范围');
  return parsed;
}

function parseJson(bytes) {
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new ConsumerError('invalid_json', '输入不是有效 UTF-8 JSON');
  }
}

export function validatePage(page, request = null) {
  requireValue(object(page) && Array.isArray(page.events) && page.events.length <= 100,
    'invalid_envelope', '页必须包含有界事件数组');
  identifier(page.stream_id);
  const next = decimal(page.next_after_seq);
  const watermark = decimal(page.watermark);
  requireValue(typeof page.has_more === 'boolean' && next <= watermark
    && page.has_more === (next < watermark), 'cursor_invalid', '页游标或分页标记不一致');
  const sequences = [];
  let previous = request === null ? null : decimal(request.after_seq);
  if (request !== null) {
    requireValue(page.stream_id === request.stream_id, 'cursor_invalid', '页不属于请求设备流');
    requireValue(next >= previous && BigInt(page.events.length) <= decimal(request.limit),
      'cursor_invalid', '页超出请求边界');
  }
  for (const slot of page.events) {
    requireValue(object(slot), 'invalid_envelope', '事件槽必须为对象');
    identifier(slot.event_id);
    const sequence = decimal(slot.event_seq);
    requireValue(slot.stream_id === page.stream_id && sequence > 0n && sequence <= watermark
      && (previous === null || sequence === previous + 1n),
    'cursor_invalid', '事件槽归属或相邻序号不一致');
    sequences.push(slot.event_seq);
    previous = sequence;
  }
  requireValue(page.events.length === 0 ? next === watermark
    && (request === null || next === previous) : next === previous,
  'cursor_invalid', '下一游标不对应实际返回的完整页');
  return { sequences, next_after_seq: page.next_after_seq, watermark: page.watermark };
}

function pullInput(input) {
  let url;
  try {
    url = new URL(input.url);
  } catch {
    throw new ConsumerError('invalid_request', '请求地址无效');
  }
  requireValue(url.protocol === 'http:' && url.hostname === '127.0.0.1' && url.port !== ''
    && !url.username && !url.password && url.pathname === '/' && !url.search && !url.hash,
  'invalid_request', '装置只访问显式端口的本机 HTTP 地址');
  requireValue(typeof input.token === 'string' && /^[A-Za-z0-9._~-]{1,4096}$/.test(input.token),
    'invalid_request', '实验设备凭证格式无效');
  identifier(input.service_id);
  identifier(input.stream_id);
  decimal(input.after_seq);
  const limit = decimal(input.limit);
  requireValue(limit >= 1n && limit <= 100n, 'invalid_request', '页上限必须为 1 到 100');
  return { url, request: { service_id: input.service_id, stream_id: input.stream_id,
    after_seq: input.after_seq, limit: input.limit } };
}

function requestPage(url, token, request) {
  return new Promise((resolveReply, rejectReply) => {
    let done = false;
    const body = Buffer.from(JSON.stringify(request));
    const connection = http.request(new URL('/v1/pull_events_signed', url), {
      method: 'POST', agent: false,
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json',
        'Content-Length': body.length, Connection: 'close' },
    });
    const timer = setTimeout(() => finish(new ConsumerError('http_timeout', 'HTTP 请求超过 10 秒')), 10_000);
    function finish(error, value) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      connection.destroy();
      if (error) rejectReply(error);
      else resolveReply(value);
    }
    connection.on('error', () => finish(new ConsumerError('http_transport', '本机 HTTP 连接失败')));
    connection.on('response', (response) => {
      const chunks = [];
      let size = 0;
      response.on('error', () => finish(new ConsumerError('http_transport', '本机 HTTP 响应未完整取得')));
      response.on('aborted', () => finish(new ConsumerError('http_transport', '本机 HTTP 响应中断')));
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_RESPONSE_BYTES) {
          finish(new ConsumerError('response_too_large', 'HTTP 响应超过 2 MiB'));
        } else if (!done) {
          chunks.push(chunk);
        }
      });
      response.on('end', () => {
        if (done) return;
        try {
          requireValue(response.statusCode === 200, 'http_status', `HTTP 状态 ${response.statusCode}`);
          const envelope = parseJson(Buffer.concat(chunks));
          requireValue(object(envelope) && envelope.ok === true && object(envelope.result),
            'http_response', 'HTTP 未返回成功结果');
          finish(null, { wrapper: envelope.result, response_status: response.statusCode });
        } catch (error) {
          finish(error);
        }
      });
    });
    connection.end(body);
  });
}

export async function consume(input) {
  requireValue(object(input), 'invalid_request', '请求必须为对象');
  if (input.operation === 'validate_page') {
    const parsed = validatePage(input.page);
    return { page: input.page, roundtrip_page: JSON.parse(JSON.stringify(input.page)), ...parsed,
      node_version: process.version, signature_verification: 'delegated_to_rust' };
  }
  requireValue(input.operation === 'pull', 'unsupported_operation', '未知消费装置操作');
  const { url, request } = pullInput(input);
  const { wrapper, response_status } = await requestPage(url, input.token, request);
  requireValue(typeof wrapper.page_bytes === 'string' && wrapper.page_bytes.length > 0
    && object(wrapper.receipt), 'invalid_envelope', '签名页包装缺少原始页或回执');
  const raw = Buffer.from(wrapper.page_bytes, 'base64');
  requireValue(raw.toString('base64') === wrapper.page_bytes, 'invalid_envelope', '页必须使用规范 Base64');
  const page = parseJson(raw);
  const { sequences } = validatePage(page, request);
  return { wrapper, page, request, sequences, node_version: process.version,
    page_sha256: createHash('sha256').update(raw).digest('hex'), response_status,
    signature_verification: 'delegated_to_rust' };
}

async function main() {
  try {
    const chunks = [];
    let size = 0;
    for await (const chunk of process.stdin) {
      size += chunk.length;
      requireValue(size <= MAX_INPUT_BYTES, 'input_too_large', '标准输入超过 1 MiB');
      chunks.push(chunk);
    }
    const result = await consume(parseJson(Buffer.concat(chunks)));
    process.stdout.write(`${JSON.stringify({ ok: true, result })}\n`);
  } catch (error) {
    const known = error instanceof ConsumerError;
    process.stdout.write(`${JSON.stringify({ ok: false, error: {
      code: known ? error.code : 'internal_error',
      message: known ? error.message : '消费装置内部错误',
    } })}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}
