/** 独立 JS 装置验证；HTTP 签名包装为合成输入，不在此测试中验证密码签名。 */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { consume, validatePage } from './sequence_consumer.mjs';

const script = fileURLToPath(new URL('./sequence_consumer.mjs', import.meta.url));
const largeSequences = ['9007199254740992', '9007199254740993'];
const token = 'synthetic-only-never-echo-this-token';

function page(sequences = largeSequences) {
  const last = sequences.at(-1) ?? '0';
  return { stream_id: 'synthetic-stream', next_after_seq: last, watermark: last, has_more: false,
    events: sequences.map((sequence, index) => ({ stream_id: 'synthetic-stream',
      event_seq: sequence, event_id: `synthetic-event-${index}`, availability: 'deleted' })) };
}

function wrapper(value = page()) {
  return { page_bytes: Buffer.from(JSON.stringify(value)).toString('base64'),
    receipt: { statement_bytes: 'synthetic-delegated-statement', signature: 'synthetic-not-verified' } };
}

function request(url) {
  return { operation: 'pull', url, token, service_id: 'synthetic-service',
    stream_id: 'synthetic-stream', after_seq: '9007199254740991', limit: '2' };
}

async function withServer(handler, action) {
  const server = http.createServer(handler);
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    await action(`http://127.0.0.1:${server.address().port}`);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
}

function cli(raw) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script], { stdio: ['pipe', 'pipe', 'pipe'] });
    const stdout = [];
    const stderr = [];
    const timer = setTimeout(() => { child.kill(); reject(new Error('CLI test timeout')); }, 15_000);
    child.on('error', (error) => { clearTimeout(timer); reject(error); });
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.stdin.on('error', (error) => { if (error.code !== 'EPIPE') reject(error); });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout: Buffer.concat(stdout).toString(), stderr: Buffer.concat(stderr).toString() });
    });
    child.stdin.end(raw);
  });
}

test('2^53 附近字符串往返不合并，Number 碰撞 oracle 能区分损失', async () => {
  const original = page();
  const result = await consume({ operation: 'validate_page', page: original });
  assert.deepEqual(result.sequences, largeSequences);
  assert.deepEqual(result.roundtrip_page, original);
  assert.equal(result.next_after_seq, largeSequences[1]);
  assert.equal(result.watermark, largeSequences[1]);
  assert.notEqual(BigInt(largeSequences[0]), BigInt(largeSequences[1]));
  // 仅负面对照故意转 Number；消费实现不得采用此转换。
  const lossy = largeSequences.map((value) => String(Number(value)));
  assert.equal(lossy[0], lossy[1]);
  assert.notDeepEqual(lossy, result.sequences);
});

test('接受普通小序号及 u64 最大字符串，不固定某个实验序号', () => {
  assert.deepEqual(validatePage(page(['1', '2'])).sequences, ['1', '2']);
  assert.deepEqual(validatePage(page(['18446744073709551615'])).sequences, ['18446744073709551615']);
  assert.deepEqual(validatePage(page([])).sequences, []);
});

const malformed = [
  ['事件序号是 number', (value) => { value.events[0].event_seq = 9007199254740992; }],
  ['下一游标是 number', (value) => { value.next_after_seq = 9007199254740992; }],
  ['水位是 number', (value) => { value.watermark = 9007199254740992; }],
  ['事件序号 u64 溢出', (value) => { value.events[0].event_seq = '18446744073709551616'; }],
  ['下一游标 u64 溢出', (value) => { value.next_after_seq = '18446744073709551616'; }],
  ['序号前导零', (value) => { value.events[0].event_seq = '09007199254740992'; }],
  ['负数序号', (value) => { value.events[0].event_seq = '-1'; }],
  ['科学记数法序号', (value) => { value.events[0].event_seq = '9e15'; }],
  ['零事件序号', (value) => { value.events[0].event_seq = '0'; }],
  ['页内序号不相邻', (value) => { value.events[0].event_seq = '9007199254740990'; }],
  ['下一游标不是实际末槽', (value) => { value.next_after_seq = '9007199254740992'; value.has_more = true; }],
  ['has_more 不匹配水位', (value) => { value.has_more = true; }],
];
for (const [name, mutate] of malformed) {
  test(`拒绝${name}`, () => {
    const invalid = page();
    mutate(invalid);
    assert.throws(() => validatePage(invalid), (error) => ['invalid_envelope', 'cursor_invalid'].includes(error.code));
  });
}

test('CLI 输出一个 JSON，错误退出 1 且不输出输入内容或 stderr', async () => {
  const good = await cli(JSON.stringify({ operation: 'validate_page', page: page() }));
  assert.equal(good.code, 0);
  assert.equal(good.stderr, '');
  assert.equal(good.stdout.trim().split('\n').length, 1);
  assert.deepEqual(JSON.parse(good.stdout).result.sequences, largeSequences);
  const invalid = await cli(`{"secret":"${token}",BROKEN}`);
  assert.equal(invalid.code, 1);
  assert.equal(invalid.stderr, '');
  assert.equal(JSON.parse(invalid.stdout).error.code, 'invalid_json');
  assert.ok(!invalid.stdout.includes(token));
});

test('CLI 标准输入超过 1 MiB 明确失败', async () => {
  const result = await cli(Buffer.alloc(1024 * 1024 + 1, 32));
  assert.equal(result.code, 1);
  assert.equal(result.stderr, '');
  assert.equal(JSON.parse(result.stdout).error.code, 'input_too_large');
});

test('实际 Node HTTP POST 保留原签名包装与精确游标，不回显凭证', async () => {
  const original = wrapper();
  let observed;
  await withServer((incoming, response) => {
    const chunks = [];
    incoming.on('data', (chunk) => chunks.push(chunk));
    incoming.on('end', () => {
      observed = { method: incoming.method, path: incoming.url, authorization: incoming.headers.authorization,
        body: JSON.parse(Buffer.concat(chunks).toString()) };
      response.end(JSON.stringify({ ok: true, result: original }));
    });
  }, async (url) => {
    const result = await consume(request(url));
    assert.deepEqual(result.wrapper, original);
    assert.deepEqual(result.page, page());
    assert.deepEqual(result.sequences, largeSequences);
    assert.equal(result.node_version, process.version);
    assert.equal(result.response_status, 200);
    assert.equal(result.signature_verification, 'delegated_to_rust');
    assert.equal(result.page_sha256, createHash('sha256').update(Buffer.from(original.page_bytes, 'base64')).digest('hex'));
    assert.deepEqual(observed, { method: 'POST', path: '/v1/pull_events_signed',
      authorization: `Bearer ${token}`, body: result.request });
    assert.equal(result.request.after_seq, '9007199254740991');
    assert.ok(!JSON.stringify(result).includes(token));
  });
});

test('HTTP 非 200 明确失败且不回显服务端秘密正文', async () => {
  await withServer((_, response) => { response.writeHead(403); response.end(token); }, async (url) => {
    const result = await cli(JSON.stringify(request(url)));
    assert.equal(result.code, 1);
    assert.equal(result.stderr, '');
    assert.deepEqual(JSON.parse(result.stdout), { ok: false, error: { code: 'http_status', message: 'HTTP 状态 403' } });
    assert.ok(!result.stdout.includes(token));
  });
});

test('HTTP 200 失败结果不降级为空页', async () => {
  await withServer((_, response) => response.end(JSON.stringify({ ok: false, error: { message: token } })), async (url) => {
    await assert.rejects(consume(request(url)), (error) => error.code === 'http_response' && !error.message.includes(token));
  });
});

test('HTTP 响应超过 2 MiB 明确中断', async () => {
  await withServer((_, response) => response.end(Buffer.alloc(2 * 1024 * 1024 + 1, 32)), async (url) => {
    await assert.rejects(consume(request(url)), (error) => error.code === 'response_too_large');
  });
});

test('HTTP 截断响应明确失败', async () => {
  await withServer((_, response) => {
    response.writeHead(200, { 'Content-Length': '100' });
    response.end('{}');
  }, async (url) => {
    await assert.rejects(consume(request(url)), (error) => error.code === 'http_transport');
  });
});

test('HTTP 成功体 JSON 损坏明确失败', async () => {
  await withServer((_, response) => response.end('{'), async (url) => {
    await assert.rejects(consume(request(url)), (error) => error.code === 'invalid_json');
  });
});

test('HTTP 页序号被转换为 Number 时拒绝', async () => {
  const invalid = page();
  invalid.events[1].event_seq = Number(invalid.events[1].event_seq);
  await withServer((_, response) => response.end(JSON.stringify({ ok: true, result: wrapper(invalid) })), async (url) => {
    await assert.rejects(consume(request(url)), (error) => error.code === 'invalid_envelope');
  });
});

test('无效请求在 HTTP 前拒绝', async () => {
  for (const fields of [{ url: 'https://example.com' }, { after_seq: 1 },
    { after_seq: '18446744073709551616' }, { after_seq: '01' }, { limit: '0' }, { limit: '101' }]) {
    await assert.rejects(consume({ ...request('http://127.0.0.1:1'), ...fields }),
      (error) => ['invalid_request', 'invalid_envelope'].includes(error.code));
  }
});

test('HTTP 总时限为 10 秒，超时销毁请求', async () => {
  await withServer(() => {}, async (url) => {
    const started = performance.now();
    await assert.rejects(consume(request(url)), (error) => error.code === 'http_timeout');
    assert.ok(performance.now() - started >= 9_500);
  });
});
