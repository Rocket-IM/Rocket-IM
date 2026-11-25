import { createInterface } from 'node:readline';
import { open, get, events, closeAll, failure, listenerErrors } from './dist/consumer.js';

// 只作独立消费控制，不访问数据库，也不导入包的私有实现。
let heartbeat = 0;
const interval = setInterval(() => { heartbeat++; }, 5);
async function dispatch(c) {
  if (c.op === 'open') return open(c.name, c.options);
  if (c.op === 'events') return events();
  if (c.op === 'listenerErrors') return listenerErrors.map(String);
  if (c.op === 'heartbeat') return heartbeat;
  if (c.op === 'exit') { await closeAll(); return null; }
  const client = get(c.name);
  switch (c.op) {
    case 'state': return client.state();
    case 'initialize': return client.initialize(c.requestId);
    case 'createGroup': return client.createGroup(c.requestId, c.conversation, c.peer);
    case 'send': return client.send(c.requestId, c.attemptId, c.messageId, c.text);
    case 'receive': return client.receive(c.requestId, c.sequence, c.envelope);
    case 'download': return client.download(c.records);
    case 'process': return client.process(c.requestId, c.sequence);
    case 'received': return client.received(c.sequence);
    case 'close': return client.close();
    case 'queue': return Promise.all(Array.from({length: 9}, () => client.state().then(() => 'ok', error => failure(error).code)));
    case 'preCancel': {
      const controller = new AbortController(); controller.abort();
      return client.initialize(c.requestId, { signal: controller.signal });
    }
    case 'cancel': {
      const controller = new AbortController();
      const request = client.send(c.requestId, c.attemptId, c.messageId, c.text, { signal: controller.signal });
      setTimeout(() => controller.abort(), 25);
      return request;
    }
    case 'closePending': {
      const request = client.send(c.requestId, c.attemptId, c.messageId, c.text);
      const closing = client.close();
      const result = await request; await closing; return result;
    }
    case 'listenerThrow': client.subscribe(() => { throw new Error('synthetic_listener_error'); }); return null;
    case 'unsubscribe': { const remove = client.subscribe(() => { throw new Error('unsubscribed_listener'); }); remove(); return null; }
    default: throw new Error('unknown_consumer_command');
  }
}
const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
try {
  for await (const line of input) {
    const c = JSON.parse(line);
    let reply;
    try { reply = { id: c.id, ok: true, result: (await dispatch(c)) ?? null }; }
    catch (error) { reply = { id: c.id, ok: false, error: failure(error) }; }
    process.stdout.write(JSON.stringify(reply) + '\n');
    if (c.op === 'exit') break;
  }
} finally {
  clearInterval(interval);
  input.close();
  process.stdin.pause();
  await closeAll();
}
