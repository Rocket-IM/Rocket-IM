// 真实包认证接入及受控故障。只访问业务后台；不实现IM网络、队列或同步。
import https from 'node:https';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
export async function createProvider(config) {
  const ca = await readFile(config.ca);
  let mode = 'normal', remaining = 0, issued = [], calls = [], active = 0, peak = 0, aborted = 0;
  const held = [], pending = new Set();
  const request = (url, token, body, signal) => new Promise((resolve, reject) => {
    const bytes = Buffer.from(JSON.stringify(body));
    const req = https.request(url, { method: 'POST', ca, minVersion: 'TLSv1.3', signal, agent: false,
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', 'content-length': bytes.length } }, res => {
      const chunks = []; let size = 0;
      res.on('data', chunk => { size += chunk.length; if (size > 16384) req.destroy(); else chunks.push(chunk); });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }); }
        catch { if (res.statusCode === 200) reject(new Error('response_invalid')); else resolve({ status: res.statusCode, body: null }); }
      });
      res.on('error', reject);
    });
    pending.add(req); req.once('close', () => pending.delete(req)); req.on('error', reject); req.end(bytes);
  });
  async function provider(context) {
    const fault = remaining-- > 0 ? mode : 'normal';
    active++; peak = Math.max(peak, active);
    calls.push({ request_id: context.request_id, scope: context.scope, reason: context.reason, attempt: context.attempt, fault });
    const onAbort = () => { aborted++; };
    context.signal.addEventListener('abort', onAbort, { once: true });
    try {
      if (['unavailable', 'login_required', 'forbidden', 'cancelled'].includes(fault)) return { kind: 'failure', code: fault };
      if (fault === 'throw') throw new Error('synthetic-provider-error-with-no-logging');
      if (fault === 'hang') return await new Promise(resolve => {
        const release = () => resolve({ kind: 'failure', code: 'cancelled' });
        context.signal.addEventListener('abort', release, { once: true });
      });
      const target = fault === 'wrong_token_identity' ? config.other : config;
      let response;
      try {
        response = await request(`${config.endpoint}/im/credential`, target.session, {
          request_id: context.request_id, device: target.device, ttl_seconds: config.ttl ?? 2,
        }, context.signal);
      } catch { return { kind: 'failure', code: context.signal.aborted ? 'cancelled' : 'unavailable' }; }
      if (response.status !== 200) return { kind: 'failure', code: response.status >= 500 || response.status === 429 ? 'unavailable' : response.status === 401 ? 'login_required' : 'forbidden' };
      const r = response.body;
      const credential = { scope: r.identity.scope, token: r.token, expires_at_unix_ms: String(Date.parse(r.expires_at)) };
      issued.push({ ...credential, credential_id: r.credential_id });
      if (fault === 'late_success' || fault === 'late_failure') await new Promise(resolve => held.push(resolve));
      if (fault === 'late_failure') throw new Error('synthetic-late-failure');
      if (fault.startsWith('scope_')) credential.scope = { ...credential.scope, [fault.slice(6)]: 'foreign' };
      if (fault === 'expired') credential.expires_at_unix_ms = String(Date.now() - 1);
      if (fault === 'wrong_purpose') credential.token = 'rimb_' + 'a'.repeat(64);
      if (fault === 'wrong_token_identity') credential.scope = context.scope; // 伪造元数据仍须被Service session身份核验拒绝。
      if (fault === 'invalid_token') credential.token = 'rimd_' + '0'.repeat(32) + '_' + '0'.repeat(64);
      return { kind: 'credential', credential };
    } finally {
      active--; context.signal.removeEventListener('abort', onAbort);
    }
  }
  return {
    provider,
    fault(value, count = 1) { mode = value; remaining = count; },
    release() { for (const resolve of held.splice(0)) resolve(); },
    stats() { return { calls, issued: issued.map(({ token, ...c }) => ({ ...c, token_sha256: createHash('sha256').update(token).digest('hex') })), active, peak, aborted, pending_http: pending.size, held: held.length }; },
    async expiredProbe(endpoint) {
      const expired = issued.filter(c => BigInt(c.expires_at_unix_ms) <= BigInt(Date.now()));
      const codes = [];
      for (const c of expired) {
        const response = await request(endpoint + '/v1/rpc', c.token, { id: 'expiry-probe', op: 'session', body: {} }); codes.push(response.status);
      }
      return { count: expired.length, codes };
    },
    async scan(paths) {
      const buffers = await Promise.all(paths.map(path => readFile(path)));
      if (issued.some(c => buffers.some(b => b.includes(Buffer.from(c.token))))) throw new Error('credential_leak');
      return { credential_samples: issued.length, matches: 0 };
    },
  };
}
