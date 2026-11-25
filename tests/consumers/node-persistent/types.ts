import { PersistentDevice, type Identity, type Envelope, type RequestState } from '@rocket-im/desktop-dev';
async function types(a: PersistentDevice, b: PersistentDevice, pinned: Identity) {
  const material = await b.joiningMaterial();
  const group = await a.createGroup('create', 'chat', pinned, material.key_package);
  await b.joinGroup('join', 'chat', (await a.state()).identity ?? pinned, group.value.welcome);
  const sent = await a.send('send', 'message', 'test');
  const envelope: Envelope = sent.value.envelope;
  const received = await b.receive('receive', envelope);
  const message: string = received.value.message.text;
  await a.recoverRequest('send', {kind:'send',message_id:'message',text:'test'});
  const recovery = await a.recovery({kind:'status'});
  const phase: string | null = recovery.phase;
  const state: RequestState = await a.request('send');
  const page = await a.history({ direction: 'backward', page_size: 20 });
  const position: string | undefined = page.items[0]?.local_position;
  if (!page.done) await a.history({ direction: page.direction, page_size: page.page_size, cursor: page.next_cursor });
  // @ts-expect-error 方向必须是公开联合类型。
  await a.history({ direction: 'sideways', page_size: 20 });
  // @ts-expect-error 游标不接受数值。
  await a.history({ direction: 'forward', page_size: 20, cursor: 1 });
  const unsubscribe = b.subscribe(async change => { await b.message(change.scope.account, change.scope.device, 'message'); });
  unsubscribe(); return { message, state };
}
void types;
async function networkTypes(device: PersistentDevice, peer: Identity) {
  await device.connect({ url: 'wss://127.0.0.1:8443/v1/ws', token: 'explicit-test-token', ca_certificate: '00', conversation: 'chat', peer, creator: true });
  const state = await device.networkState();
  const status: 'local_saved' | 'accepted' | 'delivered' | 'not_accepted' | 'context_retired' | 'rejected' | undefined = state.sending[0]?.status;
  for (const sending of state.sending) {
    if (sending.status === 'rejected') {
      const code: 'message_limit' = sending.rejection.code;
      const acceptance: null = sending.acceptance;
      void code; void acceptance;
    }
  }
  const recovery = await device.networkRecovery({kind:'status'});
  if (recovery?.requires_action) await device.networkRecovery({kind:'approve', round_id:recovery.round_id});
  if (state.unavailable_history[0]) {
    const original = await device.networkUnavailable(state.unavailable_history[0].sequence);
    const ciphertext: string | undefined = original?.envelope.ciphertext; void ciphertext;
  }
  // @ts-expect-error 联网批准只接受当前轮ID，宿主不能传递或替换协议材料。
  await device.networkRecovery({kind:'approve', offer:'arbitrary'});
  const off = device.subscribe(change => { if (change.kind === 'network_state') { const cursor: string = change.state.processed; void cursor; } });
  await device.disconnect(); off(); return status;
}
void networkTypes;
async function authenticationTypes(device: PersistentDevice, peer: Identity) {
  await device.connect({ url: 'wss://127.0.0.1:8443/v1/ws', ca_certificate: '00', conversation: 'chat', peer, creator: true,
    authentication: { timeout_ms: 5000, max_attempts: 3 },
    credentialProvider: async request => {
      const signal: AbortSignal = request.signal;
      const reason: 'initial' | 'expired' = request.reason;
      const expiry: string = '0'; void signal; void reason;
      return { kind: 'credential', credential: { scope: request.scope, token: 'rimd_example', expires_at_unix_ms: expiry } };
    },
  });
  // @ts-expect-error 静态token与认证回调互斥。
  await device.connect({ url: 'wss://127.0.0.1:8443/v1/ws', token: 'static', ca_certificate: '00', conversation: 'chat', peer, creator: true, credentialProvider: async () => ({ kind: 'failure', code: 'unavailable' }) });
}
void authenticationTypes;
async function backupTypes(device: PersistentDevice) {
  await device.disconnect();
  const info = await device.createBackup('/private/tmp/example.rimbackup');
  const version: 1 = info.format; const digest: string = info.snapshot;
  await device.close();
  await PersistentDevice.restoreBackup({path: '/private/tmp/original.db', scope: info.scope, keychain: '/private/tmp/dedicated.keychain-db'}, '/private/tmp/example.rimbackup');
  // @ts-expect-error 宿主不能注入数据库对象或导出密钥。
  await device.createBackup({sqlite: {}, exportKey: true});
  void version; void digest;
}
void backupTypes;
