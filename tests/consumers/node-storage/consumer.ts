import { DesktopStorage, StorageError, type Change, type OpenOptions, type Runtime } from '@rocket-im/stage0-desktop-storage';

export const clients = new Map<string, DesktopStorage>();
export const changes: { owner: string; change: Change; query: Promise<string> }[] = [];
export const listenerErrors: unknown[] = [];
export async function open(name: string, options: OpenOptions): Promise<Runtime> {
  const client = await DesktopStorage.open({ ...options, onListenerError: error => { listenerErrors.push(error); } });
  clients.set(name, client);
  client.subscribe(change => {
    changes.push({ owner: name, change, query: client.state().then(state => state.revision) });
  });
  return client.runtime;
}
export function get(name: string): DesktopStorage {
  const client = clients.get(name);
  if (!client) throw new Error('consumer_client_missing');
  return client;
}
export function failure(error: unknown): { code: string; paused: boolean } {
  if (error instanceof StorageError) return { code: error.code, paused: error.paused };
  throw error;
}
export async function events() {
  return Promise.all(changes.map(async item => ({ owner: item.owner, change: item.change, revisionRead: await item.query })));
}
export async function closeAll(): Promise<void> {
  await Promise.all([...clients.values()].map(client => client.close()));
}
