import type { OpenOptions, CallOptions } from './types.js';
export const VERSION: string;
export class StorageError extends Error { readonly code: string; readonly paused: boolean; constructor(code: string, paused?: boolean) }
export class Transport {
  private constructor();
  readonly ready: Promise<unknown>;
  static open(options: OpenOptions): Promise<Transport>;
  request(operation: Record<string, unknown>, options?: CallOptions): Promise<unknown>;
  stop(error: unknown): void;
  close(): Promise<void>;
}
