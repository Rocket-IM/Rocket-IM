import type { OpenOptions, CallOptions } from './types.js';
export const VERSION: string;
export class SdkError extends Error { readonly code: string; readonly paused: boolean; constructor(code: string, paused?: boolean) }
export class Transport {
  private constructor();
  readonly ready: Promise<unknown>;
  static open(options: OpenOptions, mode?: 'logout' | 'restore'): Promise<Transport>;
  request(operation: Record<string, unknown>, options?: CallOptions): Promise<unknown>;
  onEvent(listener: (event: unknown) => void): void;
  onStop(listener: () => void): void;
  control(operation: Record<string, unknown>): Promise<unknown>;
  stop(error: unknown): void;
  close(): Promise<void>;
  logout(): Promise<void>;
}
