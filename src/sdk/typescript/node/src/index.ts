/** Node宿主的阶段0薄接口；密码状态仅由包内预编译Rust核心持有。 */
import type { Stage0Device as WasmDevice } from "./generated/rocket_stage0_wasm.js";

export const SDK_VERSION = "0.1.0-stage0.1";
type Binding = typeof import("./generated/rocket_stage0_wasm.js");
let binding: Binding | undefined;
let initialization: Promise<void> | undefined;

/** 在Node工作线程内加载包内产物并核对版本。失败后须修复安装并重建工作线程，无源码编译或内存回退。 */
export function initialize(): Promise<void> {
  if (!initialization) {
    initialization = (async () => {
      let loaded: Binding;
      try {
        loaded = await import("./generated/rocket_stage0_wasm.js");
      } catch (cause) {
        throw new Error("node_initialization_failed: cannot load packaged Rust runtime", { cause });
      }
      const actual = loaded.sdkVersion();
      if (actual !== SDK_VERSION) throw new Error(`sdk_version_mismatch: expected ${SDK_VERSION}, received ${actual}`);
      binding = loaded;
    })();
  }
  return initialization;
}

function bytes(value: Uint8Array): Uint8Array {
  if (!(value instanceof Uint8Array)) throw new TypeError("Stage0Device expects Uint8Array");
  return new Uint8Array(value);
}

function text(value: string): string {
  if (typeof value !== "string") throw new TypeError("Stage0Device expects string identifiers");
  return value;
}

/**
 * 同步内存设备，必须由宿主在Node工作线程内按调用顺序使用；不会自动变成后台任务。
 * 输入/输出字节均复制，不暴露Rust内存。失败保留Rust错误码与device_poisoned标志，不隐式重试。
 * 仅一个双设备MLS群，无网络、SQLite或恢复。宿主在finally中close，再关闭工作线程。
 */
export class Stage0Device {
  #device: WasmDevice;
  #closed = false;

  constructor(serviceId: string, accountId: string, deviceId: string) {
    if (!binding) throw new Error("sdk_not_initialized: await initialize() first");
    this.#device = new binding.Stage0Device(text(serviceId), text(accountId), text(deviceId));
  }

  #open(): WasmDevice {
    if (this.#closed) throw new Error("closed; device_poisoned=false");
    return this.#device;
  }

  identityKey(): Uint8Array { return bytes(this.#open().identityKey()); }
  keyPackage(): Uint8Array { return bytes(this.#open().keyPackage()); }

  createGroup(conversationId: string, peerAccountId: string, peerDeviceId: string,
              peerIdentityKey: Uint8Array, keyPackage: Uint8Array): Uint8Array {
    return bytes(this.#open().createGroup(text(conversationId), text(peerAccountId), text(peerDeviceId),
      bytes(peerIdentityKey), bytes(keyPackage)));
  }

  joinGroup(conversationId: string, creatorAccountId: string, creatorDeviceId: string,
            creatorIdentityKey: Uint8Array, welcome: Uint8Array): void {
    this.#open().joinGroup(text(conversationId), text(creatorAccountId), text(creatorDeviceId),
      bytes(creatorIdentityKey), bytes(welcome));
  }

  /** 明文字节上限64 KiB；成功后已消耗密码发送状态，不得以再次加密代替传输重试。 */
  encrypt(plaintext: Uint8Array): Uint8Array { return bytes(this.#open().encrypt(bytes(plaintext))); }
  decrypt(ciphertext: Uint8Array): Uint8Array { return bytes(this.#open().decrypt(bytes(ciphertext))); }

  /** 幂等释放本对象Rust资源。其他对象不受影响；不承诺完整内存安全擦除。 */
  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    try { this.#device.close(); } finally { this.#device.free(); }
  }
}
