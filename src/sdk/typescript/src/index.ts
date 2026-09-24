/** 阶段0公开浏览器入口；业务密码状态仅由本次加载的预编译WASM持有。 */
import initWasm, { Stage0Device as WasmDevice, sdkVersion } from "./generated/rockets_stage0_wasm.js";

export const SDK_VERSION = "0.1.0-stage0.1";
let initialized = false;
let initialization: Promise<void> | undefined;

/** 加载包内WASM并核对版本；失败明确返回，不寻找源码或另一份二进制。 */
export function initialize(wasmUrl?: string | URL): Promise<void> {
  if (!initialization) {
    initialization = (async () => {
      try {
        await initWasm({ module_or_path: wasmUrl ?? new URL("./generated/rockets_stage0_wasm_bg.wasm", import.meta.url) });
      } catch (error) {
        throw new Error(`wasm_initialization_failed: ${error}`);
      }
      const actual = sdkVersion();
      if (actual !== SDK_VERSION) throw new Error(`sdk_version_mismatch: expected ${SDK_VERSION}, received ${actual}`);
      initialized = true;
    })();
  }
  return initialization;
}

function bytes(value: Uint8Array): Uint8Array {
  if (!(value instanceof Uint8Array)) throw new TypeError("Stage0Device expects Uint8Array");
  return new Uint8Array(value);
}

/** 每个对象持有独立内存设备；不提供持久化、网络或业务设备批准。 */
export class Stage0Device {
  #device: WasmDevice;
  #closed = false;

  constructor(serviceId: string, accountId: string, deviceId: string) {
    if (!initialized) throw new Error("sdk_not_initialized: await initialize() first");
    this.#device = new WasmDevice(serviceId, accountId, deviceId);
  }

  #open(): WasmDevice {
    if (this.#closed) throw new Error("closed; device_poisoned=false");
    return this.#device;
  }

  identityKey(): Uint8Array { return bytes(this.#open().identityKey()); }
  keyPackage(): Uint8Array { return bytes(this.#open().keyPackage()); }

  createGroup(conversationId: string, peerAccountId: string, peerDeviceId: string,
              peerIdentityKey: Uint8Array, keyPackage: Uint8Array): Uint8Array {
    return bytes(this.#open().createGroup(conversationId, peerAccountId, peerDeviceId,
      bytes(peerIdentityKey), bytes(keyPackage)));
  }

  joinGroup(conversationId: string, creatorAccountId: string, creatorDeviceId: string,
            creatorIdentityKey: Uint8Array, welcome: Uint8Array): void {
    this.#open().joinGroup(conversationId, creatorAccountId, creatorDeviceId, bytes(creatorIdentityKey), bytes(welcome));
  }

  encrypt(plaintext: Uint8Array): Uint8Array { return bytes(this.#open().encrypt(bytes(plaintext))); }
  decrypt(ciphertext: Uint8Array): Uint8Array { return bytes(this.#open().decrypt(bytes(ciphertext))); }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    try { this.#device.close(); } finally { this.#device.free(); }
  }
}
