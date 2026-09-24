import { initialize, SDK_VERSION, Stage0Device } from "@rocket-im/stage0";

interface Result { status: "PASS" | "FAIL"; checks: string[]; version?: string; browser: string; error?: string; }
declare global { interface Window { __stage0Result?: Result; } }
const checks: string[] = [];
function check(condition: boolean, label: string): void {
  if (!condition) throw new Error(label);
  checks.push(label);
}
function equal(a: Uint8Array, b: Uint8Array): boolean { return a.length === b.length && a.every((value, index) => value === b[index]); }
function rejects(action: () => unknown, label: string, code: string): void {
  let rejected = false;
  try { action(); } catch (error) { rejected = String(error).includes(code); }
  check(rejected, label);
}

async function run(): Promise<Result> {
  const mode = new URL(location.href).searchParams.get("mode") ?? "normal";
  if (mode === "missing") {
    await initialize(new URL("./absent-sdk.wasm", location.href));
    throw new Error("missing_wasm_did_not_fail");
  }
  await initialize();
  check(SDK_VERSION === "0.1.0-stage0.1", "package_version");
  const alice = new Stage0Device("consumer-service", "alice", "browser-a");
  const bob = new Stage0Device("consumer-service", "bob", "browser-b");
  const negative = new Stage0Device("consumer-service", "mallory", "browser-c");
  try {
    check(!equal(alice.identityKey(), bob.identityKey()), "independent_identity");
    const original = bob.keyPackage();
    check(equal(original, bob.keyPackage()), "key_package_exact_retry");
    const copy = bob.keyPackage(); copy[0] ^= 1;
    check(equal(original, bob.keyPackage()), "public_buffer_ownership");
    rejects(() => negative.createGroup("negative", "bob", "browser-b", alice.identityKey(), original),
      "wrong_identity_rejected", "identity_mismatch");
    const welcome = alice.createGroup("consumer-conversation", "bob", "browser-b", bob.identityKey(), original);
    bob.joinGroup("consumer-conversation", "alice", "browser-a", alice.identityKey(), welcome);
    const unicode = new TextEncoder().encode("独立浏览器包 👋\nUnicode 与零字节\0");
    const cipher = alice.encrypt(unicode);
    check(!equal(cipher, unicode), "ciphertext_differs");
    check(equal(bob.decrypt(cipher), unicode), "unicode_round_trip");
    const binary = new Uint8Array([0, 255, 1, 128, 0, 42, 127, 254]);
    check(equal(alice.decrypt(bob.encrypt(binary)), binary), "binary_reverse_round_trip");
    const corrupted = alice.encrypt(new Uint8Array([3, 4, 5])); corrupted[corrupted.length - 1] ^= 1;
    rejects(() => bob.decrypt(corrupted), "corrupted_ciphertext_rejected", "crypto_failure");
    rejects(() => bob.encrypt(new Uint8Array([1])), "poisoned_device_rejected", "poisoned");
    alice.close(); alice.close();
    rejects(() => alice.identityKey(), "closed_device_rejected", "closed");
    check(true, "idempotent_close");
  } finally { alice.close(); bob.close(); negative.close(); }
  return { status: "PASS", checks, version: SDK_VERSION, browser: navigator.userAgent };
}

try { window.__stage0Result = await run(); }
catch (error) { window.__stage0Result = { status: "FAIL", checks, error: String(error), browser: navigator.userAgent }; }
const output = document.querySelector("#result");
if (!(output instanceof HTMLElement)) throw new Error("consumer_result_element_missing");
output.textContent = JSON.stringify(window.__stage0Result, null, 2);
