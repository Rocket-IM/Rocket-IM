// 只使用安装包的公开 API；Node 调度在 run.mjs，DOM lib 仅提供字节及编码器类型。
import { initialize, SDK_VERSION, Stage0Device } from "@rocket-im/stage0-node";

export interface ConsumerResult {
  status: "PASS";
  checks: string[];
  version: string;
  identityKey: number[];
}

export async function runConsumer(): Promise<ConsumerResult> {
  const checks: string[] = [];
  const devices: Stage0Device[] = [];
  function check(condition: boolean, name: string): void {
    if (!condition) throw new Error("check_failed: " + name);
    checks.push(name);
  }
  function same(a: Uint8Array, b: Uint8Array): boolean {
    return a.length === b.length && a.every((value, index) => value === b[index]);
  }
  function rejected(action: () => unknown, name: string, code: string, poisoned?: boolean): void {
    let caught: unknown;
    try { action(); } catch (error) { caught = error; }
    const message = String(caught);
    check(caught instanceof Error && message.includes(code)
      && (poisoned === undefined || message.includes("device_poisoned=" + poisoned)), name);
  }
  function typeRejected(action: () => unknown, name: string): void {
    let caught: unknown;
    try { action(); } catch (error) { caught = error; }
    check(caught instanceof TypeError, name);
  }
  function device(service: string, account: string, id: string): Stage0Device {
    const value = new Stage0Device(service, account, id); devices.push(value); return value;
  }
  function pair(group: string, service = "node-consumer-service"): [Stage0Device, Stage0Device] {
    const a = device(service, "alice", "node-a"), b = device(service, "bob", "node-b");
    const welcome = a.createGroup(group, "bob", "node-b", b.identityKey(), b.keyPackage());
    b.joinGroup(group, "alice", "node-a", a.identityKey(), welcome);
    return [a, b];
  }

  rejected(() => new Stage0Device("service", "account", "device"), "initialization_required", "sdk_not_initialized");
  // 先执行真正的加载和版本检查；负例不能被包常量断言提前截住。
  await Promise.all([initialize(), initialize()]);
  check(SDK_VERSION === "0.1.0-stage0.1", "package_version");
  await initialize(); check(true, "initialization_repeat");
  try {
    const alice = device("node-consumer-service", "alice", "node-a");
    const bob = device("node-consumer-service", "bob", "node-b");
    const another = device("node-consumer-service", "alice", "node-a");
    const identityKey = Array.from(alice.identityKey());
    check(identityKey.length === 32 && !same(alice.identityKey(), bob.identityKey()), "independent_identity");
    check(!same(alice.identityKey(), another.identityKey()), "same_scope_new_instance_has_distinct_identity");
    rejected(() => device("", "alice", "node-a"), "empty_id_rejected", "invalid_argument", false);
    rejected(() => device("s".repeat(65), "alice", "node-a"), "oversize_id_rejected", "invalid_argument", false);
    typeRejected(() => Reflect.construct(Stage0Device, [7, "alice", "node-a"]), "non_string_constructor_rejected");
    rejected(() => alice.encrypt(new Uint8Array([1])), "encrypt_requires_group", "group_required", false);
    rejected(() => alice.decrypt(new Uint8Array([1])), "decrypt_requires_group", "group_required", false);

    const key = bob.identityKey(), originalKey = new Uint8Array(key); key[0] ^= 1;
    check(same(bob.identityKey(), originalKey), "identity_output_copy");
    const original = bob.keyPackage();
    check(same(original, bob.keyPackage()), "key_package_exact_retry");
    const changed = bob.keyPackage(); changed[0] ^= 1;
    check(same(original, bob.keyPackage()), "key_package_output_copy");
    rejected(() => another.createGroup("wrong_pin", "bob", "node-b", alice.identityKey(), original),
      "wrong_identity_rejected", "identity_mismatch", false);
    check(another.keyPackage().length > 0, "wrong_identity_preserves_device");
    const outsider = device("other-service", "bob", "node-b");
    rejected(() => another.createGroup("wrong_service", "bob", "node-b", outsider.identityKey(), outsider.keyPackage()),
      "cross_service_key_package_rejected", "identity_mismatch", false);

    const welcome = alice.createGroup("conversation", "bob", "node-b", bob.identityKey(), original);
    rejected(() => alice.keyPackage(), "grouped_key_package_rejected", "already_grouped", false);
    rejected(() => bob.joinGroup("conversation", "alice", "node-a", alice.identityKey(), new Uint8Array([1, 2])),
      "malformed_welcome_rejected", "invalid_encoding", false);
    check(same(original, bob.keyPackage()), "malformed_welcome_preserves_package");
    bob.joinGroup("conversation", "alice", "node-a", alice.identityKey(), welcome);
    rejected(() => bob.joinGroup("conversation", "alice", "node-a", alice.identityKey(), welcome),
      "second_join_rejected", "already_grouped", false);

    typeRejected(() => Reflect.apply(alice.encrypt, alice, [[1, 2, 3]]), "non_bytes_encrypt_rejected");
    typeRejected(() => Reflect.apply(bob.decrypt, bob, [new ArrayBuffer(8)]), "non_bytes_decrypt_rejected");
    typeRejected(() => Reflect.apply(another.createGroup, another, [7, "bob", "node-b", originalKey, original]),
      "non_string_group_rejected");
    typeRejected(() => Reflect.apply(alice.identityKey, undefined, []), "detached_method_rejected");
    rejected(() => alice.encrypt(new Uint8Array()), "empty_plaintext_rejected", "invalid_argument", false);
    rejected(() => alice.encrypt(new Uint8Array(65537)), "oversize_plaintext_rejected", "limit_exceeded", false);
    rejected(() => bob.decrypt(new Uint8Array(262145)), "oversize_protocol_rejected", "limit_exceeded", false);
    rejected(() => bob.decrypt(new Uint8Array([1, 2, 3])), "malformed_ciphertext_rejected", "invalid_encoding", false);

    const unicode = new TextEncoder().encode("独立 Node SDK 👋\nUnicode 与零字节\0");
    const cipher = alice.encrypt(unicode);
    check(!same(cipher, unicode), "ciphertext_differs");
    check(same(bob.decrypt(cipher), unicode), "unicode_round_trip");
    const backing = new Uint8Array([77, 66, 0, 255, 1, 128, 0, 42, 55]);
    const input = backing.subarray(2, 8), expected = new Uint8Array(input);
    const encrypted = bob.encrypt(input); backing.fill(9);
    check(same(alice.decrypt(encrypted), expected), "binary_subarray_and_input_copy");
    const maximum = new Uint8Array(65536).fill(231);
    check(same(bob.decrypt(alice.encrypt(maximum)), maximum), "maximum_payload_round_trip");
    const [other] = pair("other-conversation");
    rejected(() => bob.decrypt(other.encrypt(new Uint8Array([9]))), "wrong_conversation_rejected", "scope_mismatch", false);
    const [otherService] = pair("conversation", "other-service");
    rejected(() => bob.decrypt(otherService.encrypt(new Uint8Array([9]))), "wrong_service_ciphertext_rejected", "scope_mismatch", false);
    check(same(bob.decrypt(alice.encrypt(new Uint8Array([7]))), new Uint8Array([7])), "validation_errors_preserve_valid_state");

    const [sender, receiver] = pair("tamper-conversation");
    const tampered = sender.encrypt(new Uint8Array([3, 4, 5])); tampered[tampered.length - 1] ^= 1;
    rejected(() => receiver.decrypt(tampered), "tampered_ciphertext_rejected", "crypto_failure", true);
    rejected(() => receiver.encrypt(new Uint8Array([1])), "poisoned_encrypt_rejected", "poisoned", true);
    rejected(() => receiver.identityKey(), "poisoned_identity_rejected", "poisoned", true);
    check(sender.identityKey().length === 32, "poison_isolated_to_receiver");
    const [replaySender, replayReceiver] = pair("replay-conversation");
    const replay = replaySender.encrypt(new Uint8Array([4])); replayReceiver.decrypt(replay);
    rejected(() => replayReceiver.decrypt(replay), "duplicate_ciphertext_rejected", "crypto_failure", true);
    rejected(() => replayReceiver.decrypt(new Uint8Array([1])), "duplicate_failure_stays_poisoned", "poisoned", true);

    const creator = device("node-consumer-service", "alice", "node-a");
    const joiner = device("node-consumer-service", "bob", "node-b");
    const joinWelcome = creator.createGroup("expected-group", "bob", "node-b", joiner.identityKey(), joiner.keyPackage());
    rejected(() => joiner.joinGroup("substituted-group", "alice", "node-a", creator.identityKey(), joinWelcome),
      "wrong_welcome_scope_poisoned", "scope_mismatch", true);
    rejected(() => joiner.identityKey(), "wrong_welcome_scope_stays_poisoned", "poisoned", true);

    const before = bob.identityKey(), savedClosure = () => alice.identityKey();
    alice.close(); alice.close(); check(true, "idempotent_close");
    rejected(savedClosure, "closed_object_closure_rejected", "closed", false);
    rejected(() => alice.keyPackage(), "closed_key_package_rejected", "closed", false);
    rejected(() => alice.encrypt(new Uint8Array([1])), "closed_encrypt_rejected", "closed", false);
    rejected(() => alice.decrypt(new Uint8Array([1])), "closed_decrypt_rejected", "closed", false);
    check(same(before, bob.identityKey()), "close_isolated_to_owner");
    check(bob.encrypt(new Uint8Array([1])).length > 0, "other_device_usable_after_close");
    receiver.close(); receiver.close();
    rejected(() => receiver.identityKey(), "poisoned_device_can_close", "closed", false);
    return { status: "PASS", checks, version: SDK_VERSION, identityKey };
  } finally {
    for (const value of devices) value.close();
  }
}
