"""真实发布包的20条跨端路线及55个错误一致性场景。控制器只搬运字节。"""
from itertools import combinations

from .expectations import Case, CaseFailure, encoded, require, summary


ENDPOINTS = ("swift-ios", "kotlin-android", "browser", "flutter-ios", "flutter-android")
PAYLOADS = (
    ("unicode", "跨端互通 👋\n组合字符 e\u0301、零字节\0".encode()),
    ("binary", bytes(range(256))),
    ("one_byte", b"\x00"),
    ("64_kib", bytes(range(256)) * 256),
)


def create_args(peer, conversation):
    return {"conversation_id": conversation, "peer_account_id": peer.account,
            "peer_device_id": peer.device, "peer_identity_key": encoded(peer.identity),
            "key_package": encoded(peer.key_package)}


def join_args(creator, conversation, welcome):
    return {"conversation_id": conversation, "creator_account_id": creator.account,
            "creator_device_id": creator.device, "creator_identity_key": encoded(creator.identity),
            "welcome": encoded(welcome)}


def establish(case, creator, joiner):
    require(creator.endpoint != joiner.endpoint, "distinct_runtime_endpoints")
    conversation = "group-" + case.prefix
    welcome = case.ok(creator, "create_group", **create_args(joiner, conversation))
    case.ok(joiner, "join_group", **join_args(creator, conversation, welcome))
    return conversation, welcome


def exchange(case, sender, receiver, payload, label):
    require(sender.endpoint != receiver.endpoint, "message_crosses_runtime")
    ciphertext = case.ok(sender, "encrypt", plaintext=encoded(payload))
    require(ciphertext != payload, "ciphertext_differs_from_plaintext")
    plaintext = case.ok(receiver, "decrypt", ciphertext=encoded(ciphertext))
    require(plaintext == payload, "cross_runtime_plaintext_equality")
    case.details["checks"].append({"name": label, "sender": sender.endpoint, "receiver": receiver.endpoint,
                                   "payload": summary(payload), "ciphertext": summary(ciphertext)})
    return ciphertext


def recovered_exchange(case, first, second):
    exchange(case, first, second, PAYLOADS[0][1], "healthy_after_preflight_rejection")
    exchange(case, second, first, PAYLOADS[1][1], "healthy_reverse_after_preflight_rejection")


def route(case, creator_endpoint, joiner_endpoint):
    creator, joiner = case.new(creator_endpoint), case.new(joiner_endpoint)
    require(creator.identity != joiner.identity, "independent_runtime_identities")
    case.unchanged(creator)
    case.unchanged(joiner)
    establish(case, creator, joiner)
    for device in (creator, joiner):
        case.rejected(device, "key_package", "already_grouped")
    for label, payload in PAYLOADS:
        exchange(case, creator, joiner, payload, label + "_creator_to_joiner")
        exchange(case, joiner, creator, payload, label + "_joiner_to_creator")


def poisoned(case, target, peer, conversation, welcome):
    ciphertext = case.ok(peer, "encrypt", plaintext=encoded(PAYLOADS[1][1]))
    operations = [("identity", {}), ("key_package", {}),
                  ("encrypt", {"plaintext": encoded(b"\x01")}),
                  ("decrypt", {"ciphertext": encoded(ciphertext)}),
                  ("join_group", join_args(peer, conversation, welcome)),
                  ("create_group", create_args(peer, conversation))]
    for operation, args in operations:
        case.rejected(target, operation, "poisoned", True, **args)
    case.ok(target, "close")
    case.ok(target, "close")
    case.rejected(target, "identity", "closed")
    case.details["checks"].append("all_operations_reject_poisoned_state_then_close_is_idempotent")


def bad_key_package(case, target_endpoint, peer_endpoint, variant):
    target = case.new(target_endpoint)
    peer = case.new(peer_endpoint, "different-service" if variant == "service" else "interop-service")
    args = create_args(peer, "group-" + case.prefix)
    if variant == "identity":
        decoy = case.new(peer_endpoint)
        args["peer_identity_key"] = encoded(decoy.identity)
    elif variant == "encoding":
        args["key_package"] = encoded(peer.key_package[:-1])
    code = "invalid_encoding" if variant == "encoding" else "identity_mismatch"
    case.rejected(target, "create_group", code, **args)
    case.unchanged(target)
    if variant == "service":
        peer = case.new(peer_endpoint)
    establish(case, target, peer)
    recovered_exchange(case, target, peer)


def bad_welcome(case, target_endpoint, peer_endpoint, variant):
    target, peer = case.new(target_endpoint), case.new(peer_endpoint)
    conversation = "group-" + case.prefix
    welcome = case.ok(peer, "create_group", **create_args(target, conversation))
    args = join_args(peer, conversation, welcome)
    if variant == "scope":
        args["conversation_id"] = "wrong-" + case.prefix
        code = "scope_mismatch"
    elif variant == "creator":
        decoy = case.new(peer_endpoint)
        args["creator_identity_key"] = encoded(decoy.identity)
        code = "identity_mismatch"
    else:
        args["welcome"] = encoded(welcome[:-1])
        code = "invalid_encoding"
    case.rejected(target, "join_group", code, variant != "encoding", **args)
    if variant == "encoding":
        case.unchanged(target)
        case.ok(target, "join_group", **join_args(peer, conversation, welcome))
        recovered_exchange(case, peer, target)
    else:
        poisoned(case, target, peer, conversation, welcome)


def bad_ciphertext(case, target_endpoint, peer_endpoint, variant):
    target, peer = case.new(target_endpoint), case.new(peer_endpoint)
    conversation, welcome = establish(case, peer, target)
    plaintext = PAYLOADS[1][1]
    ciphertext = case.ok(peer, "encrypt", plaintext=encoded(plaintext))
    if variant == "replay":
        require(case.ok(target, "decrypt", ciphertext=encoded(ciphertext)) == plaintext, "first_delivery_succeeds")
        changed = ciphertext
    elif variant == "tamper":
        changed = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
    else:
        changed = ciphertext[:-1]
    case.rejected(target, "decrypt", "invalid_encoding" if variant == "encoding" else "crypto_failure",
                  variant != "encoding", ciphertext=encoded(changed))
    if variant == "encoding":
        require(case.ok(target, "identity") == target.identity, "malformed_ciphertext_preserves_identity")
        require(case.ok(target, "decrypt", ciphertext=encoded(ciphertext)) == plaintext, "original_ciphertext_still_decrypts")
        recovered_exchange(case, target, peer)
    else:
        poisoned(case, target, peer, conversation, welcome)


def closed(case, target_endpoint, peer_endpoint):
    target, peer = case.new(target_endpoint), case.new(peer_endpoint)
    conversation, welcome = establish(case, peer, target)
    ciphertext = case.ok(peer, "encrypt", plaintext=encoded(PAYLOADS[0][1]))
    case.ok(target, "close")
    case.ok(target, "close")
    operations = [("identity", {}), ("key_package", {}),
                  ("encrypt", {"plaintext": encoded(b"\x01")}),
                  ("decrypt", {"ciphertext": encoded(ciphertext)}),
                  ("join_group", join_args(peer, conversation, welcome)),
                  ("create_group", create_args(peer, conversation))]
    for operation, args in operations:
        case.rejected(target, operation, "closed", **args)
    require(case.ok(peer, "identity") == peer.identity, "closing_target_preserves_remote_identity")
    case.ok(peer, "encrypt", plaintext=encoded(PAYLOADS[1][1]))


def limits(case, target_endpoint, peer_endpoint):
    target, peer = case.new(target_endpoint), case.new(peer_endpoint)
    case.rejected(target, "encrypt", "group_required", plaintext=encoded(b"\x01"))
    args = create_args(peer, "group-" + case.prefix)
    for value, code in ((b"", "invalid_argument"), (peer.key_package + bytes(262145 - len(peer.key_package)), "limit_exceeded")):
        case.rejected(target, "create_group", code, **{**args, "key_package": encoded(value)})
    case.unchanged(target)
    conversation = "group-" + case.prefix
    welcome = case.ok(peer, "create_group", **create_args(target, conversation))
    args = join_args(peer, conversation, welcome)
    for value, code in ((b"", "invalid_argument"), (welcome + bytes(262145 - len(welcome)), "limit_exceeded")):
        case.rejected(target, "join_group", code, **{**args, "welcome": encoded(value)})
    case.unchanged(target)
    case.ok(target, "join_group", **args)
    for value, code in ((b"", "invalid_argument"), (bytes(65537), "limit_exceeded")):
        case.rejected(target, "encrypt", code, plaintext=encoded(value))
    ciphertext = case.ok(peer, "encrypt", plaintext=encoded(PAYLOADS[0][1]))
    for value, code in ((b"", "invalid_argument"), (ciphertext + bytes(262145 - len(ciphertext)), "limit_exceeded")):
        case.rejected(target, "decrypt", code, ciphertext=encoded(value))
    require(case.ok(target, "decrypt", ciphertext=encoded(ciphertext)) == PAYLOADS[0][1], "bounds_rejection_preserves_receiver")
    recovered_exchange(case, target, peer)


NEGATIVES = (
    ("kp_identity", bad_key_package, "identity"), ("kp_service", bad_key_package, "service"),
    ("welcome_scope", bad_welcome, "scope"), ("welcome_creator", bad_welcome, "creator"),
    ("malformed_key_package", bad_key_package, "encoding"),
    ("malformed_welcome", bad_welcome, "encoding"), ("malformed_ciphertext", bad_ciphertext, "encoding"),
    ("tamper", bad_ciphertext, "tamper"), ("replay", bad_ciphertext, "replay"),
    ("closed", closed, None), ("limits", limits, None),
)


def run_cases(client, endpoints: list[str], selected_case: str | None = None) -> list[dict]:
    """完整验收须不传selected_case且提供五端；on_case仅在场景清理完成后通知。"""
    require(len(endpoints) == 5 and set(endpoints) == set(ENDPOINTS), "complete_five_runtime_configuration")
    jobs = []
    for first, second in combinations(endpoints, 2):
        for creator, joiner in ((first, second), (second, first)):
            jobs.append((f"route.{creator}_to_{joiner}", route, (creator, joiner)))
    for index, endpoint in enumerate(endpoints):
        peer = endpoints[(index + 1) % len(endpoints)]
        for name, function, variant in NEGATIVES:
            args = (endpoint, peer) if variant is None else (endpoint, peer, variant)
            jobs.append((f"error.{endpoint}.{name}", function, args))
    require(len(jobs) == 75, "complete_case_count")
    if selected_case is not None:
        jobs = [job for job in jobs if job[0] == selected_case]
        require(len(jobs) == 1, "selected_case_exists")
    results = []
    for case_id, function, args in jobs:
        case = Case(client, case_id)
        case.details["mode"] = "diagnostic" if selected_case is not None else "full_matrix"
        case.details["roles"] = dict(zip(("creator", "joiner") if function is route else ("target", "material_source"), args[:2]))
        result = {"case_id": case_id, "status": "PASS", "details": case.details}
        try:
            function(case, *args)
        except CaseFailure as error:
            result.update(status="FAIL", failure=error.details)
        except Exception as error:
            result.update(status="FAIL", failure={"kind": "harness_exception", "exception_type": type(error).__name__})
        if case.cleanup():
            result["status"] = "FAIL"
            result.setdefault("failure", {"kind": "cleanup_failed"})
        results.append(result)
        callback = getattr(client, "on_case", None)
        if callback is not None:
            callback(result)
    return results
