"""仅改公开见证语义并用真实测试设备重签；合法 MLS 原件始终保持。"""

import base64
import copy
from .fixture import check
from .key_package_fixture import decode
from .join_review_regressions import enable_anchor
from .recovery_competition_cases import recovery_ledger


def different_hash(value):
    return ("0" if value[0] != "0" else "1") + value[1:]


def change_nested(value, *keys):
    container = value
    for key in keys[:-1]:
        container = container[key]
    container[keys[-1]] = different_hash(container[keys[-1]])


def bound_response(lab, variant):
    lab.setup_w1(policy_version="2")
    _, accepted = lab.accepted()
    record = accepted["record"]
    request = lab.witness_request(record)["request"]
    delivery = lab.respond(record, request)["delivery"]
    original = decode(delivery["response"])
    changed = copy.deepcopy(original)
    code = "w1_binding_mismatch"
    if variant == "policy-rollback":
        changed["policy_ref"]["policy_version"] = "1"
        code = "w1_policy_mismatch"
    elif variant == "replace-bound-policy":
        change_nested(changed, "policy_ref", "policy_sha256")
        code = "w1_policy_mismatch"
    elif variant == "r0":
        change_nested(changed, "accepted_ref", "record_sha256")
    elif variant in ("commit", "welcome"):
        change_nested(changed, variant + "_sha256")
    elif variant == "package":
        change_nested(changed, "key_package_sha256")
        raw_ref = bytearray(base64.b64decode(changed["key_package_ref"]))
        raw_ref[0] ^= 1
        changed["key_package_ref"] = base64.b64encode(raw_ref).decode()
    elif variant == "target":
        changed["target"] = lab.member("b2")
    elif variant == "scope":
        changed["scope"]["conversation_id"] = "different-conversation"
    elif variant == "predecessor":
        change_nested(changed, "previous", "checkpoint", "crypto_state_ref")
    elif variant == "successor":
        change_nested(changed, "next", "checkpoint", "crypto_state_ref")
    else:
        raise AssertionError("未声明的语义变体")
    invalid = copy.deepcopy(delivery)
    invalid["response"] = lab.sign_witness_fixture(lab.witness, "response", changed)
    ledger = recovery_ledger(lab)
    lab.observed("W", "real-r1-and-original-response-preserved", delivery)
    lab.unchanged("T", "valid-signature-" + variant,
        lambda: lab.install(record, request, invalid, expected_exit=1), code)
    check(recovery_ledger(lab) == ledger and
          lab.recovery(lab.target, "inspect")["installed_count"] == 0,
          "语义拒绝后改变接受或安装状态")
    good = lab.install(record, request, delivery)
    check(good["installed"] and not good["duplicate"], "拒绝保留状态后合法原件仍不能安装")
    lab.observed("T", "legal-control-after-semantic-rejection", good)


def identity_response(lab, variant):
    lab.setup_w1()
    _, accepted = lab.accepted()
    record = accepted["record"]
    request = lab.witness_request(record)["request"]
    delivery = lab.respond(record, request)["delivery"]
    response = decode(delivery["response"])
    signer = {"actor": lab.actor, "target": lab.target, "duplicate-key": lab.actor,
              "unlisted-member": "c1"}[variant]
    response["witness"] = lab.member(signer)
    if variant == "duplicate-key":
        response["witness"]["device_id"] = "different-device-same-key"
    invalid = copy.deepcopy(delivery)
    invalid["response"] = lab.sign_witness_fixture(signer, "response", response)
    lab.observed("W", "honest-w-original-response", delivery)
    lab.unchanged("T", "unqualified-valid-signature-" + variant,
        lambda: lab.install(record, request, invalid, expected_exit=1), "w1_witness_ineligible")
    check(lab.recovery(lab.target, "inspect")["installed_count"] == 0, "非法资格仍首次安装")


def request_id_conflict(lab):
    lab.setup_w1()
    _, accepted = lab.accepted()
    record = accepted["record"]
    request = lab.witness_request(record)["request"]
    delivery = lab.respond(record, request)["delivery"]
    if lab.target not in lab.configs:
        enable_anchor(lab, lab.target)
    lab.unchanged("T", "same-request-id-different-ttl-before-anchor-reservation",
        lambda: lab.witness_request(record, ttl="59", expected_exit=1),
        "w1_request_id_conflict")
    changed = decode(request)
    changed["challenge"] = different_hash(changed["challenge"])
    replacement = lab.sign_witness_fixture(lab.target, "request", changed)
    lab.unchanged("T", "same-request-id-different-signed-bytes",
        lambda: lab.install(record, replacement, delivery, expected_exit=1), "w1_request_id_conflict")


def cross_recovery(lab):
    lab.setup_w1()
    _, accepted = lab.accepted()
    record = accepted["record"]
    request = lab.witness_request(record)["request"]
    delivery = lab.respond(record, request)["delivery"]
    response = decode(delivery["response"])
    response["recovery_id"] = "another-recovery"
    invalid = copy.deepcopy(delivery)
    invalid["response"] = lab.sign_witness_fixture(lab.witness, "response", response)
    lab.unchanged("T", "valid-response-for-other-recovery",
        lambda: lab.install(record, request, invalid, expected_exit=1), "w1_binding_mismatch")


CASES = {
    **{"WC05-%02d-%s" % (index, variant): (lambda lab, value=variant: bound_response(lab, value))
       for index, variant in enumerate(("policy-rollback", "replace-bound-policy", "r0", "commit",
            "welcome", "package", "target", "scope", "predecessor", "successor"), 1)},
    **{"WC02-%02d-%s" % (index, variant): (lambda lab, value=variant: identity_response(lab, value))
       for index, variant in ((1, "actor"), (2, "target"), (3, "duplicate-key"), (5, "unlisted-member"))},
    "WC06-02-same-id-different-bytes": request_id_conflict,
    "WC06-05-cross-recovery": cross_recovery,
}
