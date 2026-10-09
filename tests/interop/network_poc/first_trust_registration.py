"""F01—F03：原 HTTP 注册证明、凭证盗用边界和首次身份声明。"""

import base64
import copy
import json

from .fixture import check, identity
from .first_trust_evidence import database, state
from .first_trust_fixture import DEVICES, confirm, inspect, observe, reject, roundtrip
from .first_trust_session import public_identity, verify_public


def accepted_registration(lab):
    lab.register("a1")
    committed = state(lab)
    original = lab.registrations["a1"]
    check(lab.complete_registration("a1", original["proof"]) == original["result"]
          and state(lab) == committed, "原注册证明重试不幂等")
    observe(lab, "b1", "a1")
    check(inspect(lab, "b1", "a1")["status"] == "unverified", "成功登记自动成为联系人核验")
    peers = [{"account": identity(d)["account_id"], "device": d,
              "signature_key": lab.public[d]["signature_key"], "key_package": lab.public[d]["key_package"]}
             for d in DEVICES[1:]]
    reject(lab, "create", peers=peers)
    lab.group()
    roundtrip(lab)
    lab.case_evidence["assertion"] = "REAL_POP_REGISTRATION_STILL_UNVERIFIED_UNTIL_INDEPENDENT_CONFIRMATION"


def http_reject_unchanged(lab, device, operation, request, *, code, status):
    before = state(lab)
    error = lab.http(device, operation, request, expected=status)
    check(error["code"] == code and state(lab) == before, f"注册负例改变状态或错误码不符: {error}")
    lab.case_evidence.setdefault("registration_rejections", []).append({"operation": operation,
        "error": error, "before": before, "after": state(lab)})


def stolen_credentials(lab):
    challenge = lab.begin_registration("a1")
    valid = lab.prove_registration("a1", challenge)
    other = lab.prove_registration("c1", lab.begin_registration("c1"))
    forged = {"statement_bytes": challenge["challenge_bytes"], "signature_bytes": other["signature_bytes"]}
    http_reject_unchanged(lab, "a1", "complete_device_registration",
        {"service_id": lab.service, "proof": forged}, code="registration_signature", status=403)
    http_reject_unchanged(lab, "b1", "complete_device_registration",
        {"service_id": lab.service, "proof": valid}, code="registration_context", status=403)
    http_reject_unchanged(lab, "a1", "complete_device_registration",
        {"service_id": "other-service", "proof": valid}, code="registration_context", status=403)
    changed = copy.deepcopy(valid)
    statement = json.loads(base64.b64decode(changed["statement_bytes"]))
    statement["signature_key"] = lab.public["b1"]["signature_key"]
    changed["statement_bytes"] = base64.b64encode(json.dumps(statement, separators=(",", ":")).encode()).decode()
    http_reject_unchanged(lab, "a1", "complete_device_registration",
        {"service_id": lab.service, "proof": changed}, code="registration_conflict", status=409)
    lab.register("a1")
    http_reject_unchanged(lab, "a1", "begin_device_registration",
        {"service_id": lab.service, "registration_id": "new-after-registered",
         "signature_key": lab.public["a1"]["signature_key"]}, code="registration_conflict", status=409)
    lab.group()
    roundtrip(lab, sender="b1")
    page = lab.http("d1", "pull_events_signed", {"service_id": lab.service, "after_seq": "0", "limit": "100"},
                    token=lab.tokens["a1"])
    lab.case_evidence["stolen_token_access"] = {"can_fetch_signed_ciphertext_page": "page_bytes" in page,
        "page_bytes": len(base64.b64decode(page["page_bytes"])),
        "boundary": "copied business credential can fetch victim ciphertext/metadata; not private-key possession or decryption"}


def expiration(lab):
    challenge = lab.begin_registration("a1")
    proof = lab.prove_registration("a1", challenge)
    statement = json.loads(base64.b64decode(challenge["challenge_bytes"]))
    expires = int(statement["expires_at_ms"])
    issued = int(statement["issued_at_ms"])
    check(expires - issued == 300000, "测试改变了生产注册有效期")
    lab.set_clock(expires)
    http_reject_unchanged(lab, "a1", "complete_device_registration",
        {"service_id": lab.service, "proof": proof}, code="registration_expired", status=409)
    replacement = lab.begin_registration("a1", "later-registration")
    original = lab.prove_registration("a1", replacement)
    result = lab.complete_registration("a1", original)
    saved = database(lab)
    lab.set_clock(expires + 600000)
    repeated = lab.complete_registration("a1", original)
    check(repeated == result and database(lab) == saved, "已提交原证明过期重试改变状态")
    lab.case_evidence["clock_boundary"] = {"kind": "controlled_file_clock_original_production_ttl",
        "issued_at_ms": str(issued), "expires_at_ms": str(expires), "ttl_ms": "300000"}


def false_first_identity(lab):
    lab.group()
    old = inspect(lab)
    replacement = public_identity(lab, "b1") | {"signature_key": lab.public["d1"]["signature_key"]}
    result = lab.rust("a1", "identity_trust_observe", identity=replacement)
    changed = result["record"]
    check(changed["status"] == "changed" and changed["history"] == "gap" and changed["identity"] == old["identity"]
          and changed["candidate"] == replacement, "伪称首次覆盖既有身份")
    reject(lab)
    observe(lab, "a1", "b2")
    unknown = inspect(lab, "a1", "b2")
    check(unknown["history"] == "unknown" and unknown["status"] == "unverified", "无前驱被写成连续")
    verify_public(lab, "a1", "b2")
    check(inspect(lab, "a1", "b2")["history"] == "unknown", "核验补造了历史连续性")
    check(inspect(lab)["status"] == "changed", "核验别的设备清掉旧身份冲突")
    lab.case_evidence.update(original_binding=old, observed_change=changed, new_unknown=unknown)


CASES = [("Q01.F01.registration", accepted_registration),
         ("Q01.F02.stolen_credentials", stolen_credentials),
         ("Q01.F02.expiration", expiration),
         ("Q01.F03.false_first_identity", false_first_identity)]
