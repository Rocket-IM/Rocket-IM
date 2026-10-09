"""Q01 分段装置：无公钥业务凭证、原注册、独立核验、同库群引导。"""

import json
from pathlib import Path
import secrets
import subprocess
import time

from .anchor_fixture import AnchorLab
from .fixture import ACCOUNTS, CONVERSATION, NetworkLab, check, identity, require_current_namespace
from .first_trust_evidence import database, digest, snapshot, state
from .first_trust_session import TrustSession, public_identity, verify_all, verify_public

DEVICES = tuple(ACCOUNTS)
CANDIDATES = ("d1", "b2")


class FirstTrustLab(NetworkLab):
    environment = AnchorLab.environment
    anchor = AnchorLab.anchor
    enable = AnchorLab.enable
    command = AnchorLab.command
    config_change = AnchorLab.config_change
    config_restore = AnchorLab.config_restore
    forwarding_helper = AnchorLab.forwarding_helper
    resume = AnchorLab.resume
    blocked = AnchorLab.blocked
    snapshot = AnchorLab.snapshot

    def __init__(self, binary, directory, verifier, signer, helper=None):
        super().__init__(binary, directory, verifier, signer,
                         relay_entrypoint=Path(__file__).with_name("first_trust_relay.py"))
        self.helper = Path(helper) if helper else None
        self.configs, self.materials = {}, {}
        self.helper_process_count = 0
        self.case_evidence = {}
        self.receipt_active = False
        self.registrations = {}
        self.clock = self.directory / "registration-clock.txt"
        self.relay_args = ("--registration-clock-file", str(self.clock))

    def start(self):
        signer = self.receipt_signer
        if not self.receipt_active:
            self.receipt_signer = None
        try:
            super().start()
        finally:
            self.receipt_signer = signer
        self.case_evidence.setdefault("relay_processes", []).append({"pid": self.process.pid,
            "registration_phase": not self.receipt_active, "url": self.url.geturl()})

    def raw_rust(self, device, operation, *, env=None, **fields):
        request = {"directory": str(self.directory / device), "service": self.service,
                   "account": identity(device)["account_id"], "device": device,
                   "operation": operation, **fields}
        process = subprocess.Popen([str(self.binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, env=self.environment(device, env))
        self.process_count += 1
        trace = {"device": device, "operation": operation, "pid": process.pid,
                 "anchor_configured": device in self.configs, "failpoint": fields.get("failpoint")}
        self.case_evidence.setdefault("processes", []).append(trace)
        try:
            stdout, stderr = process.communicate(json.dumps(request), timeout=30)
        except BaseException:
            process.kill()
            process.communicate(timeout=5)
            trace["interrupted"] = True
            raise
        trace.update(exit_code=process.returncode, stdout_sha256=digest(stdout.encode()),
                     stderr_sha256=digest(stderr.encode()))
        return subprocess.CompletedProcess([str(self.binary)], process.returncode, stdout, stderr)

    def rust(self, device, operation, *, expected_exit=0, **fields):
        reply = self.raw_rust(device, operation, **fields)
        check(reply.returncode == expected_exit,
              f"{operation}: exit {reply.returncode}, expected {expected_exit}; {reply.stdout[:400]}")
        if expected_exit in range(83, 89):
            check(not reply.stdout.strip(), "受控退出提前交付结果")
            return None
        value = json.loads(reply.stdout)
        check(value["ok"] == (expected_exit == 0), "退出码与响应不符")
        return value["result"] if value["ok"] else value["error"]

    def initialize(self):
        require_current_namespace(self.binary)
        for device in (*DEVICES, *CANDIDATES):
            self.tokens.setdefault(device, secrets.token_urlsafe(32))
            self.public[device] = self.rust(device, "init")
            check(self.public[device].get("identity_trust_version") == "1"
                  and self.public[device].get("identity_trust_strict") is True, "缺少显式 Q01 严格能力")
            if self.helper:
                self.enable(device)
        self.relay_receipt_key = self.relay_key("init")["signature_key"]
        self.set_clock(int(time.time() * 1000))
        self.fixture = {"service_id": self.service, "controller_token": self.controller_token,
            "devices": [{**identity(d), "token": self.tokens[d]} for d in self.public],
            "conversation": {"conversation_id": CONVERSATION, "members": [identity(d) for d in DEVICES],
                             "authorization_version": "1", "crypto_state_ref": "0" * 64}}
        self.fixture_path = self.directory / "fixture.json"
        self.fixture_path.write_text(json.dumps(self.fixture))
        self.fixture_path.chmod(0o600)
        self.start()
        empty = database(self)
        check(not empty["public_keys"], "注册前提前注入设备公钥")
        self.case_evidence["initial_registration_database"] = empty

    def set_clock(self, milliseconds):
        temporary = self.clock.with_suffix(".tmp")
        temporary.write_text(str(milliseconds) + "\n")
        temporary.chmod(0o600)
        temporary.replace(self.clock)

    def begin_registration(self, device, registration_id=None, **fields):
        return self.http(device, "begin_device_registration", {"service_id": self.service,
            "registration_id": registration_id or "register-" + device,
            "signature_key": self.public[device]["signature_key"], **fields})

    def prove_registration(self, device, challenge):
        return self.rust(device, "device_registration_prove", **challenge)["proof"]

    def complete_registration(self, device, proof, **options):
        return self.http(device, "complete_device_registration",
                         {"service_id": self.service, "proof": proof}, **options)

    def register(self, device):
        challenge = self.begin_registration(device)
        proof = self.prove_registration(device, challenge)
        result = self.complete_registration(device, proof)
        check(result == {"status": "registered", "service_id": self.service, **identity(device),
              "registration_id": "register-" + device, "signature_key": self.public[device]["signature_key"]},
              "注册固定结果不匹配")
        self.registrations[device] = {"challenge": challenge, "proof": proof, "result": result}
        self.case_evidence.setdefault("registrations", {})[device] = self.registrations[device]
        return result

    def register_all(self):
        for device in self.public:
            if device not in self.registrations:
                self.register(device)

    def group(self, *, verify=True):
        self.register_all()
        if verify:
            verify_all(self, DEVICES)
        self.authorize_fixture_peer("a1", "a2")
        self.authorize_fixture_peer("a2", "a1")
        peers = [{"account": ACCOUNTS[d], "device": d, "signature_key": self.public[d]["signature_key"],
                  "key_package": self.public[d]["key_package"]} for d in DEVICES[1:]]
        created = self.rust("a1", "create", peers=peers)
        pins = [{"account": ACCOUNTS[d], "device": d,
                 "signature_key": self.public[d]["signature_key"]} for d in DEVICES]
        for device in DEVICES[1:]:
            self.rust(device, "join", welcome=created["welcome"], pins=pins)
        references = []
        for device in DEVICES:
            self.rust(device, "wire_configure", conversation_id=CONVERSATION,
                      authorization_version="1", pending_limit=1000)
            references.append(self.rust(device, "wire_inspect")["crypto_state_ref"])
        check(len(set(references)) == 1, "群检查点不一致")
        self.state_ref = references[0]
        self.checkpoint = {"service_id": self.service, "conversation_id": CONVERSATION,
            "authorization_version": "1", "crypto_state_ref": self.state_ref, "owner_account_id": "alice",
            "members": [{**identity(d), "signature_key": self.public[d]["signature_key"]}
                        for d in sorted(DEVICES, key=lambda d: (ACCOUNTS[d], d))]}
        for device in DEVICES:
            self.rust(device, "permission_bootstrap", checkpoint=self.checkpoint,
                      relay_receipt_key=self.relay_receipt_key)
        before = database(self)
        result = self.control("first_trust_bootstrap", checkpoint=self.checkpoint,
                              relay_receipt_key=self.relay_receipt_key)
        self.receipt_active = True
        self.restart()
        after = database(self)
        check(before["public_keys"] == after["public_keys"] and
              before["tables"]["device_registrations"] == after["tables"]["device_registrations"],
              "延后群引导覆盖了原注册账本/公钥")
        self.case_evidence["group_bootstrap"] = {"result": result, "checkpoint": self.checkpoint,
            "before": before, "after": after,
            "boundary": "synthetic authorized group initialization in the same database; not a production group API"}


def inspect(lab, observer="a1", target="b1"):
    result = lab.rust(observer, "identity_trust_inspect", target=identity(target))
    check(result["strict"] is True, "新程序没有默认严格核验门禁")
    return result["records"][0] if result["records"] else None


def confirm(lab, observer="a1", target="b1", *, purpose="verify", independent=None, **options):
    with TrustSession(lab, observer) as session:
        display = session.request("identity_trust_prepare", target=identity(target), purpose=purpose)["display"]
        return session.request("identity_trust_confirm" if purpose == "verify" else "identity_trust_reset",
                               display=display, independent_identity=independent or public_identity(lab, target),
                               verification="synthetic_local", **options)


def observe(lab, observer="a1", target="b1", **changes):
    return lab.rust(observer, "identity_trust_observe", identity=public_identity(lab, target) | changes)


def reject(lab, operation="wire_send", *, device="a1", codes=("identity_unverified", "identity_changed"), **fields):
    if operation == "wire_send" and not fields:
        fields = {"logical_message_id": "must-block", "attempt_id": "P1", "payload": "synthetic-q01-blocked"}
    before = state(lab)
    error = lab.rust(device, operation, expected_exit=1, **fields)
    check(error["code"] in codes and state(lab) == before, f"拒绝改变状态或原因不符: {error}")
    lab.case_evidence.setdefault("rejections", []).append({"operation": operation, "error": error,
                                                          "before": before, "after": state(lab)})
    return error


def roundtrip(lab, logical="q01-roundtrip", sender="a1", recipients=DEVICES):
    payload = "synthetic-first-trust-" + logical
    packet = lab.rust(sender, "wire_send", logical_message_id=logical, attempt_id="P1", payload=payload)
    accepted = lab.submit(packet, device=sender)
    lab.rust(sender, "wire_accept", logical_message_id=logical, attempt_id="P1",
             acceptance_receipt=accepted["acceptance_receipt"])
    for device in recipients:
        if device == sender:
            continue
        received = lab.receive(device, packet, acceptance_id=accepted["acceptance_id"],
                               acceptance_receipt=accepted["acceptance_receipt"])
        check(received["payload_sha256"] == digest(payload.encode()) and not received["duplicate"],
              "核验后真实消息没有成功解密")
    lab.case_evidence.setdefault("roundtrips", []).append({"logical": logical, "sender": sender,
        "envelope_sha256": digest(json.dumps(packet["envelope"], sort_keys=True).encode()), "accepted": accepted})
    return packet, accepted
