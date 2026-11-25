"""W1 验收只调用真实 Rust 状态入口与 Relay，不解释或改写 MLS 私有消息。"""

import base64
import hashlib
import json
import os
import secrets
import subprocess
import time

from .fixture import ACCOUNTS, check, identity
from .first_trust_evidence import database, state
from .join_recovery_fixture import RecoveryLab, signed_digest
from .join_review_regressions import public_record
from .key_package_fixture import decode
from .recovery_watermark_cases import resume


PROFILE = "E10C-W1"
RULES = "rim-recovery-witness-rules-1"


def encoded(value):
    return base64.b64encode(value).decode()


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def source(ident):
    return {"source_id": ident, "source_sha256": sha(ident.encode())}


def canonical_envelopes(value):
    """只重排外封装；签名内的原始 statement_bytes 永不重编码。"""
    if isinstance(value, list):
        return [canonical_envelopes(item) for item in value]
    if not isinstance(value, dict):
        return value
    if set(value) == {"statement_bytes", "signature_bytes"}:
        return {key: value[key] for key in ("statement_bytes", "signature_bytes")}
    return {key: canonical_envelopes(item) for key, item in value.items()}


class WitnessLab(RecoveryLab):
    """可信配置由装置独立钉住；仅代表合成信任源，不证明部署控制域独立。"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.witness = "b1"
        self.witness_configs = {}
        self.role_results = {"A": [], "W": [], "T": []}
        self.relay_witness_config = None
        self.deferred_initial_anchors = set()
        self.frozen_definition = None

    def enable(self, device="a1"):
        if device in self.deferred_initial_anchors:
            self.case_evidence.setdefault("deferred_initial_anchors", []).append(device)
            return
        return super().enable(device)

    def setup_expired(self, target="d1", actor="a1"):
        ttl = 30 if self.helper is not None else 10
        self.case_evidence["original_package_ttl_seconds"] = ttl
        return super().setup_expired(target, actor, original_ttl=ttl)

    def start(self):
        if self.relay_witness_config is None:
            return super().start()
        path, digest = self.relay_witness_config
        previous = os.environ.get("RIM_RECOVERY_WITNESS_CONFIG_SHA256")
        previous_args = self.relay_args
        try:
            os.environ["RIM_RECOVERY_WITNESS_CONFIG_SHA256"] = digest
            self.relay_args = (*previous_args, "--recovery-witness-config", str(path))
            return super().start()
        finally:
            self.relay_args = previous_args
            if previous is None:
                os.environ.pop("RIM_RECOVERY_WITNESS_CONFIG_SHA256", None)
            else:
                os.environ["RIM_RECOVERY_WITNESS_CONFIG_SHA256"] = previous

    def environment(self, device, additions=None):
        env = super().environment(device)
        env.pop("RIM_RECOVERY_WITNESS_CONFIG", None)
        env.pop("RIM_RECOVERY_WITNESS_CONFIG_SHA256", None)
        if device in self.witness_configs:
            path, digest = self.witness_configs[device]
            env["RIM_RECOVERY_WITNESS_CONFIG"] = str(path)
            env["RIM_RECOVERY_WITNESS_CONFIG_SHA256"] = digest
        return env | (additions or {})

    def raw_rust(self, device, operation, *, env=None, **fields):
        request = {"directory": str(self.directory / device), "service": self.service,
                   "account": identity(device)["account_id"], "device": device,
                   "operation": operation, **fields}
        raw = json_bytes(canonical_envelopes(request)).decode()
        process = subprocess.Popen([str(self.binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, env=self.environment(device, env))
        self.process_count += 1
        trace = {"device": device, "operation": operation, "pid": process.pid,
                 "binary": str(self.binary),
                 "anchor_configured": device in self.configs, "failpoint": fields.get("failpoint"),
                 "anchor_failpoint": (env or {}).get("RIM_ANCHOR_FAILPOINT"),
                 "request_sha256": sha(raw.encode())}
        self.case_evidence.setdefault("processes", []).append(trace)
        try:
            stdout, stderr = process.communicate(raw, timeout=30)
        except BaseException:
            process.kill()
            process.communicate(timeout=5)
            trace["interrupted"] = True
            raise
        trace.update(exit_code=process.returncode, stdout_sha256=sha(stdout.encode()),
                     stderr_sha256=sha(stderr.encode()))
        return subprocess.CompletedProcess([str(self.binary)], process.returncode, stdout, stderr)

    def witness_command(self, device, command, **fields):
        return self.recovery(device, "witness_" + command, **fields)

    def policy(self, witness=None, version="1"):
        witness = witness or self.witness
        return {"protocol_version": "rim-recovery-witness-policy-1",
            "witness_profile": PROFILE, "policy_id": "synthetic-policy",
            "policy_version": version, "scope": self.scope,
            "target": self.member(self.target), "witness": self.member(witness),
            "validation_rules_version": RULES,
            "trust_source_ref": source("synthetic-trust-source"),
            "change_authority_ref": source("synthetic-change-authority"),
            "independence": {"control_domain_id": "independent-w",
                "confirmation_source_ref": source("synthetic-independence-confirmation"),
                "assumption": "honest_uncompromised_not_controlled_by_actor_or_target"}}

    def configure(self, device, *, policy=None, version="1", domains=None):
        raw_policy = json_bytes(policy) if policy is not None else None
        reference = None
        if raw_policy is not None:
            reference = {"policy_id": policy["policy_id"], "policy_version": policy["policy_version"],
                "policy_sha256": sha(b"Rocket-IM/POC/recovery-witness-policy/v1\0"
                    + len(raw_policy).to_bytes(8, "big") + raw_policy)}
        activation = {"protocol_version": "rim-recovery-witness-activation-1",
            "activation_id": "synthetic-activation", "activation_version": version,
            "witness_profile": PROFILE, "scope": self.scope, "target": self.member(self.target),
            "policy_ref": reference, "trusted_authorization_ref": source("synthetic-activation-" + version),
            "activated_at_unix_secs": str(int(time.time())),
            "legacy_uninstalled_target": "deny_first_install", "legacy_installed": "retain_scoped"}
        domains = domains or [
            {"member": self.member(self.actor), "control_domain_id": "actor-domain"},
            {"member": self.member(self.target), "control_domain_id": "target-domain"},
            {"member": self.member(self.witness), "control_domain_id": "independent-w"}]
        domains = sorted(domains, key=lambda item: (
            item["member"]["account_id"], item["member"]["device_id"]))
        config = {"activation_bytes": encoded(json_bytes(activation)),
                  "policy_bytes": encoded(raw_policy) if raw_policy is not None else None,
                  "control_domains": domains}
        raw = json_bytes(config)
        path = self.directory / ("witness-config-" + device + "-" + version + "-" + secrets.token_hex(4) + ".json")
        path.write_bytes(raw)
        path.chmod(0o600)
        self.witness_configs[device] = (path, sha(raw))
        self.case_evidence.setdefault("trusted_configurations", []).append({
            "device": device, "path": str(path), "sha256": sha(raw), "config": config,
            "trust_boundary": "test-only independently pinned local configuration; not deployment approval"})
        return reference

    def activate(self, *, policy=True, devices=None, **options):
        value = self.policy() if policy is True else policy if policy is not False else None
        for device in devices or (*ACCOUNTS, self.target):
            self.policy_ref = self.configure(device, policy=value, **options)
            result = self.witness_command(device, "activate")
            self.case_evidence.setdefault("activations", []).append({"device": device, "result": result})
        self.policy_value = value
        self.relay_witness_config = self.witness_configs[self.target]
        before = database(self)
        self.restart()
        after = database(self)
        for name, table in before["tables"].items():
            if name not in ("meta", "recovery_witness_configs", "recovery_witness_bindings"):
                check(after["tables"][name] == table, "Relay 迁移改写旧表 " + name)
        self.case_evidence.setdefault("relay_w1_migrations", []).append({
            "before": before, "after": after, "old_business_tables_unchanged": True})

    def setup_w1(self, *, policy=True, policy_version="1"):
        self.setup_expired()
        self.case_evidence["messages"] = [{"logical": "before-recovery", "sender": self.actor,
            "direct_receivers": [d for d in ACCOUNTS if d != self.actor],
            "payload_sha256": sha(b"synthetic-first-trust-before-recovery"),
            "packet": self.old_packet, "accepted": self.old_acceptance}]
        for observer in (self.actor, self.target, self.witness):
            for member in (self.actor, self.target, self.witness):
                self.fetch_directory(observer, member, "w1-directory-" + member)
        self.activate(policy=self.policy(version=policy_version) if policy is True else policy)

    def build_intent(self, ident="w1-recovery", actor=None, ttl=120, package_ttl=300):
        actor = actor or self.actor
        proof, _ = self.publish("publish-" + ident, self.target, count=1, ttl=package_ttl)
        package = decode(proof)["action"]["packages"][0]
        pool = self.pool(self.target)
        current = self.recovery(self.target, "inspect")
        floor = {key: current["public_head"][key] for key in ("authorization_version", "crypto_state_ref")}
        accounts = sorted({identity(d)["account_id"] for d in (actor, self.target, self.witness)})
        directories = []
        for account in accounts:
            raw = base64.b64decode(pool["directories"][account]["snapshots"][-1])
            directories.append({"account_id": account, "version": json.loads(raw)["version"], "sha256": sha(raw)})
        now = int(time.time())
        value = {"protocol_version": "rim-recovery-request-2", "witness_profile": PROFILE,
            "policy_ref": self.policy_ref, "kind": "intent", "scope": self.scope,
            "request_id": ident, "signer": self.member(self.target), "nonce": secrets.token_hex(32),
            "change_id": "change-" + ident, "root_admission": self.root,
            "current_admission": current["roots"]["original-add"], "actor": self.member(actor),
            "predecessor": floor, "known_floor": floor, "directory_refs": directories,
            "key_package_sha256": sha(base64.b64decode(package)), "history_policy": "from_recovery",
            "issued_at_unix_secs": str(now), "expires_at_unix_secs": str(now + ttl)}
        return value

    def intent(self, ident="w1-recovery", actor=None, ttl=120, package_ttl=300):
        value = self.build_intent(ident, actor, ttl, package_ttl)
        return self.recovery(self.target, "sign", request=value, intent=None)["proof"]

    def control_proof(self, intent, kind="claim", device=None, ident=None):
        device = device or self.actor
        parsed = decode(intent)
        value = {"protocol_version": "rim-recovery-request-2", "witness_profile": PROFILE,
            "policy_ref": parsed["policy_ref"], "kind": kind, "scope": self.scope,
            "request_id": ident or kind + "-" + parsed["request_id"], "signer": self.member(device),
            "nonce": secrets.token_hex(32), "recovery_id": parsed["request_id"],
            "change_id": parsed["change_id"], "intent_sha256": signed_digest(intent),
            "reason": "cancelled" if kind == "close" else None}
        return self.recovery(device, "sign", request=value, intent=intent)["proof"]

    def accepted(self, ident="w1-recovery", *, install_witness=True, install_actor=True, **options):
        intent, claim, allocated, bundle = self.prepare_recovery(ident, **options)
        accepted = self.accept_recovery(bundle)
        record = accepted["record"]
        raw = base64.b64decode(bundle["change"]["commit_bytes"])
        check(raw[:4] == b"\x00\x01\x00\x02", "合法材料不是正常私有 Commit")
        self.case_evidence["prepared"] = {"intent": intent, "claim": claim, "allocation": allocated,
            "accepted": accepted, "private_commit_sha256": sha(raw)}
        for device in (*ACCOUNTS, self.target):
            material = record if device in (self.actor, self.target) else public_record(record)
            self.recovery(device, "observe", record=material)
        for device in ACCOUNTS:
            if (device == self.witness and not install_witness) or (device == self.actor and not install_actor):
                continue
            self.apply_survivor(device, record)
        return intent, accepted

    def apply_survivor(self, device, record, **options):
        material = record if device == self.actor else public_record(record)
        result = self.recovery(device, "apply", record=material, **options)
        if result and result.get("installed"):
            resume(self, device)
        return result

    def witness_request(self, record, ident="w1-request", ttl="60", **options):
        return self.witness_command(self.target, "request", record=record,
                                    request_id=ident, ttl=ttl, **options)

    def respond(self, record, request, **options):
        return self.witness_command(self.witness, "respond", record=public_record(record),
                                    request=request, **options)

    def install(self, record, request, delivery, **options):
        return self.witness_command(self.target, "apply", record=record,
                                    request=request, delivery=delivery, **options)

    def sign_witness_fixture(self, device, kind, statement):
        check(getattr(self, "probe_binary", None), "有效语义负例需要显式 W1 公共签名夹具")
        previous = self.binary
        before = state(self)
        anchors_before = self.anchor_views()
        try:
            self.binary = self.probe_binary
            result = self.rust(device, "join_recovery_witness_sign_probe",
                               kind=kind, statement_bytes=encoded(json_bytes(statement)))
        finally:
            self.binary = previous
        anchors_after = self.anchor_views()
        self.case_evidence.setdefault("public_signature_fixture", []).append({
            "device": device, "kind": kind, "statement": statement,
            "anchors_before": anchors_before, "anchors_after": anchors_after,
            "result": result, "scope": "public signature preparation only; existing anchor permit may advance;"
                " tested Apply baseline is captured after this preparation; no MLS mutation"})
        check(state(self) == before, "公共签名夹具改变密码或业务快照")
        return result["proof"]

    def anchor_views(self):
        return {device: self.rust(device, "anchor_inspect") for device in sorted(self.configs)}

    def anchor_comparison(self, role):
        """按冻结集合取比较范围；不把所有只读业务重试扩成锚零变化承诺。"""
        definition = self.frozen_definition
        if definition is None:
            return "all", "direct fixture invocation retains strict default"
        refs = definition["expected"]["must_remain_unchanged_set_refs"]
        sets = {ref.rsplit("/", 1)[-1] for ref in refs}
        explicit = {
            "WC08-06-target-after-save-lost-output",
            "WC08-08-replace-before-apply",
            "WC11-02-legacy-target-block-survivor-catchup",
            "WC11-07-authorized-monotonic-revision-then-rollback",
        }
        if "U-APPLY-FAIL" in sets or definition["id"] in explicit:
            return "all", "frozen unchanged set or explicit operation requires all state unchanged"
        if "U-REMOTE" in sets:
            return "other_roles", "U-REMOTE requires other role anchors unchanged"
        return "record_only", "frozen set does not separately require anchor revision equality"

    def unchanged(self, role, label, action, code=None):
        before = state(self)
        anchors_before = self.anchor_views()
        result = action()
        after = state(self)
        anchors_after = self.anchor_views()
        scope, reason = self.anchor_comparison(role)
        event = {"label": label, "result": result, "before": before, "after": after,
                 "anchors_before": anchors_before, "anchors_after": anchors_after,
                 "anchor_comparison_scope": scope, "anchor_comparison_reason": reason}
        self.role_results[role].append(event)
        check(before == after, label + " 改写了有效快照或 Relay 账本")
        device = {"A": self.actor, "W": self.witness, "T": self.target}[role]
        if scope == "all":
            check(anchors_before == anchors_after, label + " 改写了独立锚")
        elif scope == "other_roles":
            check(all(anchors_after[key] == value for key, value in anchors_before.items()
                      if key != device), label + " 改写了其他角色独立锚")
        if code:
            check(result["code"] == code, label + " 错误层不符: " + json.dumps(result, ensure_ascii=False))
        return result

    def reload_diagnostic(self, device, label, operation="join_recovery", **fields):
        """新进程正常入口采样，完整保存实际拒绝；不绕过锚或改写退出码。"""
        if operation == "join_recovery" and not fields:
            fields = {"command": {"kind": "witness_inspect"}}
        before = state(self)
        anchors_before = self.anchor_views()
        process = self.raw_rust(device, operation, **fields)
        parsed = json.loads(process.stdout)
        event = {"label": label, "device": device, "exit_code": process.returncode,
                 "result": parsed, "before": before, "after": state(self),
                 "anchors_before": anchors_before, "anchors_after": self.anchor_views()}
        role = "W" if device == self.witness else "T" if device == self.target else "A"
        self.role_results[role].append(event)
        return event

    def observed(self, role, label, result):
        self.role_results[role].append({"label": label, "result": result, "state": state(self)})
