"""Q05 安全重建装置：真实 MLS/设备签名，独立进程，合成可信控制器。"""

import base64
import copy
import hashlib
import json
from pathlib import Path
import secrets
import time

from .anchor_fixture import AnchorLab, private_json, sha256
from .fixture import ACCOUNTS, SERVICE, check, identity


def decoded(statement):
    return json.loads(base64.b64decode(statement["statement_bytes"]))


def changed_bytes(encoded):
    value = bytearray(base64.b64decode(encoded))
    value[-1] ^= 1
    return base64.b64encode(value).decode()


class RebuildLab(AnchorLab):
    """逻辑别名仅定位目录；真实新设备 ID、身份钥和存储 ID 均独立产生。"""

    def __init__(self, *args):
        super().__init__(*args)
        self.identities = {d: identity(d) for d in ACCOUNTS}
        for alias, account in (("source", "alice"), ("source_twin", "alice"),
                               ("source_peer", "bob"), ("successor", "alice")):
            self.identities[alias] = {"account_id": account,
                                      "device_id": "rebuild_" + secrets.token_hex(16)}
        self.successor_secrets = {}
        self.plan = self.approval = None

    def command(self, device, operation, **fields):
        own = self.identities[device]
        return {"directory": str(self.directory / device), "service": SERVICE,
                "account": own["account_id"], "device": own["device_id"],
                "operation": operation, **fields}

    def member(self, device):
        return {**self.identities[device], "signature_key": self.public[device]["signature_key"]}

    def authorize_pair(self, signer, target):
        now = int(time.time())
        request = {"service": SERVICE, "account": self.identities[signer]["account_id"],
                   "signer_device": self.identities[signer]["device_id"],
                   "new_device": self.identities[target]["device_id"],
                   "new_signature_key": list(base64.b64decode(self.public[target]["signature_key"])),
                   "key_package_sha256": list(hashlib.sha256(base64.b64decode(
                       self.public[target]["key_package"])).digest()),
                   "expected_roster_version": 0, "nonce": list(secrets.token_bytes(32)),
                   "issued_at_unix_secs": now, "expires_at_unix_secs": now + 120}
        proof = self.rust(signer, "sign_authorization", request=request)["authorization"]
        self.rust(signer, "authorize", authorization=proof,
                  key_package=self.public[target]["key_package"], now_unix_secs=now)

    def initialize(self, **options):
        super().initialize(permissions=True)
        self.old_checkpoint = copy.deepcopy(self.checkpoint)
        self.old_inspect = self.rust("a1", "inspect")
        self.old_wire = self.rust("a1", "wire_inspect")
        group = ("source", "source_twin", "source_peer")
        for device in group:
            self.public[device] = self.rust(device, "init")
        self.authorize_pair("source", "source_twin")
        self.authorize_pair("source_twin", "source")
        peers = [{"account": self.identities[d]["account_id"],
                  "device": self.identities[d]["device_id"],
                  "signature_key": self.public[d]["signature_key"],
                  "key_package": self.public[d]["key_package"]} for d in group[1:]]
        created = self.rust("source", "create", peers=peers)
        pins = [{"account": self.identities[d]["account_id"],
                 "device": self.identities[d]["device_id"],
                 "signature_key": self.public[d]["signature_key"]} for d in group]
        for device in group[1:]:
            self.rust(device, "join", welcome=created["welcome"], pins=pins)
        refs = []
        for device in group:
            self.rust(device, "wire_configure", conversation_id="G2", authorization_version="1")
            refs.append(self.rust(device, "wire_inspect")["crypto_state_ref"])
        check(len(set(refs)) == 1 and refs[0] != self.old_checkpoint["crypto_state_ref"],
              "新通信范围没有独立真实 MLS 状态")
        checkpoint = {"service_id": SERVICE, "conversation_id": "G2", "authorization_version": "1",
                      "crypto_state_ref": refs[0], "owner_account_id": "alice",
                      "members": sorted((self.member(d) for d in group),
                                        key=lambda m: (m["account_id"], m["device_id"]))}
        for device in group:
            self.rust(device, "permission_bootstrap", checkpoint=checkpoint,
                      relay_receipt_key=self.relay_receipt_key)
        check(self.rust("source", "inspect")["group_id"] != self.old_inspect["group_id"],
              "新通信群错误复用了旧群 ID")
        self.trust = {"authorizer": self.member("source"), "checkpoint": checkpoint,
                      "relay_receipt_key": self.relay_receipt_key}
        self.enable("source")
        self.evidence["communication_scopes"] = {"old": "G1", "new": "G2", "distinct_mls_group": True}

    def enable(self, device="a1", *, rebuild_trust=None):
        trusted = self.directory / ("trusted-" + device)
        trusted.mkdir(mode=0o700)
        authority = self.directory / ("authority-" + device)
        own = self.identities[device]
        scope = {"service": SERVICE, "account": own["account_id"], "device": own["device_id"],
                 "identity_key": base64.b64decode(self.public[device]["signature_key"]).hex(),
                 "store_id": secrets.token_hex(32)}
        seed = secrets.token_hex(32)
        client_key = self.anchor({"op": "public_key", "seed": seed})["public_key"]
        bootstrap = {"op": "init", "directory": str(authority), "scope": scope,
                     "client_public_key": client_key, "anchor_seed": secrets.token_hex(32),
                     "head": sha256(self.snapshot(device))}
        if rebuild_trust is not None:
            bootstrap["rebuild_trust"] = rebuild_trust
        initialized = self.anchor(bootstrap)
        config = {"protocol_version": "rim-rollback-client-1", "scope": scope,
                  "anchor_public_key": initialized["anchor_public_key"], "client_seed": seed,
                  "journal_key": secrets.token_hex(32), "helper_path": str(self.helper),
                  "anchor_directory": str(authority)}
        if rebuild_trust is not None:
            config["rebuild_trust"] = rebuild_trust
        path = trusted / "config.json"
        private_json(path, config)
        self.configs[device] = path
        self.materials[device] = {"config": config, "bootstrap": bootstrap,
                                  "authority": authority, "trusted": trusted}

    def unresolved(self, *, point="after_reserve", code=86, trust=True):
        self.enable(rebuild_trust=self.trust if trust else None)
        self.old_backup = self.backup("old-before-unresolved", self.directory / "a1")
        self.old_state = self.snapshot().read_bytes()
        self.rust("a1", "wire_send", logical_message_id="unresolved", attempt_id="P1",
                  payload="synthetic-anchor-unresolved", expected_exit=code,
                  env={"RIM_ANCHOR_FAILPOINT": point})
        self.old_fact = self.rust("a1", "anchor_inspect")
        return self.old_fact

    def template(self, alias="successor"):
        own = self.identities[alias]
        seed = secrets.token_hex(32)
        client_public = self.anchor({"op": "public_key", "seed": seed})["public_key"]
        self.successor_secrets[alias] = {"client_seed": seed, "journal_key": secrets.token_hex(32)}
        fact = self.old_fact.get("anchor", self.old_fact)
        return {"protocol_version": "rim-anchor-rebuild-1", "rebuild_id": secrets.token_hex(32),
                "old_scope": self.materials["a1"]["config"]["scope"],
                "old_head": fact["anchor_head"], "old_txn": fact["active_txn"],
                "old_revision": fact["revision"],
                "old_conversation_id": "G1", "old_group_id": self.old_inspect["group_id"],
                "anchor_public_key": self.materials["a1"]["config"]["anchor_public_key"],
                "successor_scope": {"service": SERVICE, "account": own["account_id"],
                                    "device": own["device_id"], "identity_key": "0" * 64,
                                    "store_id": secrets.token_hex(32)},
                "successor_head": "0" * 64, "successor_client_public_key": client_public,
                "key_package_sha256": "0" * 64, "trust": copy.deepcopy(self.trust)}

    def offer(self, alias="successor", *, template=None, **options):
        result = self.rust(alias, "rebuild_init", template=template or self.template(alias), **options)
        if result is not None:
            self.public[alias], self.plan = result["identity"], result["plan"]
        return result

    def approve(self, plan=None, **options):
        chosen = plan or self.plan
        result = self.rust("source", "rebuild_approve", plan=chosen, **options)
        if result is not None:
            self.approval = result["approval"]
        return result

    def link(self, plan=None, approval=None, alias="successor", **options):
        return self.rust("a1", "anchor_rebuild", plan=plan or self.plan,
                         approval=approval or self.approval,
                         successor_directory=str(self.directory / alias), **options)

    def configure_successor(self, alias="successor", plan=None):
        chosen = plan or self.plan
        trusted = self.directory / ("trusted-" + alias)
        trusted.mkdir(mode=0o700, exist_ok=True)
        config = {"protocol_version": "rim-rollback-client-1", "scope": chosen["successor_scope"],
                  "anchor_public_key": chosen["anchor_public_key"],
                  **self.successor_secrets[alias], "helper_path": str(self.helper),
                  "anchor_directory": str(self.materials["a1"]["authority"]),
                  "rebuild_trust": chosen["trust"]}
        path = trusted / "config.json"
        private_json(path, config)
        self.configs[alias] = path
        self.materials[alias] = {"config": config, "trusted": trusted,
                                 "authority": self.materials["a1"]["authority"]}

    def accepted(self, proof):
        statement = decoded(proof)
        digest = hashlib.sha256(b"Rocket-IM/POC/permission-proof/v1\0")
        for field in ("statement_bytes", "signature_bytes", "commit_bytes"):
            value = base64.b64decode(proof[field])
            digest.update(len(value).to_bytes(8, "big")); digest.update(value)
        receipt = {"protocol_version": "rim-permission-receipt-1", "service_id": SERVICE,
                   "conversation_id": statement["conversation_id"], "actor": statement["actor"],
                   "change_id": statement["change_id"], "proof_sha256": digest.hexdigest(),
                   "outcome": "accepted", "authorization_version": statement["authorization_version"],
                   "crypto_state_ref": statement["to_state_ref"]}
        signed = self.relay_key("sign", expected_signature_key=self.relay_receipt_key,
                                statement=receipt)["receipt"]
        return {"change": proof, "receipt": signed}

    def message_receipt(self, packet, acceptance_id):
        envelope = packet["envelope"]
        header = json.loads(base64.b64decode(envelope["header_bytes"]))
        digest = hashlib.sha256(b"Rocket-IM/POC/message-envelope/v1\0")
        for field in ("header_bytes", "payload_bytes"):
            raw = base64.b64decode(envelope[field])
            digest.update(len(raw).to_bytes(8, "big")); digest.update(raw)
        statement = {"protocol_version": "rim-message-acceptance-1", "service_id": SERVICE,
                     "conversation_id": header["conversation_id"], "acceptance_id": acceptance_id,
                     "envelope_sha256": digest.hexdigest(),
                     "authorization_version": header["authorization_version"],
                     "crypto_state_ref": header["crypto_state_ref"]}
        return self.relay_key("sign", expected_signature_key=self.relay_receipt_key,
                              statement=statement)["receipt"]

    def joining(self, alias="successor"):
        self.rust(alias, "permission_device_join_anchor", **{
            "checkpoint": self.trust["checkpoint"], "relay_receipt_key": self.relay_receipt_key})
        candidate = self.rust("source", "permission_prepare_device", change_id="rebuild_join",
                              member=self.member(alias), key_package=self.public[alias]["key_package"],
                              history_policy="from_join")
        record = self.accepted(candidate["change"])
        for device in ("source", "source_twin", "source_peer"):
            self.rust(device, "permission_recover", record=record)
        self.bundle = {"record": record, "join": candidate["join"]}
        return self.bundle

    def complete(self):
        self.unresolved(); self.offer(); self.approve(); self.link(); self.configure_successor()
        self.rust("successor", "permission_join", **self.joining())

    def communicate(self, name="rebuilt", sender="successor", receiver="source"):
        packet = self.rust(sender, "wire_send", logical_message_id=name, attempt_id="P1",
                           payload="synthetic-rebuild-" + name)
        received = self.rust(receiver, "wire_receive", **packet["envelope"])
        check(received["payload_sha256"] == hashlib.sha256(("synthetic-rebuild-" + name).encode()).hexdigest(),
              "重建后真实 MLS 解密正文摘要不同")
        return packet
