"""原生安全重建的合成来源、真实 MLS 材料和有界进程装置。"""

import base64
import hashlib
import json
import os
import shutil

from anchor_support import AnchorProbe, Fixture, execute, redact, send_action
from crypto_support import CryptoProbe, execute as crypto_execute, failure, success
from support import Probe, require, sha


def metrics(response, news=0, restores=0, sends=0, receives=0, joins=0):
    actual = response.get("metrics")
    expected = {"provider_news": news, "provider_restores": restores,
                "candidate_sends": sends, "candidate_receives": receives}
    # 旧响应保持四字段协议；新增 join 计数若省略，只接受本次确实不执行 join。
    if isinstance(actual, dict) and "candidate_joins" in actual:
        expected["candidate_joins"] = joins
    else:
        require(joins == 0, "真实加入缺少 candidate_joins 计数")
    require(actual == expected, f"密码调用计数不符：{actual}，预期 {expected}")


def committed(response, kind, cached=False):
    result = success(response)
    require(result["kind"] == kind and result["cached"] is cached, "提交种类或缓存不匹配")
    if cached:
        metrics(response)
        require(response["events"] == [], "缓存重复派发成功事件")
    else:
        metrics(response, news=int(kind == "initialize"), restores=int(kind != "initialize"),
                sends=int(kind == "send"), receives=int(kind == "receive"))
        require(len(response["events"]) == 1, "新提交没有唯一成功事件")
        require(response["events"][0]["revision"] == result["revision"], "事件不是已提交版本")
        require(response["trace"][-1] == "COMMIT", "成功通知未位于事务提交之后")
    return result["value"]


def rejected(response, code=None, measured=False):
    error = failure(response, code=code, paused=True)
    if not measured:
        metrics(response)
    return error


def plan_digest(plan):
    # JSON 字段序必须与 helper Plan/Scope/Checkpoint 类型声明一致。
    scope_fields = ("service", "account", "device", "identity_key", "store_id")
    member_fields = ("account_id", "device_id", "signature_key")
    checkpoint_fields = ("service_id", "conversation_id", "authorization_version",
                         "crypto_state_ref", "owner_account_id", "members")
    fields = ("protocol_version", "rebuild_id", "old_scope", "old_head", "old_txn",
              "old_revision", "old_conversation_id", "old_group_id", "anchor_public_key",
              "successor_scope", "successor_head", "successor_client_public_key",
              "key_package_sha256", "trust")
    canonical = {field: plan[field] for field in fields}
    for field in ("old_scope", "successor_scope"):
        canonical[field] = {key: plan[field][key] for key in scope_fields}
    trust = plan["trust"]
    checkpoint = {field: trust["checkpoint"][field] for field in checkpoint_fields}
    checkpoint["members"] = [{key: item[key] for key in member_fields}
                             for item in checkpoint["members"]]
    canonical["trust"] = {"authorizer": {key: trust["authorizer"][key] for key in member_fields},
                          "checkpoint": checkpoint, "relay_receipt_key": trust["relay_receipt_key"]}
    return hashlib.sha256(json.dumps(canonical, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


class NativeFixture(Fixture):
    def __init__(self, binaries, directory, commands, device):
        directory.mkdir(mode=0o700)
        super().__init__(binaries[:3], directory, commands)
        self.scope["device"] = device

    def bootstrap(self, bind=True):
        with CryptoProbe(self.native, self.database, self.directory, self.commands,
                         device=self.scope["device"], flags=("--create", "--test-mode")) as probe:
            self.identity = committed(crypto_execute(probe, "initialize", {"op": "initialize"}), "initialize")
        self.scope.update(identity_key=base64.b64decode(self.identity["identityKey"], validate=True).hex(),
                          store_id=os.urandom(32).hex())
        self.client_key = self.helper_call(op="public_key", seed=self.client_seed)["public_key"]
        anchor_key = self.helper_call(op="public_key", seed=self.anchor_seed)["public_key"]
        self.config = {"program": str(self.helper), "directory": str(self.authority),
                       "scope": self.scope, "anchor_public_key": anchor_key,
                       "client_seed": self.client_seed}
        self.write_config()
        if bind:
            self.bind()

    def bind(self):
        binding = self.command([self.binary, self.database, self.config_path, "--bind"])
        require(binding["ok"], "显式绑定失败")
        self.binding = binding["result"]
        request = {"op": "init", "directory": str(self.authority), "scope": self.scope,
                   "client_public_key": self.client_key, "anchor_seed": self.anchor_seed,
                   "head": self.binding["head"]}
        if "rebuild_trust" in self.config:
            request["rebuild_trust"] = self.config["rebuild_trust"]
        self.helper_call(**request)

    def group(self, conversation, history=False):
        with self.peer() as peer, self.probe() as client:
            peer_identity = success(peer.request("peer_identity"))
            material = committed(execute(client, "create-group", {"op": "create_group",
                                  "conversation": conversation, "peer": peer_identity}), "create_group")
            success(peer.request("peer_join", conversation=conversation, peer=self.identity,
                                 welcome=material["welcome"]))
            if history:
                incoming = success(peer.request("peer_send", message_id="old-existing-incoming", text="旧范围已提交历史"))
                downloaded = client.request("download", request={"records": [{"sequence": "1", "envelope": incoming}], "fault": "none"})
                downloaded_value = success(downloaded)
                metrics(downloaded)
                require(downloaded_value["download_cursor"] == "1" and downloaded_value["processed_cursor"] == "0", "旧原始下载未单独持久化")
                processed = committed(client.request("process", request_id="old-existing-process", sequence="1",
                                      fault="none", anchor_fault="none"), "receive")
                require(processed["message"]["text"] == "旧范围已提交历史", "旧消息未实际解密提交")
                outgoing = committed(execute(client, "old-existing-send", send_action(
                    "old-existing-attempt", "old-existing-outgoing", "旧范围已提交待发")), "send")
                require(success(peer.request("peer_receive", envelope=outgoing))["text"] == "旧范围已提交待发", "旧待发密文不能解密")
                snapshot = success(client.request("inspect"))["snapshot"]
                require(len(snapshot["inbox"]) == len(snapshot["outbox"]) == len(snapshot["downloads"]) == 1
                        and snapshot["download_cursor"] == snapshot["processed_cursor"] == "1", "旧历史与双游标不是非空基线")
                return {"incoming": incoming, "outgoing": outgoing, "snapshot": snapshot}
        return None

    def anchor_fact(self):
        request = {"protocol_version": "rim-rollback-anchor-1", "scope": self.scope,
                   "challenge": os.urandom(32).hex(), "action": "inspect", "expected_revision": "0",
                   "txn": os.urandom(32).hex(), "head": "absent", "target": "absent"}
        signed = self.helper_call(op="sign_request", seed=self.client_seed, request=request)["request"]
        reply = self.helper_call(op="request", directory=str(self.authority), request=signed)["response"]
        value = json.loads(base64.b64decode(reply["statement_bytes"], validate=True))
        return {key: value.get(key) for key in ("scope", "head", "revision", "active_txn", "closure")}


class RebuildProbe(Probe):
    def __init__(self, fixture, candidate=None, device="alice-successor", **options):
        super().__init__(fixture.rebuild_binary, fixture.old.database, fixture.directory,
                         fixture.commands, service=str(fixture.old.config_path),
                         account=str(candidate or fixture.candidate), flags=(device, "--test-mode"),
                         timeout=100, **options)

    def record(self, direction, payload):
        super().record(direction, redact(payload))


class RebuildFixture:
    def __init__(self, binaries, directory, commands):
        self.directory, self.commands = directory, commands
        self.rebuild_binary = binaries[3]
        self.old = NativeFixture(binaries, directory / "old", commands, "alice-old")
        self.source = NativeFixture(binaries, directory / "source", commands, "alice-source")
        self.candidate = directory / "successor.db"

    def bootstrap(self, unresolved=True, trust=True):
        self.source.bootstrap()
        self.source.group("new-target")
        with self.source.probe() as source:
            response = source.request("rebuild_checkpoint")
            observed = success(response)
            metrics(response, restores=1)
            require(response["events"] == [], "公共检查点查询发布成功事件")
            # 使用真正的 MLS 密文测试门禁，避免空批次或格式错误先于门禁返回。
            self.gate_envelope = committed(execute(source, "gate-envelope", send_action(
                "gate-attempt", "gate-message", "仅用于批准门禁的合成消息")), "send")
        source_member = {"account_id": self.source.identity["account"],
                         "device_id": self.source.identity["device"],
                         "signature_key": self.source.identity["identityKey"]}
        self.trust = {"authorizer": source_member, "checkpoint": observed["checkpoint"],
                      "relay_receipt_key": base64.b64encode(bytes.fromhex(self.source.client_key)).decode()}
        require(source_member in self.trust["checkpoint"]["members"], "固定批准者不在实际群成员中")
        require(len(self.trust["checkpoint"]["members"]) == 2, "初始目标群不是真实两成员")
        self.old.bootstrap(bind=False)
        if trust:
            self.old.config["rebuild_trust"] = self.trust
            self.old.write_config()
        self.old.bind()
        self.old_history = self.old.group("old-target", history=True)
        if unresolved:
            self.interrupt_old("pause_after_crypto", "after_crypto", crypto=True)

    def interrupt_old(self, fault, checkpoint, crypto=False):
        with self.old.probe() as old:
            old.send({"op": "execute", "request": {"request_id": "uncertain-old-send",
                      "action": send_action("old-attempt", "old-message"), "fault": fault if crypto else "none"},
                      "anchor_fault": "none" if crypto else fault})
            self.old_marker = old.checkpoint(checkpoint)
            if crypto:
                metrics(self.old_marker, restores=1, sends=1)
            old.crash()
        with self.old.probe() as old:
            self.old_snapshot = success(old.request("inspect"))["snapshot"]
            if crypto:
                require(self.old_snapshot["pending"] is not None, "旧密码计算中断没有保留真实预约")
                require(self.old_snapshot["inbox"] and self.old_snapshot["outbox"]
                        and self.old_snapshot["download_cursor"] == self.old_snapshot["processed_cursor"] == "1",
                        "未决旧状态丢失已提交历史或双游标")
        self.original = self.old.save_closed("preserved-original.db")
        self.original_hash = sha(self.original)
        self.old_fact = self.old.anchor_fact()

    def probe(self, **options):
        return RebuildProbe(self, **options)

    def prepare(self, probe, fault="none"):
        response = probe.request("prepare", fault=fault)
        result = success(response)
        require(result["stage"] in ("planned", "active", "linked", "joined"), "候选阶段不明确")
        plan, identity = result["plan"], result["identity"]
        require(plan["successor_scope"]["identity_key"] == base64.b64decode(identity["identityKey"]).hex(), "新公钥不属于固定计划")
        require(plan["key_package_sha256"] == hashlib.sha256(base64.b64decode(identity["keyPackage"])).hexdigest(), "KeyPackage不属于固定计划")
        return result

    def approve(self, prepared, source=None, fault="none", anchor_fault="none", cached=False):
        def call(client):
            reply = client.request("rebuild_approve", plan=prepared["plan"], peer=prepared["identity"],
                                   confirm_plan_sha256=plan_digest(prepared["plan"]),
                                   fault=fault, anchor_fault=anchor_fault)
            return committed(reply, "rebuild_add", cached=cached)
        if source is not None:
            return call(source)
        with self.source.probe() as client:
            return call(client)

    def activate(self, probe, material, fault="none"):
        response = probe.request("activate", material=material, fault=fault)
        value = success(response)
        require(value["stage"] == "active", "加入成功却未激活")
        return response

    def old_preserved(self):
        require(sha(self.original) == self.original_hash, "保存的旧数据库原件被改写")
        fact = self.old.anchor_fact()
        require({key: fact[key] for key in self.old_fact if key != "closure"}
                == {key: value for key, value in self.old_fact.items() if key != "closure"},
                "重建清除或修改原锚预约、head或修订号")
        with self.old.probe() as old:
            rejected(execute(old, "blocked-old", send_action()))
            rejected(old.request("recover"))
        return {"original_sha256": self.original_hash, "old_anchor_fact": fact}

    def bidirectional(self, candidate, source):
        one = committed(execute(source, "source-new-send", send_action("source-new", "source-new", "批准后的源消息")), "send")
        first = committed(execute(candidate, "successor-receive", {"op": "receive", "sequence": "1", "envelope": one}), "receive")
        require(first["message"]["text"] == "批准后的源消息", "新设备未解密来源新消息")
        two = committed(execute(candidate, "successor-new-send", send_action("successor-new", "successor-new", "批准后的后继消息")), "send")
        second = committed(execute(source, "source-receive", {"op": "receive", "sequence": "1", "envelope": two}), "receive")
        require(second["message"]["text"] == "批准后的后继消息", "来源未解密后继新消息")
        return {"source_ciphertext_sha256": hashlib.sha256(base64.b64decode(one["ciphertext"])).hexdigest(),
                "successor_ciphertext_sha256": hashlib.sha256(base64.b64decode(two["ciphertext"])).hexdigest()}


def save_database(path, target):
    shutil.copyfile(path, target)
    target.chmod(0o600)
    require(sha(path) == sha(target), "关闭数据库副本摘要不一致")
    return sha(target)
