"""原生独立锚实验的有界进程与合成身份；配置和 authority 不属于设备备份。"""

import base64
import json
import os
import shutil
import subprocess

from crypto_support import (CryptoProbe, committed as crypto_committed, digest,
                            execute as crypto_execute, failure, metrics,
                            redact as crypto_redact, send_action, success)
from support import Probe, require, sha, utc_now, write_json

SECRETS = {"seed", "client_seed", "anchor_seed", "provider", "provider_blob", "text"}


def redact(value):
    if isinstance(value, dict):
        return {key: digest(item) if key in SECRETS and isinstance(item, (str, bytes))
                else redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return crypto_redact(value)


class AnchorProbe(Probe):
    def __init__(self, binary, database, config, output, commands, failpoint=None, **options):
        previous = os.environ.get("RIM_AUTHORITY_FAILPOINT")
        try:
            if failpoint is not None:
                os.environ["RIM_AUTHORITY_FAILPOINT"] = failpoint
            super().__init__(binary, database, output, commands, service=str(config),
                             account="--test-mode", timeout=100, **options)
        finally:
            if previous is None:
                os.environ.pop("RIM_AUTHORITY_FAILPOINT", None)
            else:
                os.environ["RIM_AUTHORITY_FAILPOINT"] = previous

    def record(self, direction, payload):
        super().record(direction, redact(payload))


def execute(probe, request_id, action, fault="none", anchor_fault="none"):
    return probe.request("execute", request={"request_id": request_id, "action": action,
                                              "fault": fault}, anchor_fault=anchor_fault)


def download(probe, records, fault="none", anchor_fault="none"):
    return probe.request("download", request={"records": records, "fault": fault},
                         anchor_fault=anchor_fault)


def process(probe, sequence=1, request_id="process-one", fault="none", anchor_fault="none"):
    return probe.request("process", sequence=str(sequence), request_id=request_id,
                         fault=fault, anchor_fault=anchor_fault)


def status(probe, reason=None):
    response = probe.request("status")
    value = success(response)
    metrics(response)
    require(response["events"] == [], "状态检查发布了成功事件")
    require(value["assurance"] == "synthetic_local", "本机 authority 被当作独立生产信任")
    require(value["reason"] == reason, f"锚状态不符：{value}")
    if reason is None:
        require(value["local_head"] == value["remote_head"], "健康状态下本地和锚 head 不符")
        require(value["local_pending"] is False and value["remote_pending"] is None,
                "健康状态仍有未决预约")
    return value


def snapshot(probe):
    response = probe.request("inspect")
    result = success(response)
    metrics(response)
    require(response["events"] == [], "摘要查询发布了提交事件")
    value = result["snapshot"]
    require("provider" not in value and "provider_blob" not in value, "摘要泄露 provider")
    return value


def rejected(response, code=None):
    error = failure(response, code=code, paused=True)
    metrics(response)
    return error


def recover(probe, kind):
    response = probe.request("recover")
    value = success(response)
    metrics(response)
    require(response["events"] == [], "恢复重发了数据成功事件")
    require(value["kind"] == kind, "恢复结果类型不符")
    status(probe)
    return value["value"]


class Fixture:
    def __init__(self, binaries, directory, commands):
        self.binary, self.native, self.helper = binaries
        self.directory, self.commands = directory, commands
        self.device = directory / "device"
        self.trusted = directory / "trusted"
        self.device.mkdir(mode=0o700)
        self.trusted.mkdir(mode=0o700)
        self.database = self.device / "state.db"
        self.config_path = self.trusted / "config.json"
        self.authority = self.trusted / "authority"
        self.scope = {"service": "local-service", "account": "alice", "device": "alice-device"}
        self.client_seed, self.anchor_seed = os.urandom(32).hex(), os.urandom(32).hex()

    def command(self, args, request=None, expected=0):
        """只接受少量引导请求；秘密走 stdin，并在任何日志落盘前摘要。"""
        encoded = json.dumps(request).encode() if request is not None else None
        response = subprocess.run([str(arg) for arg in args], input=encoded,
                                  capture_output=True, timeout=15, check=False)
        require(len(response.stdout) + len(response.stderr) <= 1024 * 1024, "引导进程输出超过上限")
        value = json.loads(response.stdout) if response.stdout.strip() else None
        entry = {"at": utc_now(), "direction": "oneshot", "payload": {
            "args": [str(arg) for arg in args], "request": redact(request),
            "response": redact(value), "returncode": response.returncode,
            "stderr": digest(response.stderr)}}
        self.commands.append(entry)
        require(response.returncode == expected, f"引导进程退出码不符：{redact(value)}")
        return value

    def helper_call(self, **request):
        value = self.command([self.helper], request)
        require(value.get("ok") is True, f"helper 请求失败：{redact(value)}")
        return value

    def bootstrap(self, bind=True):
        with CryptoProbe(self.native, self.database, self.directory, self.commands,
                         flags=("--create", "--test-mode")) as client:
            self.identity = crypto_committed(crypto_execute(client, "initialize", {"op": "initialize"}),
                                             "initialize")
        self.scope.update(identity_key=base64.b64decode(self.identity["identityKey"], validate=True).hex(),
                          store_id=os.urandom(32).hex())
        anchor_key = self.helper_call(op="public_key", seed=self.anchor_seed)["public_key"]
        self.client_key = self.helper_call(op="public_key", seed=self.client_seed)["public_key"]
        self.config = {"program": str(self.helper), "directory": str(self.authority),
                       "scope": self.scope, "anchor_public_key": anchor_key,
                       "client_seed": self.client_seed}
        self.write_config()
        if bind:
            self.bind()

    def write_config(self, config=None, path=None):
        path = path or self.config_path
        write_json(path, self.config if config is None else config)
        path.chmod(0o600)
        return path

    def bind(self):
        binding = self.command([self.binary, self.database, self.config_path, "--bind"])
        require(binding.get("ok") is True, f"显式绑定失败：{binding}")
        self.binding = binding["result"]
        self.helper_call(op="init", directory=str(self.authority), scope=self.scope,
                         client_public_key=self.client_key, anchor_seed=self.anchor_seed,
                         head=self.binding["head"])

    def probe(self, **options):
        return AnchorProbe(self.binary, self.database, options.pop("config", self.config_path),
                           self.directory, self.commands, **options)

    def peer(self):
        return CryptoProbe(self.native, self.directory / "unused-peer.db", self.directory,
                           self.commands, account="bob", device="bob-device",
                           flags=("--memory-peer", "--test-mode"))

    def setup(self, client, peer, records=2):
        peer_identity = success(peer.request("peer_identity"))
        self.group = {"op": "create_group", "conversation": "synthetic-conversation", "peer": peer_identity}
        welcome = crypto_committed(execute(client, "create-group", self.group), "create_group")
        success(peer.request("peer_join", conversation=self.group["conversation"], peer=self.identity,
                             welcome=welcome["welcome"]))
        items, texts = [], []
        for number in range(1, records + 1):
            text = f"原生独立锚合成消息🙂\u0000{number}"
            envelope = success(peer.request("peer_send", message_id=f"message-{number}", text=text))
            items.append({"sequence": str(number), "envelope": envelope})
            texts.append(text)
        return {"records": items, "texts": texts, "snapshot": snapshot(client), "anchor": status(client)}

    def save_closed(self, name="device-before.db"):
        destination = self.directory / name
        shutil.copyfile(self.database, destination)
        destination.chmod(0o600)
        return destination

    def restore_closed(self, source):
        shutil.copyfile(source, self.database)
        self.database.chmod(0o600)
        require(sha(source) == sha(self.database), "完整已关闭数据库恢复摘要不符")

    def blocked(self, client, records):
        requests = [execute(client, "initialize", {"op": "initialize"}),
                    execute(client, "blocked-send", send_action()),
                    download(client, records), process(client), client.request("received", sequence="1")]
        return [rejected(response) for response in requests]
