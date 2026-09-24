"""受保护原生实验装置；秘密只留在内存与有界 stdin，locator 是公开数据。"""

import base64
import json
import os
from pathlib import Path
import secrets
import selectors
import subprocess
import time
import uuid

from anchor_support import AnchorProbe as PlainAnchorProbe, Fixture as AnchorFixture
from anchor_support import SECRETS as ANCHOR_SECRETS
from crypto_support import CryptoProbe as PlainCryptoProbe, digest, execute as crypto_execute
from rebuild_support import NativeFixture as PlainNativeFixture
from rebuild_support import RebuildFixture as PlainRebuildFixture, committed
from support import Probe, kill_and_reap, require, utc_now, write_json

LOCATOR_FIELDS = {"keychain", "item", "service", "account", "device"}
SECRETS = ANCHOR_SECRETS | {
    "password", "key", "db_key", "storage_key", "trust_key", "key_bytes",
    "raw_key", "new_key", "old_key", "secret", "config_json",
}


def redact(value):
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key in SECRETS or (key == "value" and value.get("op") == "key_tamper"):
                encoded = item if isinstance(item, (str, bytes)) else json.dumps(item)
                result[key] = digest(encoded)
            else:
                result[key] = redact(item)
        return result
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    return value


class CryptoProbe(PlainCryptoProbe):
    def record(self, direction, payload):
        Probe.record(self, direction, redact(payload))


class AnchorProbe(PlainAnchorProbe):
    def __init__(self, *args, flags=(), **options):
        super().__init__(*args, flags=(*flags, "--protected"), **options)

    def record(self, direction, payload):
        Probe.record(self, direction, redact(payload))


class Fixture(PlainNativeFixture):
    def __init__(self, binaries, directory, commands, device="alice-device"):
        directory = Path(directory)
        directory.mkdir(mode=0o700, exist_ok=True)
        # 复用原初始化，允许调用者已创建当前场景目录。
        AnchorFixture.__init__(self, binaries[:3], directory, commands)
        self.protection = binaries[4]
        self.scope["device"] = device
        self.keychain = (self.trusted / f"lab-{uuid.uuid4()}.keychain-db").resolve()
        self._keychain_password = secrets.token_hex(32)
        self.locator = self.new_locator(device)
        self.write_config()
        self.ctl("keychain_create")

    def new_locator(self, device):
        return {"keychain": str(self.keychain), "item": f"lab-{uuid.uuid4()}",
                "service": self.scope["service"], "account": self.scope["account"],
                "device": device}

    def command(self, args, request=None, expected=0, timeout=15, limit=1024 * 1024):
        """写入完整 JSON 行；同时限制读写、总输出和进程组存活时间。"""
        encoded = (json.dumps(request, ensure_ascii=False, separators=(",", ":"))
                   + "\n").encode() if request is not None else b""
        require(len(encoded) <= 262144, "引导请求超过上限")
        payload = {"args": [str(arg) for arg in args], "request": redact(request)}
        entry = {"at": utc_now(), "direction": "oneshot", "pid": None, "payload": payload}
        self.commands.append(entry)
        selector = selectors.DefaultSelector()
        process = None
        outputs = {"stdout": bytearray(), "stderr": bytearray()}
        total, deadline = 0, time.monotonic() + timeout
        try:
            process = subprocess.Popen(payload["args"], stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       bufsize=0, start_new_session=True)
            entry["pid"] = process.pid
            for name in outputs:
                stream = getattr(process, name)
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            if encoded:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
            else:
                process.stdin.close()
            while selector.get_map():
                require(time.monotonic() < deadline, "引导进程超时")
                for key, _ in selector.select(min(0.2, max(0, deadline - time.monotonic()))):
                    if key.data == "stdin":
                        try:
                            encoded = encoded[os.write(key.fd, encoded[:65536]):]
                        except BlockingIOError:
                            continue
                        if not encoded:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                        continue
                    try:
                        data = os.read(key.fd, 65536)
                    except BlockingIOError:
                        continue
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(data)
                    require(total <= limit, "引导进程输出超过上限")
                    outputs[key.data].extend(data)
            actual = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            raw = bytes(outputs["stdout"])
            value = json.loads(raw) if raw.strip() else None
            require(isinstance(value, dict), "引导进程未返回 JSON 对象")
            payload["response"] = redact(value)
            require(actual == expected, f"引导进程退出码 {actual}，预期 {expected}")
            return value
        except Exception as error:
            payload["error"] = type(error).__name__
            raise
        finally:
            actual = kill_and_reap(process) if process is not None else None
            payload.update(returncode=actual, reaped=process is not None, output_bytes=total,
                           stdout_sha256=digest(bytes(outputs["stdout"])),
                           stderr=digest(bytes(outputs["stderr"])), finished_at=utc_now())
            selector.close()
            if process is not None:
                for stream in (process.stdin, process.stdout, process.stderr):
                    stream.close()

    def ctl(self, op, expected=0, **fields):
        if op in {"keychain_create", "keychain_lock", "keychain_unlock"}:
            request = {"op": op, "path": str(self.keychain),
                       "password": self._keychain_password, **fields}
        else:
            request = {"op": op, "db": str(self.database),
                       "locator": json.dumps(self.locator), "trust": False, **fields}
        value = self.command([self.protection, "--test-mode"], request, expected=expected)
        if expected == 0:
            require(value.get("ok") is True, f"保护控制请求失败：{redact(value)}")
        return value

    def write_config(self, config=None, path=None):
        """仅写公开 locator；完整 Config 和 client_seed 不能通过此入口落盘。"""
        value = self.locator if config is None else config
        require(isinstance(value, dict) and set(value) == LOCATOR_FIELDS,
                "公开配置文件只允许 locator 字段")
        require(all(isinstance(item, str) for item in value.values()), "locator 字段必须是文本")
        target = Path(path) if path is not None else self.config_path
        write_json(target, value)
        target.chmod(0o600)
        return target

    def bootstrap(self, bind=True):
        with CryptoProbe(self.native, self.database, self.directory, self.commands,
                         service=self.scope["service"], account=self.scope["account"],
                         device=self.scope["device"], flags=("--create", "--test-mode",
                         "--protected", str(self.config_path))) as probe:
            self.identity = committed(crypto_execute(probe, "initialize", {"op": "initialize"}),
                                      "initialize")
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
        binding = self.command([self.binary, self.database, self.config_path,
                                "--protected", "--bind"], self.config)
        require(binding.get("ok") is True, "受保护显式绑定失败")
        self.binding = binding["result"]
        request = {"op": "init", "directory": str(self.authority), "scope": self.scope,
                   "client_public_key": self.client_key, "anchor_seed": self.anchor_seed,
                   "head": self.binding["head"]}
        if "rebuild_trust" in self.config:
            request["rebuild_trust"] = self.config["rebuild_trust"]
        self.helper_call(**request)

    def probe(self, **options):
        return AnchorProbe(self.binary, self.database, options.pop("config", self.config_path),
                           self.directory, self.commands, **options)

    def peer(self):
        return CryptoProbe(self.native, self.directory / "unused-peer.db", self.directory,
                           self.commands, account="bob", device="bob-device",
                           flags=("--memory-peer", "--test-mode"))


NativeFixture = Fixture


class RebuildProbe(Probe):
    def __init__(self, fixture, candidate=None, device="alice-successor", **options):
        target = Path(candidate) if candidate is not None else fixture.candidate
        locator = fixture.candidate_locator(target, device)
        super().__init__(fixture.rebuild_binary, fixture.old.database, fixture.directory,
                         fixture.commands, service=str(fixture.old.config_path), account=str(target),
                         flags=(device, "--test-mode", "--protected", str(locator)),
                         timeout=100, **options)

    def record(self, direction, payload):
        Probe.record(self, direction, redact(payload))


class RebuildFixture(PlainRebuildFixture):
    def __init__(self, binaries, directory, commands):
        self.directory, self.commands = Path(directory), commands
        self.directory.mkdir(mode=0o700, exist_ok=True)
        self.rebuild_binary = binaries[3]
        self.old = Fixture(binaries, self.directory / "old", commands, "alice-old")
        self.source = Fixture(binaries, self.directory / "source", commands, "alice-source")
        self.candidate = self.directory / "successor.db"
        self._candidate_locators = {}

    def candidate_locator(self, candidate=None, device="alice-successor"):
        target = Path(candidate) if candidate is not None else self.candidate
        pair = (str(target.resolve()), device)
        if pair not in self._candidate_locators:
            path = self.old.trusted / f"candidate-{uuid.uuid4()}.json"
            self.old.write_config(self.old.new_locator(device), path)
            self._candidate_locators[pair] = path
        return self._candidate_locators[pair]

    def probe(self, **options):
        return RebuildProbe(self, **options)

    def ctl(self, op, candidate=None, device="alice-successor", expected=0, **fields):
        if op in {"keychain_create", "keychain_lock", "keychain_unlock"}:
            return self.old.ctl(op, expected=expected, **fields)
        target = Path(candidate) if candidate is not None else self.candidate
        locator = self.candidate_locator(target, device).read_text()
        return self.old.ctl(op, expected=expected, db=str(target), locator=locator, **fields)
