"""独立进程锚装置：真实 MLS/签名，合成独立目录；不启动 HTTP 或证明故障域独立。"""

import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys

from .fixture import NetworkLab, SERVICE, check, identity, require_current_namespace


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def private_json(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)


class AnchorLab(NetworkLab):
    def __init__(self, binary, directory, permission_verifier, receipt_signer, helper):
        super().__init__(binary, directory, permission_verifier, receipt_signer)
        self.helper = Path(helper).resolve()
        self.configs = {}
        self.materials = {}
        self.helper_process_count = 0
        self.evidence = {}

    def start(self):
        # 本项只重用 MLS 与公钥 fixture 引导，不把合成签名回执写成 HTTP 接受。
        pass

    def initialize(self, *, permissions=False, **options):
        require_current_namespace(self.helper, b"Rocket-IM/POC/rollback-anchor-request/v1")
        super().initialize(permissions=permissions, **options)

    def command(self, device, operation, **fields):
        return {"directory": str(self.directory / device), "service": SERVICE,
                "account": identity(device)["account_id"], "device": device,
                "operation": operation, **fields}

    def environment(self, device, additions=None):
        env = dict(os.environ)
        env.pop("RIM_ROLLBACK_ANCHOR_CONFIG", None)
        env.pop("RIM_ANCHOR_FAILPOINT", None)
        if device in self.configs:
            env["RIM_ROLLBACK_ANCHOR_CONFIG"] = str(self.configs[device])
        return env | (additions or {})

    def raw_rust(self, device, operation, *, env=None, directory=None, **fields):
        data = self.command(device, operation, **fields)
        if directory is not None:
            data["directory"] = str(directory)
        result = subprocess.run([str(self.binary)], input=json.dumps(data), text=True,
                                capture_output=True, timeout=12,
                                env=self.environment(device, env))
        self.process_count += 1
        return result

    def rust(self, device, operation, *, expected_exit=0, env=None, directory=None, **fields):
        result = self.raw_rust(device, operation, env=env, directory=directory, **fields)
        check(result.returncode == expected_exit,
              f"{operation}: exit={result.returncode}, expected={expected_exit}; {result.stdout[:400]}")
        if expected_exit in range(83, 89):
            check(not result.stdout.strip(), "受控退出在响应提交前输出了结果")
            return None
        reply = json.loads(result.stdout)
        check(reply["ok"] == (expected_exit == 0), "退出码与响应状态不符")
        return reply["result"] if reply["ok"] else reply["error"]

    def anchor(self, request, *, expected_exit=0, raw=None):
        result = subprocess.run([str(self.helper)],
                                input=json.dumps(request) if raw is None else raw,
                                text=True, capture_output=True, timeout=10)
        self.helper_process_count += 1
        check(result.returncode == expected_exit,
              f"独立锚 exit={result.returncode}, expected={expected_exit}; {result.stdout[:300]}")
        reply = json.loads(result.stdout)
        check(reply["ok"] == (expected_exit == 0), "锚退出码与响应不符")
        return reply.get("result", reply) if reply["ok"] else reply["error"]

    def enable(self, device="a1"):
        trusted = self.directory / ("trusted-" + device)
        trusted.mkdir(mode=0o700)
        authority = self.directory / ("authority-" + device)
        scope = {"service": SERVICE, "account": identity(device)["account_id"],
                 "device": device,
                 "identity_key": base64.b64decode(self.public[device]["signature_key"]).hex(),
                 "store_id": secrets.token_hex(32)}
        seed = secrets.token_hex(32)
        client_key = self.anchor({"op": "public_key", "seed": seed})["public_key"]
        bootstrap = {"op": "init", "directory": str(authority), "scope": scope,
                     "client_public_key": client_key, "anchor_seed": secrets.token_hex(32),
                     "head": sha256(self.snapshot(device))}
        initialized = self.anchor(bootstrap)
        config = {"protocol_version": "rim-rollback-client-1", "scope": scope,
                  "anchor_public_key": initialized["anchor_public_key"], "client_seed": seed,
                  "journal_key": secrets.token_hex(32), "helper_path": str(self.helper),
                  "anchor_directory": str(authority)}
        path = trusted / "config.json"
        private_json(path, config)
        self.configs[device] = path
        self.materials[device] = {"config": config, "bootstrap": bootstrap,
                                  "authority": authority, "trusted": trusted}

    def snapshot(self, device="a1"):
        return self.directory / device / "state.enc"

    def backup(self, name, path):
        target = self.directory / ("backup-" + name)
        shutil.copytree(path, target)
        return target

    @staticmethod
    def restore(backup, path):
        shutil.rmtree(path)
        shutil.copytree(backup, path)

    def blocked(self, device="a1", operation="send", **fields):
        if not fields and operation == "send":
            fields = {"id": "anchor_must_block", "payload": "synthetic-must-not-encrypt"}
        before = self.snapshot(device).read_bytes() if self.snapshot(device).exists() else None
        error = self.rust(device, operation, expected_exit=1, **fields)
        check(bool(error.get("code")), "拒绝缺少明确原因")
        after = self.snapshot(device).read_bytes() if self.snapshot(device).exists() else None
        check(after == before, "拒绝路径更改了密码快照")
        return error

    def resume(self, device="a1", **options):
        before = self.snapshot(device).read_bytes()
        result = self.rust(device, "anchor_resume", **options)
        check(self.snapshot(device).read_bytes() == before, "锚恢复重新执行或重写了 MLS 状态")
        return result

    def send(self, ident, device="a1", **options):
        return self.rust(device, "send", id=ident, payload="synthetic-anchor-" + ident, **options)

    def config_change(self, device="a1", **changes):
        config = self.materials[device]["config"] | changes
        private_json(self.configs[device], config)

    def config_restore(self, device="a1"):
        private_json(self.configs[device], self.materials[device]["config"])

    def forwarding_helper(self, mode="capture", action="reserve", device="a1", replacement=None):
        """转发到真实锚；只在传输边界注入丢响应、篡改、重放或超时。"""
        script = self.materials[device]["trusted"] / "transport.py"
        capture = self.materials[device]["trusted"] / "transport.json"
        settings = {"helper": str(self.helper), "capture": str(capture),
                    "mode": mode, "action": action,
                    "replacement": str(replacement) if replacement else None,
                    "snapshot": str(self.snapshot(device))}
        source = '''import base64, json, os, pathlib, subprocess, sys, time
settings = SETTINGS
data = json.load(sys.stdin)
statement = json.loads(base64.b64decode(data["request"]["statement_bytes"]))
chosen = statement["action"] == settings["action"]
capture = pathlib.Path(settings["capture"])
if chosen and settings["mode"] == "timeout":
    time.sleep(10)
if chosen and settings["mode"] == "oversize":
    sys.stdout.write("x" * (128 * 1024)); sys.exit(0)
if chosen and settings["mode"] == "replay":
    sys.stdout.write(json.loads(capture.read_text())["response"]); sys.exit(0)
if chosen and settings["mode"].startswith("crash_"):
    data["failpoint"] = settings["mode"][6:]
result = subprocess.run([settings["helper"]], input=json.dumps(data), text=True, capture_output=True)
if chosen and settings["mode"] == "replace_snapshot" and result.returncode == 0:
    pathlib.Path(settings["snapshot"]).write_bytes(pathlib.Path(settings["replacement"]).read_bytes())
if chosen and settings["mode"] == "capture":
    capture.write_text(json.dumps({"request": data, "response": result.stdout}))
    capture.chmod(0o600)
if chosen and settings["mode"] == "drop":
    sys.exit(0)
if chosen and settings["mode"] == "tamper":
    reply = json.loads(result.stdout)
    signed = reply.get("result", reply)
    if "response" in signed: signed = signed["response"]
    raw = bytearray(base64.b64decode(signed["signature_bytes"]))
    raw[-1] ^= 1
    signed["signature_bytes"] = base64.b64encode(raw).decode()
    sys.stdout.write(json.dumps(reply)); sys.exit(0)
sys.stdout.write(result.stdout)
sys.exit(result.returncode)
'''
        script.write_text("#!" + sys.executable + "\n" + source.replace("SETTINGS", repr(settings)))
        script.chmod(0o700)
        self.config_change(device, helper_path=str(script))
        return capture
