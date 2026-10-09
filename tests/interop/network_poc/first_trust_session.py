"""真实 Rust JSONL 会话；进程生命周期和独立公开对象分别取证。"""

import hashlib
import json
import os
import selectors
import subprocess

from .fixture import check, identity


def digest(value):
    return hashlib.sha256(value).hexdigest()


def public_identity(lab, device):
    return {"protocol_version": "rim-device-identity-1", "service_id": lab.service,
            **identity(device), "signature_key": lab.public[device]["signature_key"]}


class TrustSession:
    def __init__(self, lab, device, *, env=None):
        self.lab, self.device = lab, device
        environment = dict(os.environ)
        environment.pop("RIM_ROLLBACK_ANCHOR_CONFIG", None)
        environment.pop("RIM_ANCHOR_FAILPOINT", None)
        environment = (lab.environment(device, env) if hasattr(lab, "environment")
                       else {**environment, **(env or {})})
        self.closed = False
        self.process = subprocess.Popen([str(lab.binary), "--session"], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True, bufsize=1, env=environment)
        lab.process_count += 1
        if not hasattr(lab, "case_evidence"):
            lab.case_evidence = {}
        self.trace = {"pid": self.process.pid, "device": device, "requests": [],
                      "anchor_configured": "RIM_ROLLBACK_ANCHOR_CONFIG" in environment}
        lab.case_evidence.setdefault("trust_sessions", []).append(self.trace)

    def request(self, operation, *, device=None, expected_error=None, expected_exit=None, **fields):
        device = device or self.device
        data = {"directory": str(self.lab.directory / device), "service": self.lab.service,
                "account": identity(device)["account_id"], "device": device,
                "operation": operation, **fields}
        record = {"operation": operation, "device": device,
                  "input_sha256": digest(json.dumps(data, sort_keys=True).encode())}
        self.trace["requests"].append(record)
        self.process.stdin.write(json.dumps(data) + "\n")
        self.process.stdin.flush()
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            check(bool(selector.select(timeout=30)), "Rust session 响应超时")
            line = self.process.stdout.readline()
        record["stdout_sha256"] = digest(line.encode())
        if expected_exit is not None:
            code = self.process.wait(timeout=10)
            record["exit_code"] = code
            check(code == expected_exit and not line.strip(), "受控退出错误或提前输出成功")
            return None
        check(bool(line), "Rust session 提前退出")
        reply = json.loads(line)
        record["ok"] = reply["ok"]
        if expected_error is not None:
            check(not reply["ok"], "错误输入意外成功")
            record["error"] = reply["error"]
            expected = expected_error if isinstance(expected_error, tuple) else (expected_error,)
            check(reply["error"]["code"] in expected, f"错误码不符: {reply['error']}")
            return reply["error"]
        check(reply["ok"], f"Rust session {operation} 失败: {reply.get('error')}")
        return reply["result"]

    def close(self, *, kill=False):
        if self.closed:
            return
        if self.process.poll() is None:
            if kill:
                self.process.kill()
            elif self.process.stdin:
                self.process.stdin.close()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
                self.trace["close_timeout"] = True
                raise
        self.trace["exit_code"] = self.process.returncode
        self.trace["stderr_sha256"] = digest(self.process.stderr.read().encode())
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            if stream and not stream.closed:
                stream.close()
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def verify_public(lab, observer, target):
    """测试控制器独立取得原设备公开对象；不从目录候选或 pin 推导核验。"""
    independent = public_identity(lab, target)
    with TrustSession(lab, observer) as session:
        session.request("identity_trust_observe", identity=independent)
        display = session.request("identity_trust_prepare", target=identity(target), purpose="verify")["display"]
        result = session.request("identity_trust_confirm", display=display,
                                 independent_identity=independent, verification="synthetic_local")
    check(result["record"]["status"] == "verified", "合成独立核验未完成")
    lab.case_evidence.setdefault("synthetic_verifications", []).append({
        "observer": observer, "target": target, "independent_identity": independent,
        "meaning": "test-controller public-object exchange; not real human verification"})
    return result


def verify_all(lab, devices=None):
    devices = tuple(devices or lab.public)
    for observer in devices:
        for target in devices:
            if observer != target:
                verify_public(lab, observer, target)
