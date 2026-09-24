#!/usr/bin/env python3
"""用独立进程验证合成设备、原子快照、重试和不透明信箱；不执行旧钥攻击。"""

import argparse
import base64
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests/interop"))
from network_poc.fixture import require_current_namespace
OUTPUT = ROOT / "dist/crypto-probes"
TOOLCHAIN = tomllib.loads((ROOT / "poc/rust-toolchain.toml").read_text())["toolchain"]["channel"]


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


class Lab:
    def __init__(self, binary, directory):
        self.binary = binary
        self.directory = directory
        self.relay = directory / "relay"
        self.relay.mkdir(mode=0o700)
        self.public = {}
        self.passed = []
        self.processes = 0

    def request(self, device, operation, *, expected_exit=0, **fields):
        account = {"a1": "alice", "a2": "alice", "b1": "bob", "c1": "charlie"}[device]
        request = {"directory": str(self.directory / device), "service": "synthetic-service",
                   "account": account, "device": device, "operation": operation, **fields}
        run = subprocess.run([str(self.binary)], input=json.dumps(request), text=True,
                             capture_output=True, timeout=20)
        self.processes += 1
        check(run.returncode == expected_exit,
              f"{operation} exit={run.returncode}, expected={expected_exit}; output={run.stdout[:500]}")
        if expected_exit in (83, 84, 85):
            check(not run.stdout.strip(), f"{operation} 在提交响应前中断却输出了成功")
            return None
        reply = json.loads(run.stdout)
        check(reply["ok"] == (expected_exit == 0), f"{operation} 响应状态错误")
        return reply.get("result") if expected_exit == 0 else reply["error"]

    def record(self, name):
        self.passed.append(name)
        print(f"PASS {name}", flush=True)

    def route(self, message_id, sender, recipient, ciphertext):
        envelope = {"sender": sender, "recipient": recipient, "ciphertext": ciphertext}
        self.relay_request({"operation": "put", "id": message_id, "envelope": envelope})
        return self.relay_request({"operation": "get", "id": message_id})["ciphertext"]

    def relay_request(self, request):
        run = subprocess.run([sys.executable, str(ROOT / "tools/poc_relay.py"), str(self.relay)],
                             input=json.dumps(request), text=True, capture_output=True, timeout=10)
        check(run.returncode == 0, "独立 Relay 进程失败")
        self.processes += 1
        return json.loads(run.stdout)["result"]

    def initialize(self):
        for device in ("a1", "b1", "c1", "a2"):
            self.public[device] = self.request(device, "init")
        peers = [{"account": account, "device": device,
                  "key_package": self.public[device]["key_package"],
                  "signature_key": self.public[device]["signature_key"]}
                 for account, device in (("bob", "b1"), ("charlie", "c1"))]
        created = self.request("a1", "create", peers=peers)
        repeated = self.request("a1", "create", peers=peers)
        check(repeated["welcome"] == created["welcome"], "建群重试改变了已保存Welcome")
        pins = [{"account": account, "device": device,
                 "signature_key": self.public[device]["signature_key"]}
                for account, device in (("alice", "a1"), ("bob", "b1"), ("charlie", "c1"))]
        for device in ("b1", "c1"):
            self.request(device, "join", welcome=created["welcome"], pins=pins)
            self.request(device, "join", welcome=created["welcome"], pins=pins)
        self.record("独立设备进程建群与可信测试公钥匹配")

    def messaging(self):
        message = self.request("a1", "send", id="offline-1", payload="synthetic-offline")
        relay_bytes = self.route("offline-1", "a1", "b1", message["ciphertext"])
        received = self.request("b1", "receive", id="offline-1", ciphertext=relay_bytes)
        check(received["payload_sha256"] == hashlib.sha256(b"synthetic-offline").hexdigest(), "离线接收摘要不一致")
        self.record("离线收发与Relay只传不透明密文")
        again = self.request("a1", "send", id="offline-1", payload="synthetic-offline")
        check(again["ciphertext"] == message["ciphertext"] and again["reused"], "重启重试没有复用已存密文")
        duplicate = self.request("b1", "receive", id="offline-1", ciphertext=relay_bytes)
        check(duplicate["duplicate"], "接收重复记录未去重")
        self.request("a1", "send", id="offline-1", payload="synthetic-conflict", expected_exit=1)
        self.record("发送幂等重试与接收持久去重、同ID冲突拒绝")
        first = self.request("a1", "send", id="order-1", payload="synthetic-one")
        second = self.request("a1", "send", id="order-2", payload="synthetic-two")
        for ident, packet in (("order-2", second), ("order-1", first)):
            self.request("b1", "receive", id=ident, ciphertext=packet["ciphertext"])
        self.record("跨进程乱序接收")
        valid = self.request("a1", "send", id="tamper-1", payload="synthetic-valid")
        corrupted = bytearray(base64.b64decode(valid["ciphertext"]))
        corrupted[-1] ^= 1
        before = (self.directory / "b1/state.enc").read_bytes()
        error = self.request("b1", "receive", id="relabelled", ciphertext=valid["ciphertext"], expected_exit=1)
        check(error["code"] == "message_binding", "外层ID替换未在认证绑定处拒绝")
        check((self.directory / "b1/state.enc").read_bytes() == before, "ID替换拒绝后覆盖状态")
        self.record("外层消息ID替换拒绝且不消费有效接收状态")
        self.request("b1", "receive", id="tamper-1", ciphertext=base64.b64encode(corrupted).decode(), expected_exit=1)
        check((self.directory / "b1/state.enc").read_bytes() == before, "拒绝输入后覆盖有效状态")
        self.request("b1", "receive", id="tamper-1", ciphertext=valid["ciphertext"])
        self.record("无效消息失败保留快照、随后有效接收恢复")

    def interruptions(self):
        for point, code in (("before_save", 83), ("before_rename", 84), ("after_save", 85)):
            ident = "send-" + point
            prior = (self.directory / "a1/state.enc").read_bytes()
            self.request("a1", "send", id=ident, payload="synthetic-interruption", failpoint=point, expected_exit=code)
            changed = (self.directory / "a1/state.enc").read_bytes() != prior
            check(changed == (point == "after_save"), "中断点的持久化边界错误")
            resumed = self.request("a1", "send", id=ident, payload="synthetic-interruption")
            check(resumed["reused"] == (point == "after_save"), "重启恢复没有遵守提交边界")
            retransmitted = self.request("a1", "send", id=ident, payload="synthetic-interruption")
            check(resumed["ciphertext"] == retransmitted["ciphertext"], "恢复重试密文变化")
            self.request("b1", "receive", id=ident, ciphertext=resumed["ciphertext"])
            self.record(f"发送端进程中断恢复：{point}")
        for point, code in (("before_save", 83), ("before_rename", 84), ("after_save", 85)):
            ident = "receive-" + point
            message = self.request("a1", "send", id=ident, payload="synthetic-receive")
            self.request("b1", "receive", id=ident, ciphertext=message["ciphertext"], failpoint=point, expected_exit=code)
            resumed = self.request("b1", "receive", id=ident, ciphertext=message["ciphertext"])
            check(resumed["duplicate"] == (point == "after_save"), "接收去重与密码状态提交不一致")
            self.record(f"接收端进程中断恢复：{point}")

    def removal(self):
        self.request("a1", "remove", id="remove-c-1", member="c1", failpoint="after_save", expected_exit=85)
        removed = self.request("a1", "remove", id="remove-c-1", member="c1")
        retry = self.request("a1", "remove", id="remove-c-1", member="c1")
        check(removed["commit"] == retry["commit"], "移除重试未复用Commit")
        self.request("b1", "apply_commit", commit=removed["commit"])
        alice = self.request("a1", "inspect")
        bob = self.request("b1", "inspect")
        charlie = self.request("c1", "inspect")
        check(len(alice["members"]) == len(bob["members"]) == 2
              and len(charlie["members"]) == 3
              and alice["epoch"] == bob["epoch"] != charlie["epoch"], "新旧成员状态边界错误")
        message = self.request("a1", "send", id="new-epoch", payload="synthetic-new-epoch")
        self.request("b1", "receive", id="new-epoch", ciphertext=message["ciphertext"])
        self.request("c1", "receive", id="new-epoch", ciphertext=message["ciphertext"], expected_exit=1)
        self.record("移除Commit持久重试、新状态收发与旧状态API拒绝")

    def authorization(self):
        now = int(datetime.now(timezone.utc).timestamp())
        package = base64.b64decode(self.public["a2"]["key_package"])
        request = {"service": "synthetic-service", "account": "alice", "signer_device": "a1",
                   "new_device": "a2", "new_signature_key": list(base64.b64decode(self.public["a2"]["signature_key"])),
                   "key_package_sha256": list(hashlib.sha256(package).digest()),
                   "expected_roster_version": 0, "nonce": list(os.urandom(32)),
                   "issued_at_unix_secs": now, "expires_at_unix_secs": now + 120}
        signed = self.request("a1", "sign_authorization", request=request)["authorization"]
        invalid = json.loads(json.dumps(signed))
        invalid["signature"][0] ^= 1
        before = (self.directory / "a1/state.enc").read_bytes()
        error = self.request("a1", "authorize", authorization=invalid,
                     key_package=self.public["a2"]["key_package"], now_unix_secs=now, expected_exit=1)
        check(error["code"] == "authorization_signature", "错签名没有在验签处被拒绝")
        check((self.directory / "a1/state.enc").read_bytes() == before, "授权失败覆盖有效快照")
        self.request("a1", "authorize", authorization=signed,
                     key_package=self.public["a2"]["key_package"], now_unix_secs=now,
                     failpoint="after_save", expected_exit=85)
        committed = (self.directory / "a1/state.enc").read_bytes()
        error = self.request("a1", "authorize", authorization=signed,
                     key_package=self.public["a2"]["key_package"], now_unix_secs=now, expected_exit=1)
        check(error["code"] == "authorization_replay", "不能仅用旧版本拒绝证明nonce已持久化")
        check((self.directory / "a1/state.enc").read_bytes() == committed, "重放拒绝后覆盖有效快照")
        check(self.request("a1", "inspect")["roster_version"] == 1, "授权版本未恢复")
        self.record("真实KeyPackage授权验签、失败保留状态、已提交nonce跨进程防重放")

    def isolation(self):
        path = self.directory / "b1/state.enc"
        before = path.read_bytes()
        with (self.directory / "b1/writer.lock").open("rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            error = self.request("b1", "inspect", expected_exit=1)
            check(error["code"] == "busy", "并行进程没有遵守设备文件锁")
            check(path.read_bytes() == before, "锁冲突时覆盖了状态")
        self.record("跨进程写锁冲突显式拒绝且保留状态")
        alice_snapshot = (self.directory / "a1/state.enc").read_bytes()
        path.write_bytes(alice_snapshot)
        try:
            self.request("b1", "inspect", expected_exit=1)
            check(path.read_bytes() == alice_snapshot, "跨账号加载失败却重建覆盖了文件")
        finally:
            path.write_bytes(before)
        self.request("b1", "inspect")
        self.record("跨设备快照错钥/上下文拒绝且不静默重建")
        for path in self.directory.rglob('*'):
            if path.is_file():
                content = path.read_bytes()
                for marker in (b"synthetic-offline", b"synthetic-interruption", b"synthetic-new-epoch"):
                    check(marker not in content, "合成消息正文出现在持久化文件中")
        self.record("合成客户端快照与Relay文件无测试正文")

    def run(self):
        self.initialize()
        self.authorization()
        self.messaging()
        self.interruptions()
        self.removal()
        self.isolation()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, help="使用已构建的原生实验二进制，跳过构建")
    parser.add_argument("--output", type=Path, default=OUTPUT, help="本轮独立构建、报告及临时状态目录")
    args = parser.parse_args()
    output_directory = args.output.resolve()
    logs = output_directory / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    binary = args.binary or output_directory / "target/openmls/release/openmls-state-lab"
    report = {"status": "RUNNING", "run_id": str(uuid.uuid4()),
              "executed_at": datetime.now(timezone.utc).isoformat(),
              "scope": "synthetic native processes; stdio relay; controlled interruption",
              "raw_old_key_attack": "NOT_EXECUTED_ACCESS_RESTRICTED", "cases": []}
    report_path = logs / "state-lab-results.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    lab = None
    try:
        if args.binary is None:
            command = ["cargo", f"+{TOOLCHAIN}", "build", "--locked", "--release",
                       "--manifest-path", str(ROOT / "poc/openmls-probe/Cargo.toml"),
                       "--bin", "openmls-state-lab"]
            with (logs / "state-lab-build.log").open("w") as output:
                build = subprocess.run(command, cwd=ROOT / "poc",
                                       env={**os.environ, "CARGO_TARGET_DIR": str(output_directory / "target/openmls")},
                                       stdout=output, stderr=subprocess.STDOUT)
            check(build.returncode == 0, "原生实验构建失败，查看 state-lab-build.log")
        require_current_namespace(binary)
        with tempfile.TemporaryDirectory(prefix="state-lab-", dir=output_directory) as directory:
            lab = Lab(binary.resolve(), Path(directory))
            lab.run()
            report.update(status="PASS", cases=lab.passed, process_count=lab.processes,
                          binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    except (RuntimeError, OSError, KeyError, ValueError, subprocess.SubprocessError) as error:
        report.update(status="FAIL", error=str(error))
        raise
    finally:
        if lab is not None:
            report.update(cases=lab.passed, process_count=lab.processes)
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(f"PASS {len(report['cases'])} 项进程场景，完整安全验收仍未完成")


if __name__ == "__main__":
    main()
