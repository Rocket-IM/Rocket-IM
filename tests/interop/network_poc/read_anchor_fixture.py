"""复用独立锚与真实 HTTP；所有登记后的设备命令保持可信锚配置。"""

import hashlib
import json
import subprocess

from .anchor_fixture import AnchorLab
from .fixture import NetworkLab, check
from .read_support import DEVICES, inspect, pending, snapshot


class ReadAnchorLab(AnchorLab):
    start = NetworkLab.start

    def initialize(self, **options):
        super().initialize(**options)
        for device in DEVICES:
            self.enable(device)
        self.case_evidence["anchor_scopes"] = {
            device: self.rust(device, "anchor_inspect") for device in DEVICES}

    def raw_rust(self, device, operation, *, env=None, directory=None, **fields):
        request = self.command(device, operation, **fields)
        if directory is not None:
            request["directory"] = str(directory)
        environment = self.environment(device, env)
        configured = device in self.configs
        check(not configured or environment.get("RIM_ROLLBACK_ANCHOR_CONFIG") == str(self.configs[device]),
              "已登记设备命令缺少原可信锚配置")
        process = subprocess.Popen([str(self.binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, env=environment)
        self.process_count += 1
        evidence = {"device": device, "operation": operation, "pid": process.pid,
                    "anchor_configured": configured, "failpoint": fields.get("failpoint"),
                    "anchor_failpoint": environment.get("RIM_ANCHOR_FAILPOINT")}
        self.case_evidence.setdefault("anchor_processes", []).append(evidence)
        try:
            stdout, stderr = process.communicate(json.dumps(request), timeout=30)
        except BaseException:
            process.kill()
            process.communicate(timeout=5)
            evidence.update(exit_code=process.returncode, interrupted=True)
            raise
        evidence.update(exit_code=process.returncode, stdout_bytes=len(stdout.encode()),
                        stdout_sha256=hashlib.sha256(stdout.encode()).hexdigest(),
                        stderr_bytes=len(stderr.encode()),
                        stderr_sha256=hashlib.sha256(stderr.encode()).hexdigest())
        if stdout.strip():
            reply = json.loads(stdout)
            if not reply.get("ok"):
                evidence["error_code"] = reply["error"]["code"]
        return subprocess.CompletedProcess([str(self.binary)], process.returncode, stdout, stderr)


def state(lab, device="b1"):
    before = snapshot(lab, device)
    result = {"snapshot_sha256": before, "reads": inspect(lab, device),
              "pending": pending(lab, device), "wire": lab.rust(device, "wire_inspect"),
              "message_slot": lab.rust(device, "wire_slot_inspect", event_seq="1")}
    check(snapshot(lab, device) == before, "诊断改变原加密快照")
    return result


def anchor_state(lab, device="b1"):
    result = lab.rust(device, "anchor_inspect")
    check(result["local_head"] == snapshot(lab, device), "锚观察没有绑定当前完整快照")
    return result


def assert_blocked(lab, operation, fields, *, code="anchor_paused", device="b1"):
    result = lab.blocked(device, operation, **fields)
    check(result["code"] == code, f"预期 {code}，实际 {result['code']}")
    return result
