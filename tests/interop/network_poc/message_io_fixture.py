"""M06 本机装置：真实 HTTP，独立 CLI；故障库仅装入指定的单次 CLI。"""

import errno
import json
import os
from pathlib import Path

from .anchor_fixture import AnchorLab, sha256
from .fixture import NetworkLab, SERVICE, check


class MessageIoLab(AnchorLab):
    def __init__(self, binary, directory, helper, library):
        super().__init__(binary, directory, None, None, helper)
        self.library = Path(library).resolve()
        self.case_evidence = {}

    def start(self):
        NetworkLab.start(self)

    def environment(self, device, additions=None):
        env = super().environment(device)
        for name in list(env):
            if name.startswith("RIM_M06_") or name == "DYLD_INSERT_LIBRARIES":
                env.pop(name)
        return env | (additions or {})

    def fault(self, device, operation, kind, **fields):
        trace = self.directory / "syscalls.jsonl"
        additions = {"DYLD_INSERT_LIBRARIES": str(self.library),
                     "RIM_M06_TARGET": str(self.snapshot(device)),
                     "RIM_M06_FAULT": kind, "RIM_M06_TRACE": str(trace),
                     "RIM_M06_SKIP_WRITES": "1" if device in self.configs else "0"}
        result = self.raw_rust(device, operation, env=additions, **fields)
        self.case_evidence.update(exit_code=result.returncode, diagnostic_stderr=result.stderr[:3000])
        check(trace.is_file(), "故障库未命中目标快照，不能算作真实故障已执行")
        calls = [json.loads(line) for line in trace.read_text().splitlines()]
        self.case_evidence["syscalls"] = calls
        check(result.returncode == 1, f"故障未明确失败: exit={result.returncode}; {result.stdout[:300]}")
        reply = json.loads(result.stdout)
        self.case_evidence["response"] = reply
        check(reply["ok"] is False and set(reply) == {"ok", "error"}, "失败输出了业务成功/密文/送达结果")
        expected_errno = {"write": errno.EFBIG, "rename": errno.EACCES,
                          "file_sync": errno.EBADF, "directory_sync": errno.EBADF}[kind]
        # 跟踪由独立 C 装置记录真实内核返回值，不从 Rust 错误文字推断命中位置。
        failed = [call for call in calls if call.get("stage") == kind and call.get("ret") == -1]
        check(len(failed) == 1 and failed[0]["errno"] == expected_errno, "未出现所需的真实系统错误")
        expected_code = "snapshot_commit_unknown" if kind == "directory_sync" else "snapshot_save"
        check(reply["error"]["code"] == expected_code,
              f"错误分类不明确：预期 {expected_code}，实际 {reply['error']}")
        return reply

    def dispatch(self, reply, operation, receipt=None):
        """本实验宿主只转发成功输出；无自动网络 worker，不扩展为正式 SDK 门禁验收。"""
        if not reply.get("ok"):
            return
        result = reply["result"]
        if operation == "wire_send":
            return self.submit(result)
        elif operation == "wire_receive":
            check(receipt is not None, "接收缺少预置事件归属")
            return self.http("b1", "report_delivery", {"service_id": SERVICE, **receipt})
        elif operation == "wire_process":
            return [self.http("b1", "report_delivery", {"service_id": SERVICE, **item})
                    for item in result["deliveries"]]

    def paused_after_restart(self, device, operation, fields):
        saved = sha256(self.snapshot(device))
        inspected = self.rust(device, "anchor_inspect")
        self.case_evidence["anchor_after_failure"] = inspected
        check(inspected["status"] == "reserved", "密码操作失败后独立预约没有保留")
        for _ in range(2):
            blocked = self.blocked(device=device, operation=operation, **fields)
            check(blocked["code"] == "anchor_paused", "未在独立锚暂停门拒绝重试")
        error = self.blocked(device=device, operation="anchor_resume")
        check(error["code"] == "anchor_unresolved", "无完整日志却可解除未决预约")
        check(sha256(self.snapshot(device)) == saved, "暂停/恢复请求重算或重写密码状态")
        self.case_evidence["recovery"] = "persistent_pause_without_complete_journal"
