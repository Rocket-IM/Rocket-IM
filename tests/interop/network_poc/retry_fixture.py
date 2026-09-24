"""M02 独立 CLI 观测装置；计数只接受显式启用的 Rust 测试探针。"""

import json
import re
import subprocess

from .fixture import NetworkLab, check, identity


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        check(key not in result, "Rust 加密探针含重复字段")
        result[key] = value
    return result


def _probe_calls(stderr, enabled):
    if not enabled:
        check(stderr == "", "未启用探针的 Rust CLI 不应输出 stderr")
        return None
    lines = stderr.splitlines()
    check(len(lines) == 1 and bool(lines[0]), "Rust 加密探针缺失或不是单行记录")
    try:
        record = json.loads(lines[0], object_pairs_hook=_unique_object)
    except (ValueError, TypeError):
        raise AssertionError("Rust 加密探针不是合法 JSON") from None
    check(isinstance(record, dict) and set(record) == {"probe", "version", "calls"},
          "Rust 加密探针字段不完整或含额外字段")
    check(record["probe"] == "wire_send_create_message", "Rust 加密探针名称不匹配")
    check(type(record["version"]) is int and record["version"] == 1,
          "Rust 加密探针版本不匹配")
    calls = record["calls"]
    check(isinstance(calls, str) and re.fullmatch(r"0|[1-9][0-9]{0,19}", calls) is not None,
          "Rust 加密探针计数不是规范 u64 字符串")
    check(int(calls) <= 18446744073709551615, "Rust 加密探针计数超出 u64")
    return calls


class RetryLab(NetworkLab):
    def __init__(self, *args, probe_enabled=False, **kwargs):
        check(type(probe_enabled) is bool, "探针开关必须显式使用布尔值")
        super().__init__(*args, **kwargs)
        self.probe_enabled = probe_enabled
        self.encryption_observations = []

    def rust(self, device, operation, *, expected_exit=0, **fields):
        """每次调用一个进程；只记录元数据，不保存输入、stdout 或原始 stderr。"""
        check(type(expected_exit) is int and expected_exit in (0, 1),
              "M02 观测装置仅支持正常成功或业务失败退出")
        data = {"directory": str(self.directory / device), "service": self.service,
                "account": identity(device)["account_id"], "device": device,
                "operation": operation, **fields}
        with subprocess.Popen([str(self.binary)], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
            self.process_count += 1
            observation = {"device": device, "operation": operation, "pid": process.pid,
                           "exit_code": None, "measurement": "NOT_INSTRUMENTED", "calls": None}
            self.encryption_observations.append(observation)
            try:
                stdout, stderr = process.communicate(json.dumps(data), timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                observation["exit_code"] = process.returncode
                raise TimeoutError(f"Rust {operation} 执行超时，已终止并回收进程") from None
            observation["exit_code"] = process.returncode
        calls = _probe_calls(stderr, self.probe_enabled)
        if self.probe_enabled:
            observation.update(measurement="measured", calls=calls)
            check(operation == "wire_send" or calls == "0", "非发送操作出现 wire_send 加密计数")
        check(process.returncode == expected_exit,
              f"Rust {operation}: exit {process.returncode}, expected {expected_exit}")
        try:
            reply = json.loads(stdout)
        except (ValueError, TypeError):
            raise AssertionError(f"Rust {operation} 响应不是合法 JSON") from None
        check(isinstance(reply, dict) and type(reply.get("ok")) is bool
              and reply["ok"] == (expected_exit == 0), "Rust 响应状态与退出码不符")
        result_key = "result" if reply["ok"] else "error"
        check(result_key in reply, "Rust 响应缺少结果字段")
        return reply[result_key]
