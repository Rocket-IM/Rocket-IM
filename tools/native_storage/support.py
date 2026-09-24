"""隔离原生存储验收的有界子进程、协议记录和摘要工具。"""

from collections import deque
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "dist/native-storage"
CRATE = ROOT / "poc/native-storage"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def source_hashes():
    files = [ROOT / "poc/rust-toolchain.toml"]
    for folder in (CRATE, ROOT / "tools/native_storage"):
        files.extend(path for path in folder.rglob("*") if path.is_file()
                     and not {"target", "__pycache__", ".DS_Store"}.intersection(path.parts))
    return {str(path.relative_to(ROOT)): sha(path) for path in sorted(files)}


def environment():
    env = os.environ.copy()
    env.update(CARGO_HOME=str(ROOT / "dist/toolchains/rust/cargo"),
               RUSTUP_HOME=str(ROOT / "dist/toolchains/rust/rustup"),
               CARGO_NET_OFFLINE="true")
    env["PATH"] = str(ROOT / "dist/toolchains/rust/cargo/bin") + os.pathsep + env["PATH"]
    return env


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def kill_and_reap(process):
    try:
        # 即使父命令已退出，仍清理可能持有输出管道的编译子进程。
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    return process.wait(timeout=5)


def run_command(args, log, records, timeout=600, limit=32 * 1024 * 1024):
    """限时、限输出并保留失败日志；命令及子编译器共享独立进程组。"""
    record = {"args": [str(arg) for arg in args], "started_at": utc_now(), "log": str(log)}
    records.append(record)
    process = subprocess.Popen(record["args"], cwd=ROOT, env=environment(),
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=True)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline, total = time.monotonic() + timeout, 0
    try:
        with log.open("wb") as output:
            while selector.get_map():
                require(time.monotonic() < deadline, "构建命令超时")
                for key, _ in selector.select(min(0.2, max(0, deadline - time.monotonic()))):
                    data = os.read(key.fd, 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(data)
                    require(total <= limit, "构建命令输出超过上限")
                    output.write(data)
            record["returncode"] = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            require(record["returncode"] == 0, f"命令失败：{log.name}")
    except Exception as error:
        record["error"] = str(error)
        raise
    finally:
        record["returncode"] = kill_and_reap(process)
        record.update(finished_at=utc_now(), output_bytes=total)
        selector.close()
        process.stdout.close()
    return log.read_text()


class Probe:
    """只通过 Rust CLI 访问数据库；所有管道读取和进程存活有上限。"""

    def __init__(self, binary, database, output, log, flags=(), service="local-service",
                 account="alice", ready=True, timeout=60):
        self.log, self.ready, self.finished = log, False, False
        self.selector, self.stdout, self.stderr = selectors.DefaultSelector(), deque(), deque()
        self.buffers, self.total, self.sequence = {}, 0, 0
        self.process, self.raw, self.disposed = None, None, False
        self.deadline = time.monotonic() + timeout
        try:
            self.process = subprocess.Popen([str(binary), str(database), service, account, *flags],
                                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, bufsize=0, start_new_session=True)
            self.raw = (output / f"process-{self.process.pid}.jsonl").open("w")
            self.record("spawn", {"database": str(database), "service": service,
                                  "account": account, "flags": list(flags)})
            for name in ("stdout", "stderr"):
                stream = getattr(self.process, name)
                os.set_blocking(stream.fileno(), False)
                self.selector.register(stream, selectors.EVENT_READ, name)
                self.buffers[name] = b""
            if ready is not None:
                self.startup = self.next_stdout()
                require(self.startup.get("ready") is ready, f"启动状态不符：{self.startup}")
                self.ready = ready
                if ready:
                    self.check_threads(self.startup)
                else:
                    self.finish(1)
        except Exception:
            self.abort()
            raise

    def record(self, direction, payload):
        item = {"at": utc_now(), "pid": self.process.pid if self.process else None,
                "direction": direction, "payload": payload}
        self.log.append(item)
        if self.raw is not None and not self.raw.closed:
            self.raw.write(json.dumps(item, ensure_ascii=False) + "\n")
            self.raw.flush()

    def check_threads(self, response):
        require(response.get("worker_thread") is not None, "缺少工作线程证据")
        require(response.get("caller_thread") is not None, "缺少调用线程证据")
        require(response["worker_thread"] != response.get("caller_thread"), "数据库在调用线程执行")

    def pump(self, deadline):
        require(time.monotonic() < min(deadline, self.deadline), "CLI 响应或进程总时限超时")
        for key, _ in self.selector.select(min(0.2, max(0, deadline - time.monotonic()))):
            data = os.read(key.fd, 65536)
            name = key.data
            if not data:
                self.selector.unregister(key.fileobj)
                require(not self.buffers[name], f"{name} 返回不完整行")
                continue
            self.total += len(data)
            require(self.total <= 16 * 1024 * 1024, "CLI 输出超过上限")
            self.buffers[name] += data
            require(len(self.buffers[name]) <= 4 * 1024 * 1024, "CLI 单行超过上限")
            while b"\n" in self.buffers[name]:
                line, self.buffers[name] = self.buffers[name].split(b"\n", 1)
                payload = json.loads(line)
                require(isinstance(payload, dict), "CLI 返回不是对象")
                getattr(self, name).append(payload)
                self.record(name, payload)

    def next_stdout(self, timeout=8):
        deadline = min(self.deadline, time.monotonic() + timeout)
        while not self.stdout:
            self.pump(deadline)
            require(self.selector.get_map() or self.stdout, "CLI 在返回响应前退出")
        return self.stdout.popleft()

    def send(self, request):
        self.sequence += 1
        request = {"id": f"r{self.sequence}", **request}
        encoded = (json.dumps(request, ensure_ascii=False) + "\n").encode()
        require(len(encoded) <= 65536, "请求超过控制器上限")
        self.record("stdin", request)
        fd = self.process.stdin.fileno()
        os.set_blocking(fd, False)
        selector = selectors.DefaultSelector()
        selector.register(fd, selectors.EVENT_WRITE)
        try:
            while encoded:
                require(time.monotonic() < self.deadline, "CLI 写入超时")
                if selector.select(0.2):
                    try:
                        encoded = encoded[os.write(fd, encoded):]
                    except BlockingIOError:
                        continue
        finally:
            selector.close()
        return request["id"]

    def request(self, op, **values):
        request_id = self.send({"op": op, **values})
        response = self.next_stdout()
        require(response.get("id") == request_id, "CLI 响应 ID 不匹配")
        self.check_threads(response)
        return response

    def checkpoint(self, expected):
        deadline = min(self.deadline, time.monotonic() + 8)
        while True:
            while self.stderr:
                response = self.stderr.popleft()
                if response.get("checkpoint") == expected:
                    require(response.get("pid") == self.process.pid, "checkpoint PID 不匹配")
                    return response
            require(not self.stdout, "checkpoint 前意外发布响应")
            self.pump(deadline)
            require(self.selector.get_map(), "checkpoint 前进程退出")

    def finish(self, expected=0):
        deadline = min(self.deadline, time.monotonic() + 5)
        while self.selector.get_map():
            self.pump(deadline)
        actual = self.process.wait(timeout=max(0.01, deadline - time.monotonic()))
        self.record("exit", {"returncode": actual, "expected": expected})
        require(actual == expected, f"进程退出码 {actual}，预期 {expected}")
        self.finished = True

    def crash(self):
        self.process.kill()
        self.finish(-signal.SIGKILL)
        require(not self.stdout, "强杀窗口发布了成功响应")

    def close(self):
        if not self.finished:
            if self.process.poll() is None and self.ready:
                response = self.request("close")
                require(response.get("ok") is True, f"正常关闭失败：{response}")
            self.finish()
            require(not self.stdout, "正常关闭出现多余响应")
        self.dispose()

    def dispose(self):
        try:
            self.selector.close()
            if self.process is not None:
                for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                    stream.close()
            if self.raw is not None:
                self.raw.close()
        finally:
            self.disposed = True

    def abort(self):
        try:
            actual = kill_and_reap(self.process) if self.process is not None else None
            self.record("cleanup", {"returncode": actual, "reaped": True})
        finally:
            self.dispose()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, _error, _traceback):
        try:
            if exc_type is None:
                self.close()
        finally:
            if not self.disposed:
                self.abort()
