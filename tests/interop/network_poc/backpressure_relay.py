#!/usr/bin/env python3
"""M12.e只读时序观察包装器；沿用原8槽、8秒socket和HTTP/事务路径。"""

import argparse
import json
from pathlib import Path
import socket
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "poc/network-relay"))
import server


class Events:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.index = 0
        self.path.touch(mode=0o600, exist_ok=False)

    def record(self, stage, address, **fields):
        # 仅记录本机端口、时间和固定事件类型；不保存头、正文或凭证。
        with self.lock:
            self.index += 1
            if self.index > 1024:
                raise RuntimeError("并发观察事件超过装置上限")
            event = {"index": self.index, "stage": stage, "client_port": address[1],
                     "monotonic_ns": time.monotonic_ns(), **fields}
            with self.path.open("a") as output:
                output.write(json.dumps(event) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument("--events", type=Path, required=True)
    args, rest = parser.parse_known_args()
    if not args.events.is_absolute() or "--enable-test-controls" not in rest:
        parser.error("观察日志必须是绝对路径，且显式启用测试控制")
    events = Events(args.events)
    original_handler, original_server = server.Handler, server.RelayServer

    class ObservedHandler(original_handler):
        def request_body(self):
            started = time.monotonic_ns()
            events.record("body_read_entered", self.client_address)
            try:
                return super().request_body()
            except (socket.timeout, TimeoutError):
                events.record("body_read_timeout", self.client_address,
                              elapsed_ns=time.monotonic_ns() - started,
                              socket_timeout_seconds=self.connection.gettimeout())
                raise

    class ObservedServer(original_server):
        def process_request_thread(self, request, client_address):
            try:
                super().process_request_thread(request, client_address)
            finally:
                # 原方法返回时已在finally释放信号量；这里只追加观察结果。
                events.record("worker_finished", client_address)

    server.Handler = ObservedHandler
    server.RelayServer = ObservedServer
    sys.argv = [sys.argv[0], *rest]
    server.main()


if __name__ == "__main__":
    main()
