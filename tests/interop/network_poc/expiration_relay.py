#!/usr/bin/env python3
"""M11.c 测试专用启动器：短保留期与可选时钟输入，复用原 Relay 到期判断。"""

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "poc/network-relay"))

import messages
import server
import storage
import synchronization

MAX_RETENTION_MS = storage.RETENTION_MS
MAX_CLOCK_MS = (1 << 64) - 1
MAX_CLOCK_BYTES = 21


@dataclass(frozen=True)
class Configuration:
    arguments: tuple
    retention_ms: int
    clock: object = None


class FileClock:
    """只读当前测试文件；调用方用原子替换推进时间，重启仍读取同一位置。"""

    def __init__(self, path):
        self.path = Path(path)
        self()

    def __call__(self):
        path = self.path
        if (not path.is_absolute() or ".." in path.parts
                or path.resolve(strict=True) != path):
            raise ValueError("测试时钟必须使用无符号链接的绝对规范路径")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or metadata.st_uid != os.getuid() or metadata.st_mode & 0o022):
                raise ValueError("测试时钟必须是当前用户独占写入的普通单链接文件")
            if metadata.st_size > MAX_CLOCK_BYTES:
                raise ValueError("测试时钟文件超过 21 字节")
            raw = os.read(descriptor, MAX_CLOCK_BYTES + 1)
        finally:
            os.close(descriptor)
        if re.fullmatch(rb"(?:0|[1-9][0-9]{0,19})\n?", raw) is None:
            raise ValueError("测试时钟必须是规范非负十进制毫秒，可带一个末尾换行")
        value = int(raw)
        if value > MAX_CLOCK_MS:
            raise ValueError("测试时钟超过 u64 毫秒范围")
        return value


def prepare(argv):
    """仅校验启动参数；未识别参数保留给原 server.main 的解析器。"""
    parser = argparse.ArgumentParser(description=__doc__, add_help=False, allow_abbrev=False)
    parser.add_argument("--test-retention-ms", required=True)
    parser.add_argument("--test-clock-file")
    for flag in ("--test-retention-ms", "--test-clock-file"):
        if sum(item.split("=", 1)[0] == flag for item in argv) > 1:
            parser.error(flag + " 不得重复")
    args, remaining = parser.parse_known_args(argv)
    if "--enable-test-controls" not in remaining:
        parser.error("M11.c 启动器必须显式启用 --enable-test-controls")
    if re.fullmatch(r"[1-9][0-9]{0,9}", args.test_retention_ms) is None:
        parser.error("--test-retention-ms 必须是规范正十进制毫秒")
    retention = int(args.test_retention_ms)
    if retention > MAX_RETENTION_MS:
        parser.error("--test-retention-ms 不得超过原默认 30 天")
    clock = None
    if args.test_clock_file is not None:
        try:
            clock = FileClock(args.test_clock_file)
        except (OSError, ValueError) as error:
            parser.error(str(error))
    return Configuration(tuple(remaining), retention, clock)


def main(argv=None):
    configuration = prepare(sys.argv[1:] if argv is None else argv)
    previous = (sys.argv, messages.RETENTION_MS, messages.now_ms, synchronization.now_ms)
    try:
        sys.argv = [sys.argv[0], *configuration.arguments]
        messages.RETENTION_MS = configuration.retention_ms
        if configuration.clock is not None:
            messages.now_ms = synchronization.now_ms = configuration.clock
        # 不覆盖存储、到期比较、接受回执或 HTTP 路由；无文件时沿用原真实时钟。
        return server.main()
    finally:
        sys.argv, messages.RETENTION_MS, messages.now_ms, synchronization.now_ms = previous


if __name__ == "__main__":
    main()
