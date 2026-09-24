#!/usr/bin/env python3
"""仅用于合成测试的文件信箱：独立进程、stdio 控制，不是业务后端或网络 Service。"""

import base64
import json
import os
from pathlib import Path
import re
import stat
import sys


LIMIT = 1_048_576


def read_envelope(path):
    # 不跟随信箱中的符号链接；该合成调度器仍只串行访问自己的信箱。
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("not_regular_file")
        raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError("stored_envelope_too_large")
    return json.loads(raw)


def execute(root, request):
    operation = request.get("operation")
    message_id = request.get("id", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", message_id):
        raise ValueError("invalid_message_id")
    path = root / f"{message_id}.json"
    if operation == "put":
        envelope = request["envelope"]
        if set(envelope) != {"sender", "recipient", "ciphertext"}:
            raise ValueError("invalid_envelope")
        for name in ("sender", "recipient"):
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", envelope[name]):
                raise ValueError("invalid_route")
        raw = base64.b64decode(envelope["ciphertext"], validate=True)
        if not raw or len(raw) > 524_288:
            raise ValueError("invalid_ciphertext_size")
        if path.exists():
            if read_envelope(path) != envelope:
                raise ValueError("id_conflict")
        else:
            if sum(1 for _ in root.glob("*.json")) >= 2048:
                raise ValueError("mailbox_full")
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
                stream.write(json.dumps(envelope))
        return {"accepted": True}
    if operation == "get":
        return read_envelope(path)
    raise ValueError("invalid_operation")


def main():
    root = Path(sys.argv[1])
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise ValueError("fixture_directory_required")
    # 每次启动只处理一条请求，信箱只保存公开路由和不透明密文。
    line = sys.stdin.buffer.readline(LIMIT + 1)
    try:
        if len(line) > LIMIT:
            raise ValueError("request_too_large")
        result = execute(root, json.loads(line))
        print(json.dumps({"ok": True, "result": result}))
        return 0
    except (ValueError, KeyError, OSError, TypeError):
        print(json.dumps({"ok": False, "error": "relay_request_failed"}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
