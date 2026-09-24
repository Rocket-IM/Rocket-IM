"""对已明确配置的本机 helper 统一执行输入、输出与超时边界。"""

import os
import selectors
import subprocess
import time


def run_helper(path, raw, timeout, max_output, unavailable):
    process = subprocess.Popen([str(path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, cwd=path.parent,
                               env={"PATH": os.defpath, "LANG": "C.UTF-8"}, close_fds=True)
    output = bytearray()
    offset = 0
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE)
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise unavailable()
                for key, _ in selector.select(remaining):
                    if key.fileobj is process.stdin:
                        offset += os.write(process.stdin.fileno(), raw[offset:offset + 65536])
                        if offset == len(raw):
                            selector.unregister(process.stdin)
                            process.stdin.close()
                    else:
                        chunk = os.read(process.stdout.fileno(), 65536)
                        if not chunk:
                            selector.unregister(process.stdout)
                            process.stdout.close()
                        else:
                            output.extend(chunk)
                            if len(output) > max_output:
                                raise unavailable()
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
            return bytes(output), process.returncode
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=1)
        if not process.stdin.closed:
            process.stdin.close()
        if not process.stdout.closed:
            process.stdout.close()
