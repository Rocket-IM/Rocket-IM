#!/usr/bin/env python3
"""验证隔离密码候选；日志和临时产物仅写入 dist/crypto-probes。"""

import argparse
from datetime import datetime, timezone
import errno
from functools import partial
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib
import uuid


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "dist" / "crypto-probes"
CANDIDATES = ("vodozemac", "openmls")


def run(candidate, label, arguments, environment):
    log = OUTPUT / "logs" / f"{candidate}-{label}.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w") as output:
        output.write("command: " + " ".join(map(str, arguments)) + "\n")
        output.flush()
        result = subprocess.run(arguments, cwd=ROOT / "poc", env=environment,
                                stdout=output, stderr=subprocess.STDOUT, check=False)
    print(f"{'PASS' if result.returncode == 0 else 'FAIL'} {candidate} {label}: {log}", flush=True)
    if result.returncode:
        print(log.read_text()[-6000:], file=sys.stderr)
    return result.returncode == 0


def verify(candidate, mode):
    manifest = ROOT / "poc" / f"{candidate}-probe" / "Cargo.toml"
    lockfile = manifest.with_name("Cargo.lock")
    if not lockfile.is_file():
        raise RuntimeError(f"缺少已锁定依赖: {lockfile}")
    target = OUTPUT / "target" / candidate
    environment = {**os.environ, "CARGO_TARGET_DIR": str(target)}
    toolchain = tomllib.loads((ROOT / "poc/rust-toolchain.toml").read_text())["toolchain"]["channel"]
    cargo = ["cargo", f"+{toolchain}"]
    base = ["--manifest-path", str(manifest), "--locked"]
    if mode == "native":
        commands = [
            ("fmt", cargo + ["fmt", "--manifest-path", str(manifest), "--check"]),
            ("clippy", cargo + ["clippy", *base, "--all-targets", "--", "-D", "warnings"]),
            ("test", cargo + ["test", *base, "--release"]),
            ("run", cargo + ["run", *base, "--release"]),
        ]
        for label, arguments in commands:
            if not run(candidate, label, arguments, environment):
                return False
        return True
    if not run(candidate, "wasm-build", cargo + ["build", *base, "--release", "--lib",
                                                "--target", "wasm32-unknown-unknown"], environment):
        return False
    if shutil.which("wasm-bindgen") is None:
        raise RuntimeError("WASM 构建后仍需匹配锁文件版本的 wasm-bindgen CLI，未生成浏览器包")
    packages = tomllib.loads(lockfile.read_text())["package"]
    versions = {p["version"] for p in packages if p["name"] == "wasm-bindgen"}
    cli = subprocess.check_output(["wasm-bindgen", "--version"], text=True).strip()
    if len(versions) != 1 or cli != f"wasm-bindgen {next(iter(versions))}":
        raise RuntimeError(f"wasm-bindgen CLI 与锁文件不匹配: {cli}, {versions}")
    package = tomllib.loads(manifest.read_text())["package"]["name"].replace("-", "_")
    wasm = target / "wasm32-unknown-unknown" / "release" / f"{package}.wasm"
    output = OUTPUT / "browser" / candidate
    return run(candidate, "wasm-bindgen", ["wasm-bindgen", str(wasm), "--target", "web",
                                           "--out-dir", str(output), "--out-name", "probe"], environment)


class BrowserProbeHandler(SimpleHTTPRequestHandler):
    def send_head(self):
        # 生成目录中的符号链接也不能把工作区其他文件暴露给 HTTP 请求。
        path = Path(self.translate_path(self.path)).resolve()
        if path.is_dir():
            for name in ("index.html", "index.htm"):
                if (path / name).is_file():
                    path = (path / name).resolve()
                    break
        if not path.is_relative_to(Path(self.directory).resolve()):
            self.send_error(403, "Outside browser output directory")
            return None
        return super().send_head()

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


def serve():
    browser = OUTPUT / "browser"
    if not browser.is_dir():
        raise RuntimeError(f"浏览器产物目录不存在: {browser}；请先执行 wasm 构建")
    for name in ("index.html", "build.json"):
        if not (browser / name).is_file():
            raise RuntimeError(f"缺少浏览器产物: {browser / name}；请先执行 wasm 构建")
    handler = partial(BrowserProbeHandler, directory=str(browser))
    try:
        server = ThreadingHTTPServer(("127.0.0.1", 8765), handler)
    except OSError as error:
        if error.errno == errno.EADDRINUSE:
            raise RuntimeError("127.0.0.1:8765 已被占用；请关闭占用该端口的服务后重试") from error
        raise RuntimeError(f"无法启动本机服务 127.0.0.1:8765: {error}") from error
    with server:
        print("浏览器验证地址: http://127.0.0.1:8765/", flush=True)
        print(f"仅提供已生成目录: {browser}", flush=True)
        print("保持本终端运行；按 Ctrl+C 停止服务。此操作不重建，也不需要 Cargo。", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n本机浏览器验证服务已停止。", flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("native", "wasm", "serve"))
    parser.add_argument("--candidate", choices=CANDIDATES)
    args = parser.parse_args()
    if args.mode == "serve":
        if args.candidate:
            parser.error("serve 使用已有构建清单，不接受 --candidate")
        try:
            return serve()
        except (RuntimeError, OSError) as error:
            print(f"FAIL serve: {error}", file=sys.stderr)
            return 1
    if shutil.which("cargo") is None:
        parser.error("未找到 Cargo；请按文档提供维护者工具链，不会自动改为其他构建方式")
    candidates = (args.candidate,) if args.candidate else CANDIDATES
    build = None
    if args.mode == "wasm":
        browser = OUTPUT / "browser"
        browser.mkdir(parents=True, exist_ok=True)
        build = {"status": "building", "id": str(uuid.uuid4()),
                 "created_at": datetime.now(timezone.utc).isoformat(), "candidates": []}
        (browser / "build.json").write_text(json.dumps(build, indent=2) + "\n")
        shutil.copy2(ROOT / "poc/browser-smoke.html", browser / "index.html")
    ok = True
    for candidate in candidates:
        try:
            ok = verify(candidate, args.mode) and ok
        except (RuntimeError, OSError, subprocess.SubprocessError) as error:
            print(f"FAIL {candidate}: {error}", file=sys.stderr)
            ok = False
    if build is not None:
        build["status"] = "ready" if ok else "failed"
        if ok:
            for candidate in candidates:
                wasm = OUTPUT / "browser" / candidate / "probe_bg.wasm"
                lockfile = ROOT / "poc" / f"{candidate}-probe" / "Cargo.lock"
                build["candidates"].append({"name": candidate,
                    "wasm_sha256": hashlib.sha256(wasm.read_bytes()).hexdigest(),
                    "lock_sha256": hashlib.sha256(lockfile.read_bytes()).hexdigest()})
        (OUTPUT / "browser/build.json").write_text(json.dumps(build, indent=2) + "\n")
        if ok:
            print("浏览器装置已生成，仍须通过 HTTP 在真实浏览器执行；本脚本不将构建当成运行通过。")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
