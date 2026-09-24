#!/usr/bin/env python3
"""打包阶段0浏览器SDK，并从tgz安装到独立消费目录执行真实Chrome验证。"""

import argparse
from datetime import datetime, timezone
from functools import partial
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import uuid

ROOT = Path(__file__).resolve().parents[2]
VERSION = "0.1.0-stage0.1"
PACKAGE = ROOT / "src/sdk/typescript"
TEMPLATE = ROOT / "tests/consumers/browser"
DEFAULT_OUTPUT = ROOT / "dist/platform-release/browser"
WASM_NAME = "rocket_stage0_wasm_bg.wasm"
NPM_CACHE = Path(os.environ.get("ROCKET_IM_NPM_CACHE", ROOT / "dist/platform-release/npm-cache")).resolve()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def source_hashes():
    paths = [Path(__file__).resolve()]
    for directory in (PACKAGE, TEMPLATE):
        paths.extend(p for p in directory.rglob("*") if p.is_file() and "node_modules" not in p.parts)
    return {str(p.relative_to(ROOT)):sha(p) for p in sorted(paths)}


def command(args, directory, log):
    environment = os.environ.copy()
    if Path(args[0]).name == "npm":
        environment.update(npm_config_cache=str(NPM_CACHE), npm_config_update_notifier="false")
    result = subprocess.run([str(arg) for arg in args], cwd=directory, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180, env=environment)
    log.write_text(result.stdout)
    if result.returncode:
        raise RuntimeError(f"{Path(args[0]).name} exit={result.returncode}; log={log}")
    return result.stdout


def pack(args):
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=True)
    compiler = PACKAGE / "node_modules/typescript/bin/tsc"
    compiler_package = compiler.parent.parent / "package.json"
    if not compiler.is_file() or json.loads(compiler_package.read_text())["version"] != "5.9.3":
        raise RuntimeError("维护者须先按package-lock安装固定TypeScript 5.9.3；不静默跳过严格编译")
    required = ["rocket_stage0_wasm.js", "rocket_stage0_wasm.d.ts", WASM_NAME]
    for name in required:
        if not (args.generated / name).is_file():
            raise RuntimeError("缺少真实wasm-bindgen产物：" + str(args.generated / name))
    if (args.generated / WASM_NAME).read_bytes()[:8] != b"\0asm\x01\0\0\0":
        raise RuntimeError("产物不是WebAssembly模块")
    with tempfile.TemporaryDirectory(prefix="browser-package-", dir=output) as temporary:
        stage = Path(temporary) / "package"
        shutil.copytree(PACKAGE, stage, ignore=shutil.ignore_patterns("generated", "node_modules", "dist"))
        generated = stage / "src/generated"; generated.mkdir()
        for source in args.generated.iterdir():
            if source.is_file() and source.suffix in (".js", ".ts", ".wasm"):
                shutil.copy2(source, generated / source.name)
        command(["node", compiler, "-p", stage / "tsconfig.json"], stage, output / "typescript-build.log")
        shutil.copytree(generated, stage / "dist/generated")
        shutil.copytree(args.licenses, stage / "licenses")
        compiler_license = stage / "licenses/typescript-5.9.3"; compiler_license.mkdir()
        shutil.copy2(compiler.parent.parent / "LICENSE.txt", compiler_license / "LICENSE.txt")
        shutil.copy2(ROOT / "dist/platform-release/typescript-metadata.json", compiler_license / "metadata.json")
        inputs = {str(path.relative_to(stage)): sha(path) for directory in (stage / "dist", stage / "licenses")
                  for path in sorted(directory.rglob("*")) if path.is_file()}
        inputs["package.json"] = sha(stage / "package.json")
        write_json(stage / "artifact.json", {"version": VERSION, "target": "wasm32-unknown-unknown",
                   "scope": "stage0 independent in-memory devices", "files_sha256": inputs})
        packed = json.loads(command(["npm", "pack", "--json", "--ignore-scripts", "--pack-destination", output],
                                    stage, output / "npm-pack.log"))
        archive = output / packed[0]["filename"]
    report = {"status": "PASS", "phase": "pack", "run_id":str(uuid.uuid4()), "version": VERSION, "archive": str(archive),
              "sha256": sha(archive), "generated_sha256": {name: sha(args.generated / name) for name in required}}
    write_json(output / "package-report.json", report); print(json.dumps(report, ensure_ascii=False))


NODE_RUNNER = r'''const fs = require("fs");
const {chromium} = require(process.argv[2]);
(async () => {
  const browser = await chromium.launch({executablePath:process.argv[3], headless:true});
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    const consoleMessages=[];
    page.on("console", message => consoleMessages.push({type:message.type(),text:message.text()}));
    page.on("pageerror", error => consoleMessages.push({type:"pageerror",text:String(error)}));
    await page.goto(process.argv[4], {waitUntil:"load"});
    await page.waitForFunction(() => window.__stage0Result !== undefined, {timeout:60000});
    const result = await page.evaluate(() => window.__stage0Result);
    await page.screenshot({path:process.argv[5], fullPage:true});
    console.log(JSON.stringify({...result,console:consoleMessages}));
  } finally { await browser.close(); }
})().catch(error => {console.error(error);process.exitCode=1;});
'''


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def verify(args):
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=True)
    run_id = str(uuid.uuid4())
    consumer = output / "consumers" / run_id
    shutil.copytree(TEMPLATE, consumer)
    report = {"run_id": run_id, "status": "RUNNING", "target": "real Chrome / browser WASM",
              "executed_at": datetime.now(timezone.utc).isoformat(), "archive": str(args.archive.resolve()),
              "archive_sha256": sha(args.archive), "consumer": str(consumer), "cases": [],
              "source_sha256_before":source_hashes()}
    report_path = output / ("run-" + run_id + ".json")
    server = None
    try:
        if not args.playwright_module.exists() or not args.browser.exists():
            raise RuntimeError("缺少指定的Playwright模块或Chrome程序；不会自动下载")
        command(["npm", "install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", args.archive.resolve()],
                consumer, consumer / "npm-install.log")
        command(["npm", "run", "build"], consumer, consumer / "typescript-build.log")
        installed = consumer / "node_modules/@rocket-im/stage0"
        package = json.loads((installed / "package.json").read_text())
        if package["version"] != VERSION or package["name"] != "@rocket-im/stage0":
            raise RuntimeError("独立消费安装的包名称或版本不符")
        manifest = json.loads((installed / "artifact.json").read_text())
        if manifest["version"] != VERSION or any(sha(installed / path) != digest for path,digest in manifest["files_sha256"].items()):
            raise RuntimeError("安装后SDK版本或文件摘要不符")
        runner = consumer / "run-browser.cjs"; runner.write_text(NODE_RUNNER)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), partial(QuietHandler, directory=str(consumer)))
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        url = f"http://127.0.0.1:{server.server_port}/index.html"

        def run_case(name):
            result = json.loads(command(["node", runner, args.playwright_module.resolve(), args.browser.resolve(), url,
                                         consumer / (name + ".png")], consumer, consumer / (name + ".log")))
            record = {"name": name, **result}
            report["cases"].append(record); write_json(report_path, report)
            return record

        normal = run_case("public_api")
        if normal["status"] != "PASS" or len(normal["checks"]) < 10:
            raise RuntimeError("真实浏览器公共API消费失败")
        wasm = installed / "dist/generated" / WASM_NAME
        hidden = wasm.with_suffix(".unavailable")
        wasm.rename(hidden)
        try:
            missing = run_case("missing_wasm")
            if missing["status"] != "FAIL" or "wasm_initialization_failed" not in missing.get("error", ""):
                raise RuntimeError("缺少包内WASM时没有明确失败")
            missing["expected_failure"] = True
        finally:
            hidden.rename(wasm)
        entry = installed / "dist/index.js"; original = entry.read_text()
        changed = original.replace(f'export const SDK_VERSION = "{VERSION}";', 'export const SDK_VERSION = "0.0.0-invalid";')
        if changed == original:
            raise RuntimeError("版本不匹配故障没有注入消费副本")
        entry.write_text(changed)
        try:
            mismatch = run_case("mismatched_version")
            if mismatch["status"] != "FAIL" or "sdk_version_mismatch" not in mismatch.get("error", ""):
                raise RuntimeError("JS包与WASM版本不匹配时没有明确失败")
            mismatch["expected_failure"] = True
        finally:
            entry.write_text(original)
        report.update(status="PASS", version=VERSION, browser=normal["browser"],
                      package_sha256={str(p.relative_to(installed)):sha(p) for p in sorted(installed.rglob("*")) if p.is_file()},
                      source_dependency="消费目录仅从tgz安装；无Rust源码或生成器")
    except Exception as error:
        report.update(status="FAIL", error=str(error))
    finally:
        if server is not None:
            server.shutdown(); server.server_close()
        report["source_sha256_after"] = source_hashes()
        report["archive_sha256_after"] = sha(args.archive)
        report["inputs_unchanged"] = (report["source_sha256_before"] == report["source_sha256_after"]
                                      and report["archive_sha256"] == report["archive_sha256_after"])
        if not report["inputs_unchanged"]:
            report.update(status="FAIL", error="验证期间源码或已打包SDK改变")
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        write_json(report_path, report); write_json(output / "latest.json", report)
    print(json.dumps({"status":report["status"], "run_id":run_id, "report":str(report_path),
                      "cases":len(report["cases"]), "error":report.get("error")}, ensure_ascii=False))
    return 0 if report["status"] == "PASS" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    package = sub.add_parser("pack"); package.add_argument("--generated", type=Path, required=True)
    package.add_argument("--licenses", type=Path, default=ROOT / "dist/platform-release/licenses")
    package.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    test = sub.add_parser("verify"); test.add_argument("--archive", type=Path, required=True)
    test.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    test.add_argument("--browser", type=Path, default=Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"))
    test.add_argument("--playwright-module", type=Path, default=Path.home() / ".cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright")
    args = parser.parse_args()
    return pack(args) if args.operation == "pack" else verify(args)


if __name__ == "__main__":
    raise SystemExit(main())
