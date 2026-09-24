#!/usr/bin/env python3
"""构建隔离 Q05 实验包；不修改已验收的四端 SDK 与消费产物。"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = Path(os.environ.get("ROCKET_IM_BROWSER_STORAGE_OUTPUT", ROOT / "dist/browser-storage")).resolve()
CRATE = ROOT / "poc/browser-storage"
COMPILER = ROOT / "src/sdk/typescript/node_modules/typescript/bin/tsc"
BINDGEN = ROOT / "dist/platform-release/codegen/wasm-bindgen-0.2.128-aarch64-apple-darwin/wasm-bindgen-0.2.128-aarch64-apple-darwin/wasm-bindgen"
NDK = Path("/Users/amant/Library/Android/sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/darwin-x86_64/bin")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def sources():
    result = {}
    for folder in (CRATE, ROOT / "tools/browser_storage", ROOT / "tests/consumers/browser-storage"):
        for path in sorted(folder.rglob("*")):
            if path.is_file() and not any(x in path.parts for x in ("node_modules", "target", "__pycache__", "generated", "dist")):
                result[str(path.relative_to(ROOT))] = sha(path)
    return result


def environment():
    env = os.environ.copy()
    env.update(CARGO_HOME=str(ROOT / "dist/toolchains/rust/cargo"),
               RUSTUP_HOME=str(ROOT / "dist/toolchains/rust/rustup"),
               CARGO_NET_OFFLINE="true", PATH=str(ROOT / "dist/toolchains/rust/cargo/bin") + os.pathsep + env["PATH"],
               CC_wasm32_unknown_unknown=str(NDK / "clang"), AR_wasm32_unknown_unknown=str(NDK / "llvm-ar"),
               npm_config_cache=str(OUTPUT / "npm-cache"), npm_config_update_notifier="false")
    return env


def run(args, cwd, log, timeout=240):
    with log.open("w") as output:
        result = subprocess.run([str(a) for a in args], cwd=cwd, env=environment(),
                                stdout=output, stderr=subprocess.STDOUT, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{Path(args[0]).name} exit={result.returncode}; {log}")
    return log.read_text()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", default=str(uuid.uuid4()))
    args = parser.parse_args()
    output = OUTPUT / "builds" / args.run_id
    output.mkdir(parents=True, exist_ok=False)
    report = {"run_id": args.run_id, "status": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat(),
              "scope": "isolated Q05 OpenMLS SQLite transactions, rollback anchor and approved unique browser successor; synthetic local identities and recovery authority only", "source_sha256_before": sources()}
    try:
        if json.loads((COMPILER.parent.parent / "package.json").read_text())["version"] != "5.9.3":
            raise RuntimeError("需要现有锁定的 TypeScript 5.9.3")
        run(["cargo", "+1.98.1", "fmt", "--manifest-path", CRATE / "Cargo.toml", "--check"], ROOT, output / "format.log")
        cargo = ["cargo", "+1.98.1", "clippy", "--manifest-path", CRATE / "Cargo.toml", "--locked", "--offline",
                 "--target", "wasm32-unknown-unknown", "--target-dir", OUTPUT / "target", "--release"]
        run(cargo + ["--", "-D", "warnings"], ROOT, output / "clippy.log")
        cargo[2] = "build"
        run(cargo, ROOT, output / "rust-build.log")
        stage = output / "package"
        shutil.copytree(CRATE / "package", stage, ignore=shutil.ignore_patterns("generated", "dist", "node_modules"))
        generated = stage / "generated"
        wasm = OUTPUT / "target/wasm32-unknown-unknown/release/rocket_browser_storage_probe.wasm"
        run([BINDGEN, "--target", "web", "--out-dir", generated, wasm], ROOT, output / "bindgen.log")
        run(["node", COMPILER, "-p", stage / "tsconfig.json"], stage, output / "typescript.log")
        run(["python3", ROOT / "tools/browser_storage/licenses.py", "--output", stage / "licenses"], ROOT, output / "licenses.log")
        licensing = json.loads((stage / "licenses/dependencies.json").read_text())
        report["license_collection"] = {key: licensing.get(key) for key in ("license_review_status", "distribution_approval", "collection_complete", "counts")}
        manifest = {str(p.relative_to(stage)): sha(p) for folder in (stage / "dist", generated, stage / "licenses")
                    for p in sorted(folder.rglob("*")) if p.is_file()}
        manifest["package.json"] = sha(stage / "package.json")
        write_json(stage / "artifact.json", {"run_id": args.run_id, "scope": report["scope"], "files_sha256": manifest,
                   "source_sha256": report["source_sha256_before"]})
        packed = json.loads(run(["npm", "pack", "--offline", "--json", "--ignore-scripts", "--pack-destination", output],
                                stage, output / "npm-pack.log"))
        archive = output / packed[0]["filename"]
        report.update(status="PASS", archive=str(archive), archive_sha256=sha(archive), files_sha256=manifest,
                      toolchain={"rust": "1.98.1", "wasm_bindgen": "0.2.128", "typescript": "5.9.3", "c_compiler": str(NDK / "clang")})
    except Exception as error:
        report.update(status="FAIL", error=str(error))
    report["source_sha256_after"] = sources()
    report["sources_unchanged"] = report["source_sha256_before"] == report["source_sha256_after"]
    if not report["sources_unchanged"]:
        report.update(status="FAIL", error="构建期间源码发生变化，产物不能作为最终验收依据")
    write_json(output / "report.json", report)
    print(json.dumps({k: v for k, v in report.items() if k not in ("files_sha256", "source_sha256_before", "source_sha256_after")}, ensure_ascii=False))
    raise SystemExit(0 if report["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
