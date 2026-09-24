#!/usr/bin/env python3
"""维护者生成Flutter绑定；固定生成器，不安装依赖、不改版本、不启用源码回退。"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "dist/platform-release"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--flutter-sdk", type=Path, default=Path.home() / "fvm/versions/3.41.0")
    args = parser.parse_args()
    codegen = OUTPUT / "codegen/flutter_rust_bridge_codegen-aarch64-apple-darwin-v2.11.1/flutter_rust_bridge_codegen"
    expand = OUTPUT / "codegen/bin/cargo-expand"
    for path in (codegen, expand, args.flutter_sdk / "bin/dart"):
        if not path.is_file():
            raise RuntimeError("缺少已固定的维护者工具：" + str(path))
    version = subprocess.check_output([str(codegen), "--version"], text=True).strip()
    if version != "flutter_rust_bridge_codegen 2.11.1":
        raise RuntimeError("FRB生成器版本不匹配：" + version)
    run_id = str(uuid.uuid4())
    output = OUTPUT / "flutter-generation" / run_id
    output.mkdir(parents=True)
    env = os.environ.copy()
    env.update(CARGO_HOME=str(ROOT / "dist/toolchains/rust/cargo"),
               RUSTUP_HOME=str(ROOT / "dist/toolchains/rust/rustup"),
               CARGO_TARGET_DIR=str(OUTPUT / "target"), CARGO_NET_OFFLINE="true",
               FLUTTER_SUPPRESS_ANALYTICS="true", DART_SUPPRESS_ANALYTICS="true")
    env["PATH"] = os.pathsep.join((str(expand.parent), env["CARGO_HOME"] + "/bin",
                                  str(args.flutter_sdk / "bin"), env.get("PATH", "")))
    command = [str(codegen), "generate", "--rust-input", "crate::api",
               "--rust-root", "src/sdk/rust/crates/bindings-flutter",
               "--rust-output", "src/sdk/rust/crates/bindings-flutter/src/frb_generated.rs",
               "--dart-output", "src/sdk/flutter/lib/src/rust", "--dart-root", "src/sdk/flutter",
               "--no-web", "--no-deps-check", "--no-auto-upgrade-dependency", "--no-dart-fix",
               "--no-dart-format", "--no-rust-format", "--stop-on-error"]
    report = {"run_id": run_id, "status": "RUNNING", "version": version,
              "started_at": datetime.now(timezone.utc).isoformat(), "command": command,
              "codegen_sha256": digest(codegen), "expand_sha256": digest(expand)}
    try:
        with (output / "generate.log").open("w") as log:
            subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        with (output / "format.log").open("w") as log:
            subprocess.run(["cargo", "+1.98.1", "fmt", "--manifest-path", "src/sdk/rust/Cargo.toml", "--all"],
                           cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        paths = list((ROOT / "src/sdk/flutter/lib/src/rust").glob("*.dart"))
        paths.append(ROOT / "src/sdk/rust/crates/bindings-flutter/src/frb_generated.rs")
        report["generated_sha256"] = {str(p.relative_to(ROOT)): digest(p) for p in paths}
        report["status"] = "PASS"
    except Exception as error:
        report["status"] = "FAIL"
        report["error"] = str(error)
        raise
    finally:
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        (output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        print(output / "report.json")


if __name__ == "__main__":
    main()
