#!/usr/bin/env python3
"""维护者构建入口：只消费锁文件，输出预编译库、生成绑定和可追溯报告。"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[2]
WORKSPACE = ROOT / "src/sdk/rust"
OUTPUT = ROOT / "dist/platform-release"
TARGETS = ("aarch64-apple-darwin", "aarch64-apple-ios", "aarch64-apple-ios-sim",
           "x86_64-apple-ios", "aarch64-linux-android", "x86_64-linux-android",
           "wasm32-unknown-unknown")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_digests():
    return {str(p.relative_to(ROOT)): digest(p) for p in sorted(WORKSPACE.rglob("*"))
            if p.is_file() and p.suffix in (".rs", ".toml", ".lock")}


def environment(output=OUTPUT):
    env = os.environ.copy()
    env.update(CARGO_HOME=str(ROOT / "dist/toolchains/rust/cargo"),
               RUSTUP_HOME=str(ROOT / "dist/toolchains/rust/rustup"),
               CARGO_TARGET_DIR=str(output / "target"), CARGO_NET_OFFLINE="true")
    env["PATH"] = env["CARGO_HOME"] + "/bin:" + env.get("PATH", "")
    return env


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", action="append", choices=TARGETS)
    parser.add_argument("--checks", action="store_true")
    parser.add_argument("--generate-uniffi", action="store_true")
    parser.add_argument("--generate-wasm", action="store_true")
    parser.add_argument("--generate-node", action="store_true")
    parser.add_argument("--flutter-xcframework", action="store_true")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--ndk", type=Path,
                        default=Path.home() / "Library/Android/sdk/ndk/28.2.13676358")
    args = parser.parse_args()
    if not (args.target or args.checks or args.generate_uniffi or args.generate_wasm or args.generate_node or args.flutter_xcframework):
        parser.error("必须明确选择构建、检查或生成操作")
    output = args.output.resolve()
    if not output.is_relative_to((ROOT / "dist").resolve()):
        parser.error("构建输出必须位于项目dist目录内")
    output.mkdir(parents=True, exist_ok=True)
    run_id = str(uuid.uuid4())
    run = output / "rust-runs" / run_id
    run.mkdir(parents=True)
    report = {"run_id": run_id, "status": "RUNNING", "scope": "maintainer_release_build",
              "started_at": datetime.now(timezone.utc).isoformat(), "steps": [],
              "source_before": source_digests(), "outputs": {}}
    report_path = run / "report.json"
    env = environment(output)

    def save():
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")

    def execute(label, command, extra=None):
        logfile = run / (label + ".log")
        step = {"name": label, "command": command, "log": str(logfile.relative_to(ROOT))}
        report["steps"].append(step)
        save()
        with logfile.open("w") as stream:
            result = subprocess.run(command, cwd=WORKSPACE, env=env | (extra or {}),
                                    stdout=stream, stderr=subprocess.STDOUT, check=False)
        step["exit_code"] = result.returncode
        step["log_sha256"] = digest(logfile)
        save()
        if result.returncode:
            raise RuntimeError(f"{label}失败，见{logfile}")
        print("PASS", label, flush=True)

    def record(path):
        if not path.is_file():
            raise RuntimeError(f"缺少本次预编译产物：{path}")
        report["outputs"][str(path.relative_to(ROOT))] = digest(path)

    cargo = ["cargo", "+1.98.1"]
    fixed = ["--manifest-path", str(WORKSPACE / "Cargo.toml"), "--locked", "--offline"]
    try:
        if args.checks:
            execute("fmt", cargo + ["fmt", "--all", "--check"])
            execute("clippy", cargo + ["clippy", *fixed, "--workspace", "--all-targets",
                                       "--release", "--", "-D", "warnings"])
            execute("tests", cargo + ["test", *fixed, "--workspace", "--release"])
        targets = list(args.target or [])
        # Node包的生成必须绑定本次源码的Release构建，不能把缓存WASM冒充当前产物。
        if args.generate_node and "wasm32-unknown-unknown" not in targets:
            targets.append("wasm32-unknown-unknown")
        for target in targets:
            extra = {}
            packages = ["rocket-bindings-uniffi", "rocket-bindings-flutter"]
            if target.endswith("linux-android"):
                triple = "aarch64-linux-android" if target.startswith("aarch64") else "x86_64-linux-android"
                compiler = args.ndk / "toolchains/llvm/prebuilt/darwin-x86_64/bin" / (triple + "23-clang")
                if not compiler.is_file():
                    raise RuntimeError(f"缺少NDK链接器：{compiler}")
                extra["CARGO_TARGET_" + target.upper().replace("-", "_") + "_LINKER"] = str(compiler)
                extra["CARGO_TARGET_" + target.upper().replace("-", "_") + "_RUSTFLAGS"] = "-C link-arg=-Wl,-z,max-page-size=16384"
                # Cargo的Rust链接器设置不会传播给dart-sys所用的cc-rs C构建。
                extra["CC_" + target.replace("-", "_")] = str(compiler)
                extra["AR_" + target.replace("-", "_")] = str(compiler.parent / "llvm-ar")
            if target.startswith("wasm"):
                packages = ["rocket-bindings-wasm"]
            selection = [arg for package in packages for arg in ("-p", package)]
            execute("build-" + target, cargo + ["build", *fixed, "--release", "--lib",
                                                "--target", target, *selection], extra)
            folder = output / "target" / target / "release"
            if target.startswith("wasm"):
                record(folder / "rocket_stage0_wasm.wasm")
            else:
                for library in ("uniffi", "flutter"):
                    suffix = ".so" if "android" in target else ".a"
                    record(folder / ("librocket_stage0_" + library + suffix))
        if args.generate_uniffi:
            # 绑定元数据来自当前源码构建的宿主库，不能误用先前生成器/动态库。
            execute("build-uniffi-generator", cargo + ["build", *fixed, "--release",
                "-p", "rocket-bindings-uniffi", "--features", "bindgen",
                "--lib", "--bin", "rocket-uniffi-bindgen"])
            generator = output / "target/release/rocket-uniffi-bindgen"
            library = output / "target/release/librocket_stage0_uniffi.dylib"
            record(generator)
            record(library)
            config = WORKSPACE / "crates/bindings-uniffi/uniffi.toml"
            for language in ("swift", "kotlin"):
                destination = output / "generated" / language
                destination.mkdir(parents=True, exist_ok=True)
                execute("generate-" + language, [str(generator), "generate", "--library",
                    str(library), "--language", language, "--config", str(config),
                    "--out-dir", str(destination), "--no-format"])
                for path in sorted(destination.rglob("*")):
                    if path.is_file():
                        record(path)
        for generate, target, folder in ((args.generate_wasm, "web", "wasm"),
                                         (args.generate_node, "nodejs", "node")):
            if not generate:
                continue
            tool = OUTPUT / "codegen/wasm-bindgen-0.2.128-aarch64-apple-darwin/wasm-bindgen-0.2.128-aarch64-apple-darwin/wasm-bindgen"
            destination = output / "generated" / folder
            destination.mkdir(parents=True, exist_ok=True)
            execute("generate-" + folder, [str(tool), str(output / "target/wasm32-unknown-unknown/release/rocket_stage0_wasm.wasm"),
                    "--target", target, "--out-name", "rocket_stage0_wasm", "--out-dir", str(destination)])
            for path in sorted(destination.rglob("*")):
                if path.is_file():
                    record(path)
        if args.flutter_xcframework:
            directory = output / "flutter-native" / run_id
            directory.mkdir(parents=True)
            library = "librocket_stage0_flutter.a"
            simulator = directory / library
            release = output / "target"
            execute("flutter-lipo", ["xcrun", "lipo", "-create",
                str(release / "aarch64-apple-ios-sim/release" / library),
                str(release / "x86_64-apple-ios/release" / library), "-output", str(simulator)])
            # CocoaPods以framework路径声明复制输出；提供真正的静态framework目录，
            # 避免原始.a切片与其输出依赖声明不一致。二进制仍是同一Release归档。
            slices = []
            for variant, binary, platform in (
                ("device", release / "aarch64-apple-ios/release" / library, "iPhoneOS"),
                ("simulator", simulator, "iPhoneSimulator"),
            ):
                bundle = directory / variant / "RocketStage0Flutter.framework"
                bundle.mkdir(parents=True)
                shutil.copy2(binary, bundle / "RocketStage0Flutter")
                info = {"CFBundleExecutable": "RocketStage0Flutter",
                        "CFBundleIdentifier": "dev.rocketim.stage0.flutter",
                        "CFBundleName": "RocketStage0Flutter", "CFBundlePackageType": "FMWK",
                        "CFBundleVersion": "1", "CFBundleShortVersionString": "0.1.0",
                        "CFBundleSupportedPlatforms": [platform], "MinimumOSVersion": "13.0"}
                (bundle / "Info.plist").write_bytes(plistlib.dumps(info))
                slices.extend(("-framework", str(bundle)))
            framework = directory / "RocketStage0Flutter.xcframework"
            execute("flutter-xcframework", ["xcodebuild", "-create-xcframework", *slices,
                "-output", str(framework)])
            for path in sorted(framework.rglob("*")):
                if path.is_file():
                    record(path)
            report["flutter_xcframework"] = str(framework)
        report["source_after"] = source_digests()
        report["source_stable"] = report["source_before"] == report["source_after"]
        if not report["source_stable"]:
            raise RuntimeError("构建期间Rust源码变化，需按最终版本重建")
        report["status"] = "PASS"
    except Exception as error:
        report["status"] = "FAIL"
        report["error"] = str(error)
        raise
    finally:
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        save()
        print("报告：", report_path, flush=True)


if __name__ == "__main__":
    main()
