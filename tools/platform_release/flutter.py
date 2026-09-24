#!/usr/bin/env python3
"""Flutter双端预编译包与独立消费验证；无Cargo、代码生成或源码编译兜底。"""

import argparse
import datetime
import json
from pathlib import Path
import plistlib
import re
import shutil
import tarfile
import time
import uuid
from urllib.parse import unquote, urlparse

from android import ROOT, SDK, VERSION, command, copy_rust_licenses, digest, environment, native_alignment, run_consumer

FLUTTER = Path.home() / "fvm/versions/3.41.0/bin/flutter"
ANDROID_ID = "io.rocketim.consumer.rocket_stage0_consumer"


def package(args, work, log, env):
    staged = work / "package"
    shutil.copytree(ROOT / "src/sdk/flutter", staged, ignore=shutil.ignore_patterns(".dart_tool", "build", ".gradle"))
    if not (staged / "lib/src/rust/frb_generated.dart").is_file():
        raise RuntimeError("发布包缺少已生成的FRB Dart绑定")
    for abi, library in (("arm64-v8a", args.arm64_lib), ("x86_64", args.x64_lib)):
        destination = staged / "android/src/main/jniLibs" / abi
        destination.mkdir(parents=True)
        shutil.copy2(library, destination / "librocket_stage0_flutter.so")
    framework = staged / "ios/Frameworks/RocketStage0Flutter.xcframework"
    shutil.copytree(args.ios_xcframework, framework)
    info = plistlib.loads((framework / "Info.plist").read_bytes())
    libraries = info["AvailableLibraries"]
    paths = {entry["LibraryPath"] for entry in libraries}
    if paths != {"RocketStage0Flutter.framework"}:
        raise RuntimeError("Flutter iOS包只接受明确的静态Framework XCFramework")
    architectures = {(entry.get("SupportedPlatformVariant", "device"), architecture)
                     for entry in libraries for architecture in entry["SupportedArchitectures"]}
    if not {("device", "arm64"), ("simulator", "arm64"), ("simulator", "x86_64")} <= architectures:
        raise RuntimeError("iOS XCFramework缺少要求的设备或模拟器架构")
    for entry in libraries:
        slice_framework = framework / entry["LibraryIdentifier"] / entry["LibraryPath"]
        metadata = plistlib.loads((slice_framework / "Info.plist").read_bytes())
        if metadata["CFBundleExecutable"] != "RocketStage0Flutter":
            raise RuntimeError("Flutter静态Framework二进制名称不匹配")
        if not (slice_framework / "RocketStage0Flutter").is_file():
            raise RuntimeError("Flutter静态Framework缺少二进制")
    spec = staged / "ios/rocket_im_stage0.podspec"
    copy_rust_licenses(args.output, staged / "licenses")
    command([args.flutter, "pub", "get"], staged, log, env, timeout=600)
    configuration = json.loads((staged / ".dart_tool/package_config.json").read_text())
    symbol_sources = [staged / "lib/src/rust/frb_generated.io.dart"]
    for dependency in configuration["packages"]:
        if dependency["name"] == "rocket_im_stage0":
            continue
        uri = dependency["rootUri"]
        source = Path(unquote(urlparse(uri).path)) if uri.startswith("file:") else (staged / ".dart_tool" / uri).resolve()
        if dependency["name"] == "flutter_rust_bridge":
            symbol_sources.extend(sorted((source / "lib").rglob("*.dart")))
        license_file = source / "LICENSE"
        if not license_file.is_file():
            raise RuntimeError(f"Dart运行依赖缺少LICENSE: {dependency['name']}")
        destination = staged / "licenses/dart" / source.name
        destination.mkdir(parents=True, exist_ok=True)
        shutil.copy2(license_file, destination / "LICENSE")
    # 动态Dart lookup没有静态引用；精确保留实际生成器和运行时查找的Rust符号。
    # 不把Xcode中间目录的framework内部文件额外声明为未生成的构建输入。
    exports = set()
    for source in symbol_sources:
        found = re.findall(r"_lookup<.*?>\(\s*['\"]([^'\"]+)['\"]\s*\)", source.read_text(), re.S)
        exports.update(name for name in found if name.startswith(("frb_", "frbgen_")) or name == "store_dart_post_cobject")
    if len(exports) != 17 or any(not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", name) for name in exports):
        raise RuntimeError("固定FRB 2.11.1原生符号集合与预期不一致")
    flags = " ".join(f"-Wl,-u,_{name}" for name in sorted(exports))
    spec.write_text(spec.read_text().replace("@ROCKET_IOS_RETAIN_SYMBOLS@", flags))
    (staged / "ios/ffi-exports.json").write_text(json.dumps({"symbols": sorted(exports), "flutter_rust_bridge": "2.11.1"}, indent=2) + "\n")
    shutil.rmtree(staged / ".dart_tool")
    target = work / "release" / f"rocket_im_stage0-{VERSION}.tar.gz"
    target.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(target, "w:gz") as output:
        for path in sorted(staged.iterdir()):
            output.add(path, arcname=path.name)
    installed = work / "installed-package"
    installed.mkdir()
    with tarfile.open(target, "r:gz") as source:
        source.extractall(installed, filter="data")
    return {"package": str(target), "package_sha256": digest(target), "ios_architectures": sorted(architectures), "ios_ffi_exports": sorted(exports),
            "android_libraries": {"arm64-v8a": digest(args.arm64_lib), "x86_64": digest(args.x64_lib)}}


def prepare_consumer(args, work, log, env):
    consumer = work / "consumer"
    command([args.flutter, "create", "--platforms=android,ios", "--org", "io.rocketim.consumer", "--project-name",
             "rocket_stage0_consumer", "--no-pub", consumer], work, log, env, timeout=300)
    template = ROOT / "tests/consumers/flutter"
    shutil.copy2(template / "pubspec.yaml", consumer / "pubspec.yaml")
    shutil.copy2(template / ".fvmrc", consumer / ".fvmrc")
    shutil.copy2(template / "analysis_options.yaml", consumer / "analysis_options.yaml")
    shutil.rmtree(consumer / "lib")
    shutil.copytree(template / "lib", consumer / "lib")
    if (consumer / "test").exists():
        shutil.rmtree(consumer / "test")
    command([args.flutter, "pub", "get"], consumer, log, env, timeout=600)
    # 消费锁文件和解析后的包路径记录留在独立consumer目录，不触碰SDK源码。
    configuration = json.loads((consumer / ".dart_tool/package_config.json").read_text())
    sdk = next(entry for entry in configuration["packages"] if entry["name"] == "rocket_im_stage0")
    resolved = ((consumer / ".dart_tool") / sdk["rootUri"]).resolve() if not sdk["rootUri"].startswith("file:") else Path(sdk["rootUri"].removeprefix("file://")).resolve()
    if resolved != (work / "installed-package").resolve():
        raise RuntimeError("消费者没有解析到已解压的Release包")
    command([args.flutter, "analyze", "--no-pub"], consumer, log, env, timeout=180)
    return consumer


def android(args, consumer, work, run_id, log, env):
    rejected = None
    if not args.no_run:
        negative_id = f"{run_id}-version"
        command([args.flutter, "build", "apk", "--release", "--target-platform", "android-arm64,android-x64",
                 f"--dart-define=RUN_ID={negative_id}", "--dart-define=NEGATIVE_VERSION=true", "--no-pub"], consumer, log, env, timeout=1200)
        rejected = run_consumer(consumer / "build/app/outputs/flutter-apk/app-release.apk", ANDROID_ID, ".MainActivity",
                                negative_id, args.output, args.android_sdk, log, env, marker="flutter")
    command([args.flutter, "build", "apk", "--release", "--target-platform", "android-arm64,android-x64",
             f"--dart-define=RUN_ID={run_id}", "--no-pub"], consumer, log, env, timeout=1200)
    apk = consumer / "build/app/outputs/flutter-apk/app-release.apk"
    result = {"apk": str(apk), "apk_sha256": digest(apk), "native": native_alignment(apk, args.android_sdk, work, log, env)}
    if not args.no_run:
        result["runtime"] = run_consumer(apk, ANDROID_ID, ".MainActivity", run_id, args.output, args.android_sdk, log, env, marker="flutter")
        result["version_rejected"] = rejected
    return result


def simulator_result(simulator, bundle, run_id, consumer, log, env):
    # iOS上的Flutter日志进入Unified Logging，simctl --console不会稳定转发Dart输出。
    command(["xcrun", "simctl", "launch", "--terminate-running-process", simulator, bundle], consumer, log, env, timeout=30)
    predicate = f'process == "Runner" AND eventMessage CONTAINS "ROCKET_STAGE0_RESULT:" AND eventMessage CONTAINS "{run_id}"'
    expected_scenario = "version-rejected" if run_id.endswith("-version") else "public-api"
    expected_checks = 2 if expected_scenario == "version-rejected" else 8
    deadline = time.monotonic() + 120
    try:
        while time.monotonic() < deadline:
            data, _ = command(["xcrun", "simctl", "spawn", simulator, "log", "show", "--style", "compact", "--last", "3m",
                               "--info", "--debug", "--predicate", predicate], consumer, log, env, timeout=30)
            for line in data.splitlines():
                if "ROCKET_STAGE0_RESULT:" not in line or "{" not in line:
                    continue
                result = json.loads(line.split("ROCKET_STAGE0_RESULT:", 1)[1])
                if result.get("run_id") != run_id:
                    continue
                if (result.get("scenario"), result.get("checks"), result.get("package_version"), result.get("platform")) != (expected_scenario, expected_checks, VERSION, "flutter"):
                    raise RuntimeError(f"iOS消费者场景不匹配: {result}")
                if result.get("status") != "passed":
                    raise RuntimeError(f"iOS独立消费失败: {result}")
                return result
            time.sleep(1)
        raise RuntimeError("iOS消费者未在120秒内给出本次结果")
    finally:
        command(["xcrun", "simctl", "terminate", simulator, bundle], consumer, log, env, timeout=20, check=False)


def ios(args, consumer, run_id, log, env):
    # Release设备App验证预编译静态库链接；真实运行在专用模拟器内消费同一Release库。
    command([args.flutter, "build", "ios", "--release", "--no-codesign", f"--dart-define=RUN_ID={run_id}", "--no-pub"], consumer, log, env, timeout=1200)
    device_app = consumer / "build/ios/iphoneos/Runner.app"
    result = {"device_release_binary_sha256": digest(device_app / "Runner")}
    if not args.no_run:
        if not args.ios_simulator:
            raise RuntimeError("真实iOS运行须显式指定专用--ios-simulator；不自动操作其他模拟器")
        negative_id = f"{run_id}-version"
        command([args.flutter, "build", "ios", "--simulator", "--debug", "--no-codesign", f"--dart-define=RUN_ID={negative_id}",
                 "--dart-define=NEGATIVE_VERSION=true", "--no-pub"], consumer, log, env, timeout=1200)
        negative_app = consumer / "build/ios/iphonesimulator/Runner.app"
        bundle = plistlib.loads((negative_app / "Info.plist").read_bytes())["CFBundleIdentifier"]
        command(["xcrun", "simctl", "boot", args.ios_simulator], consumer, log, env, timeout=30, check=False)
        command(["xcrun", "simctl", "bootstatus", args.ios_simulator, "-b"], consumer, log, env, timeout=180)
        command(["xcrun", "simctl", "install", args.ios_simulator, negative_app], consumer, log, env, timeout=60)
        result["version_rejected"] = simulator_result(args.ios_simulator, bundle, negative_id, consumer, log, env)
    command([args.flutter, "build", "ios", "--simulator", "--debug", "--no-codesign", f"--dart-define=RUN_ID={run_id}", "--no-pub"], consumer, log, env, timeout=1200)
    app = consumer / "build/ios/iphonesimulator/Runner.app"
    info = plistlib.loads((app / "Info.plist").read_bytes())
    bundle = info["CFBundleIdentifier"]
    result.update(simulator_app=str(app), simulator_binary_sha256=digest(app / "Runner"), bundle_id=bundle)
    if not args.no_run:
        if not args.ios_simulator:
            raise RuntimeError("真实iOS运行须显式指定专用--ios-simulator；不自动操作其他模拟器")
        command(["xcrun", "simctl", "boot", args.ios_simulator], consumer, log, env, timeout=30, check=False)
        command(["xcrun", "simctl", "bootstatus", args.ios_simulator, "-b"], consumer, log, env, timeout=180)
        command(["xcrun", "simctl", "install", args.ios_simulator, app], consumer, log, env, timeout=60)
        result["runtime"] = simulator_result(args.ios_simulator, bundle, run_id, consumer, log, env)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/platform-release")
    parser.add_argument("--arm64-lib", type=Path, required=True)
    parser.add_argument("--x64-lib", type=Path, required=True)
    parser.add_argument("--ios-xcframework", type=Path, required=True)
    parser.add_argument("--ios-simulator")
    parser.add_argument("--android-sdk", type=Path, default=SDK)
    parser.add_argument("--flutter", type=Path, default=FLUTTER)
    parser.add_argument("--platform", choices=("android", "ios", "all"), default="all")
    parser.add_argument("--no-run", action="store_true")
    args = parser.parse_args()
    args.output = args.output.resolve()
    run_id = str(uuid.uuid4())
    work = args.output / "runs" / f"flutter-{run_id}"
    work.mkdir(parents=True)
    log = work / "build.log"
    result = {"run_id": run_id, "version": VERSION, "platform": "flutter", "status": "failed", "log": str(log),
              "started_at": datetime.datetime.now(datetime.UTC).isoformat()}
    try:
        env = environment(args.output, args.android_sdk)
        env["FLUTTER_SUPPRESS_ANALYTICS"] = "true"
        result["flutter"] = json.loads((args.flutter.parent / "cache/flutter.version.json").read_text())
        if result["flutter"]["frameworkVersion"] != "3.41.0":
            raise RuntimeError("本次消费基线固定Flutter3.41.0")
        result.update(package(args, work, log, env))
        consumer = prepare_consumer(args, work, log, env)
        if args.platform in ("android", "all"):
            result["android"] = android(args, consumer, work, run_id, log, env)
        if args.platform in ("ios", "all"):
            result["ios"] = ios(args, consumer, run_id, log, env)
        published = args.output / "packages/flutter" / Path(result["package"]).name
        published.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(result["package"], published)
        result["published_package"] = str(published)
        result["status"] = "built" if args.no_run else "passed"
    except Exception as error:
        result["error"] = str(error)
    result["finished_at"] = datetime.datetime.now(datetime.UTC).isoformat()
    (work / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(result, ensure_ascii=False), flush=True)
    return 1 if result["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
