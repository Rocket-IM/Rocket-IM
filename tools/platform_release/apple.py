#!/usr/bin/env python3
"""组合真实Release XCFramework，并从zip消费Swift包执行独立iOS应用。"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import time
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[2]
VERSION = "0.1.0-stage0.1"
DEFAULT_OUTPUT = ROOT / "dist/platform-release/swift"
FRAMEWORK = "RocketIMStage0FFI.xcframework"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def source_hashes():
    paths = [Path(__file__).resolve()]
    for directory in (ROOT / "src/sdk/swift", ROOT / "tests/consumers/swift"):
        paths.extend(p for p in directory.rglob("*") if p.is_file())
    return {str(p.relative_to(ROOT)):sha(p) for p in sorted(paths)}


def command(args, directory, log, *, expected=0, timeout=240):
    result = subprocess.run([str(arg) for arg in args], cwd=directory, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    log.write_text(result.stdout)
    if (result.returncode == 0) != (expected == 0):
        raise RuntimeError(f"{Path(args[0]).name} exit={result.returncode}; log={log}")
    return result.stdout


def pack(args):
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=True)
    run_id = str(uuid.uuid4()); logs = output / ("pack-" + run_id); logs.mkdir()
    libraries = {name:getattr(args, name).resolve() for name in ("device_lib", "sim_arm64_lib", "sim_x86_64_lib")}
    for path in libraries.values():
        if not path.is_file():
            raise RuntimeError("缺少实际预编译库：" + str(path))
    swift = list(args.generated.glob("*.swift")); headers = list(args.generated.glob("*.h"))
    maps = list(args.generated.glob("*.modulemap"))
    if not swift or not headers or len(maps) != 1:
        raise RuntimeError("需要真实UniFFI Swift、C header和唯一modulemap，不能使用占位绑定")
    with tempfile.TemporaryDirectory(prefix="swift-package-", dir=output) as temporary:
        stage = Path(temporary)
        package = stage / "RocketIMStage0"
        generated = package / "Sources/RocketIMStage0/Generated"; generated.mkdir(parents=True)
        shutil.copy2(ROOT / "src/sdk/swift/Package.swift", package / "Package.swift")
        for path in (ROOT / "src/sdk/swift/Sources/RocketIMStage0").glob("*.swift"):
            shutil.copy2(path, generated.parent / path.name)
        for path in swift:
            shutil.copy2(path, generated / path.name)
        shutil.copytree(args.licenses, package / "licenses")
        include = stage / "headers"; include.mkdir()
        for path in headers:
            shutil.copy2(path, include / path.name)
        shutil.copy2(maps[0], include / "module.modulemap")
        simulator = stage / "librocket_stage0_uniffi.a"
        command(["xcrun", "lipo", "-create", libraries["sim_arm64_lib"], libraries["sim_x86_64_lib"], "-output", simulator],
                ROOT, logs / "lipo.log")
        arches = {"device": command(["xcrun", "lipo", "-archs", libraries["device_lib"]], ROOT, logs / "device-arches.log").strip(),
                  "simulator": command(["xcrun", "lipo", "-archs", simulator], ROOT, logs / "simulator-arches.log").strip()}
        if set(arches["device"].split()) != {"arm64"} or set(arches["simulator"].split()) != {"arm64", "x86_64"}:
            raise RuntimeError("真实原生库架构与要求不符")
        artifacts = package / "Artifacts"; artifacts.mkdir()
        command(["xcodebuild", "-create-xcframework", "-library", libraries["device_lib"], "-headers", include,
                 "-library", simulator, "-headers", include, "-output", artifacts / FRAMEWORK], ROOT, logs / "xcframework.log")
        info = plistlib.loads((artifacts / FRAMEWORK / "Info.plist").read_bytes())
        manifest = {"version": VERSION, "architectures": arches, "xcframework_libraries": info["AvailableLibraries"],
                    "files_sha256": {str(p.relative_to(package)):sha(p) for p in sorted(package.rglob("*")) if p.is_file()}}
        write_json(package / "artifact.json", manifest)
        archive = output / ("RocketIMStage0-" + VERSION + ".zip")
        # Cargo归档可保留早于1980年的可复现时间戳；ZIP仅规范元数据，许可证正文不变。
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, strict_timestamps=False) as bundle:
            for path in sorted(package.rglob("*")):
                if path.is_file():
                    bundle.write(path, path.relative_to(stage))
    report = {"status":"PASS", "phase":"pack", "run_id":run_id, "version":VERSION,
              "archive":str(archive), "archive_sha256":sha(archive), "architectures":arches,
              "input_libraries_sha256":{name:sha(path) for name,path in libraries.items()}}
    write_json(logs / "report.json", report); write_json(output / "package-report.json", report)
    print(json.dumps(report, ensure_ascii=False))


def extract(archive, destination):
    with zipfile.ZipFile(archive) as bundle:
        for item in bundle.infolist():
            target = (destination / item.filename).resolve()
            if not target.is_relative_to(destination.resolve()) or (item.external_attr >> 16) & 0o170000 == 0o120000:
                raise RuntimeError("SDK压缩包包含越界路径或符号链接")
        bundle.extractall(destination)


def verify(args):
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=True)
    run_id = str(uuid.uuid4())
    consumer = output / "consumers" / run_id
    shutil.copytree(ROOT / "tests/consumers/swift", consumer)
    vendor = consumer / "Vendor"; vendor.mkdir(); extract(args.archive, vendor)
    package = vendor / "RocketIMStage0"
    report = {"run_id":run_id, "status":"RUNNING", "version":VERSION, "archive":str(args.archive.resolve()),
              "archive_sha256":sha(args.archive), "consumer":str(consumer), "cases":[],
              "source_sha256_before":source_hashes(),
              "executed_at":datetime.now(timezone.utc).isoformat(), "physical_ios_runtime":"NOT_TESTED"}
    report_path = output / ("run-" + run_id + ".json")
    device = None; booted_here = False; installed = []
    try:
        report["tools"] = {"xcode":command(["xcodebuild", "-version"], ROOT, consumer / "xcode-version.log").strip(),
                           "swift":command(["xcrun", "swift", "--version"], ROOT, consumer / "swift-version.log").strip()}
        manifest = json.loads((package / "artifact.json").read_text())
        if manifest["version"] != VERSION or any(sha(package / path) != digest for path,digest in manifest["files_sha256"].items()):
            raise RuntimeError("已解压SDK版本或文件摘要不符")
        if any(package.rglob("*.rs")) or any(package.rglob("Cargo.toml")):
            raise RuntimeError("消费者SDK错误携带Rust源码构建依赖")
        available = json.loads(command(["xcrun", "simctl", "list", "devices", "available", "--json"],
                                       ROOT, consumer / "simulators.log"))["devices"]
        choices = [(runtime, item) for runtime,items in available.items() for item in items if item.get("isAvailable")]
        selected = next(((runtime,item) for runtime,item in choices if item["udid"] == args.device), None) if args.device else next(
            ((runtime,item) for runtime,item in choices if item["state"] == "Shutdown" and item["name"].startswith("iPhone")), None)
        if selected is None:
            raise RuntimeError("没有指定或可用的既有iPhone模拟器；不自动创建设备")
        runtime, target = selected; device = target["udid"]
        report["target"] = {"runtime":runtime, **{name:target[name] for name in ("udid","name","state")}}
        project = consumer / "Stage0Consumer.xcodeproj"

        def build(name, bundle_id, *, generic=False, expected=0):
            derived = consumer / ("DerivedData-" + name)
            destination = "generic/platform=iOS" if generic else "id=" + device
            command(["xcodebuild", "-project", project, "-scheme", "Stage0Consumer", "-configuration", "Release",
                     "-sdk", "iphoneos" if generic else "iphonesimulator", "-destination", destination,
                     "-derivedDataPath", derived, "-disableAutomaticPackageResolution", "CODE_SIGNING_ALLOWED=NO",
                     "PRODUCT_BUNDLE_IDENTIFIER=" + bundle_id, "build"], consumer, consumer / (name + "-build.log"), expected=expected)
            return derived / "Build/Products" / ("Release-iphoneos" if generic else "Release-iphonesimulator") / "Stage0Consumer.app"

        base_bundle = "dev.rocketim.stage0.consumer.r" + run_id.replace("-", "")[:12]
        application = build("public_api", base_bundle + ".normal")
        report["cases"].append({"name":"simulator_release_build", "status":"PASS"})
        build("device_release", base_bundle + ".device", generic=True)
        report["cases"].append({"name":"unsigned_device_release_build", "status":"PASS", "runtime":"NOT_TESTED"})
        if target["state"] == "Shutdown":
            command(["xcrun", "simctl", "boot", device], ROOT, consumer / "boot.log")
            booted_here = True
        command(["xcrun", "simctl", "bootstatus", device, "-b"], ROOT, consumer / "bootstatus.log", timeout=180)

        def run_application(name, path, bundle_id):
            command(["xcrun", "simctl", "install", device, path], ROOT, consumer / (name + "-install.log"))
            installed.append(bundle_id)
            command(["xcrun", "simctl", "launch", device, bundle_id], ROOT, consumer / (name + "-launch.log"))
            container = command(["xcrun", "simctl", "get_app_container", device, bundle_id, "data"],
                                ROOT, consumer / (name + "-container.log")).strip()
            result_file = Path(container) / "Documents/result.json"
            deadline = time.monotonic() + 40
            while not result_file.exists() and time.monotonic() < deadline:
                time.sleep(0.2)
            if not result_file.exists():
                raise RuntimeError("独立iOS应用没有返回公开API验证结果：" + name)
            result = json.loads(result_file.read_text())
            write_json(consumer / (name + "-result.json"), result)
            record = {"name":name, **result}; report["cases"].append(record); write_json(report_path, report)
            return record

        normal = run_application("public_api", application, base_bundle + ".normal")
        if normal["status"] != "PASS" or len(normal.get("checks", [])) < 10:
            raise RuntimeError("独立Swift消费真实预编译包失败")
        wrapper = package / "Sources/RocketIMStage0/Stage0Device.swift"; original = wrapper.read_text()
        changed = original.replace(f'public let stage0SDKVersion = "{VERSION}"', 'public let stage0SDKVersion = "0.0.0-invalid"')
        if changed == original:
            raise RuntimeError("没有向解压后的SDK副本注入包与binary版本差异")
        wrapper.write_text(changed)
        try:
            app = build("mismatched_version", base_bundle + ".mismatch")
            mismatch = run_application("mismatched_version", app, base_bundle + ".mismatch")
            if mismatch["status"] != "FAIL" or "sdk_version_mismatch" not in mismatch.get("error", ""):
                raise RuntimeError("SDK构造器未拒绝与真实native binary不匹配的包版本")
            mismatch["expected_failure"] = True
        finally:
            wrapper.write_text(original)
        framework = package / "Artifacts" / FRAMEWORK; hidden = framework.with_suffix(".unavailable")
        framework.rename(hidden)
        try:
            build("missing_binary", base_bundle + ".missing", expected=1)
            missing_log = (consumer / "missing_binary-build.log").read_text()
            if "RocketIMStage0FFI" not in missing_log or "does not contain a binary artifact" not in missing_log:
                raise RuntimeError("缺失二进制负例没有得到具体binary artifact缺失诊断")
            report["cases"].append({"name":"missing_binary", "status":"FAIL", "expected_failure":True,
                                    "assertion":"新DerivedData消费缺失XCFramework明确失败，未调用Rust构建"})
        finally:
            hidden.rename(framework)
        report.update(status="PASS", package_sha256={str(p.relative_to(package)):sha(p) for p in sorted(package.rglob("*")) if p.is_file()},
                      source_dependency="仅从zip解压的Swift Package、生成绑定和XCFramework，无源码路径依赖")
    except Exception as error:
        report.update(status="FAIL", error=str(error))
    finally:
        cleanup_errors = []
        for bundle_id in installed:
            try:
                command(["xcrun", "simctl", "uninstall", device, bundle_id], ROOT, consumer / (bundle_id + "-uninstall.log"))
            except Exception as error:
                cleanup_errors.append(str(error))
        if booted_here:
            try:
                command(["xcrun", "simctl", "shutdown", device], ROOT, consumer / "shutdown.log")
            except Exception as error:
                cleanup_errors.append(str(error))
        if cleanup_errors:
            report.update(status="FAIL", cleanup_errors=cleanup_errors)
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
    package = sub.add_parser("pack")
    for option in ("generated", "device-lib", "sim-arm64-lib", "sim-x86_64-lib"):
        package.add_argument("--" + option, type=Path, required=True)
    package.add_argument("--licenses", type=Path, default=ROOT / "dist/platform-release/licenses")
    package.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    test = sub.add_parser("verify"); test.add_argument("--archive", type=Path, required=True)
    test.add_argument("--device", help="既有模拟器UDID；缺省选择已关闭的可用iPhone")
    test.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    return pack(args) if args.operation == "pack" else verify(args)


if __name__ == "__main__":
    raise SystemExit(main())
