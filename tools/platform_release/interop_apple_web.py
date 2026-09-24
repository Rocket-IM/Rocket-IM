#!/usr/bin/env python3
"""从已验收归档构建Swift/browser互通控制端；不生成SDK、不管理模拟器或浏览器。"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools.platform_release import apple, web

ACCEPTED = ROOT / "dist/platform-interop/accepted-packages.json"
OUTPUT = ROOT / "dist/platform-interop"
VERSION = "0.1.0-stage0.1"


def configure(accepted_path=None, output=None):
    """显式选择本轮验收清单和输出；不改写历史清单或放宽逐包摘要检查。"""
    global ACCEPTED, OUTPUT
    for value in (accepted_path, output):
        if value is not None and not Path(value).resolve().is_relative_to((ROOT / "dist").resolve()):
            raise ValueError("互通输入和输出必须位于项目dist内")
    if accepted_path is not None:
        ACCEPTED = Path(accepted_path).resolve()
    if output is not None:
        OUTPUT = Path(output).resolve()


def accepted_entries(platforms=None):
    """默认验完整四端；单端/配对消费只依赖明确选择的已验收包。"""
    entries = json.loads(ACCEPTED.read_text())
    all_platforms = {"swift", "browser", "kotlin", "flutter"}
    required = all_platforms if platforms is None else set(platforms)
    if not required or not required <= all_platforms:
        raise ValueError("invalid_accepted_platform_selection")
    if not isinstance(entries, list) or not all(isinstance(entry, dict) for entry in entries):
        raise RuntimeError("invalid_accepted_package_set")
    selected = [entry for entry in entries if isinstance(entry.get("platform"), str) and entry["platform"] in required]
    if (len(selected) != len(required) or {entry["platform"] for entry in selected} != required
            or platforms is None and len(entries) != len(required)):
        raise RuntimeError("invalid_accepted_package_set")
    for entry in selected:
        artifact = (ROOT / entry["artifact"]).resolve()
        if not artifact.is_relative_to((ROOT / "dist").resolve()) or sha(artifact) != entry["sha256"]:
            raise RuntimeError("accepted_package_changed")
        if ACCEPTED != ROOT / "dist/platform-interop/accepted-packages.json" and "report_sha256" not in entry:
            raise RuntimeError("explicit_acceptance_report_digest_required")
        if "report_sha256" in entry:
            report = (ROOT / entry["report"]).resolve()
            if not report.is_relative_to((ROOT / "dist").resolve()) or sha(report) != entry["report_sha256"]:
                raise RuntimeError("accepted_report_changed")
            result = json.loads(report.read_text())
            key = {"swift": "archive_sha256", "browser": "archive_sha256", "kotlin": "aar_sha256",
                   "flutter": "package_sha256"}[entry["platform"]]
            if (result.get("status") not in {"PASS", "passed"} or result.get("run_id") != entry["run_id"]
                    or result.get(key) != entry["sha256"]):
                raise RuntimeError("accepted_package_not_verified")
    return selected


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def hashes(directory: Path) -> dict[str, str]:
    return {str(path.relative_to(directory)): sha(path) for path in sorted(directory.rglob("*")) if path.is_file()}


def inputs(platform: str) -> dict[str, str]:
    source = ROOT / "tests/consumers" / platform
    files = {str(path.relative_to(ROOT)): sha(path) for path in sorted(source.rglob("*"))
             if path.is_file() and "node_modules" not in path.parts}
    for path in (Path(__file__).resolve(), Path(apple.__file__).resolve(), Path(web.__file__).resolve(), ACCEPTED):
        files[str(path.relative_to(ROOT))] = sha(path)
    return files


def accepted(platform: str) -> tuple[Path, dict]:
    entries = accepted_entries({platform})
    entry = next(item for item in entries if item["platform"] == platform)
    archive = (ROOT / entry["artifact"]).resolve()
    if not archive.is_relative_to(ROOT / "dist") or sha(archive) != entry["sha256"]:
        raise RuntimeError("已验收归档缺失、越界或摘要改变；不重新打包作为回退")
    return archive, entry


def start(work: Path, platform: str) -> tuple[Path, Path, dict]:
    work = work.resolve()
    if not work.is_relative_to(OUTPUT):
        raise RuntimeError("互通消费构建输出必须位于显式选择的独立输出目录")
    work.mkdir(parents=True, exist_ok=True)
    directory = work / "consumer"
    archive, acceptance = accepted(platform)
    report = {"status": "RUNNING", "platform": platform, "build_id": str(uuid.uuid4()),
              "started_at": datetime.now(timezone.utc).isoformat(), "directory": str(directory),
              "archive": str(archive), "archive_sha256": sha(archive), "accepted_run_id": acceptance["run_id"],
              "source_sha256_before": inputs(platform), "version": VERSION}
    apple.write_json(work / "build-report.json", report)
    shutil.copytree(ROOT / "tests/consumers" / platform, directory,
                    ignore=shutil.ignore_patterns("node_modules", "dist", "DerivedData*"))
    return work, archive, report


def verify_package(directory: Path) -> dict[str, str]:
    manifest = json.loads((directory / "artifact.json").read_text())
    if manifest["version"] != VERSION:
        raise RuntimeError("安装的SDK版本与已验收版本不同")
    for name, digest in manifest["files_sha256"].items():
        path = (directory / name).resolve()
        if not path.is_relative_to(directory.resolve()) or sha(path) != digest:
            raise RuntimeError("安装SDK文件摘要不符：" + name)
    if any(directory.rglob("*.rs")) or any(directory.rglob("Cargo.toml")):
        raise RuntimeError("实际消费包包含Rust源码构建输入")
    return hashes(directory)


def finish(work: Path, report: dict, archive: Path, package: Path, before: dict[str, str]) -> dict:
    report["source_sha256_after"] = inputs(report["platform"])
    report["archive_sha256_after"] = sha(archive)
    report["package_sha256"] = hashes(package)
    report["inputs_unchanged"] = (report["source_sha256_before"] == report["source_sha256_after"]
                                   and report["archive_sha256"] == report["archive_sha256_after"]
                                   and before == report["package_sha256"])
    if not report["inputs_unchanged"]:
        raise RuntimeError("消费构建期间源码、归档或解压SDK改变")
    report.update(status="PASS", finished_at=datetime.now(timezone.utc).isoformat())
    apple.write_json(work / "build-report.json", report)
    return report


def failed(work: Path, report: dict, error: Exception) -> None:
    report.update(status="FAIL", error=str(error), finished_at=datetime.now(timezone.utc).isoformat())
    apple.write_json(work / "build-report.json", report)


def prepare_swift(work: Path) -> dict:
    """构建ARM64 simulator Release app。返回app/bundle_id；不启动、安装或关闭模拟器。"""
    work, archive, report = start(work, "swift")
    directory = Path(report["directory"])
    try:
        vendor = directory / "Vendor"; vendor.mkdir()
        apple.extract(archive, vendor)
        package = vendor / "RocketIMStage0"
        before = verify_package(package)
        bundle_id = "dev.rocketim.stage0.interop.r" + report["build_id"].replace("-", "")[:16]
        derived = work / "DerivedData"
        apple.command(["xcodebuild", "-project", directory / "Stage0Consumer.xcodeproj", "-scheme", "Stage0Consumer",
                       "-configuration", "Release", "-sdk", "iphonesimulator", "-destination", "generic/platform=iOS Simulator",
                       "-derivedDataPath", derived, "-disableAutomaticPackageResolution", "CODE_SIGNING_ALLOWED=NO",
                       "ARCHS=arm64", "ONLY_ACTIVE_ARCH=YES", "PRODUCT_BUNDLE_IDENTIFIER=" + bundle_id, "build"],
                      directory, work / "xcodebuild.log")
        app = derived / "Build/Products/Release-iphonesimulator/Stage0Consumer.app"
        if not (app / "Stage0Consumer").is_file():
            raise RuntimeError("Xcode未输出预期应用二进制")
        report.update(app=str(app), bundle_id=bundle_id, app_sha256=hashes(app),
                      binary_sha256=sha(app / "Stage0Consumer"), configuration="Release", architecture="arm64",
                      runtime="NOT_STARTED", launch_environment=["ROCKET_INTEROP_URL", "ROCKET_INTEROP_RUN_ID", "ROCKET_INTEROP_ENDPOINT_ID"])
        return finish(work, report, archive, package, before)
    except Exception as error:
        failed(work, report, error)
        raise


def prepare_browser(work: Path) -> dict:
    """离线安装准确TGZ并严格编译消费端。返回directory/index，不启动HTTP或Chrome。"""
    work, archive, report = start(work, "browser")
    directory = Path(report["directory"])
    try:
        web.command(["npm", "install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", archive],
                    directory, work / "npm-install.log")
        package = directory / "node_modules/@rocket-im/stage0"
        before = verify_package(package)
        compiler = json.loads((directory / "node_modules/typescript/package.json").read_text())
        if compiler["version"] != "5.9.3":
            raise RuntimeError("消费者TypeScript版本与锁定版本不符")
        web.command(["npm", "run", "build"], directory, work / "typescript-build.log")
        if not (directory / "dist/interop.js").is_file():
            raise RuntimeError("未生成独立浏览器互通端")
        report.update(index="index.html", compiled_sha256=hashes(directory / "dist"), typescript=compiler["version"],
                      runtime="NOT_STARTED", launch_query=["interop_url", "interop_run_id", "interop_endpoint_id"])
        return finish(work, report, archive, package, before)
    except Exception as error:
        failed(work, report, error)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("platform", choices=("swift", "browser"))
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--accepted-packages", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    configure(args.accepted_packages, args.output)
    result = prepare_swift(args.work) if args.platform == "swift" else prepare_browser(args.work)
    print(json.dumps({key: result.get(key) for key in ("status", "build_id", "directory", "app", "bundle_id", "archive_sha256")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
