"""Node 与移动端同包互通的构建、来源核验及目标运行适配。"""

import json
from pathlib import Path

from interop import ROOT, reuse_build, verify_build_package
from interop_mobile import FLUTTER_SHA256, KOTLIN_SHA256, prepare_flutter, prepare_kotlin
from platform_release import artifacts
from platform_release.runtime import FLUTTER_SIMULATOR

PEERS = ["kotlin-android", "flutter-ios", "flutter-android"]


def accepted_mobile_packages(entries=None):
    """复用同一验收清单，只要求本项实际消费的 Kotlin 和 Flutter 原包。"""
    if entries is None:
        entries = json.loads((ROOT / "dist/platform-interop/accepted-packages.json").read_text())
    artifacts.require(isinstance(entries, list) and all(isinstance(entry, dict) for entry in entries),
                      "invalid_mobile_accepted_package_manifest")
    expected = {"kotlin": KOTLIN_SHA256, "flutter": FLUTTER_SHA256}
    selected = [entry for entry in entries
                if isinstance(entry.get("platform"), str) and entry["platform"] in expected]
    artifacts.require(len(selected) == 2 and {entry["platform"] for entry in selected} == set(expected),
                      "invalid_mobile_accepted_package_set")
    for entry in selected:
        artifacts.require(isinstance(entry.get("artifact"), str) and bool(entry["artifact"])
                          and entry.get("sha256") == expected[entry["platform"]],
                          "mobile_accepted_package_metadata_mismatch:" + entry["platform"])
        archive = (ROOT / entry["artifact"]).resolve()
        artifacts.require(archive.is_relative_to(ROOT / "dist/platform-release") and archive.is_file(),
                          "mobile_accepted_archive_missing_or_outside:" + entry["platform"])
        artifacts.require(artifacts.sha(archive) == entry["sha256"],
                          "mobile_accepted_archive_changed:" + entry["platform"])
    return selected


def prepare(work, url, run_id, kotlin_report=None):
    """Kotlin 可通过 Intent 换 run；Flutter 的 run 与 URL 编入本轮消费 App。"""
    work = Path(work).resolve()
    packages = accepted_mobile_packages()
    kotlin = (reuse_build("kotlin", Path(kotlin_report), packages) if kotlin_report
              else prepare_kotlin(work / "kotlin"))
    verify_build_package("kotlin", kotlin, packages)
    flutter = prepare_flutter(work / "flutter", url, run_id)
    verify_build_package("flutter", flutter, packages)
    return {"kotlin": kotlin, "flutter": flutter}


def audit(builds):
    """只核验两种移动 SDK；Node 来源由既有 Node 验证入口负责。"""
    artifacts.require(set(builds) == {"node", "kotlin", "flutter"},
                      "node_mobile_artifact_platform_set_mismatch")
    accepted = {entry["platform"]: entry for entry in accepted_mobile_packages()}
    result = {"status": "PASS", "acceptance_sha256": artifacts.sha(
        ROOT / "dist/platform-interop/accepted-packages.json"), "packages": {}, "runtime_files": {}}
    for platform in ("kotlin", "flutter"):
        entry, build = accepted[platform], builds[platform]
        verify_build_package(platform, build, list(accepted.values()))
        archive = ROOT / entry["artifact"]
        original_report = json.loads((ROOT / entry["report"]).read_text())
        checker = artifacts.kotlin if platform == "kotlin" else artifacts.flutter
        provenance, runtime_files = checker(build, archive, original_report, ROOT)
        result["packages"][platform] = {
            "archive": str(archive), "archive_sha256": entry["sha256"], **provenance}
        if platform == "kotlin":
            result["runtime_files"]["kotlin-android"] = runtime_files
        else:
            result["runtime_files"].update(runtime_files)
    return result


def launch(runtime, builds, url, run_id):
    """先完成移动端启动；父入口最后启动有总时限的 Node 控制端。"""
    flutter = builds["flutter"]
    artifacts.require(flutter["run_id"] == run_id, "flutter_build_run_mismatch")
    runtime.ios(FLUTTER_SIMULATOR, flutter["ios_app"], flutter["ios_bundle_id"],
                "flutter-ios", url, run_id)
    runtime.android(builds["kotlin"], flutter, url, run_id)


def audit_installed(runtime, builds):
    """卸载前复核目标内完整 App/APK，不能只核对主机上的构建副本。"""
    result = {"status": "PASS", "runtime_files": {}}
    flutter = builds["flutter"]
    initial_ios = runtime.metadata["flutter-ios"]
    artifacts.require(initial_ios["device"]["udid"] == FLUTTER_SIMULATOR,
                      "installed_flutter_simulator_changed")
    installed = runtime.command(["xcrun", "simctl", "get_app_container", FLUTTER_SIMULATOR,
                                 flutter["ios_bundle_id"], "app"]).strip()
    actual = artifacts.tree(installed)
    artifacts.require(actual == artifacts.tree(flutter["ios_app"]),
                      "installed_flutter_ios_app_changed")
    artifacts.require(actual["files_sha256"] == initial_ios["installed_app_sha256"],
                      "installed_flutter_ios_app_changed_since_launch")
    result["runtime_files"]["flutter-ios"] = {"path": installed, **actual}
    targets = [
        ("kotlin-android", builds["kotlin"]["bundle_id"], builds["kotlin"]["apk"],
         builds["kotlin"]["apk_sha256"]),
        ("flutter-android", flutter["android_bundle_id"], flutter["android_apk"],
         flutter["android_apk_sha256"]),
    ]
    for endpoint, bundle, apk, expected in targets:
        initial = runtime.metadata[endpoint]
        artifacts.require(initial["bundle_id"] == bundle, "installed_android_bundle_changed:" + endpoint)
        adb, serial = initial["adb"], initial["serial"]
        installed = runtime.command([adb, "-s", serial, "shell", "pm", "path", bundle]).strip()
        artifacts.require(installed.startswith("package:") and "\n" not in installed,
                          "unexpected_android_package_paths:" + endpoint)
        pulled = runtime.work / (endpoint + "-installed-after.apk")
        artifacts.require(not pulled.exists(), "installed_after_apk_already_exists:" + endpoint)
        runtime.command([adb, "-s", serial, "pull", installed.removeprefix("package:"), pulled])
        actual = artifacts.sha(pulled)
        artifacts.require(actual == expected == artifacts.sha(apk) == initial["installed_apk_sha256"],
                          "installed_android_apk_changed_since_launch:" + endpoint)
        result["runtime_files"][endpoint] = {
            "path": str(pulled), "sha256": actual, "serial": serial, "bundle_id": bundle}
    return result
