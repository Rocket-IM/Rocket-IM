#!/usr/bin/env python3
"""构建互通用独立移动消费端；只安装已验收包，不构建SDK或操作模拟器。"""

import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import shutil
import tarfile
import uuid
from urllib.parse import urlsplit, urlunsplit
import xml.etree.ElementTree as ET

from android import ROOT, SDK, GRADLE, command, digest, environment, native_alignment
from flutter import FLUTTER, prepare_consumer

RELEASE = ROOT / "dist/platform-release"
KOTLIN_COORDINATE = "io/rocketsim/rockets-stage0/0.1.0-stage0.1/rockets-stage0-0.1.0-stage0.1.aar"
KOTLIN_SHA256 = "0c6a16438587583b46363bc657624d38fcb7652efface98ff3edc584bbd2487a"
FLUTTER_ARCHIVE = RELEASE / "packages/flutter/rockets_im_stage0-0.1.0-stage0.1.tar.gz"
FLUTTER_SHA256 = "52f328a9a96bfb2e52553463c170b10a0d06233e78305788e58671fa6af91164"
ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"


def checked(path, expected):
    if not path.is_file() or digest(path) != expected:
        raise RuntimeError(f"已验收发布包缺失或摘要改变: {path}")


def prepare_kotlin(work: Path) -> dict:
    """work须为本轮独立目录；返回APK及启动身份，由总runner负责安装与Intent配置。"""
    work = Path(work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    log = work / "kotlin-build.log"
    build_id = uuid.uuid4().hex
    application_id = f"io.rocketsim.consumer.kotlin.interop.r{build_id}"
    original = RELEASE / "packages/maven" / KOTLIN_COORDINATE
    checked(original, KOTLIN_SHA256)
    repository = work / "installed-maven"
    shutil.copytree(RELEASE / "packages/maven", repository)
    checked(repository / KOTLIN_COORDINATE, KOTLIN_SHA256)
    consumer = work / "consumer"
    shutil.copytree(ROOT / "tests/consumers/kotlin", consumer)
    (consumer / "local.properties").write_text(f"sdk.dir={SDK}\n")
    env = environment(work, SDK)
    command([GRADLE, "--no-daemon", "--max-workers=2", ":app:assembleDebug", f"-PreleaseRepository={repository}",
             f"-PinteropApplicationId={application_id}"],
            consumer, log, env, timeout=1200)
    apk = consumer / "app/build/outputs/apk/debug/app-debug.apk"
    result = {"apk": str(apk), "apk_sha256": digest(apk), "bundle_id": application_id,
              "activity": "io.rocketsim.consumer.kotlin.MainActivity", "build_id": build_id,
              "sdk_sha256": KOTLIN_SHA256, "sdk_package": str(repository / KOTLIN_COORDINATE), "consumer": str(consumer), "log": str(log),
              "native": native_alignment(apk, SDK, work, log, env)}
    (work / "kotlin-build.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    return result


def configure_local_http(consumer):
    """仅消费App允许两个回环目标，控制端代码另有严格URL校验。"""
    manifest = consumer / "android/app/src/main/AndroidManifest.xml"
    ET.register_namespace("android", ANDROID_NAMESPACE)
    document = ET.parse(manifest)
    root = document.getroot()
    ET.SubElement(root, "uses-permission", {f"{{{ANDROID_NAMESPACE}}}name": "android.permission.INTERNET"})
    application = root.find("application")
    if application is None:
        raise RuntimeError("Flutter消费者没有application节点")
    application.set(f"{{{ANDROID_NAMESPACE}}}networkSecurityConfig", "@xml/network_security_config")
    document.write(manifest, encoding="utf-8", xml_declaration=True)
    destination = consumer / "android/app/src/main/res/xml/network_security_config.xml"
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / "tests/consumers/kotlin/app/src/main/res/xml/network_security_config.xml", destination)
    info_path = consumer / "ios/Runner/Info.plist"
    info = plistlib.loads(info_path.read_bytes())
    info["NSAppTransportSecurity"] = {"NSExceptionDomains": {
        "127.0.0.1": {"NSExceptionAllowsInsecureHTTPLoads": True, "NSIncludesSubdomains": False},
    }}
    info_path.write_bytes(plistlib.dumps(info, sort_keys=False))


def configure_flutter_identity(consumer, run_id):
    """只改本轮生成App身份；namespace及Activity代码包名保持生成器原值。"""
    suffix = "r" + hashlib.sha256(run_id.encode("ascii")).hexdigest()
    android_id = f"io.rocketsim.consumer.rockets_stage0_consumer.interop.{suffix}"
    ios_id = f"io.rocketsim.consumer.rocketsStage0Consumer.interop.{suffix}"
    gradle = consumer / "android/app/build.gradle.kts"
    changed, count = re.subn(r'\bapplicationId\s*=\s*"io\.rocketsim\.consumer\.rockets_stage0_consumer"',
                             f'applicationId = "{android_id}"', gradle.read_text())
    if count != 1:
        raise RuntimeError("Flutter生成器Android应用标识与固定模板不符")
    gradle.write_text(changed)
    project = consumer / "ios/Runner.xcodeproj/project.pbxproj"
    changed, count = re.subn(r'PRODUCT_BUNDLE_IDENTIFIER = io\.rocketsim\.consumer\.rocketsStage0Consumer(\.RunnerTests)?;',
                             lambda match: f'PRODUCT_BUNDLE_IDENTIFIER = {ios_id}{match.group(1) or ""};', project.read_text())
    if count != 6:
        raise RuntimeError("Flutter生成器iOS应用标识与固定模板不符")
    project.write_text(changed)
    return android_id, ios_id


def prepare_flutter(work: Path, url: str, run_id: str) -> dict:
    """url是控制器127.0.0.1来源；Android编入10.0.2.2，端ID各自固定。"""
    parsed = urlsplit(url)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port or
            parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/") or
            not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", run_id)):
        raise ValueError("需要固定本机控制器URL及有界run_id")
    android_url = urlunsplit(("http", f"10.0.2.2:{parsed.port}", "", "", ""))
    work = Path(work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    log = work / "flutter-build.log"
    checked(FLUTTER_ARCHIVE, FLUTTER_SHA256)
    installed = work / "installed-package"
    installed.mkdir()
    with tarfile.open(FLUTTER_ARCHIVE) as source:
        source.extractall(installed, filter="data")
    args = argparse.Namespace(flutter=FLUTTER)
    env = environment(work, SDK)
    env["FLUTTER_SUPPRESS_ANALYTICS"] = "true"
    consumer = prepare_consumer(args, work, log, env)
    configure_local_http(consumer)
    android_id, ios_id = configure_flutter_identity(consumer, run_id)
    common = [f"--dart-define=ROCKETS_INTEROP_RUN_ID={run_id}", "--no-pub"]
    command([FLUTTER, "build", "apk", "--release", "--target-platform", "android-arm64,android-x64",
             f"--dart-define=ROCKETS_INTEROP_URL={android_url}", "--dart-define=ROCKETS_INTEROP_ENDPOINT_ID=flutter-android", *common],
            consumer, log, env, timeout=1200)
    apk = consumer / "build/app/outputs/flutter-apk/app-release.apk"
    native = native_alignment(apk, SDK, work, log, env)
    command([FLUTTER, "build", "ios", "--simulator", "--debug", "--no-codesign",
             f"--dart-define=ROCKETS_INTEROP_URL={url}", "--dart-define=ROCKETS_INTEROP_ENDPOINT_ID=flutter-ios", *common],
            consumer, log, env, timeout=1200)
    app = consumer / "build/ios/iphonesimulator/Runner.app"
    bundle_id = plistlib.loads((app / "Info.plist").read_bytes())["CFBundleIdentifier"]
    if bundle_id != ios_id:
        raise RuntimeError("Flutter iOS产物身份与本轮配置不符")
    result = {"android_apk": str(apk), "android_apk_sha256": digest(apk), "android_bundle_id": android_id,
              "android_activity": "io.rocketsim.consumer.rockets_stage0_consumer.MainActivity",
              "ios_app": str(app), "ios_bundle_id": bundle_id, "ios_binary_sha256": digest(app / "Runner"),
              "sdk_package": str(FLUTTER_ARCHIVE), "sdk_sha256": FLUTTER_SHA256, "consumer": str(consumer), "log": str(log),
              "run_id": run_id, "android_native": native}
    (work / "flutter-build.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("platform", choices=("kotlin", "flutter"))
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--url")
    parser.add_argument("--run-id")
    args = parser.parse_args()
    result = prepare_kotlin(args.work) if args.platform == "kotlin" else prepare_flutter(args.work, args.url or "", args.run_id or "")
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
