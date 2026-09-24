#!/usr/bin/env python3
"""本地Kotlin Release AAR/Maven打包及独立Android消费者；只操作专用模拟器。"""

import argparse
import datetime
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
VERSION = "0.1.0-stage0.1"
SDK = Path.home() / "Library/Android/sdk"
GRADLE = Path.home() / ".gradle/wrapper/dists/gradle-8.14-bin/38aieal9i53h9rfe7vjup95b9/gradle-8.14/bin/gradle"
AVD_NAME = "RocketsIM_Stage0_16k"
SERIAL = "emulator-5580"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def copy_rust_licenses(output, destination):
    source = output / "licenses"
    if not (source / "PROJECT-LICENSE-STATUS.txt").is_file():
        raise RuntimeError("缺少维护者生成的许可清单和项目许可状态")
    shutil.copytree(source, destination)


def command(args, directory, log, env=None, timeout=600, stdin=None, check=True):
    args = [str(value) for value in args]
    print("Running", args[0], args[1] if len(args) > 1 else "", flush=True)
    started = time.monotonic()
    with Path(log).open("a+") as output:
        output.write(json.dumps({"command": args, "cwd": str(directory)}) + "\n")
        output.flush()
        start_offset = output.tell()
        result = subprocess.run(args, cwd=directory, env=env, input=stdin, text=True,
                                stdout=output, stderr=subprocess.STDOUT, timeout=timeout)
        output.seek(start_offset)
        stdout = output.read()
        output.write(json.dumps({"seconds": round(time.monotonic() - started, 3), "exit": result.returncode}) + "\n")
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}); see {log}")
    return stdout, result.returncode


def environment(output, android_sdk=SDK):
    env = os.environ.copy()
    env.update(ANDROID_HOME=str(android_sdk), ANDROID_SDK_ROOT=str(android_sdk),
               ANDROID_USER_HOME=str(output / "android-user"), ANDROID_AVD_HOME=str(output / "android-avd"),
               JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home")
    for name in ("ANDROID_USER_HOME", "ANDROID_AVD_HOME"):
        Path(env[name]).mkdir(parents=True, exist_ok=True)
    return env


def gradle(project, tasks, args, env, log):
    if not args.gradle.is_file():
        raise RuntimeError("指定Gradle安装不存在")
    command([args.gradle, "--no-daemon", "--max-workers=2", *tasks], project, log, env, timeout=1200)


def prepare_emulator(output, android_sdk, log, env):
    adb, emulator = android_sdk / "platform-tools/adb", android_sdk / "emulator/emulator"
    command([adb, "start-server"], output, log, env, timeout=30)
    state, code = command([adb, "-s", SERIAL, "get-state"], output, log, env, timeout=10, check=False)
    if code == 0 and "device" in state:
        name, _ = command([adb, "-s", SERIAL, "emu", "avd", "name"], output, log, env, timeout=10)
        if AVD_NAME not in name.splitlines():
            raise RuntimeError("专用端口已被其他AVD占用；不操作该设备")
        return adb, None
    avd = output / "android-avd" / f"{AVD_NAME}.avd"
    if not avd.exists():
        manager = android_sdk / "cmdline-tools/latest/bin/avdmanager"
        command([manager, "create", "avd", "--name", AVD_NAME, "--package",
                 "system-images;android-37.1;google_apis_playstore_ps16k;arm64-v8a",
                 "--device", "pixel_8", "--path", avd], output, log, env, stdin="no\n", timeout=120)
    emulator_log = Path(log).with_suffix(".emulator.log")
    with emulator_log.open("a") as stream:
        process = subprocess.Popen([str(emulator), "-avd", AVD_NAME, "-port", "5580", "-no-window", "-no-audio",
                                    "-no-boot-anim", "-no-snapshot", "-gpu", "swiftshader_indirect"],
                                   cwd=output, env=env, stdout=stream, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"专用模拟器启动退出；见 {emulator_log}")
        boot, _ = command([adb, "-s", SERIAL, "shell", "getprop", "sys.boot_completed"], output, log, env, timeout=10, check=False)
        if boot.strip() == "1":
            command([adb, "-s", SERIAL, "emu", "avd", "name"], output, log, env, timeout=10)
            return adb, process
        time.sleep(2)
    process.terminate()
    raise RuntimeError("专用模拟器未在240秒内启动")


def native_alignment(apk, android_sdk, directory, log, env):
    llvm = android_sdk / "ndk/28.2.13676358/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-readelf"
    results = {}
    with zipfile.ZipFile(apk) as archive:
        for name in archive.namelist():
            if not name.startswith(("lib/arm64-v8a/", "lib/x86_64/")) or not name.endswith(".so"):
                continue
            target = directory / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(name))
            data, _ = command([llvm, "-Wl", target], directory, log, env, timeout=20)
            alignments = [int(line.split()[-1], 16) for line in data.splitlines() if line.strip().startswith("LOAD ")]
            if not alignments or min(alignments) < 16384:
                raise RuntimeError(f"原生库未满足16KiB ELF对齐: {name}")
            results[name] = {"sha256": digest(target), "load_alignment": min(alignments)}
    command([android_sdk / "build-tools/36.0.0/zipalign", "-c", "-P", "16", "4", apk], directory, log, env, timeout=30)
    return results


def run_consumer(apk, package, activity, run_id, output, android_sdk, log, env, marker="RocketsStage0", scenario="public-api"):
    # 两种消费者共享专用AVD，启动、安装、读取本次结果与关闭必须串行。
    with (output / "android-consumer.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _run_consumer(apk, package, activity, run_id, output, android_sdk, log, env, marker, scenario)


def _run_consumer(apk, package, activity, run_id, output, android_sdk, log, env, marker, scenario):
    adb, process = prepare_emulator(output, android_sdk, log, env)
    try:
        abi, _ = command([adb, "-s", SERIAL, "shell", "getprop", "ro.product.cpu.abi"], output, log, env, timeout=10)
        page_size, _ = command([adb, "-s", SERIAL, "shell", "getconf", "PAGE_SIZE"], output, log, env, timeout=10)
        command([adb, "-s", SERIAL, "install", "-r", apk], output, log, env, timeout=120)
        command([adb, "-s", SERIAL, "shell", "am", "start", "-S", "-n", f"{package}/{activity}", "--es", "run_id", run_id,
                 "--es", "scenario", scenario], output, log, env, timeout=30)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            data, _ = command([adb, "-s", SERIAL, "logcat", "-d", "-v", "brief", "-s", f"{marker}:I", "*:S"], output, log, env, timeout=15)
            for line in reversed(data.splitlines()):
                if run_id not in line or "{" not in line:
                    continue
                result = json.loads(line[line.index("{"):])
                if result.get("run_id") == run_id:
                    if result.get("status") != "passed":
                        raise RuntimeError(f"独立消费运行失败: {result}")
                    return {**result, "abi": abi.strip(), "page_size": page_size.strip()}
            time.sleep(1)
        raise RuntimeError("未取得本次独立消费者运行结果")
    finally:
        if process is not None:
            command([adb, "-s", SERIAL, "emu", "kill"], output, log, env, timeout=10, check=False)
            process.wait(timeout=20)


def package_and_run(args, work, log, env, run_id):
    sdk = work / "sdk"
    shutil.copytree(ROOT / "src/sdk/kotlin", sdk)
    licenses = sdk / "src/main/assets/rockets-stage0-licenses"
    copy_rust_licenses(args.output, licenses)
    jna = args.output / "dependencies" / f"jna-{args.jna_version}.aar"
    if args.jna_version != "5.17.0":
        raise RuntimeError("本次发布运行时固定JNA 5.17.0")
    jna.parent.mkdir(parents=True, exist_ok=True)
    if not jna.is_file():
        urllib.request.urlretrieve(f"https://repo.maven.apache.org/maven2/net/java/dev/jna/jna/{args.jna_version}/{jna.name}", jna)
    if digest(jna) != "4dbeffffa665d97ad5aa7eee297531d3c841a86716ab7f774fd6956422b3cf38":
        raise RuntimeError("JNA AAR与本次验证固定摘要不一致")
    apache = jna.parent / "JNA-5.17.0-AL2.0"
    if not apache.is_file():
        urllib.request.urlretrieve("https://raw.githubusercontent.com/java-native-access/jna/5.17.0/AL2.0", apache)
    with zipfile.ZipFile(jna) as archive:
        with zipfile.ZipFile(io.BytesIO(archive.read("classes.jar"))) as classes:
            if "com/sun/jna/internal/Cleaner.class" not in classes.namelist():
                raise RuntimeError("JNA缺少生成器要求的Cleaner运行时")
            destination = licenses / "jna-5.17.0"
            destination.mkdir()
            (destination / "LICENSE").write_bytes(classes.read("META-INF/LICENSE"))
            shutil.copy2(apache, destination / "AL2.0")
            (destination / "artifact.json").write_text(json.dumps({"coordinate": "net.java.dev.jna:jna:5.17.0@aar", "sha256": digest(jna)}) + "\n")
    generated = sdk / "src/main/generated"
    if args.generated_kotlin.is_dir():
        shutil.copytree(args.generated_kotlin, generated)
    else:
        generated.mkdir(parents=True)
        shutil.copy2(args.generated_kotlin, generated / args.generated_kotlin.name)
    for abi, library in (("arm64-v8a", args.arm64_lib), ("x86_64", args.x64_lib)):
        destination = sdk / "src/main/jniLibs" / abi
        destination.mkdir(parents=True)
        shutil.copy2(library, destination / "librockets_stage0_uniffi.so")
    (sdk / "local.properties").write_text(f"sdk.dir={args.android_sdk}\n")
    repository = args.output / "packages/maven"
    repository.mkdir(parents=True, exist_ok=True)
    gradle(sdk, ["publishReleasePublicationToMavenRepository", f"-PjnaVersion={args.jna_version}", f"-PreleaseRepository={repository}"], args, env, log)
    artifact = repository / f"io/rocketsim/rockets-stage0/{VERSION}/rockets-stage0-{VERSION}.aar"
    with zipfile.ZipFile(artifact) as archive:
        for abi in ("arm64-v8a", "x86_64"):
            if f"jni/{abi}/librockets_stage0_uniffi.so" not in archive.namelist():
                raise RuntimeError("AAR缺少要求的预编译ABI")
    snapshot = work / "release" / artifact.name
    snapshot.parent.mkdir()
    shutil.copy2(artifact, snapshot)
    consumer = work / "consumer"
    shutil.copytree(ROOT / "tests/consumers/kotlin", consumer)
    (consumer / "local.properties").write_text(f"sdk.dir={args.android_sdk}\n")
    gradle(consumer, [":app:assembleDebug", "--refresh-dependencies", f"-PreleaseRepository={repository}"], args, env, log)
    apk = consumer / "app/build/outputs/apk/debug/app-debug.apk"
    native = native_alignment(apk, args.android_sdk, work, log, env)
    result = {"aar": str(snapshot), "maven_aar": str(artifact), "aar_sha256": digest(snapshot), "apk": str(apk), "apk_sha256": digest(apk),
              "jna_version": args.jna_version, "jna_aar_sha256": digest(jna), "native": native}
    if not args.no_run:
        result["runtime"] = run_consumer(apk, "io.rocketsim.consumer.kotlin", ".MainActivity", run_id, args.output, args.android_sdk, log, env)
        result["version_rejected"] = verify_rejected_version(args, work, sdk, consumer, log, env, run_id)
    return result


def verify_rejected_version(args, work, sdk, consumer, log, env, run_id):
    # 仅修改隔离验收副本的SDK版本常量；正式Maven包保持不变。
    negative_sdk, negative_consumer = work / "negative-sdk", work / "negative-consumer"
    ignored = shutil.ignore_patterns("build", ".gradle")
    shutil.copytree(sdk, negative_sdk, ignore=ignored)
    wrapper = negative_sdk / "src/main/java/io/rocketsim/stage0/Stage0Device.kt"
    original = wrapper.read_text()
    replaced = original.replace(f'private const val SDK_VERSION = "{VERSION}"', 'private const val SDK_VERSION = "deliberately-incompatible"')
    if replaced == original:
        raise RuntimeError("负向验收未找到SDK版本常量")
    wrapper.write_text(replaced)
    repository = work / "negative-maven"
    gradle(negative_sdk, ["publishReleasePublicationToMavenRepository", f"-PjnaVersion={args.jna_version}", f"-PreleaseRepository={repository}"], args, env, log)
    shutil.copytree(consumer, negative_consumer, ignore=ignored)
    gradle(negative_consumer, [":app:assembleDebug", "--refresh-dependencies", f"-PreleaseRepository={repository}"], args, env, log)
    apk = negative_consumer / "app/build/outputs/apk/debug/app-debug.apk"
    result = run_consumer(apk, "io.rocketsim.consumer.kotlin", ".MainActivity", f"{run_id}-version", args.output,
                          args.android_sdk, log, env, scenario="version-rejected")
    return {"runtime": result, "apk_sha256": digest(apk), "modified_sdk_constant_only": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/platform-release")
    parser.add_argument("--generated-kotlin", type=Path)
    parser.add_argument("--arm64-lib", type=Path)
    parser.add_argument("--x64-lib", type=Path)
    parser.add_argument("--jna-version")
    parser.add_argument("--android-sdk", type=Path, default=SDK)
    parser.add_argument("--gradle", type=Path, default=GRADLE)
    parser.add_argument("--no-run", action="store_true")
    parser.add_argument("--prepare-emulator", action="store_true")
    args = parser.parse_args()
    args.output = args.output.resolve()
    run_id = str(uuid.uuid4())
    work = args.output / "runs" / f"kotlin-{run_id}"
    work.mkdir(parents=True)
    log = work / "build.log"
    result = {"run_id": run_id, "version": VERSION, "platform": "kotlin-android", "status": "failed", "log": str(log),
              "started_at": datetime.datetime.now(datetime.UTC).isoformat()}
    try:
        env = environment(args.output, args.android_sdk)
        if args.prepare_emulator:
            adb, _ = prepare_emulator(args.output, args.android_sdk, log, env)
            result.update(status="emulator_ready", serial=SERIAL, adb=str(adb))
        else:
            if not all((args.generated_kotlin, args.arm64_lib, args.x64_lib, args.jna_version)):
                raise RuntimeError("打包必须显式提供生成Kotlin、两份Release库和JNA版本")
            versions, _ = command([args.gradle, "--version"], work, log, env)
            result["gradle_toolchain"] = versions
            result.update(package_and_run(args, work, log, env, run_id), status="built" if args.no_run else "passed")
    except Exception as error:
        result["error"] = str(error)
    result["finished_at"] = datetime.datetime.now(datetime.UTC).isoformat()
    (work / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(result, ensure_ascii=False), flush=True)
    return 1 if result["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
