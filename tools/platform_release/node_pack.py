"""Node实验包组装、输入摘要和有界维护者命令；不修改原Web归档。"""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tarfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
VERSION = "0.1.0-stage0.1"
NAME = "@rockets-im/stage0-node"
PACKAGE = ROOT / "src/sdk/typescript/node"
TEMPLATE = ROOT / "tests/consumers/node"
OUTPUT = ROOT / "dist/platform-release/node"
NPM_CACHE = ROOT / "dist/platform-release/npm-cache"
COMPILER = ROOT / "src/sdk/typescript/node_modules/typescript/bin/tsc"
WASM_NAME = "rockets_stage0_wasm_bg.wasm"
GENERATED_FILES = ("rockets_stage0_wasm.js", "rockets_stage0_wasm.d.ts", WASM_NAME,
                   "rockets_stage0_wasm_bg.wasm.d.ts")


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def tree_hashes(directory):
    return {path.relative_to(directory).as_posix(): sha(path) for path in sorted(directory.rglob("*"))
            if path.is_file() and not any(part in ("node_modules", "__pycache__", "dist", "generated")
                                          for part in path.relative_to(directory).parts)}


def all_hashes(directory):
    result = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise RuntimeError("包内不允许符号链接：" + str(path))
        if path.is_file():
            result[path.relative_to(directory).as_posix()] = sha(path)
    return result


def source_hashes():
    result = {}
    for directory in (PACKAGE, TEMPLATE):
        result.update({(directory.relative_to(ROOT) / name).as_posix(): digest
                       for name, digest in tree_hashes(directory).items()})
    for name in ("node.py", "node_pack.py", "build_rust.py"):
        path = ROOT / "tools/platform_release" / name
        result[path.relative_to(ROOT).as_posix()] = sha(path)
    for path in sorted((ROOT / "src/sdk/rust").rglob("*")):
        if path.is_file() and path.suffix in (".rs", ".toml", ".lock") and "target" not in path.parts:
            result[path.relative_to(ROOT).as_posix()] = sha(path)
    return result


def start(output, phase):
    output = output.resolve()
    if not output.is_relative_to(OUTPUT.resolve()):
        raise RuntimeError("Node输出只允许dist/platform-release/node及其子目录")
    run_id = str(uuid.uuid4())
    run = output / "runs" / run_id
    run.mkdir(parents=True)
    report = {"run_id": run_id, "phase": phase, "status": "RUNNING", "started_at": now(),
              "version": VERSION, "package_name": NAME, "source_sha256_before": source_hashes()}
    write_json(run / "report.json", report)
    return run, report


def finish(run, report):
    report["source_sha256_after"] = source_hashes()
    report["source_stable"] = report["source_sha256_before"] == report["source_sha256_after"]
    if not report["source_stable"]:
        report.update(status="FAIL", error="操作期间源码变化，需从稳定源码重新执行")
    if report["status"] != "PASS":
        for name, value in report.get("runtime_matrix", {}).items():
            if value == "PASS":
                report["runtime_matrix"][name] = "FAIL"
    report["finished_at"] = now()
    write_json(run / "report.json", report)
    print(json.dumps({"status": report["status"], "phase": report["phase"], "run_id": report["run_id"],
                      "report": str(run / "report.json"), "archive": report.get("archive"),
                      "error": report.get("error")}, ensure_ascii=False))
    return 0 if report["status"] == "PASS" else 1


def node_binary():
    value = shutil.which("node")
    if value is None:
        raise RuntimeError("缺少Node运行时，不自动下载")
    return str(Path(value).resolve())


def npm_command():
    value = shutil.which("npm")
    if value is None:
        raise RuntimeError("缺少npm，不自动下载")
    path = Path(value).resolve()
    candidates = (path, path.parent / "node_modules/npm/bin/npm-cli.js")
    for candidate in candidates:
        if candidate.is_file() and candidate.name == "npm-cli.js":
            return [node_binary(), str(candidate)]
    raise RuntimeError("无法定位npm-cli.js，不通过shell执行未知安装入口")


def command(arguments, directory, logfile, timeout=180, required=True):
    """记录完整日志；超时终止本次子进程组并回收，不遗留阻塞Node工作者。"""
    environment = os.environ.copy()
    environment.update(npm_config_cache=str(NPM_CACHE), npm_config_update_notifier="false",
                       npm_config_audit="false", npm_config_fund="false")
    started = time.monotonic()
    timed_out = False
    with Path(logfile).open("wb") as stream:
        process = subprocess.Popen([str(arg) for arg in arguments], cwd=directory, env=environment,
                                   stdout=stream, stderr=subprocess.STDOUT, start_new_session=os.name != "nt")
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            if os.name == "nt":
                process.terminate()
            else:
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                if os.name == "nt":
                    process.kill()
                else:
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
    result = {"command": [str(arg) for arg in arguments], "exit_code": process.returncode,
              "timed_out": timed_out, "reaped": process.poll() is not None,
              "duration_ms": round((time.monotonic() - started) * 1000),
              "log": str(logfile), "log_sha256": sha(logfile)}
    if required and (timed_out or process.returncode != 0):
        raise RuntimeError(f"命令失败：exit={process.returncode}, timeout={timed_out}, log={logfile}")
    return result


def json_output(logfile):
    path = Path(logfile)
    if path.stat().st_size > 1024 * 1024:
        raise RuntimeError("命令JSON输出超过1MiB")
    return json.loads(path.read_text(encoding="utf-8"))


def build_provenance(generated, build_report):
    report = json.loads(build_report.read_text(encoding="utf-8"))
    if report.get("status") != "PASS" or report.get("source_stable") is not True:
        raise RuntimeError("仅接受源码稳定且PASS的Rust构建报告")
    if not any(step.get("exit_code") == 0 and any(command[index:index + 2] == ["--target", "nodejs"]
               for index in range(len(command) - 1)) for step in report.get("steps", [])
               for command in [step.get("command", [])]):
        raise RuntimeError("构建报告未证明wasm-bindgen --target nodejs成功")
    if not any(step.get("exit_code") == 0 and "build" in command and "--release" in command
               and any(command[index:index + 2] == ["--target", "wasm32-unknown-unknown"]
                       for index in range(len(command) - 1)) for step in report.get("steps", [])
               for command in [step.get("command", [])]):
        raise RuntimeError("Node生成必须关联同次成功的Release WASM编译，不能仅复用旧二进制")
    sources = report.get("source_after")
    if not isinstance(sources, dict) or not sources or report.get("source_before") != sources:
        raise RuntimeError("构建报告缺少一致的Rust源码摘要")
    for name, digest in sources.items():
        path = (ROOT / name).resolve()
        if not path.is_relative_to(ROOT / "src/sdk/rust") or sha(path) != digest:
            raise RuntimeError("当前Rust源码与构建证据不同：" + name)
    outputs = report.get("outputs", {})
    raw_wasm = ROOT / "dist/platform-release/target/wasm32-unknown-unknown/release/rockets_stage0_wasm.wasm"
    if not raw_wasm.is_file() or outputs.get(raw_wasm.relative_to(ROOT).as_posix()) != sha(raw_wasm):
        raise RuntimeError("同次Release WASM编译输出缺失或摘要不符")
    for name in GENERATED_FILES:
        path = generated / name
        if not path.is_file() or not path.resolve().is_relative_to(ROOT):
            raise RuntimeError("缺少本项目Node生成产物：" + str(path))
        if outputs.get(path.resolve().relative_to(ROOT).as_posix()) != sha(path):
            raise RuntimeError("Node生成产物与构建报告摘要不符：" + name)
    if (generated / WASM_NAME).read_bytes()[:8] != b"\0asm\x01\0\0\0":
        raise RuntimeError("产物不是WebAssembly模块")
    return {"run_id": report["run_id"], "sha256": sha(build_report), "source_sha256": sources,
            "raw_wasm_sha256": sha(raw_wasm),
            "generated_sha256": {name: sha(generated / name) for name in GENERATED_FILES}}


def validate_package(directory):
    package = json.loads((directory / "package.json").read_text(encoding="utf-8"))
    if package.get("name") != NAME or package.get("version") != VERSION or package.get("private") is not True:
        raise RuntimeError("Node包名称、版本或private配置不符")
    if package.get("license") != "UNLICENSED" or any(name in package.get("scripts", {})
            for name in ("preinstall", "install", "postinstall", "prepare")):
        raise RuntimeError("Node实验包许可/安装脚本不符合限定范围")
    manifest = json.loads((directory / "artifact.json").read_text(encoding="utf-8"))
    if manifest.get("version") != VERSION or manifest.get("binding_target") != "nodejs":
        raise RuntimeError("不是本轮Node目标包")
    actual = all_hashes(directory)
    expected = manifest.get("files_sha256", {})
    if not isinstance(expected, dict) or set(actual) != set(expected) | {"artifact.json"}:
        raise RuntimeError("Node包文件清单与artifact.json不符")
    for name, digest in expected.items():
        if actual[name] != digest:
            raise RuntimeError("Node包文件摘要不符：" + name)
    if any(name.endswith(".rs") or Path(name).name in ("Cargo.toml", "Cargo.lock", "tsconfig.json")
           or name.startswith(("src/", "node_modules/")) for name in actual):
        raise RuntimeError("Node消费包混入源码构建输入")
    generated = directory / "dist/generated/package.json"
    if json.loads(generated.read_text(encoding="utf-8")) != {"type": "commonjs"}:
        raise RuntimeError("Node生成JS的CommonJS边界缺失")
    return actual


def pack(args):
    run, report = start(args.output, "pack")
    try:
        generated = args.generated.resolve()
        provenance = build_provenance(generated, args.build_report.resolve())
        report["build_provenance"] = provenance
        compiler_package = COMPILER.parent.parent / "package.json"
        if not COMPILER.is_file() or json.loads(compiler_package.read_text(encoding="utf-8")).get("version") != "5.9.3":
            raise RuntimeError("缺少已固定的TypeScript 5.9.3，不自动安装")
        stage = run / "package"
        shutil.copytree(PACKAGE, stage, ignore=shutil.ignore_patterns("node_modules", "dist", "generated"))
        destination = stage / "src/generated"
        destination.mkdir(parents=True)
        for name in GENERATED_FILES:
            shutil.copy2(generated / name, destination / name)
        write_json(destination / "package.json", {"type": "commonjs"})
        command([node_binary(), COMPILER, "-p", stage / "tsconfig.json"], stage, run / "typescript-build.log")
        shutil.copytree(destination, stage / "dist/generated")
        shutil.copytree(ROOT / "dist/platform-release/licenses", stage / "licenses")
        license_directory = stage / "licenses/typescript-5.9.3"
        license_directory.mkdir()
        shutil.copy2(COMPILER.parent.parent / "LICENSE.txt", license_directory / "LICENSE.txt")
        shutil.copy2(ROOT / "dist/platform-release/typescript-metadata.json", license_directory / "metadata.json")
        shutil.copy2(args.build_report, run / "rust-build-report.json")
        # 打包白名单外的维护者输入不进入npm；README由npm自动携带时也纳入摘要。
        expected = {"package.json": sha(stage / "package.json")}
        for directory in (stage / "dist", stage / "licenses"):
            expected.update({(directory.relative_to(stage) / name).as_posix(): digest
                             for name, digest in all_hashes(directory).items()})
        for path in stage.iterdir():
            if path.is_file() and path.name.lower().startswith(("readme", "license", "licence")):
                expected[path.name] = sha(path)
        write_json(stage / "artifact.json", {"version": VERSION, "target": "wasm32-unknown-unknown",
                   "binding_target": "nodejs", "scope": "stage0 independent in-memory devices",
                   "generator": {"name": "wasm-bindgen", "version": "0.2.128"},
                   "build_provenance": provenance, "source_sha256": report["source_sha256_before"],
                   "files_sha256": expected})
        command(npm_command() + ["pack", "--json", "--ignore-scripts", "--pack-destination", str(run)],
                stage, run / "npm-pack.log")
        packed = json_output(run / "npm-pack.log")
        archive = run / packed[0]["filename"]
        with tarfile.open(archive) as tar:
            actual = {}
            for item in tar.getmembers():
                if not item.isfile() or not item.name.startswith("package/") or ".." in Path(item.name).parts:
                    raise RuntimeError("npm归档包含意外条目")
                name = item.name[len("package/"):]
                if name in actual:
                    raise RuntimeError("npm归档包含重复条目")
                actual[name] = hashlib.sha256(tar.extractfile(item).read()).hexdigest()
        if actual != expected | {"artifact.json": sha(stage / "artifact.json")}:
            raise RuntimeError("npm TGZ内容与预期白名单/摘要不同")
        if provenance != build_provenance(generated, args.build_report.resolve()):
            raise RuntimeError("打包期间Rust构建报告或生成产物变化")
        report.update(status="PASS", archive=str(archive), archive_sha256=sha(archive),
                      package_files_sha256=actual, typescript="5.9.3")
    except Exception as error:
        report.update(status="FAIL", error=str(error))
    return finish(run, report)
