#!/usr/bin/env python3
"""将已验收的同一SDK和冻结消费工程组装为离线Windows验收ZIP，不重打SDK。"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import uuid
import zipfile

from node import WORKER_CHECKS
from node_pack import ROOT, NAME, VERSION, TEMPLATE, sha, write_json

OUTPUT = ROOT / "dist/platform-release/node/windows"
CONSUMER_FILES = ("package.json", "package-lock.json", "tsconfig.json", "consumer.ts", "run.mjs")
RUNNER_FILES = ("node_verify.mjs", "node_verify_support.mjs")
SDK_FILENAME = "rockets-im-stage0-node-0.1.0-stage0.1.tgz"


def now():
    return datetime.now(timezone.utc).isoformat()


def safe_name(value):
    name = PurePosixPath(value)
    if not value or "\\" in value or ":" in value or name.is_absolute() or ".." in name.parts:
        raise ValueError("invalid relative archive path")
    return value


def archive_hashes(archive):
    files, metadata = {}, {}
    with tarfile.open(archive, "r:gz") as source:
        for item in source.getmembers():
            if not item.isfile() or not item.name.startswith("package/"):
                raise ValueError("archive contains non-file or unexpected prefix")
            key = safe_name(item.name[len("package/"):])
            if key in files:
                raise ValueError("duplicate archive entry")
            data = source.extractfile(item).read()
            files[key] = hashlib.sha256(data).hexdigest()
            if key in ("package.json", "artifact.json"):
                metadata[key] = json.loads(data)
    return files, metadata


def read_report(path):
    report = json.loads(path.read_text(encoding="utf-8"))
    if report.get("status") != "PASS" or report.get("source_stable") is not True:
        raise ValueError("only successful source-stable SDK reports can be bundled")
    return report


def build(args):
    bundle_id = str(uuid.uuid4())
    output = OUTPUT / "bundles" / bundle_id
    output.mkdir(parents=True)
    report = {"bundle_id": bundle_id, "status": "RUNNING", "started_at": now(),
              "scope": "offline acceptance kit; no Windows execution", "windows_acceptance": "NOT_TESTED"}
    watched = {}
    try:
        initial_reports = {path.resolve(): sha(path) for path in (args.pack_report, args.verify_report)}
        packed, accepted = read_report(args.pack_report), read_report(args.verify_report)
        if packed.get("phase") != "pack" or accepted.get("phase") != "verify":
            raise ValueError("report phases do not identify pack and consumption")
        archive = Path(packed["archive"])
        sdk_digest = sha(archive)
        if (sdk_digest != packed.get("archive_sha256") or sdk_digest != accepted.get("archive_sha256")
                or accepted.get("archive_stable") is not True or accepted.get("package_restored") is not True):
            raise ValueError("SDK archive does not match accepted immutable package")
        files, metadata = archive_hashes(archive)
        if files != packed.get("package_files_sha256") or files != accepted.get("package_sha256"):
            raise ValueError("archive files differ from the independently consumed package")
        package, artifact = metadata["package.json"], metadata["artifact.json"]
        if package.get("name") != NAME or package.get("version") != VERSION or artifact.get("binding_target") != "nodejs":
            raise ValueError("SDK package identity or target mismatch")
        source_provenance = artifact.get("source_sha256", {})
        consumer_hashes = {name: sha(TEMPLATE / name) for name in CONSUMER_FILES}
        for name, digest in consumer_hashes.items():
            source_key = (TEMPLATE.relative_to(ROOT) / name).as_posix()
            if source_provenance.get(source_key) != digest or accepted["source_sha256_before"].get(source_key) != digest:
                raise ValueError("consumer source differs from accepted SDK provenance: " + name)
        check_result = next(case["result"] for case in accepted["cases"] if case["name"] == "public_api")
        for worker in check_result["workers"]:
            if worker["checks"] != WORKER_CHECKS:
                raise ValueError("worker assertions differ from accepted contract")
        compiler_archive = args.typescript_archive.resolve()
        lock = json.loads((TEMPLATE / "package-lock.json").read_text(encoding="utf-8"))
        integrity = lock["packages"]["node_modules/typescript"]["integrity"]
        compiler_bytes = compiler_archive.read_bytes()
        compiler_digest = hashlib.sha256(compiler_bytes).hexdigest()
        actual_integrity = "sha512-" + base64.b64encode(hashlib.sha512(compiler_bytes).digest()).decode("ascii")
        if actual_integrity != integrity:
            raise ValueError("TypeScript original archive fails frozen lock integrity")
        compiler_files, compiler_metadata = archive_hashes(compiler_archive)
        compiler = compiler_metadata["package.json"]
        if compiler.get("name") != "typescript" or compiler.get("version") != "5.9.3":
            raise ValueError("wrong TypeScript archive")
        if not {"LICENSE.txt", "ThirdPartyNoticeText.txt"}.issubset(compiler_files):
            raise ValueError("TypeScript archive is missing license or notices")

        inputs = [Path(__file__).resolve(), args.pack_report.resolve(), args.verify_report.resolve(), archive,
                  compiler_archive, ROOT / "tools/platform_release/node.py", ROOT / "tools/platform_release/node_pack.py"]
        inputs += [TEMPLATE / name for name in CONSUMER_FILES]
        inputs += [Path(__file__).parent / name for name in RUNNER_FILES]
        watched = {path: sha(path) for path in inputs}
        verified_inputs = initial_reports | {archive: sdk_digest, compiler_archive: compiler_digest}
        verified_inputs.update({TEMPLATE / name: digest for name, digest in consumer_hashes.items()})
        if any(watched[path] != digest for path, digest in verified_inputs.items()):
            raise ValueError("an input changed after its provenance was checked")
        report["source_and_inputs_sha256"] = {str(path): digest for path, digest in watched.items()}
        kit = output / "windows-node-acceptance"
        (kit / "packages").mkdir(parents=True)
        (kit / "consumer").mkdir()
        shutil.copy2(archive, kit / "packages" / SDK_FILENAME)
        shutil.copy2(compiler_archive, kit / "packages/typescript-5.9.3.tgz")
        for name in CONSUMER_FILES:
            shutil.copy2(TEMPLATE / name, kit / "consumer" / name)
        for name in RUNNER_FILES:
            shutil.copy2(Path(__file__).parent / name, kit / name)
        copied_inputs = {kit / "packages" / SDK_FILENAME: sdk_digest,
                         kit / "packages/typescript-5.9.3.tgz": compiler_digest}
        copied_inputs.update({kit / "consumer" / name: digest for name, digest in consumer_hashes.items()})
        copied_inputs.update({kit / name: watched[Path(__file__).parent / name] for name in RUNNER_FILES})
        if any(sha(path) != digest for path, digest in copied_inputs.items()):
            raise ValueError("copied kit differs from verified frozen inputs")
        (kit / "README.md").write_text(
            "# Windows Node SDK 离线验收\n\n"
            "解压整个ZIP到较短的可写目录（如C:/rim），保留中文和空格路径即可。准备Windows版Node/npm；本包不包含Node安装程序。\n"
            "在本目录执行：\n\n```sh\nnode node_verify.mjs\n```\n\n"
            "非标准Node安装可使用 `--npm-cli` 指定实际 `npm-cli.js`。"
            "使用当前Node运行npm JS入口，不调用npm.cmd，不需要PowerShell脚本执行权限。\n\n"
            "SDK TGZ与macOS已验收版本完全相同；TypeScript5.9.3原始TGZ与冻结锁文件SHA-512相同。"
            "每次生成独立空npm缓存，离线安装包并禁用安装脚本，无需联网、Cargo、Rust源码、Python或原项目。\n\n"
            "脚本执行严格TS编译、两个真实Worker共104项检查、缺WASM、错版本、复原重验和超时回收。"
            "结果和日志位于runs/<运行ID>/。将该运行目录交回维护者核对，保留原始ZIP及其SHA-256。\n\n"
            "默认入口只在Windows运行；其他系统默认明确拒绝。维护者显式添加 `--rehearsal` 可排练流程，"
            "排练结果不会标记Windows通过。真实运行应记录Windows版本、CPU与Node/npm版本。"
            "本包是阶段0内存实验，无完整IM网络、持久化或桌面UI。\n\n"
            "SDK归档SHA-256：`" + sdk_digest + "`。ZIP内清单用于发现文件缺失或变化，"
            "不构成对远端操作系统的独立证明；真实Windows归属仍须结合执行环境核验。"
            "项目分发许可未确定；依赖许可原文随SDK和TypeScript归档保留。\n", encoding="utf-8")
        bundle_files = {path.relative_to(kit).as_posix(): sha(path) for path in sorted(kit.rglob("*")) if path.is_file()}
        manifest = {"schema_version": 1, "bundle_id": bundle_id, "target_os": "win32",
                    "sdk": {"name": NAME, "version": VERSION, "archive": "packages/" + SDK_FILENAME,
                            "sha256": sdk_digest, "package_files_sha256": files},
                    "typescript": {"version": "5.9.3", "archive": "packages/typescript-5.9.3.tgz",
                                   "sha256": compiler_digest, "integrity": integrity},
                    "consumer_directory": "consumer", "consumer_files_sha256": consumer_hashes,
                    "worker_checks": WORKER_CHECKS, "bundle_files_sha256": bundle_files,
                    "provenance": {"sdk_pack_run_id": packed["run_id"], "sdk_verify_run_id": accepted["run_id"],
                                   "sdk_archive_sha256": sdk_digest,
                                   "consumer_source_sha256": {(TEMPLATE.relative_to(ROOT) / name).as_posix(): digest
                                                              for name, digest in consumer_hashes.items()}}}
        write_json(kit / "manifest.json", manifest)
        destination = output / ("rockets-node-windows-acceptance-" + bundle_id + ".zip")
        with zipfile.ZipFile(destination, "x", zipfile.ZIP_DEFLATED) as zipped:
            for path in sorted(kit.rglob("*")):
                if path.is_file():
                    zipped.write(path, path.relative_to(output).as_posix())
        with zipfile.ZipFile(destination) as zipped:
            zipped_files = bundle_files | {"manifest.json": sha(kit / "manifest.json")}
            names = ["windows-node-acceptance/" + key for key in zipped_files]
            if sorted(zipped.namelist()) != sorted(names):
                raise ValueError("ZIP entry set differs from the closed bundle list")
            for key, digest in zipped_files.items():
                if hashlib.sha256(zipped.read("windows-node-acceptance/" + key)).hexdigest() != digest:
                    raise ValueError("ZIP bytes differ from bundle manifest")
        report.update(status="PASS", archive=str(destination), archive_sha256=sha(destination),
                      manifest_sha256=sha(kit / "manifest.json"), kit_directory=str(kit),
                      sdk_archive_sha256=sdk_digest, files=len(bundle_files) + 1,
                      typescript_integrity=integrity, source_provenance=manifest["provenance"])
    except Exception as error:
        report.update(status="FAIL", error=str(error))
    finally:
        report["inputs_stable"] = bool(watched) and all(path.is_file() and sha(path) == digest for path, digest in watched.items())
        if report["status"] == "PASS" and not report["inputs_stable"]:
            report.update(status="FAIL", error="bundle inputs changed during assembly")
        report["finished_at"] = now()
        write_json(output / "bundle-report.json", report)
        print(json.dumps({key: report.get(key) for key in ("bundle_id", "status", "archive", "error")}, ensure_ascii=False))
    return 0 if report["status"] == "PASS" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack-report", type=Path, required=True)
    parser.add_argument("--verify-report", type=Path, required=True)
    parser.add_argument("--typescript-archive", type=Path, required=True)
    return build(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
