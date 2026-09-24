"""独立消费同一Node TGZ；不编译Rust、不修改SDK或原冻结消费工程。"""
import base64
import hashlib
import json
from pathlib import Path
import shutil

from node_pack import (ROOT, all_hashes, command, node_binary, npm_command, sha,
                       validate_package, write_json)
from platform_release.artifacts import installed_archive, tar_files

PACK_REPORT = ROOT / "dist/platform-release/node/runs/031972fa-e088-4552-824c-ee1a441b6331/report.json"
COMPILER = ROOT / "dist/platform-release/node/portable-dependencies/a0cd0d6b-fb54-4d5e-9295-04e6a53b7fef/typescript-5.9.3.tgz"


def accepted_node(pack_report):
    report = json.loads(pack_report.read_text())
    if report.get("status") != "PASS" or not report.get("source_stable"):
        raise RuntimeError("node_package_not_accepted")
    archive = Path(report["archive"]).resolve()
    if not archive.is_relative_to(ROOT / "dist") or sha(archive) != report["archive_sha256"]:
        raise RuntimeError("accepted_node_archive_changed")
    if tar_files(archive, "package/") != report["package_files_sha256"]:
        raise RuntimeError("node_archive_inventory_mismatch")
    sources = report["source_sha256_before"]
    if not sources or sources != report["source_sha256_after"]:
        raise RuntimeError("node_original_source_evidence_missing")
    for name, digest in sources.items():
        path = (ROOT / name).resolve()
        if not path.is_relative_to(ROOT) or sha(path) != digest:
            raise RuntimeError("node_original_source_changed")
    return {"archive": str(archive), "archive_sha256": sha(archive),
            "pack_report": str(pack_report), "pack_report_sha256": sha(pack_report),
            "accepted_run_id": report["run_id"], "original_source_sha256": sources}


def prepare(work, pack_report, compiler):
    work.mkdir(parents=True)
    build = {"status": "RUNNING", **accepted_node(pack_report)}
    write_json(work / "build-report.json", build)
    try:
        source = ROOT / "tests/consumers/node-interop"
        directory = work / "consumer space 中文"
        shutil.copytree(source, directory)
        for name in ("package.json", "package-lock.json"):
            shutil.copy2(ROOT / "tests/consumers/node" / name, directory / name)
        build["directory"] = str(directory)
        build["consumer_inputs_sha256"] = all_hashes(directory)
        lock = json.loads((directory / "package-lock.json").read_text())
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(compiler.read_bytes()).digest()).decode()
        if integrity != lock["packages"]["node_modules/typescript"]["integrity"]:
            raise RuntimeError("compiler_archive_not_locked")
        build.update(typescript_archive=str(compiler), typescript_archive_sha256=sha(compiler))
        command(npm_command() + ["install", "--offline", "--ignore-scripts", "--include=dev", "--no-bin-links",
                                "--no-audit", "--no-fund", build["archive"], str(compiler)],
                directory, work / "npm-install.log")
        package = directory / "node_modules/@rocket-im/stage0-node"
        validate_package(package)
        installed_archive(package, tar_files(Path(build["archive"]), "package/"), "node")
        if json.loads((directory / "node_modules/typescript/package.json").read_text())["version"] != "5.9.3":
            raise RuntimeError("compiler_version_mismatch")
        command([node_binary(), directory / "node_modules/typescript/bin/tsc", "-p", "tsconfig.interop.json"],
                directory, work / "typescript-build.log")
        if not (directory / "dist/interop.js").is_file():
            raise RuntimeError("compiled_node_interop_missing")
        build.update(status="PASS", runtime="NOT_STARTED", files_sha256=all_hashes(directory))
    except Exception as error:
        build.update(status="FAIL", error={"exception_type": type(error).__name__, "phase": "node_consumer_build"})
        raise
    finally:
        write_json(work / "build-report.json", build)
    return build


def audit(build):
    directory = Path(build["directory"])
    if sha(build["archive"]) != build["archive_sha256"] or sha(build["typescript_archive"]) != build["typescript_archive_sha256"]:
        raise RuntimeError("node_build_archive_changed")
    if accepted_node(Path(build["pack_report"]))["pack_report_sha256"] != build["pack_report_sha256"]:
        raise RuntimeError("node_build_acceptance_changed")
    package = directory / "node_modules/@rocket-im/stage0-node"
    installed_archive(package, tar_files(Path(build["archive"]), "package/"), "node")
    actual = all_hashes(directory)
    if actual != build["files_sha256"]:
        raise RuntimeError("node_consumer_or_install_changed")
    return {"directory": str(directory), "files_sha256": actual,
            "archive_sha256": sha(build["archive"]), "typescript_archive_sha256": sha(build["typescript_archive"])}
