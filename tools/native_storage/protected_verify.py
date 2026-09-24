#!/usr/bin/env python3
"""真实 macOS 专用钥匙串、SQLCipher 与既有锚/重建的隔离验证；保留每轮失败。"""
import argparse
import json
import platform
import shutil
import sys
import uuid

import anchor_verify
from download_verify import licenses
from protected_cases import CASE_NAMES as BASIC_NAMES, Cases as BasicCases
from protected_recovery_cases import CASE_NAMES as RECOVERY_NAMES, Cases as RecoveryCases
from protected_support import redact
from rebuild_verify import package_hashes
from support import CRATE, ROOT, require, run_command, sha, utc_now, write_json

OUTPUT = ROOT / "dist/native-storage/protected"
CASE_NAMES = (*BASIC_NAMES, *RECOVERY_NAMES)


def binaries():
    target = OUTPUT / "target/release"
    return (target / "native_anchored", target / "native_crypto",
            ROOT / "dist/native-storage/anchor/helper-target/release/openmls-rollback-anchor",
            target / "native_rebuild", target / "native_protection")


def build(output, report):
    commands = report["build_commands"]
    cargo = [ROOT / "dist/toolchains/rust/cargo/bin/cargo", "+1.98.1"]
    common = ["--manifest-path", CRATE / "Cargo.toml", "--features", "protected-storage", "--locked", "--offline"]
    target = ["--target-dir", OUTPUT / "target", "--release"]
    report["rustc_verbose"] = run_command([ROOT / "dist/toolchains/rust/cargo/bin/rustc", "+1.98.1", "-vV"],
                                         output / "rustc.log", commands)
    native = output / "native"; native.mkdir()
    metadata = json.loads(run_command([*cargo, "metadata", *common, "--format-version", "1"],
                                     native / "metadata.json", commands))
    report["native_dependency_count"] = licenses(metadata, native)
    codec = next(package for package in metadata["packages"] if package["name"] == "libsqlite3-sys")
    from pathlib import Path
    codec_dir = Path(codec["manifest_path"]).parent / "sqlcipher"
    codec_files = [codec_dir / "LICENSE", codec_dir / "sqlite3.c", codec_dir / "sqlite3.h"]
    report["sqlcipher_sources"] = {str(path): sha(path) for path in codec_files}
    shutil.copyfile(codec_dir / "LICENSE", native / "SQLCipher-LICENSE")
    report["platform_crypto"] = "SQLCipher 4.14.0 Community, SQLite 3.51.3, Apple CommonCrypto; explicit experiment keychain ACL"
    run_command([*cargo, "fmt", "--manifest-path", CRATE / "Cargo.toml", "--check"], output / "format.log", commands)
    run_command([*cargo, "clippy", *common, *target, "--all-targets", "--", "-D", "warnings"],
                output / "clippy.log", commands)
    report["rust_tests"] = anchor_verify.test_summary(run_command([*cargo, "test", *common, *target],
                                                output / "tests.log", commands))
    run_command([*cargo, "build", *common, *target, "--bins"], output / "build.log", commands)
    result = binaries()
    require(all(path.is_file() for path in result), "缺少既有helper或保护二进制")
    return result


def run_cases(binary_paths, output, report, commands, names):
    for name in names:
        directory = output / name; directory.mkdir(mode=0o700)
        case = {"name": name, "status": "RUNNING", "started_at": utc_now(), "command_offset": len(commands)}
        report["cases"].append(case); write_json(output / "report.json", report)
        try:
            cls = BasicCases if name in BASIC_NAMES else RecoveryCases
            case["evidence"] = redact(cls(binary_paths, directory, commands).run(name))
            case["status"] = "PASS"
        except Exception as error:
            case.update(status="FAIL", error=f"{type(error).__name__}: {error}")
        case.update(finished_at=utc_now(), command_count=len(commands) - case["command_offset"])
        write_json(directory / "case.json", case)
        write_json(output / "report.json", report)
        with (output / "commands.jsonl").open("w") as target:
            for item in commands: target.write(json.dumps(redact(item), ensure_ascii=False) + "\n")
        print(json.dumps({"case": name, "status": case["status"], "error": case.get("error")}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", action="append", choices=CASE_NAMES)
    args = parser.parse_args()
    names = tuple(dict.fromkeys(args.case or CASE_NAMES))
    output = OUTPUT / "runs" / str(uuid.uuid4()); output.mkdir(mode=0o700, parents=True)
    commands, binary_paths = [], None
    report = {"run_id": output.name, "status": "RUNNING", "started_at": utc_now(),
              "scope": "isolated macOS protected native storage, pinned configuration and exact anchored recovery",
              "assurance": "synthetic_local", "full_suite": not args.case, "planned_cases": list(names),
              "host": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
              "cases": [], "build_commands": [], "source_sha256_before": anchor_verify.source_hashes(),
              "packages_sha256_before": package_hashes(),
              "privacy": "synthetic data only; passwords and client seeds only in memory/stdin; per-run experiment keychains locked after cases; process data redacted before persistence",
              "not_tested": ["production Data Protection, screen lock or hardware anti-rollback",
                             "Windows, mobile devices, formal SDK integration or Go Service",
                             "production independent authority and first trust; helper anchor.key remains synthetic local",
                             "Keychain plus encrypted database plus authority common rollback",
                             "secure erasure, memory/swap dumps, physical power loss, full disk or storage device failure",
                             "WAL, attachments, production capacity or independent production security acceptance"]}
    write_json(output / "report.json", report)
    print(json.dumps({"run_id": output.name, "report": str(output / "report.json")}), flush=True)
    try:
        binary_paths = build(output, report)
        report["binaries_sha256_before"] = {str(path): sha(path) for path in binary_paths}
        run_cases(binary_paths, output, report, commands, names)
        report["status"] = ("PASS" if not args.case else "PASS_PARTIAL") if all(case["status"] == "PASS" for case in report["cases"]) else "FAIL"
    except Exception as error:
        report.update(status="FAIL", error=f"{type(error).__name__}: {error}")
    finally:
        report["source_sha256_after"] = anchor_verify.source_hashes()
        report["sources_unchanged"] = report["source_sha256_after"] == report["source_sha256_before"]
        report["packages_sha256_after"] = package_hashes()
        report["packages_unchanged"] = report["packages_sha256_after"] == report["packages_sha256_before"]
        report["binaries_sha256_after"] = {str(path): sha(path) for path in binary_paths} if binary_paths else None
        report["binaries_unchanged"] = report.get("binaries_sha256_before") == report["binaries_sha256_after"] if binary_paths else None
        if not report["sources_unchanged"] or not report["packages_unchanged"] or report["binaries_unchanged"] is False:
            report.update(status="FAIL", stability_error="验证期间源码、包或二进制变化")
        report["counts"] = {"planned": len(names), "total": len(report["cases"]),
                            "passed": sum(case["status"] == "PASS" for case in report["cases"])}
        if report["counts"]["total"] != len(names): report["status"] = "FAIL"
        report["finished_at"] = utc_now()
        report["command_entries"] = len(commands)
        with (output / "commands.jsonl").open("w") as target:
            for item in commands: target.write(json.dumps(redact(item), ensure_ascii=False) + "\n")
        write_json(output / "report.json", report)
    print(json.dumps({"status": report["status"], "run_id": output.name, "counts": report["counts"],
                      "rust_tests": report.get("rust_tests"), "error": report.get("error")}), flush=True)
    return 0 if report["status"] in ("PASS", "PASS_PARTIAL") else 1


if __name__ == "__main__":
    sys.exit(main())
