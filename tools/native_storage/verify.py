#!/usr/bin/env python3
"""构建隔离 Rust POC 并保留逐次原生文件/进程恢复验证证据。"""

import argparse
import json
import platform
import re
import sys
import uuid

from cases import CASE_NAMES, Cases
from support import (CRATE, OUTPUT, ROOT, require, run_command, sha, source_hashes,
                     utc_now, write_json)


def build(output, report):
    commands = report["build_commands"]
    cargo = [ROOT / "dist/toolchains/rust/cargo/bin/cargo", "+1.98.1"]
    common = ["--manifest-path", CRATE / "Cargo.toml", "--offline", "--locked"]
    target = ["--target-dir", OUTPUT / "target"]
    report["rustc_verbose"] = run_command(
        [ROOT / "dist/toolchains/rust/cargo/bin/rustc", "+1.98.1", "-vV"],
        output / "rustc.log", commands, timeout=30)
    metadata = json.loads(run_command(
        [*cargo, "metadata", *common, "--format-version", "1"],
        output / "metadata.json", commands, timeout=60))
    dependencies = [{key: package.get(key) for key in ("name", "version", "license", "license_file", "source")}
                    for package in metadata["packages"]]
    dependencies.sort(key=lambda item: (item["name"], item["version"]))
    write_json(output / "dependencies.json", dependencies)
    report["dependency_count"] = len(dependencies)
    run_command([*cargo, "fmt", "--manifest-path", CRATE / "Cargo.toml", "--check"],
                output / "format.log", commands)
    run_command([*cargo, "clippy", *common, *target, "--all-targets", "--release", "--", "-D", "warnings"],
                output / "clippy.log", commands)
    tests = run_command([*cargo, "test", *common, *target, "--release"],
                        output / "tests.log", commands)
    counts = re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored", tests)
    require(counts and all(status == "ok" and failed == "0" for status, _, failed, _ in counts),
            "没有完整成功的 Rust 测试摘要")
    report["rust_tests"] = {"passed": sum(int(row[1]) for row in counts),
                            "failed": sum(int(row[2]) for row in counts),
                            "ignored": sum(int(row[3]) for row in counts)}
    require(report["rust_tests"]["passed"] > 0, "Rust 单测未实际执行")
    run_command([*cargo, "build", *common, *target, "--release"], output / "build.log", commands)
    binary = OUTPUT / "target/release/rockets-native-storage-probe"
    require(binary.is_file(), "缺少构建后的原生二进制")
    report.update(binary=str(binary), binary_sha256_before=sha(binary))
    return binary


def run_cases(binary, output, report, commands, names):
    for name in names:
        directory = output / name
        directory.mkdir()
        case = {"name": name, "status": "RUNNING", "started_at": utc_now(),
                "command_offset": len(commands)}
        report["cases"].append(case)
        write_json(output / "report.json", report)
        try:
            case["evidence"] = getattr(Cases(binary, directory, commands), name)()
            case["status"] = "PASS"
        except Exception as error:
            case.update(status="FAIL", error=f"{type(error).__name__}: {error}")
        case.update(finished_at=utc_now(), command_count=len(commands) - case["command_offset"])
        write_json(directory / "case.json", case)
        write_json(output / "report.json", report)
        print(json.dumps({"case": name, "status": case["status"], "error": case.get("error")}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", action="append", choices=CASE_NAMES,
                        help="仅复查指定场景；最终完整验收不传此参数")
    args = parser.parse_args()
    names = tuple(dict.fromkeys(args.case or CASE_NAMES))
    run_id = str(uuid.uuid4())
    output = OUTPUT / "runs" / run_id
    output.mkdir(parents=True, exist_ok=False)
    commands, binary = [], None
    report = {
        "run_id": run_id, "status": "RUNNING", "started_at": utc_now(),
        "scope": "isolated native Rust SQLite synthetic records and process recovery",
        "full_suite": names == CASE_NAMES, "planned_cases": list(names), "cases": [],
        "host": {"system": platform.system(), "release": platform.release(), "machine": platform.machine(),
                 "python": platform.python_version()}, "build_commands": [],
        "source_sha256_before": source_hashes(),
        "not_tested": ["Windows and other native systems", "mobile physical devices",
                       "real power loss, disk full and hardware/storage failure", "cryptographic state and MLS",
                       "formal SDK integration or published artifacts", "performance and production capacity",
                       "database at-rest encryption, secret storage and secure deletion"],
    }
    write_json(output / "report.json", report)
    print(json.dumps({"run_id": run_id, "report": str(output / "report.json")}), flush=True)
    try:
        binary = build(output, report)
        run_cases(binary, output, report, commands, names)
        if all(case["status"] == "PASS" for case in report["cases"]):
            report["status"] = "PASS" if report["full_suite"] else "PASS_PARTIAL"
        else:
            report["status"] = "FAIL"
    except Exception as error:
        report.update(status="FAIL", error=f"{type(error).__name__}: {error}")
    finally:
        report["source_sha256_after"] = source_hashes()
        report["sources_unchanged"] = report["source_sha256_before"] == report["source_sha256_after"]
        if binary is not None:
            report["binary_sha256_after"] = sha(binary) if binary.exists() else None
            report["binary_unchanged"] = report["binary_sha256_before"] == report["binary_sha256_after"]
        else:
            report["binary_unchanged"] = None
        if not report["sources_unchanged"] or report["binary_unchanged"] is False:
            report.update(status="FAIL", stability_error="验证期间源或二进制变化")
        report["counts"] = {"planned": len(names), "total": len(report["cases"]),
                            "passed": sum(case["status"] == "PASS" for case in report["cases"])}
        if report["counts"]["total"] != len(names):
            report["status"] = "FAIL"
        report["finished_at"] = utc_now()
        with (output / "commands.jsonl").open("w") as destination:
            for item in commands:
                destination.write(json.dumps(item, ensure_ascii=False) + "\n")
        report["command_entries"] = len(commands)
        write_json(output / "report.json", report)
    print(json.dumps({"status": report["status"], "run_id": run_id,
                      "report": str(output / "report.json"), "counts": report["counts"],
                      "rust_tests": report.get("rust_tests"), "error": report.get("error")}), flush=True)
    return 0 if report["status"] in ("PASS", "PASS_PARTIAL") else 1


if __name__ == "__main__":
    sys.exit(main())
