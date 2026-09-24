#!/usr/bin/env python3
"""构建并验证原始下载记录、下载游标共同提交及保存后处理；保留所有失败轮次。"""

import argparse
import json
import platform
from pathlib import Path
import re
import shutil
import sys
import uuid

from download_cases import CASE_NAMES, Cases
from crypto_support import redact
from support import (CRATE, OUTPUT as STORAGE_OUTPUT, ROOT, require, run_command,
                     sha, source_hashes, utc_now, write_json)

OUTPUT = STORAGE_OUTPUT / "download"


def licenses(metadata, output):
    dependencies = []
    for package in sorted(metadata["packages"], key=lambda item: (item["name"], item["version"])):
        entry = {key: package.get(key) for key in ("name", "version", "license", "license_file", "source")}
        package_root = Path(package["manifest_path"]).parent
        candidates = {path for pattern in ("LICENSE*", "LICENCE*", "COPYING*", "NOTICE*")
                      for path in package_root.glob(pattern) if path.is_file()}
        if package.get("license_file"):
            declared = package_root / package["license_file"]
            require(declared.is_file(), f"缺少声明的许可文件：{package['name']}")
            candidates.add(declared)
        entry["license_files"] = []
        destination = output / "licenses" / f"{package['name']}-{package['version']}"
        for candidate in sorted(candidates):
            require(candidate.stat().st_size <= 2 * 1024 * 1024, "许可文件超过采集上限")
            destination.mkdir(parents=True, exist_ok=True)
            copied = destination / candidate.name
            shutil.copyfile(candidate, copied)
            entry["license_files"].append({"path": str(copied.relative_to(output)), "sha256": sha(copied)})
        dependencies.append(entry)
    write_json(output / "dependencies.json", dependencies)
    return len(dependencies)


def build(output, report):
    commands = report["build_commands"]
    cargo = [ROOT / "dist/toolchains/rust/cargo/bin/cargo", "+1.98.1"]
    common = ["--manifest-path", CRATE / "Cargo.toml", "--locked", "--offline"]
    target = ["--target-dir", OUTPUT / "target"]
    report["rustc_verbose"] = run_command(
        [ROOT / "dist/toolchains/rust/cargo/bin/rustc", "+1.98.1", "-vV"],
        output / "rustc.log", commands, timeout=30)
    metadata = json.loads(run_command([*cargo, "metadata", *common, "--format-version", "1"],
                                    output / "metadata.json", commands, timeout=60))
    report["dependency_count"] = licenses(metadata, output)
    run_command([*cargo, "fmt", "--manifest-path", CRATE / "Cargo.toml", "--check"],
                output / "format.log", commands)
    run_command([*cargo, "clippy", *common, *target, "--all-targets", "--release", "--", "-D", "warnings"],
                output / "clippy.log", commands)
    tests = run_command([*cargo, "test", *common, *target, "--release"], output / "tests.log", commands)
    counts = re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored", tests)
    require(counts and all(status == "ok" and failed == "0" for status, _, failed, _ in counts),
            "没有完整成功的 Rust 测试摘要")
    report["rust_tests"] = {"passed": sum(int(row[1]) for row in counts),
                            "failed": sum(int(row[2]) for row in counts),
                            "ignored": sum(int(row[3]) for row in counts)}
    ordinary = []
    for filename in ("boundaries.rs", "contract.rs", "lifecycle.rs"):
        ordinary += re.findall(r"#\[test\]\s*fn\s+(\w+)", (CRATE / "tests" / filename).read_text())
    require(len(ordinary) == 14, "原普通存储测试基线不再是 14 项，需人工核对")
    require(all(re.search(rf"^test {re.escape(name)} \.\.\. ok$", tests, re.MULTILINE)
                for name in ordinary), "原 14 项普通存储测试没有全部实际通过")
    report["ordinary_rust_tests"] = {"passed": len(ordinary), "names": ordinary}
    run_command([*cargo, "build", *common, *target, "--release", "--bin", "native_crypto"],
                output / "build.log", commands)
    binary = OUTPUT / "target/release/native_crypto"
    require(binary.is_file(), "缺少原生密码实验二进制")
    report.update(binary=str(binary), binary_sha256_before=sha(binary))
    return binary


def run_cases(binary, output, report, commands, names):
    for name in names:
        directory = output / name
        directory.mkdir(mode=0o700)
        case = {"name": name, "status": "RUNNING", "started_at": utc_now(), "command_offset": len(commands)}
        report["cases"].append(case)
        write_json(output / "report.json", report)
        try:
            case["evidence"] = redact(Cases(binary, directory, commands).run(name))
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
                        help="仅复查指定场景，状态标为 PASS_PARTIAL；完整验收不传")
    args = parser.parse_args()
    names = tuple(dict.fromkeys(args.case or CASE_NAMES))
    run_id = str(uuid.uuid4())
    output = OUTPUT / "runs" / run_id
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    commands, binary = [], None
    report = {"run_id": run_id, "status": "RUNNING", "started_at": utc_now(),
              "scope": "isolated native Rust raw download records and download cursor atomic commit, durable stored-envelope processing",
              "full_suite": not args.case, "planned_cases": list(names), "cases": [],
              "host": {"system": platform.system(), "release": platform.release(),
                       "machine": platform.machine(), "python": platform.python_version()},
              "build_commands": [], "source_sha256_before": source_hashes(),
              "limits": {"download_batch": 16, "raw_download_records": 128, "crypto_results_including_initialize_and_group": 128},
              "privacy": "synthetic identities only; text compared in memory and logged as hash/bytes; provider never crosses CLI; case directories mode 0700",
              "not_tested": ["Windows or other native systems", "mobile physical devices",
                             "real power loss, disk full or hardware storage failure",
                             "network download, service delivery, authenticated pull/ack cursor and server acknowledgements",
                             "migration of existing crypto v1/v2 databases (explicitly rejected)",
                             "formal retry/recovery of unresolved crypto reservations",
                             "persistent group-join receiver or multi-member groups",
                             "independent rollback anchor or safe rebuild of pending state",
                             "formal SDK integration or published package changes",
                             "secret storage, database encryption or secure deletion",
                             "independent security acceptance, performance or production capacity"]}
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
        report["binary_sha256_after"] = sha(binary) if binary is not None and binary.exists() else None
        report["binary_unchanged"] = (report.get("binary_sha256_before") == report["binary_sha256_after"]
                                       if binary is not None else None)
        if not report["sources_unchanged"] or report["binary_unchanged"] is False:
            report.update(status="FAIL", stability_error="验证期间源码或二进制变化")
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
