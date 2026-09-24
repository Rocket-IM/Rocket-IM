#!/usr/bin/env python3
"""顺序构建原生锚实验和既有 authority，验证完整库回滚与有限日志恢复，保留失败轮次。"""

import argparse
import json
import platform
import re
import sys
import uuid

from anchor_cases import CASE_NAMES, Cases
from anchor_support import redact
from download_verify import licenses
from support import (CRATE, OUTPUT as STORAGE_OUTPUT, ROOT, require, run_command,
                     sha, source_hashes as native_sources, utc_now, write_json)

OUTPUT = STORAGE_OUTPUT / "anchor"
HELPER_CRATE = ROOT / "poc/openmls-probe"


def source_hashes():
    sources = native_sources()
    for path in sorted(HELPER_CRATE.rglob("*")):
        if path.is_file() and not {"target", "__pycache__", ".DS_Store"}.intersection(path.parts):
            sources[str(path.relative_to(ROOT))] = sha(path)
    return dict(sorted(sources.items()))


def test_summary(output):
    counts = re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored", output)
    require(counts and all(state == "ok" and failed == "0" for state, _, failed, _ in counts),
            "没有完整通过的 Rust 测试摘要")
    return {"passed": sum(int(item[1]) for item in counts),
            "failed": sum(int(item[2]) for item in counts),
            "ignored": sum(int(item[3]) for item in counts)}


def build(output, report):
    commands = report["build_commands"]
    cargo = [ROOT / "dist/toolchains/rust/cargo/bin/cargo", "+1.98.1"]
    common = ["--manifest-path", CRATE / "Cargo.toml", "--locked", "--offline"]
    target = ["--target-dir", OUTPUT / "target"]
    helper_common = ["--manifest-path", HELPER_CRATE / "Cargo.toml", "--locked", "--offline"]
    helper_target = ["--target-dir", OUTPUT / "helper-target"]
    report["rustc_verbose"] = run_command(
        [ROOT / "dist/toolchains/rust/cargo/bin/rustc", "+1.98.1", "-vV"],
        output / "rustc.log", commands, timeout=30)
    for label, options in (("native", common), ("helper", helper_common)):
        directory = output / label
        directory.mkdir(mode=0o700)
        metadata = json.loads(run_command([*cargo, "metadata", *options, "--format-version", "1"],
                                        directory / "metadata.json", commands, timeout=60))
        report[f"{label}_dependency_count"] = licenses(metadata, directory)
    run_command([*cargo, "fmt", "--manifest-path", CRATE / "Cargo.toml", "--check"],
                output / "format.log", commands)
    run_command([*cargo, "clippy", *common, *target, "--all-targets", "--release", "--", "-D", "warnings"],
                output / "clippy.log", commands)
    report["rust_tests"] = test_summary(run_command(
        [*cargo, "test", *common, *target, "--release"], output / "tests.log", commands))
    run_command([*cargo, "build", *common, *target, "--release", "--bin", "native_crypto", "--bin", "native_anchored"],
                output / "build.log", commands)
    # Cargo 使用共同包缓存；两个清单的 metadata/build/test 全部顺序执行。
    report["helper_anchor_rust_tests"] = test_summary(run_command(
        [*cargo, "test", *helper_common, *helper_target, "--release", "--lib", "rollback_anchor"],
        output / "helper-tests.log", commands))
    run_command([*cargo, "build", *helper_common, *helper_target, "--release", "--bin", "openmls-rollback-anchor"],
                output / "helper-build.log", commands)
    binaries = (OUTPUT / "target/release/native_anchored", OUTPUT / "target/release/native_crypto",
                OUTPUT / "helper-target/release/openmls-rollback-anchor")
    require(all(path.is_file() for path in binaries), "缺少配套实验二进制")
    report["binaries_sha256_before"] = {str(path): sha(path) for path in binaries}
    return binaries


def run_cases(binaries, output, report, commands, names):
    for name in names:
        directory = output / name
        directory.mkdir(mode=0o700)
        case = {"name": name, "status": "RUNNING", "started_at": utc_now(), "command_offset": len(commands)}
        report["cases"].append(case)
        write_json(output / "report.json", report)
        try:
            case["evidence"] = redact(Cases(binaries, directory, commands).run(name))
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
                        help="只复查指定场景并标记 PASS_PARTIAL；完整验收不传")
    args = parser.parse_args()
    names = tuple(dict.fromkeys(args.case or CASE_NAMES))
    output = OUTPUT / "runs" / str(uuid.uuid4())
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    commands, binaries = [], None
    report = {"run_id": output.name, "status": "RUNNING", "started_at": utc_now(),
              "scope": "isolated native full-database rollback, fixed trusted configuration, synthetic external anchor, exact committed-journal recovery",
              "assurance": "synthetic_local", "full_suite": not args.case,
              "planned_cases": list(names), "cases": [], "build_commands": [],
              "host": {"system": platform.system(), "release": platform.release(),
                       "machine": platform.machine(), "python": platform.python_version()},
              "source_sha256_before": source_hashes(),
              "privacy": "synthetic identities only; credentials/provider/plaintext recursively redacted before logging; private configs mode 0600; directories mode 0700",
              "not_tested": ["production independent authority or hardware rollback protection",
                             "Windows, mobile devices, desktop SDK integration or published package changes",
                             "power loss, storage device failure, full disk or production storage encryption",
                             "network Service, production authentication or business server deployment",
                             "automatic cleanup, resumption or safe rebuild of unresolved crypto operations",
                             "migration of arbitrary old stores or existing production identities",
                             "malicious host controlling database plus trusted config plus authority (expected-undetectable case included)",
                             "independent security acceptance, performance or production capacity"]}
    write_json(output / "report.json", report)
    print(json.dumps({"run_id": output.name, "report": str(output / "report.json")}), flush=True)
    try:
        binaries = build(output, report)
        run_cases(binaries, output, report, commands, names)
        report["status"] = ("PASS" if report["full_suite"] else "PASS_PARTIAL") if all(
            case["status"] == "PASS" for case in report["cases"]) else "FAIL"
    except Exception as error:
        report.update(status="FAIL", error=f"{type(error).__name__}: {error}")
    finally:
        report["source_sha256_after"] = source_hashes()
        report["sources_unchanged"] = report["source_sha256_before"] == report["source_sha256_after"]
        report["binaries_sha256_after"] = {str(path): sha(path) for path in binaries} if binaries else None
        report["binaries_unchanged"] = (report.get("binaries_sha256_before") == report["binaries_sha256_after"]
                                          if binaries else None)
        if not report["sources_unchanged"] or report["binaries_unchanged"] is False:
            report.update(status="FAIL", stability_error="验证期间输入源码或实验二进制变化")
        report["counts"] = {"planned": len(names), "total": len(report["cases"]),
                            "passed": sum(case["status"] == "PASS" for case in report["cases"])}
        if report["counts"]["total"] != len(names):
            report["status"] = "FAIL"
        report["finished_at"] = utc_now()
        with (output / "commands.jsonl").open("w") as destination:
            for item in commands:
                destination.write(json.dumps(redact(item), ensure_ascii=False) + "\n")
        report["command_entries"] = len(commands)
        write_json(output / "report.json", report)
    print(json.dumps({"status": report["status"], "run_id": output.name,
                      "report": str(output / "report.json"), "counts": report["counts"],
                      "rust_tests": report.get("rust_tests"), "error": report.get("error")}), flush=True)
    return 0 if report["status"] in ("PASS", "PASS_PARTIAL") else 1


if __name__ == "__main__":
    sys.exit(main())
