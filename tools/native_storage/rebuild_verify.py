#!/usr/bin/env python3
"""顺序构建并验证原生未决范围安全重建；子集、失败和限制分别保留。"""

import argparse
import json
import platform
import sys
import uuid

import anchor_verify
from anchor_support import redact
from rebuild_cases import CASE_NAMES, Cases
from support import CRATE, OUTPUT as STORAGE_OUTPUT, ROOT, require, run_command, sha, utc_now, write_json

OUTPUT = STORAGE_OUTPUT / "rebuild"


def package_hashes():
    files = (
        "dist/platform-release/runs/flutter-c3cc915a-a271-49de-ab69-eae8d9dd84ac/release/rockets_im_stage0-0.1.0-stage0.1.tar.gz",
        "dist/platform-release/swift/RocketsIMStage0-0.1.0-stage0.1.zip",
        "dist/platform-release/browser/rockets-im-stage0-0.1.0-stage0.1.tgz",
        "dist/platform-release/node/runs/031972fa-e088-4552-824c-ee1a441b6331/rockets-im-stage0-node-0.1.0-stage0.1.tgz",
        "dist/platform-release/runs/kotlin-b66d360f-42a6-427b-b3f2-535b163cf8a1/release/rockets-stage0-0.1.0-stage0.1.aar",
    )
    require(all((ROOT / name).is_file() for name in files), "缺少此前已验收的五份SDK归档")
    return {name: sha(ROOT / name) for name in files}


def build(output, report):
    binaries = anchor_verify.build(output, report)
    run_command([ROOT / "dist/toolchains/rust/cargo/bin/cargo", "+1.98.1", "build",
                 "--manifest-path", CRATE / "Cargo.toml", "--locked", "--offline",
                 "--target-dir", anchor_verify.OUTPUT / "target", "--release", "--bin", "native_rebuild"],
                output / "rebuild-build.log", report["build_commands"])
    binary = anchor_verify.OUTPUT / "target/release/native_rebuild"
    require(binary.is_file(), "缺少原生重建二进制")
    binaries = (*binaries, binary)
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
                        help="只执行指定场景；通过也标记PASS_PARTIAL")
    args = parser.parse_args()
    names = tuple(dict.fromkeys(args.case or CASE_NAMES))
    output = OUTPUT / "runs" / str(uuid.uuid4())
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    commands, binaries = [], None
    report = {"run_id": output.name, "status": "RUNNING", "started_at": utc_now(),
              "scope": "native SQLite unresolved scope rebuild with a fresh device, pinned independent approval, immutable successor and real OpenMLS Add/Welcome",
              "assurance": "synthetic_local", "full_suite": not args.case, "planned_cases": list(names),
              "cases": [], "build_commands": [],
              "host": {"system": platform.system(), "release": platform.release(),
                       "machine": platform.machine(), "python": platform.python_version()},
              "source_sha256_before": anchor_verify.source_hashes(),
              "packages_sha256_before": package_hashes(),
              "privacy": "synthetic identities only; seeds/provider/plaintext recursively redacted before logging; old originals retained; database and trusted directories separated",
              "not_tested": ["Windows, mobile real devices, TypeScript native binding or formal SDK integration",
                             "Go Service, production authority failure domains or real first trust",
                             "system secret storage, secure erasure, power loss or physical storage failure",
                             "old restricted-key attack; only this run synthetic identities used",
                             "database plus authority plus trusted configuration rollback may be undetectable",
                             "old history, old provider state or old cursors recovery through rebuild",
                             "full production Permission/Relay RecoveryRecord pipeline or persistent business membership",
                             "performance capacity or independent production security acceptance"]}
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
        report["source_sha256_after"] = anchor_verify.source_hashes()
        report["sources_unchanged"] = report["source_sha256_before"] == report["source_sha256_after"]
        report["packages_sha256_after"] = package_hashes()
        report["packages_unchanged"] = report["packages_sha256_before"] == report["packages_sha256_after"]
        report["binaries_sha256_after"] = {str(path): sha(path) for path in binaries} if binaries else None
        report["binaries_unchanged"] = (report.get("binaries_sha256_before") == report["binaries_sha256_after"]
                                          if binaries else None)
        if not report["sources_unchanged"] or not report["packages_unchanged"] or report["binaries_unchanged"] is False:
            report.update(status="FAIL", stability_error="验证期间源码、固定SDK包或二进制变化")
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
    print(json.dumps({"status": report["status"], "run_id": output.name, "counts": report["counts"],
                      "rust_tests": report.get("rust_tests"), "error": report.get("error")}), flush=True)
    return 0 if report["status"] in ("PASS", "PASS_PARTIAL") else 1


if __name__ == "__main__":
    sys.exit(main())
