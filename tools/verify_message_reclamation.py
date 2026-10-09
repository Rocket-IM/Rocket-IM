#!/usr/bin/env python3
"""M12 显式终态回收、真实满快照及中断恢复的限定联合验证。"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import shutil
import sqlite3
import sys
import tempfile
import traceback
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests/interop"))
from network_poc.reclamation_fixture import ReclamationLab, ReclamationAnchorLab
from network_poc.reclamation_cases import CASES as MAIN_CASES
from network_poc.reclamation_boundaries import CASES as BOUNDARY_CASES
from network_poc.reclamation_faults import CASES as FAULT_CASES, ANCHOR_CASES
from network_poc.reclamation_preparation_cases import CASES as PREPARATION_CASES
from network_poc.reclamation_preparation_faults import ANCHOR_CASES as PREPARATION_ANCHOR_CASES
from network_poc.reclamation_preparation_legacy import CASES as LEGACY_CASES

CASES = MAIN_CASES + BOUNDARY_CASES + FAULT_CASES
PREPARATION_CASES += LEGACY_CASES


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources():
    paths = [Path(__file__), ROOT / "poc/openmls-probe/Cargo.toml",
             ROOT / "poc/openmls-probe/Cargo.lock", ROOT / "poc/rust-toolchain.toml"]
    for folder in ("api", "poc/network-relay", "poc/openmls-probe/src", "tests/interop/network_poc"):
        paths.extend(path for path in (ROOT / folder).rglob("*")
                     if path.is_file() and path.suffix in (".rs", ".py", ".json", ".c", ".mjs"))
    return {str(path.relative_to(ROOT)): digest(path) for path in sorted(set(paths))}


def write(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "permission-verifier", "receipt-signer"):
        parser.add_argument("--" + name, type=Path, required=True,
                            help="显式指定本轮构建程序，禁止把旧运行算作当前实现")
    parser.add_argument("--anchor-helper", type=Path, help="选择独立锚矩阵；使用本轮锚helper")
    parser.add_argument("--old-binary", type=Path, help="显式旧版真实程序，只读验证拒绝新回收快照")
    parser.add_argument("--legacy-binary", type=Path, help="真实 build5，构造旧 v1 applied 与从未持久的历史计划")
    parser.add_argument("--suite", choices=("reclamation", "preparation"), default="reclamation")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--case", action="append", choices=sorted({ident for ident, _ in
                        CASES + ANCHOR_CASES + PREPARATION_CASES + PREPARATION_ANCHOR_CASES}))
    args = parser.parse_args()
    cases = ANCHOR_CASES if args.anchor_helper else CASES
    if args.suite == "preparation":
        cases = PREPARATION_ANCHOR_CASES if args.anchor_helper else PREPARATION_CASES
    if args.case and not set(args.case) <= {ident for ident, _ in cases}:
        parser.error("所选场景不属于当前普通/锚模式")
    artifacts = {name: getattr(args, name).resolve()
                 for name in ("binary", "permission_verifier", "receipt_signer")}
    if args.anchor_helper:
        artifacts["anchor_helper"] = args.anchor_helper.resolve()
    if args.old_binary:
        artifacts["old_binary"] = args.old_binary.resolve()
    if args.legacy_binary:
        artifacts["legacy_binary"] = args.legacy_binary.resolve()
    run_id = str(uuid.uuid4())
    default_output = ROOT / "dist/network-relay/m12-reclamation"
    if args.suite == "preparation":
        default_output /= "durable-preparation"
    output = (args.output or default_output).resolve()
    run = output / "runs" / run_id
    run.mkdir(parents=True)
    report_path = run / "report.json"
    report = {"run_id": run_id, "status": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat(),
        "scope": "Explicit selected terminal-message reclamation in original Rust snapshots and loopback HTTP/SQLite Relay",
        "platform": platform.platform(), "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
        "selected_cases": args.case or [ident for ident, _ in cases], "anchor_mode": bool(args.anchor_helper),
        "suite": args.suite,
        "artifacts": {key: str(path) for key, path in artifacts.items()},
        "pass_meaning": "Only named assertions; refused reclamation remains blocked, not a recovered capacity claim",
        "limits": ["Synthetic local identities, explicit host orchestration and real MLS/signatures",
                   "No production retention TTL, offline eviction policy or automatic worker",
                   "Natural snapshot loads and synthetic near-count limits are reported separately",
                   "Logical payload reclamation is not secure erasure, disk shrink or backup deletion",
                   "No formal SDK/Go Service, target-platform capacity or arbitrary power-loss validation"],
        "process_count_scope": "Rust CLI, explicit signer and Relay starts; excludes Relay internal helpers",
        "full_M12": "NOT_COMPLETE", "full_stage0": "NOT_COMPLETE",
        "cases": [], "process_count": 0, "http_count": 0, "direct_anchor_process_count": 0,
        "host_process_count": 0}
    if args.suite == "preparation":
        report["scope"] = "Durable local preparation, bounded list/recover, fresh host processes and fixed confirm encoding"
        report["limits"] += ["Local query commands keep anchor Reserve/journal/Finish and may advance anchor revision",
                             "Fresh host input isolation is not an OS filesystem security boundary",
                             "Legacy never-persisted lost requests remain an observed limitation"]
    if args.anchor_helper:
        report["independence"] = "synthetic_local; device restoration excludes trusted config and authority"
    write(report_path, report)
    try:
        report["source_sha256_before"] = sources()
        report["artifact_sha256_before"] = {key: digest(path) for key, path in artifacts.items()}
        report["artifact_provenance"] = {}
        for key, path in artifacts.items():
            candidates = [path.parent / "provenance.json", path.parent / "source.tar.gz"]
            if key == "old_binary" and len(path.parents) > 2:
                candidates.append(path.parents[2] / "report.json")
            report["artifact_provenance"][key] = [{"path": str(p), "sha256": digest(p)}
                                                  for p in candidates if p.is_file()]
        for relative in report["source_sha256_before"]:
            saved = run / "source-snapshot" / relative
            saved.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, saved)
        write(report_path, report)
        for ident, operation in cases:
            if args.case and ident not in args.case:
                continue
            record = {"id": ident, "status": "RUNNING"}
            report["cases"].append(record)
            write(report_path, report)
            with tempfile.TemporaryDirectory(prefix=ident + "-", dir=output) as temporary:
                arguments = [artifacts["binary"], Path(temporary).resolve(),
                             artifacts["permission_verifier"], artifacts["receipt_signer"]]
                lab = (ReclamationAnchorLab(*arguments, artifacts["anchor_helper"])
                       if args.anchor_helper else ReclamationLab(*arguments))
                lab.case_evidence = {}
                lab.old_binary = artifacts.get("old_binary")
                lab.legacy_binary = artifacts.get("legacy_binary")
                try:
                    try:
                        lab.initialize(permissions=True)
                        operation(lab)
                    finally:
                        lab.close()
                    record["status"] = lab.case_evidence.get("outcome", "PASS")
                    record["verification"] = "PASS"
                    print(record["status"] + " " + ident, flush=True)
                except Exception as error:
                    record.update(status="FAIL", error=str(error))
                    (run / (ident + "-failure.log")).write_text(traceback.format_exc())
                    raise
                finally:
                    record["evidence"] = lab.case_evidence
                    stderr = lab.directory / "relay.stderr.log"
                    if stderr.exists():
                        shutil.copy2(stderr, run / (ident + "-relay.stderr.log"))
                    for name in ("process_count", "http_count"):
                        record[name] = getattr(lab, name)
                        report[name] += record[name]
                    record["direct_anchor_process_count"] = getattr(lab, "helper_process_count", 0)
                    report["direct_anchor_process_count"] += record["direct_anchor_process_count"]
                    record["host_process_count"] = len(lab.case_evidence.get("host_processes", []))
                    report["host_process_count"] += record["host_process_count"]
                    write(report_path, report)
        report["status"] = "PASS_SCOPED"
    except Exception as error:
        report.update(status="FAIL", error=str(error))
        (run / "failure.log").write_text(traceback.format_exc())
        print("FAIL " + str(error), file=sys.stderr)
    finally:
        try:
            report["source_sha256_after"] = sources()
            report["artifact_sha256_after"] = {key: digest(path) for key, path in artifacts.items()}
            if (report.get("source_sha256_before") != report["source_sha256_after"]
                    or report.get("artifact_sha256_before") != report["artifact_sha256_after"]):
                report.update(status="FAIL", integrity_error="运行期间源码或程序变化，本轮不能验收")
        except Exception as error:
            report.update(status="FAIL", integrity_error=str(error))
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        write(report_path, report)
    print(json.dumps({"status": report["status"], "run_id": run_id,
                      "cases": len(report["cases"]), "report": str(report_path)}, ensure_ascii=False))
    return 0 if report["status"] == "PASS_SCOPED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
