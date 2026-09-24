#!/usr/bin/env python3
"""M11.d：真实删除投影、精确重试、重启签页与既存副本边界的本机矩阵。"""

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
from network_poc.deletion_cases import CASES as NORMAL_CASES
from network_poc.deletion_boundaries import CASES as BOUNDARY_CASES
from network_poc.fixture import NetworkLab

CASES = NORMAL_CASES + BOUNDARY_CASES


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes():
    paths = [Path(__file__), ROOT / "poc/openmls-probe/Cargo.toml", ROOT / "poc/openmls-probe/Cargo.lock", ROOT / "poc/rust-toolchain.toml"]
    for folder in ("api", "poc/network-relay", "poc/openmls-probe/src", "tests/interop/network_poc"):
        paths.extend(p for p in (ROOT / folder).rglob("*") if p.suffix in (".rs", ".py", ".json", ".c"))
    return {str(p.relative_to(ROOT)): digest(p) for p in sorted(set(paths))}


def save_source_snapshot(run, hashes):
    snapshot = run / "source-snapshot"
    saved = {}
    for relative, expected in hashes.items():
        target = snapshot / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
        saved[relative] = digest(target)
        if saved[relative] != expected:
            raise RuntimeError("源码快照复制期间发生变化，不能验收")
    return saved


def write(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--permission-verifier", type=Path, required=True)
    parser.add_argument("--receipt-signer", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/network-relay/m11-deletion")
    parser.add_argument("--case", action="append", choices=[ident for ident, _ in CASES])
    args = parser.parse_args()
    artifacts = {name: getattr(args, name).resolve() for name in ("binary", "permission_verifier", "receipt_signer")}
    output = args.output.resolve()
    run_id = str(uuid.uuid4())
    run = output / "runs" / run_id
    run.mkdir(parents=True)
    report_path = run / "report.json"
    report = {"run_id": run_id, "status": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat(),
              "scope": "synthetic local M11.d terminal projection and signed incremental notification; real HTTP/SQLite and matching Release Rust CLI",
              "platform": platform.platform(), "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
              "selected_cases": args.case or "ten_current_deletion_and_incremental_cases",
              "source_sha256": source_hashes(), "source_snapshot": "source-snapshot", "artifacts": {name: str(path) for name, path in artifacts.items()},
              "artifact_sha256": {name: digest(path) for name, path in artifacts.items()},
              "limits": ["delete uses existing test controller, not public product delete authorization",
                         "server original ciphertext and previously downloaded local copies remain stored; no physical erase",
                         "terminal deletion appends a signed incremental notification for each still-authorized original message slot",
                         "this runner requires matching lifecycle-aware Release binaries; legacy binaries reject the new event",
                         "tail and overlap pulls are explicit test scheduling, not a shipped SDK automatic sync worker",
                         "notification does not erase successful copies; full pending-queue recovery and garbage collection are not implemented",
                         "real TTL, backup cleanup, UI deletion, platform release, production trust and old-key attack not tested"],
              "process_count_scope": "Rust CLI and Relay starts; excludes Relay internal verifier/signer helper processes",
              "raw_old_key_attack": "NOT_EXECUTED_ACCESS_RESTRICTED", "full_M11": "NOT_COMPLETE", "full_stage0": "NOT_COMPLETE",
              "cases": [], "process_count": 0, "http_count": 0}
    write(report_path, report)
    try:
        report["source_snapshot_sha256"] = save_source_snapshot(run, report["source_sha256"])
        write(report_path, report)
        for ident, operation in CASES:
            if args.case and ident not in args.case:
                continue
            record = {"id": ident, "status": "RUNNING"}
            report["cases"].append(record)
            write(report_path, report)
            with tempfile.TemporaryDirectory(prefix=ident + "-", dir=output) as temporary:
                lab = NetworkLab(artifacts["binary"], Path(temporary).resolve(), artifacts["permission_verifier"], artifacts["receipt_signer"])
                lab.case_evidence = {}
                try:
                    lab.initialize(permissions=True)
                    operation(lab)
                    record["status"] = "PASS"
                    print(record["status"] + " " + ident, flush=True)
                except Exception as error:
                    record.update(status="FAIL", error=str(error))
                    (run / "failure.log").write_text(traceback.format_exc())
                    raise
                finally:
                    lab.close()
                    record["evidence"] = lab.case_evidence
                    stderr = lab.directory / "relay.stderr.log"
                    if stderr.exists():
                        shutil.copy2(stderr, run / (ident + "-relay.stderr.log"))
                    report["process_count"] += lab.process_count
                    report["http_count"] += lab.http_count
                    write(report_path, report)
        report["status"] = "PASS_SCOPED"
    except Exception as error:
        report.update(status="FAIL", error=str(error))
        print(f"FAIL {error}", file=sys.stderr)
    finally:
        report["source_sha256_after"] = source_hashes()
        report["artifact_sha256_after"] = {name: digest(path) for name, path in artifacts.items()}
        if (report["source_sha256"] != report["source_sha256_after"]
                or report["artifact_sha256"] != report["artifact_sha256_after"]):
            report.update(status="FAIL", error="运行期间源码或程序变化，不能验收")
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        write(report_path, report)
    print(json.dumps({"status": report["status"], "run_id": run_id,
                      "cases": len(report["cases"]), "report": str(report_path)}, ensure_ascii=False))
    return 0 if report["status"] == "PASS_SCOPED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
