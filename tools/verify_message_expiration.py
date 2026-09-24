#!/usr/bin/env python3
"""M11.c：原到期判断、精确时钟边界、真实短保留期及重启签页的本机矩阵。"""

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
from network_poc.expiration_cases import CASES as NORMAL_CASES
from network_poc.expiration_boundaries import CASES as BOUNDARY_CASES
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
    parser.add_argument("--output", type=Path, default=ROOT / "dist/network-relay/m11-expiration")
    parser.add_argument("--case", action="append", choices=[ident for ident, _ in CASES])
    args = parser.parse_args()
    artifacts = {name: getattr(args, name).resolve() for name in ("binary", "permission_verifier", "receipt_signer")}
    output = args.output.resolve()
    run_id = str(uuid.uuid4())
    run = output / "runs" / run_id
    run.mkdir(parents=True)
    report_path = run / "report.json"
    report = {"run_id": run_id, "status": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat(),
              "scope": "synthetic local M11.c request-triggered TTL projection and signed incremental notification; real HTTP/SQLite and matching Release Rust CLI",
              "platform": platform.platform(), "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
              "selected_cases": args.case or "thirteen_ttl_and_incremental_cases_with_separate_wall_and_injected_clocks",
              "source_sha256": source_hashes(), "source_snapshot": "source-snapshot", "artifacts": {name: str(path) for name, path in artifacts.items()},
              "artifact_sha256": {name: digest(path) for name, path in artifacts.items()},
              "limits": ["test-only launcher changes retention and optionally clock; original deadline predicate and explicit transaction boundary retained, lifecycle notification joins that transaction",
                         "server original ciphertext and previously downloaded local copies remain stored; no physical erase",
                         "TTL remains request-triggered and appends a signed incremental notification for each still-authorized original message slot",
                         "this runner requires matching lifecycle-aware Release binaries; legacy binaries reject the new event",
                         "tail and overlap pulls are explicit test scheduling, not a shipped SDK automatic sync worker",
                         "notification does not erase successful copies; full pending-queue recovery and garbage collection are not implemented",
                         "one real 5-second wall-clock case; other deadline boundaries use an injected test clock, not 30 days of elapsed time",
                         "backup cleanup, physical erasure, platform release, production trust and old-key attack not tested"],
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
                directory = Path(temporary).resolve()
                wall_clock = ident == "M11.expire.wall_clock"
                retention_ms = 5000 if wall_clock else 1000
                relay_args = ["--test-retention-ms", str(retention_ms)]
                clock_path = None
                if not wall_clock:
                    clock_path = directory / "ttl-clock.txt"
                    clock_path.write_text("1800000000000\n")
                    clock_path.chmod(0o600)
                    relay_args.extend(["--test-clock-file", str(clock_path)])
                lab = NetworkLab(artifacts["binary"], directory, artifacts["permission_verifier"], artifacts["receipt_signer"],
                                 relay_entrypoint=ROOT / "tests/interop/network_poc/expiration_relay.py", relay_args=relay_args)
                lab.clock_path, lab.ttl_base_ms, lab.retention_ms = clock_path, 1800000000000, retention_ms
                lab.case_evidence = {"clock_mode": "real_wall_clock" if wall_clock else "injected_file_clock",
                                     "retention_ms": retention_ms, "expiry_trigger": "original project_expiration predicate"}
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
