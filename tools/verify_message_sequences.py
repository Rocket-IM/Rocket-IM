#!/usr/bin/env python3
"""M12.c：大事件序号经默认Rust、签页和真实Node消费的精确往返。"""

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
from network_poc.sequence_cases import CASES
from network_poc.fixture import NetworkLab


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes():
    paths = [Path(__file__), ROOT / "poc/openmls-probe/Cargo.toml",
             ROOT / "poc/openmls-probe/Cargo.lock", ROOT / "poc/rust-toolchain.toml"]
    for folder in ("api", "poc/network-relay", "poc/openmls-probe/src", "tests/interop/network_poc"):
        paths.extend(p for p in (ROOT / folder).rglob("*") if p.suffix in (".rs", ".py", ".json", ".c", ".mjs"))
    return {str(p.relative_to(ROOT)): digest(p) for p in sorted(set(paths))}


def write(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--seed-binary", type=Path, required=True)
    parser.add_argument("--permission-verifier", type=Path, required=True)
    parser.add_argument("--receipt-signer", type=Path, required=True)
    parser.add_argument("--node-binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/network-relay/m12-sequence")
    parser.add_argument("--case", action="append", choices=[ident for ident, _ in CASES])
    args = parser.parse_args()
    artifacts = {name: getattr(args, name).resolve() for name in
                 ("binary", "seed_binary", "permission_verifier", "receipt_signer", "node_binary")}
    output = args.output.resolve()
    run_id = str(uuid.uuid4())
    run = output / "runs" / run_id
    run.mkdir(parents=True)
    report_path = run / "report.json"
    report = {"run_id": run_id, "status": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat(),
              "scope": "synthetic local M12.c large event sequences, real Node HTTP, signed Relay pages and default Release Rust encrypted snapshot CLI",
              "platform": platform.platform(), "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
              "selected_cases": args.case or "all_four_sequence_cases",
              "source_sha256": source_hashes(), "artifacts": {name: str(path) for name, path in artifacts.items()},
              "artifact_sha256": {name: digest(path) for name, path in artifacts.items()},
              "limits": ["one-shot feature-only client seed and offline Relay sequence relocation; no 2^53 event history is generated or verified",
                         "default Release CLI consumes the test-generated checkpoint; subsequent pages are real HTTP and verified by original Rust signed-page processing",
                         "original allocator remains limited to 10000; no high-sequence allocation or receipt append capacity claim",
                         "positive Relay storage values are within SQLite i64; u64 maximum is only an above-watermark input rejection",
                         "Node is a transport test consumer, not a released TypeScript SDK; no browser or Windows claim",
                         "encrypted snapshots and normal restarts; no formal SDK SQLite, automatic worker, arbitrary power-loss, TLS/WSS or production identity acceptance"],
              "process_count_scope": "Rust CLI, explicit signer, Relay starts and Node calls; excludes Relay internal signing/verifying helpers",
              "raw_old_key_attack": "NOT_EXECUTED_ACCESS_RESTRICTED", "full_stage0": "NOT_COMPLETE",
              "cases": [], "process_count": 0, "http_count": 0, "node_count": 0}
    write(report_path, report)
    try:
        for ident, operation in CASES:
            if args.case and ident not in args.case:
                continue
            record = {"id": ident, "status": "RUNNING"}
            report["cases"].append(record)
            write(report_path, report)
            with tempfile.TemporaryDirectory(prefix=ident + "-", dir=output) as temporary:
                lab = NetworkLab(artifacts["binary"], Path(temporary).resolve(), artifacts["permission_verifier"], artifacts["receipt_signer"])
                lab.seed_binary = artifacts["seed_binary"]
                lab.node_binary = artifacts["node_binary"]
                lab.node_count = 0
                lab.case_evidence = {}
                try:
                    lab.initialize(permissions=True)
                    operation(lab)
                    record["status"] = "PASS"
                    print(record["status"] + " " + ident, flush=True)
                except Exception as error:
                    failure_log = ident + "-failure.log"
                    record.update(status="FAIL", error=str(error), failure_log=failure_log)
                    (run / failure_log).write_text(traceback.format_exc())
                    raise
                finally:
                    lab.close()
                    record["evidence"] = lab.case_evidence
                    stderr = lab.directory / "relay.stderr.log"
                    if stderr.exists():
                        shutil.copy2(stderr, run / (ident + "-relay.stderr.log"))
                    record["process_count"] = lab.process_count
                    record["http_count"] = lab.http_count
                    record["node_count"] = lab.node_count
                    report["process_count"] += lab.process_count
                    report["http_count"] += lab.http_count
                    report["node_count"] += lab.node_count
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
