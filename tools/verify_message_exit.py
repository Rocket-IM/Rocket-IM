#!/usr/bin/env python3
"""M08：消息接受、拒绝和封口在提交前后真实退出的本机矩阵。"""

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
from network_poc.exit_cases import CASES
from network_poc.fixture import NetworkLab


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes():
    paths = [Path(__file__), ROOT / "poc/openmls-probe/Cargo.toml",
             ROOT / "poc/openmls-probe/Cargo.lock", ROOT / "poc/rust-toolchain.toml"]
    for folder in ("api", "poc/network-relay", "poc/openmls-probe/src", "tests/interop/network_poc"):
        paths.extend(p for p in (ROOT / folder).rglob("*") if p.suffix in (".rs", ".py", ".json", ".c"))
    return {str(p.relative_to(ROOT)): digest(p) for p in sorted(set(paths))}


def write(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--permission-verifier", type=Path, required=True)
    parser.add_argument("--receipt-signer", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/network-relay/m08-exit")
    parser.add_argument("--case", action="append", choices=[ident for ident, _ in CASES])
    args = parser.parse_args()
    artifacts = {name: getattr(args, name).resolve() for name in ("binary", "permission_verifier", "receipt_signer")}
    output = args.output.resolve()
    run_id = str(uuid.uuid4())
    run = output / "runs" / run_id
    run.mkdir(parents=True)
    report_path = run / "report.json"
    report = {"run_id": run_id, "status": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat(),
              "scope": "synthetic local M08 controlled process exits before/after transaction commit; HTTP/Relay SQLite and Release Rust encrypted snapshot CLI",
              "platform": platform.platform(), "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
              "selected_cases": args.case or "all_sixteen_terminal_exit_cases",
              "source_sha256": source_hashes(), "artifacts": {name: str(path) for name, path in artifacts.items()},
              "artifact_sha256": {name: digest(path) for name, path in artifacts.items()},
              "limits": ["controlled os._exit(86/87) at named transaction points; not arbitrary power loss or physical disk failure",
                         "state_stale uses original MLS packet after signed R0; other rejection headers are synthetic HTTP negative inputs",
                         "pre-accept cancellation has NULL stored header/payload; no original server message bytes to preserve",
                         "closure_id is an opaque persisted identifier, not a client-verifiable signed closure proof",
                         "capture compares message-related rows and device streams, not all database bytes",
                         "no formal SDK automatic recovery, TLS/WSS, production identity or platform release acceptance"],
              "process_count_scope": "Rust CLI and Relay starts; excludes Relay internal verifier/signer helper processes",
              "raw_old_key_attack": "NOT_EXECUTED_ACCESS_RESTRICTED", "full_stage0": "NOT_COMPLETE",
              "cases": [], "process_count": 0, "http_count": 0}
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
