#!/usr/bin/env python3
"""M02：默认与计数构建分别验证丢接受响应后的原尝试恢复。"""

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
from network_poc.retry_cases import CASES
from network_poc.retry_fixture import RetryLab


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
    for flag in ("binary", "probe-binary", "permission-verifier", "receipt-signer"):
        parser.add_argument("--" + flag, type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/network-relay/m02-retry")
    parser.add_argument("--case", action="append", choices=[ident for ident, _ in CASES])
    parser.add_argument("--mode", choices=("both", "default", "probe"), default="both")
    args = parser.parse_args()
    artifacts = {name: getattr(args, name).resolve()
                 for name in ("binary", "probe_binary", "permission_verifier", "receipt_signer")}
    output = args.output.resolve()
    run_id = str(uuid.uuid4())
    run = output / "runs" / run_id
    run.mkdir(parents=True)
    report_path = run / "report.json"
    report = {"run_id": run_id, "status": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat(),
              "scope": "synthetic local M02 committed ACK loss; HTTP/Relay SQLite and Rust encrypted snapshot CLI",
              "platform": platform.platform(), "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
              "selected_cases": args.case or "all", "selected_mode": args.mode,
              "source_sha256": source_hashes(), "artifacts": {k: str(p) for k, p in artifacts.items()},
              "artifact_sha256": {k: digest(p) for k, p in artifacts.items()},
              "probe_scope": "wire_send create_message call site on current synchronous execute thread; not snapshot encryption or legacy send",
              "limits": ["probe feature is off by default; default runs explicitly NOT_INSTRUMENTED",
                         "controlled response drop/exit and separate CLI processes; not arbitrary power loss",
                         "no formal SDK automatic retry worker, TLS/WSS, production identity or platform release acceptance"],
              "process_count_scope": "Rust CLI and Relay starts; excludes Relay internal verifier/signer helper processes",
              "raw_old_key_attack": "NOT_EXECUTED_ACCESS_RESTRICTED", "full_stage0": "NOT_COMPLETE",
              "cases": [], "process_count": 0, "http_count": 0}
    write(report_path, report)
    try:
        modes = ("default", "probe") if args.mode == "both" else (args.mode,)
        for mode in modes:
            for ident, operation in CASES:
                if args.case and ident not in args.case:
                    continue
                record = {"id": ident + "." + mode, "build_mode": mode, "status": "RUNNING"}
                report["cases"].append(record)
                write(report_path, report)
                with tempfile.TemporaryDirectory(prefix=record["id"] + "-", dir=output) as temporary:
                    binary = artifacts["probe_binary" if mode == "probe" else "binary"]
                    lab = RetryLab(binary, Path(temporary).resolve(), artifacts["permission_verifier"],
                                   artifacts["receipt_signer"], probe_enabled=mode == "probe")
                    lab.case_evidence = {}
                    try:
                        lab.initialize(permissions=True)
                        operation(lab)
                        record["status"] = "PASS"
                        print("PASS " + record["id"], flush=True)
                    except Exception as error:
                        record.update(status="FAIL", error=str(error))
                        (run / "failure.log").write_text(traceback.format_exc())
                        raise
                    finally:
                        lab.close()
                        lab.case_evidence["encryption_observations"] = lab.encryption_observations
                        record["evidence"] = lab.case_evidence
                        stderr = lab.directory / "relay.stderr.log"
                        if stderr.exists():
                            shutil.copy2(stderr, run / (record["id"] + "-relay.stderr.log"))
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
