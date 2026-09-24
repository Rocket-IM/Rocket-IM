#!/usr/bin/env python3
"""M09：旧请求、封口、双后继与真实签名R0/R1的独立逐轮验证。"""

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
from network_poc.attempt_cases import CASES as RACE_CASES
from network_poc.attempt_permission_cases import CASES as PERMISSION_CASES
from network_poc.concurrency_fixture import ConcurrencyLab

CASES = RACE_CASES + PERMISSION_CASES


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes():
    paths = [Path(__file__), ROOT / "tools/verify_message_concurrency.py",
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
    parser.add_argument("--binary", type=Path, required=True, help="明确使用已构建的Release Rust CLI")
    parser.add_argument("--permission-verifier", type=Path, help="默认使用binary同目录的openmls-permission-verify")
    parser.add_argument("--receipt-signer", type=Path, help="默认使用binary同目录的openmls-relay-receipt")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/network-relay/m09")
    parser.add_argument("--case", action="append", choices=[case[0] for case in CASES])
    args = parser.parse_args()
    binary, output = args.binary.resolve(), args.output.resolve()
    verifier = (args.permission_verifier or binary.parent / "openmls-permission-verify").resolve()
    signer = (args.receipt_signer or binary.parent / "openmls-relay-receipt").resolve()
    artifacts = {"binary": binary, "permission_verifier": verifier, "receipt_signer": signer}
    artifact_hashes = {name: digest(path) for name, path in artifacts.items()}
    run_id = str(uuid.uuid4())
    run = output / "runs" / run_id
    run.mkdir(parents=True)
    report_path = run / "report.json"
    report = {"run_id": run_id, "status": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat(),
              "scope": "synthetic local Rust CLI and instrumented real HTTP/SQLite Relay; not production SDK/Go Service",
              "platform": platform.platform(), "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
              "selected_cases": args.case or "all_M09_cases", "source_sha256": source_hashes(),
              "artifacts": {name: str(path) for name, path in artifacts.items()}, "artifact_sha256": artifact_hashes,
              "ordering": "held real transactions plus actual BEGIN signals; 24 explicit permutations of four concurrent in-flight HTTP requests; no SQLite FIFO claim",
              "successors": "real MLS ciphertexts generated sequentially without state rollback; P3 uses synthetic local P2 closure, submitted as adversarial HTTP sibling of P2 with real P1 closure; not SDK concurrent replacement acceptance",
              "permissions": "five real Rust-signed permission and Service-signed receipt cases; no test set_state mutation",
              "raw_old_key_attack": "NOT_EXECUTED_ACCESS_RESTRICTED", "full_stage0": "NOT_COMPLETE",
              "cases": [], "process_count": 0, "http_count": 0}
    write(report_path, report)
    try:
        for ident, execute in CASES:
            if args.case and ident not in args.case:
                continue
            record = {"id": ident, "status": "RUNNING"}
            report["cases"].append(record)
            write(report_path, report)
            permissions = ident.startswith("M09.permission.")
            with tempfile.TemporaryDirectory(prefix=ident + "-", dir=output) as temporary:
                lab = ConcurrencyLab(binary, Path(temporary).resolve(),
                                     verifier if permissions else None, signer if permissions else None)
                try:
                    lab.initialize(permissions=permissions)
                    execute(lab)
                    record["status"] = "PASS"
                    print(f"PASS {ident}", flush=True)
                except Exception as error:
                    record.update(status="FAIL", error=str(error))
                    (run / "failure.log").write_text(traceback.format_exc())
                    if lab.process is not None and lab.process.poll() is None:
                        try:
                            lab.case_evidence["failure_timeline"] = lab.probe("status")
                        except Exception as probe_error:
                            lab.case_evidence["failure_timeline_error"] = str(probe_error)
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
        report["status"] = "PASS"
    except Exception as error:
        report.update(status="FAIL", error=str(error))
        print(f"FAIL {error}", file=sys.stderr)
    finally:
        report["source_sha256_after"] = source_hashes()
        report["artifact_sha256_after"] = {name: digest(path) for name, path in artifacts.items()}
        if (report["source_sha256"] != report["source_sha256_after"]
                or report["artifact_sha256"] != report["artifact_sha256_after"]):
            report.update(status="FAIL", error="运行期间源码或Rust程序变化，不能验收")
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        write(report_path, report)
    print(json.dumps({"status": report["status"], "run_id": run_id,
                      "cases": len(report["cases"]), "report": str(report_path)}, ensure_ascii=False))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
