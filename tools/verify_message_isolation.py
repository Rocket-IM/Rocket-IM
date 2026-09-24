#!/usr/bin/env python3
"""M11.a：双真实实例隔离矩阵与签名首流来源拒绝回归。"""

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
from network_poc.isolation_cases import CASES, execute_isolation
from network_poc.isolation_fixture import IsolationPair
from network_poc.isolation_initial_stream import verify_initial_source

INITIAL = "M11.isolation.initial_stream_boundary"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes():
    paths = [Path(__file__), ROOT / "poc/openmls-probe/Cargo.lock", ROOT / "poc/rust-toolchain.toml"]
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
    parser.add_argument("--output", type=Path, default=ROOT / "dist/network-relay/m11-isolation")
    parser.add_argument("--case", action="append", choices=[c[0] for c in CASES] + [INITIAL])
    args = parser.parse_args()
    artifacts = {name: getattr(args, name).resolve() for name in ("binary", "permission_verifier", "receipt_signer")}
    output = args.output.resolve()
    run_id = str(uuid.uuid4())
    run = output / "runs" / run_id
    run.mkdir(parents=True)
    report_path = run / "report.json"
    report = {"run_id": run_id, "status": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat(),
              "scope": "two concurrent loopback Relay processes and eight Rust device stores; synthetic local POC, pinned signed-page source and bound-stream isolation",
              "platform": platform.platform(), "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
              "selected_cases": args.case or "six_isolation_cases_and_initial_stream_boundary",
              "source_sha256": source_hashes(), "artifacts": {name: str(path) for name, path in artifacts.items()},
              "artifact_sha256": {name: digest(path) for name, path in artifacts.items()},
              "limits": ["first Service signing key remains a synthetic trusted fixture; no production trust bootstrap acceptance",
                         "delivery/read slots gain signed page origin but no independent client receipt business state",
                         "numeric cursor alone has no source identity; complete correct scope+directory switch is valid"],
              "raw_old_key_attack": "NOT_EXECUTED_ACCESS_RESTRICTED", "full_M11": "NOT_COMPLETE", "full_stage0": "NOT_COMPLETE",
              "cases": [], "process_count": 0, "http_count": 0}
    write(report_path, report)
    try:
        for ident, operation in [*CASES, (INITIAL, verify_initial_source)]:
            if args.case and ident not in args.case:
                continue
            record = {"id": ident, "status": "RUNNING"}
            report["cases"].append(record)
            write(report_path, report)
            with tempfile.TemporaryDirectory(prefix=ident + "-", dir=output) as temporary:
                pair = IsolationPair(artifacts["binary"], Path(temporary).resolve(),
                                     artifacts["permission_verifier"], artifacts["receipt_signer"])
                try:
                    pair.initialize()
                    if ident == INITIAL:
                        operation(pair)
                        record["status"] = "PASS"
                    else:
                        execute_isolation(pair, operation)
                        record["status"] = "PASS"
                    print(record["status"] + " " + ident, flush=True)
                except Exception as error:
                    record.update(status="FAIL", error=str(error))
                    (run / "failure.log").write_text(traceback.format_exc())
                    raise
                finally:
                    pair.close()
                    record["evidence"] = pair.evidence
                    for label, lab in pair.labs.items():
                        stderr = lab.directory / "relay.stderr.log"
                        if stderr.exists():
                            shutil.copy2(stderr, run / (ident + "-" + label + "-relay.stderr.log"))
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
