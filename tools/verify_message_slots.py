#!/usr/bin/env python3
"""M11.e/f/g：原槽持久保留、同槽冲突与签名消息异槽去重的本机联合矩阵。"""

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
from network_poc.slot_conflict_cases import CASES as CONFLICT_CASES
from network_poc.slot_duplicate_cases import CASES as DUPLICATE_CASES
from network_poc.slot_fixture import SlotLab

CASES = CONFLICT_CASES + DUPLICATE_CASES


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
    parser.add_argument("--binary", type=Path, required=True, help="明确使用含单槽观察入口的Release Rust CLI")
    parser.add_argument("--permission-verifier", type=Path, required=True)
    parser.add_argument("--receipt-signer", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/network-relay/m11-slots")
    parser.add_argument("--case", action="append", choices=[case[0] for case in CASES])
    args = parser.parse_args()
    binary, output = args.binary.resolve(), args.output.resolve()
    verifier, signer = args.permission_verifier.resolve(), args.receipt_signer.resolve()
    artifacts = {"binary": binary, "permission_verifier": verifier, "receipt_signer": signer}
    artifact_hashes = {name: digest(path) for name, path in artifacts.items()}
    run_id = str(uuid.uuid4())
    run = output / "runs" / run_id
    run.mkdir(parents=True)
    report_path = run / "report.json"
    report = {"run_id": run_id, "status": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat(),
              "scope": "synthetic local Rust CLI and real HTTP/SQLite Relay; M11 slots only, not production SDK/Go Service",
              "platform": platform.platform(), "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
              "selected_cases": args.case or "all_M11_slot_cases", "source_sha256": source_hashes(),
              "artifacts": {name: str(path) for name, path in artifacts.items()}, "artifact_sha256": artifact_hashes,
              "conflicts": "single-field mutation of a real returned page copy; Relay original rows unchanged",
              "duplicates": "controller-gated test wrapper appends existing signed message via original Store.append_event; real public pull/report_delivery handlers",
              "readback": "Rust loaded snapshot, one original network slot and persisted result; no host decryption/SQL of client state",
              "receipts": "two persistent candidates per target; explicit script retries; not SDK receipt outbox or UI display acceptance",
              "raw_old_key_attack": "NOT_EXECUTED_ACCESS_RESTRICTED", "full_M11": "NOT_COMPLETE", "full_stage0": "NOT_COMPLETE",
              "cases": [], "process_count": 0, "http_count": 0}
    write(report_path, report)
    try:
        for ident, execute in CASES:
            if args.case and ident not in args.case:
                continue
            record = {"id": ident, "status": "RUNNING"}
            report["cases"].append(record)
            write(report_path, report)
            with tempfile.TemporaryDirectory(prefix=ident + "-", dir=output) as temporary:
                lab = SlotLab(binary, Path(temporary).resolve(), verifier, signer)
                try:
                    lab.initialize(permissions=True)
                    execute(lab)
                    record["status"] = "PASS"
                    print(f"PASS {ident}", flush=True)
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
