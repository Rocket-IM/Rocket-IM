#!/usr/bin/env python3
"""M11删除/到期增量签页、事务及快照中断的真实本机验证。"""

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
DEFAULT_BINARIES = ROOT / "dist/network-relay/m11-lifecycle/artifacts/default"
sys.path.insert(0, str(ROOT / "tests/interop"))
from network_poc.lifecycle_cases import CASES as NORMAL_CASES
from network_poc.lifecycle_faults import CASES as FAULT_CASES
from network_poc.lifecycle_boundaries import CASES as BOUNDARY_CASES
from network_poc.fixture import NetworkLab
from network_poc.rebuild_sync_fixture import RebuildSyncLab
from network_poc.lifecycle_rebuild import CASES as REBUILD_CASES

CASES = NORMAL_CASES + FAULT_CASES + BOUNDARY_CASES + REBUILD_CASES


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes():
    paths = [Path(__file__), ROOT / "poc/openmls-probe/Cargo.toml",
             ROOT / "poc/openmls-probe/Cargo.lock", ROOT / "poc/rust-toolchain.toml"]
    for folder in ("api", "poc/network-relay", "poc/openmls-probe/src", "tests/interop/network_poc"):
        paths.extend(p for p in (ROOT / folder).rglob("*")
                     if p.is_file() and p.suffix in (".rs", ".py", ".json", ".c", ".mjs"))
    return {str(p.relative_to(ROOT)): digest(p) for p in sorted(set(paths))}


def write(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARIES / "openmls-state-lab")
    parser.add_argument("--permission-verifier", type=Path, default=DEFAULT_BINARIES / "openmls-permission-verify")
    parser.add_argument("--receipt-signer", type=Path, default=DEFAULT_BINARIES / "openmls-relay-receipt")
    parser.add_argument("--helper", type=Path, default=DEFAULT_BINARIES / "openmls-rollback-anchor")
    parser.add_argument("--old-binary", type=Path, default=ROOT / "dist/network-relay/m01-secrets/artifacts/default/openmls-state-lab")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/network-relay/m11-lifecycle")
    parser.add_argument("--case", action="append", choices=[ident for ident, _ in CASES])
    args = parser.parse_args()
    artifacts = {name: getattr(args, name).resolve()
                 for name in ("binary", "permission_verifier", "receipt_signer", "old_binary", "helper")}
    output = args.output.resolve()
    run_id = str(uuid.uuid4())
    run = output / "runs" / run_id
    run.mkdir(parents=True)
    report_path = run / "report.json"
    report = {"run_id": run_id, "status": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat(),
              "scope": "signed incremental deletion and expiry events; real MLS, loopback HTTP, Relay SQLite and Rust encrypted snapshots",
              "platform": platform.platform(), "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
              "selected_cases": args.case or [ident for ident, _ in CASES],
              "artifacts": {name: str(path) for name, path in artifacts.items()},
              "pass_meaning": "selected lifecycle assertions only; full pending retains an explicit limitation, not automatic recovery",
              "ratchet_configuration_changed": False,
              "limits": ["synthetic identities, actual MLS and loopback HTTP; no TLS/WSS or production service",
                         "expiration is request-triggered; no background timer or automatic SDK network worker",
                         "existing plaintext copies, valid delivery/read facts and server ciphertext remain; no physical erasure",
                         "full global/device queues can atomically reject projection; local pending can block downloading notifications",
                         "old binaries reject the new event and snapshots containing it; no transparent downgrade",
                         "one real wall-clock case, other TTL cases use the explicit test clock",
                         "rebuild trust and independent anchor are synthetic local fixtures, not production isolation",
                         "this runner does not invoke historical backfill; schema6 maintenance is verified separately",
                         "controlled exits do not prove arbitrary power failure, target-platform or release acceptance"],
              "process_count_scope": "Rust CLI, explicit signer and Relay starts; excludes Relay internal signing/verifying helpers",
              "raw_old_key_attack": "NOT_EXECUTED_ACCESS_RESTRICTED", "full_M11": "NOT_COMPLETE", "full_stage0": "NOT_COMPLETE",
              "cases": [], "process_count": 0, "http_count": 0, "direct_anchor_process_count": 0}
    write(report_path, report)
    try:
        report["source_sha256"] = source_hashes()
        report["artifact_sha256"] = {name: digest(path) for name, path in artifacts.items()}
        # 每轮保留原源码，失败后修改装置也能还原当时输入。
        for relative in report["source_sha256"]:
            saved = run / "source-snapshot" / relative
            saved.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, saved)
        write(report_path, report)
        for ident, operation in CASES:
            if args.case and ident not in args.case:
                continue
            record = {"id": ident, "status": "RUNNING"}
            report["cases"].append(record)
            write(report_path, report)
            with tempfile.TemporaryDirectory(prefix=ident + "-", dir=output) as temporary:
                directory = Path(temporary).resolve()
                wall_clock = ident == "M11.lifecycle.wall_clock"
                retention_ms = 5000 if wall_clock else 1000
                relay_args = ["--test-retention-ms", str(retention_ms)]
                clock_path = directory / "ttl-clock.txt"
                if not wall_clock:
                    clock_path.write_text("1800000000000\n")
                    clock_path.chmod(0o600)
                    relay_args.extend(["--test-clock-file", str(clock_path)])
                if ".rebuild." in ident:
                    lab = RebuildSyncLab(artifacts["binary"], directory, artifacts["permission_verifier"],
                                         artifacts["receipt_signer"], artifacts["helper"])
                    lab.relay_entrypoint = ROOT / "tests/interop/network_poc/expiration_relay.py"
                    lab.relay_args = tuple(relay_args)
                else:
                    lab = NetworkLab(artifacts["binary"], directory, artifacts["permission_verifier"],
                                     artifacts["receipt_signer"],
                                     relay_entrypoint=ROOT / "tests/interop/network_poc/expiration_relay.py", relay_args=relay_args)
                lab.clock_path, lab.old_binary = clock_path, artifacts["old_binary"]
                lab.case_evidence = {"clock_mode": "real_wall_clock" if wall_clock else "injected_file_clock",
                                     "retention_ms": retention_ms}
                try:
                    try:
                        lab.initialize(pending_limit=1 if ident.endswith("full_pending") else 1000, permissions=True)
                        operation(lab)
                    finally:
                        lab.close()
                    record["verification_status"] = "PASS"
                    record["status"] = "OBSERVED_LIMITATION" if ident.endswith("full_pending") else "PASS"
                    print(record["status"] + " " + ident, flush=True)
                except Exception as error:
                    failure_log = ident + "-failure.log"
                    record.update(status="FAIL", error=str(error), failure_log=failure_log)
                    (run / failure_log).write_text(traceback.format_exc())
                    raise
                finally:
                    record["evidence"] = lab.case_evidence
                    if ".rebuild." in ident:
                        record["rebuild_fixture_evidence"] = lab.evidence
                    record["direct_anchor_process_count"] = getattr(lab, "helper_process_count", 0)
                    report["direct_anchor_process_count"] += record["direct_anchor_process_count"]
                    stderr = lab.directory / "relay.stderr.log"
                    if stderr.exists():
                        saved = run / (ident + "-relay.stderr.log")
                        shutil.copy2(stderr, saved)
                        record["relay_stderr_sha256"] = digest(saved)
                    record["temporary_corpus_cleanup"] = "TemporaryDirectory_finally"
                    record["process_count"] = lab.process_count
                    record["http_count"] = lab.http_count
                    report["process_count"] += lab.process_count
                    report["http_count"] += lab.http_count
                    write(report_path, report)
        report["status"] = "PASS_SCOPED"
    except Exception as error:
        report.update(status="FAIL", error=str(error))
        (run / "failure.log").write_text(traceback.format_exc())
        print(f"FAIL {error}", file=sys.stderr)
    finally:
        try:
            report["source_sha256_after"] = source_hashes()
            report["artifact_sha256_after"] = {name: digest(path) for name, path in artifacts.items()}
            if (report.get("source_sha256") != report["source_sha256_after"]
                    or report.get("artifact_sha256") != report["artifact_sha256_after"]):
                report.update(status="FAIL", integrity_error="运行期间源码或程序变化，不能验收")
        except Exception as error:
            report.update(status="FAIL", integrity_error=str(error))
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        write(report_path, report)
    print(json.dumps({"status": report["status"], "run_id": run_id,
                      "cases": len(report["cases"]), "report": str(report_path)}, ensure_ascii=False))
    return 0 if report["status"] == "PASS_SCOPED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
