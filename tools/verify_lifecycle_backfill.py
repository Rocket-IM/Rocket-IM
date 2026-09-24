#!/usr/bin/env python3
"""M11保存的旧Relay真实建库、结构升级与历史终态通知回填。"""

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
from network_poc.backfill_cases import CASES as NORMAL_CASES
from network_poc.backfill_boundaries import CASES as BOUNDARY_CASES
from network_poc.backfill_fixture import LEGACY_ROOT, INCREMENTAL_ROOT, LEGACY_RELAY, INCREMENTAL_RELAY
from network_poc.fixture import NetworkLab
from network_poc.rebuild_sync_fixture import RebuildSyncLab
from network_poc.backfill_rebuild import CASES as REBUILD_CASES

CASES = NORMAL_CASES + BOUNDARY_CASES + REBUILD_CASES


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes():
    paths = [Path(__file__), ROOT / "poc/openmls-probe/Cargo.toml",
             ROOT / "poc/openmls-probe/Cargo.lock", ROOT / "poc/rust-toolchain.toml"]
    for folder in ("api", "poc/network-relay", "poc/openmls-probe/src", "tests/interop/network_poc"):
        paths.extend(p for p in (ROOT / folder).rglob("*")
                     if p.is_file() and p.suffix in (".rs", ".py", ".json", ".c", ".mjs"))
    for legacy in (LEGACY_ROOT, INCREMENTAL_ROOT):
        paths.extend((legacy / "poc/network-relay").glob("*.py"))
        paths.append(legacy / "tests/interop/network_poc/expiration_relay.py")
    return {str(p.relative_to(ROOT)): digest(p) for p in sorted(set(paths))}


def write(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, help="明确指定本轮构建产物；不默认复用历史程序")
    parser.add_argument("--permission-verifier", type=Path, required=True, help="明确指定本轮构建产物；不默认复用历史程序")
    parser.add_argument("--receipt-signer", type=Path, required=True, help="明确指定本轮构建产物；不默认复用历史程序")
    parser.add_argument("--helper", type=Path, required=True, help="明确指定本轮构建产物；不默认复用历史程序")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/network-relay/m11-backfill")
    parser.add_argument("--case", action="append", choices=[ident for ident, _ in CASES])
    args = parser.parse_args()
    artifacts = {name: getattr(args, name).resolve()
                 for name in ("binary", "permission_verifier", "receipt_signer", "helper")}
    output = args.output.resolve()
    run_id = str(uuid.uuid4())
    run = output / "runs" / run_id
    run.mkdir(parents=True)
    report_path = run / "report.json"
    report = {"run_id": run_id, "status": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat(),
              "scope": "schema5 actual old-server terminal rows to schema6 frozen ledger and transactional backfill; existing Rust signed-page consumption",
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
                         "all TTL cases in this run use the explicit test clock; prior wall-clock evidence is historical only",
                         "rebuild trust and independent anchor are synthetic local fixtures, not production isolation",
                         "unsigned legacy permission history cannot prove eligibility and is explicitly refused",
                         "schema6 rejects old server downgrade; only migration-time terminal original slots are scanned",
                         "operator explicitly runs synthetic control maintenance; no public product migration endpoint",
                         "controlled exits do not prove arbitrary power failure, target-platform or release acceptance"],
              "process_count_scope": "Rust CLI, explicit signer and Relay starts; excludes Relay internal signing/verifying helpers",
              "raw_old_key_attack": "NOT_EXECUTED_ACCESS_RESTRICTED", "full_M11": "NOT_COMPLETE", "full_stage0": "NOT_COMPLETE",
              "cases": [], "process_count": 0, "http_count": 0, "direct_anchor_process_count": 0}
    write(report_path, report)
    try:
        prior_build = ROOT / "dist/network-relay/m11-lifecycle/rust-runs/0934da97-dd74-462f-8df0-dea5dbf7c4bb/report.json"
        build = json.loads(prior_build.read_text())
        assert build["status"] == "PASS" and all(digest(ROOT / p) == h for p, h in build["source_sha256_after"].items())
        report["reused_rust_build"] = {"report": str(prior_build.relative_to(ROOT)), "sha256": digest(prior_build),
            "rust_sources_match": True, "recompiled_this_run": False}
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
                wall_clock = False
                retention_ms = 5000 if wall_clock else 1000
                relay_args = ["--test-retention-ms", str(retention_ms)]
                clock_path = directory / "ttl-clock.txt"
                if not wall_clock:
                    clock_path.write_text("1800000000000\n")
                    clock_path.chmod(0o600)
                    relay_args.extend(["--test-clock-file", str(clock_path)])
                relay_entrypoint = INCREMENTAL_RELAY if ident.endswith("existing_notices") else LEGACY_RELAY
                if ".rebuild." in ident:
                    lab = RebuildSyncLab(artifacts["binary"], directory, artifacts["permission_verifier"],
                                         artifacts["receipt_signer"], artifacts["helper"])
                    lab.relay_entrypoint = relay_entrypoint
                    lab.relay_args = tuple(relay_args)
                else:
                    lab = NetworkLab(artifacts["binary"], directory, artifacts["permission_verifier"],
                                     artifacts["receipt_signer"],
                                     relay_entrypoint=relay_entrypoint, relay_args=relay_args)
                lab.clock_path = clock_path
                lab.case_evidence = {"clock_mode": "real_wall_clock" if wall_clock else "injected_file_clock",
                                     "retention_ms": retention_ms, "legacy_entrypoint": str(relay_entrypoint)}
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
