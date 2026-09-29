#!/usr/bin/env python3
"""M03：默认首发/显式启用的单未决门、旧 outbox 和恢复契约验证。"""

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
OLD_BINARY = ROOT / "dist/network-relay/m12-sequence/artifacts/default/openmls-state-lab"
sys.path.insert(0, str(ROOT / "tests/interop"))
from network_poc.send_order_cases import CASES
from network_poc.send_order_compatibility import DEFAULT_CASES, COMPATIBILITY_CASES
from network_poc.fixture import NetworkLab


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
    parser.add_argument("--binary", type=Path, required=True, help="明确指定本轮构建产物；不默认复用历史程序")
    parser.add_argument("--permission-verifier", type=Path, required=True, help="明确指定本轮构建产物；不默认复用历史程序")
    parser.add_argument("--receipt-signer", type=Path, required=True, help="明确指定本轮构建产物；不默认复用历史程序")
    parser.add_argument("--old-binary", type=Path, default=OLD_BINARY)
    parser.add_argument("--activation", choices=("default", "explicit"), default="default")
    parser.add_argument("--legacy-binary", type=Path, help="修改前同命名域程序；提供时运行旧 outbox/隔离兼容验证")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/network-relay/m03-send-order")
    parser.add_argument("--case", action="append", choices=[ident for ident, _ in CASES + DEFAULT_CASES + COMPATIBILITY_CASES])
    args = parser.parse_args()
    cases = CASES + (DEFAULT_CASES if args.activation == "default" else [])
    if args.legacy_binary:
        cases += COMPATIBILITY_CASES
    if args.case and not set(args.case) <= {ident for ident, _ in cases}:
        parser.error("所选场景需要 --activation default 或 --legacy-binary")
    artifacts = {name: getattr(args, name).resolve()
                 for name in ("binary", "permission_verifier", "receipt_signer", "old_binary")}
    if args.legacy_binary:
        artifacts["legacy_binary"] = args.legacy_binary.resolve()
    output = args.output.resolve()
    run_id = str(uuid.uuid4())
    run = output / "runs" / run_id
    run.mkdir(parents=True)
    report_path = run / "report.json"
    report = {"run_id": run_id, "status": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat(),
              "scope": "synthetic local M03 Rust persistent single-unresolved-send-slot gate with real HTTP and encrypted snapshots",
              "platform": platform.platform(), "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
              "selected_cases": args.case or [ident for ident, _ in cases],
              "artifacts": {name: str(path) for name, path in artifacts.items()},
              "pass_meaning": "scoped gate and recovery evidence only; PASS does not complete a formal SDK or recover existing quarantined messages",
              "gate_scope": args.activation + "_single_unresolved_send_slot",
              "ratchet_configuration_changed": False,
              "limits": ["synthetic identities and signed-permission fixtures on loopback HTTP with the original Relay server",
                         "default activation is tested only with signed permission trust; unsigned mechanism probes are outside this contract",
                         "the next send advances only after the accepted proof is durably persisted; rejection or closure without trusted terminal recovery remains blocking",
                         "original OpenMLS default ratchet window and retention policy are unchanged",
                         "not a formal SDK network worker or a queue of multiple pending plaintext messages",
                         "not protection against arbitrary malicious Relay reordering or recovery of existing quarantined messages",
                         "not complete protocol, production capacity, arbitrary power-loss, TLS/WSS, production identity or release acceptance"],
              "process_count_scope": "Rust CLI, explicit signer and Relay starts; excludes Relay internal signing/verifying helpers",
              "raw_old_key_attack": "NOT_EXECUTED_ACCESS_RESTRICTED", "full_stage0": "NOT_COMPLETE",
              "cases": [], "process_count": 0, "http_count": 0}
    write(report_path, report)
    try:
        report["source_sha256"] = source_hashes()
        for name in report["source_sha256"]:
            archived = run / "source" / name
            archived.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, archived)
        report["artifact_sha256"] = {name: digest(path) for name, path in artifacts.items()}
        write(report_path, report)
        for ident, operation in cases:
            if args.case and ident not in args.case:
                continue
            record = {"id": ident, "status": "RUNNING"}
            report["cases"].append(record)
            write(report_path, report)
            with tempfile.TemporaryDirectory(prefix=ident + "-", dir=output) as temporary:
                lab = NetworkLab(artifacts["binary"], Path(temporary).resolve(),
                                 artifacts["permission_verifier"], artifacts["receipt_signer"])
                lab.old_binary = artifacts["old_binary"]
                lab.send_order_activation = args.activation
                lab.legacy_binary = artifacts.get("legacy_binary")
                lab.case_evidence = {}
                try:
                    try:
                        lab.initialize(permissions=True)
                        operation(lab)
                    finally:
                        lab.close()
                    record["status"] = "PASS"
                    print(record["status"] + " " + ident, flush=True)
                except Exception as error:
                    failure_log = ident + "-failure.log"
                    record.update(status="FAIL", error=str(error), failure_log=failure_log)
                    (run / failure_log).write_text(traceback.format_exc())
                    raise
                finally:
                    record["evidence"] = lab.case_evidence
                    stderr = lab.directory / "relay.stderr.log"
                    if stderr.exists():
                        shutil.copy2(stderr, run / (ident + "-relay.stderr.log"))
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
