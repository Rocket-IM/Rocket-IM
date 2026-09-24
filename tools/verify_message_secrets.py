#!/usr/bin/env python3
"""M01正常消息、拒绝输入与主动明文负对照的本机秘密观测。"""

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
DEFAULT_BINARIES = ROOT / "dist/network-relay/m01-secrets/artifacts/default"
sys.path.insert(0, str(ROOT / "tests/interop"))
from network_poc.secret_cases import CASES
from network_poc.secret_fixture import SecretLab


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
    parser.add_argument("--secret-observer", type=Path, default=ROOT / "dist/network-relay/m01-secrets/artifacts/all-features/openmls-secret-surface-scan")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/network-relay/m01-secrets")
    parser.add_argument("--case", action="append", choices=[ident for ident, _ in CASES])
    args = parser.parse_args()
    artifacts = {name: getattr(args, name).resolve()
                 for name in ("binary", "permission_verifier", "receipt_signer", "secret_observer")}
    output = args.output.resolve()
    run_id = str(uuid.uuid4())
    run = output / "runs" / run_id
    run.mkdir(parents=True)
    report_path = run / "report.json"
    report = {"run_id": run_id, "status": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat(),
              "scope": "selected normal message HTTP, server database, logs and SQLite backup observed against synthetic plaintext and actual sampled client secrets",
              "platform": platform.platform(), "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
              "selected_cases": args.case or [ident for ident, _ in CASES],
              "artifacts": {name: str(path) for name, path in artifacts.items()},
              "pass_meaning": "selected surfaces and sampled secrets only; intentional plaintext persistence is a preserved expected limitation, not a secrecy PASS",
              "ratchet_configuration_changed": False,
              "limits": ["synthetic identities, actual MLS, loopback HTTP; no TLS/WSS or production credentials",
                         "client secrets sampled after initialization and after operations, not every ratchet/heap state",
                         "observer checks bounded listed encodings and surfaces, not arbitrary transformations",
                         "raw temporary corpus and sampled secrets are deleted; report preserves hashes and hit classifications",
                         "intentional plaintext submission shows Relay does not enforce payload encryption",
                         "same OS user does not isolate Relay from client files",
                         "no process memory, crash dump, OS diagnostics, proxy/APM or published SDK acceptance",
                         "SQLite test backup copy is not deployment backup/restore acceptance"],
              "process_count_scope": "Rust CLI, explicit signer, observer and Relay starts; excludes Relay internal signing/verifying helpers",
              "raw_old_key_attack": "NOT_EXECUTED_ACCESS_RESTRICTED", "full_stage0": "NOT_COMPLETE",
              "cases": [], "process_count": 0, "http_count": 0}
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
                lab = SecretLab(artifacts["binary"], Path(temporary).resolve(),
                                 artifacts["permission_verifier"], artifacts["receipt_signer"])
                lab.secret_observer = artifacts["secret_observer"]
                lab.case_evidence = {}
                try:
                    try:
                        lab.initialize(permissions=True)
                        operation(lab)
                    finally:
                        lab.close()
                    record["verification_status"] = "PASS"
                    record["status"] = "OBSERVED_LIMITATION" if ident.endswith("opaque_payload_control") else "PASS"
                    print(record["status"] + " " + ident, flush=True)
                except Exception as error:
                    failure_log = ident + "-failure.log"
                    record.update(status="FAIL", error=str(error), failure_log=failure_log)
                    (run / failure_log).write_text(traceback.format_exc())
                    raise
                finally:
                    record["evidence"] = lab.case_evidence
                    record["surface_manifest"] = [{"label": item["label"], "kind": item["kind"],
                        "bytes": Path(item["path"]).stat().st_size, "sha256": digest(Path(item["path"]))}
                        for item in lab.surfaces]
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
