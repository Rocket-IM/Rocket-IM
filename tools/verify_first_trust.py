#!/usr/bin/env python3
"""Q01 F01—F10：实际 Rust 会话、HTTP 注册及本机核验的限定联合矩阵。"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import shutil
import sqlite3
import sys
import traceback
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests/interop"))
from network_poc.fixture import check
from network_poc.first_trust_fixture import FirstTrustLab
from network_poc.first_trust_evidence import state
from network_poc.first_trust_registration import CASES as REGISTRATION
from network_poc.first_trust_cases import CASES as MAIN
from network_poc.first_trust_boundaries import CASES as BOUNDARIES, COMMON_CASES
from network_poc.first_trust_guards import CASES as GUARDS
from network_poc.first_trust_faults import CASES as FAULTS, ANCHOR_CASES as ANCHOR_FAULTS
from network_poc.first_trust_legacy import CASES as LEGACY
from network_poc.first_trust_anchored import CASES as CONFIRM_ANCHOR

CASES = REGISTRATION + MAIN + BOUNDARIES + GUARDS + FAULTS + LEGACY
ANCHOR_CASES = REGISTRATION + MAIN + COMMON_CASES + GUARDS + ANCHOR_FAULTS + CONFIRM_ANCHOR


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources():
    paths = [Path(__file__), ROOT / "poc/openmls-probe/Cargo.toml",
             ROOT / "poc/openmls-probe/Cargo.lock", ROOT / "poc/rust-toolchain.toml"]
    for folder in ("api", "poc/network-relay", "poc/openmls-probe/src", "tests/interop/network_poc"):
        paths.extend(path for path in (ROOT / folder).rglob("*")
                     if path.is_file() and path.suffix in (".rs", ".py", ".json", ".c", ".mjs"))
    return {str(path.relative_to(ROOT)): digest(path) for path in sorted(set(paths))}


def write(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(path)


def provenance(artifacts, source, development=False):
    result = {}
    for name, path in artifacts.items():
        if name == "old_fixture":
            result[name] = {"path": str(path), "sha256": digest(path), "role": "copied archived fixture"}
            continue
        manifest = path.parent / "provenance.json"
        if development and not manifest.is_file():
            result[name] = {"status": "DEVELOPMENT_ONLY_NO_RELEASE_PROVENANCE", "path": str(path)}
            continue
        check(manifest.is_file(), "程序缺少独立构建来源: " + str(path))
        recorded = json.loads(manifest.read_text())
        expected = recorded["binaries"][path.name]
        check(expected == digest(path), "程序与构建记录摘要不同: " + str(path))
        drift = [key for key, value in recorded["source"].items() if source.get(key) != value]
        if not name.startswith("old_"):
            check(not drift, "新程序与本轮 Rust 来源不同: " + repr(drift))
            rust = {key: value for key, value in source.items()
                    if key.startswith("poc/openmls-probe/") or key == "poc/rust-toolchain.toml"}
            check(rust == recorded["source"], "Rust 来源缺失或多余输入")
        result[name] = {"path": str(manifest), "sha256": digest(manifest), "source_count": len(recorded["source"]),
                        "current_source_differences": drift, "historical_program": name.startswith("old_")}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "permission-verifier", "receipt-signer"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--anchor-helper", type=Path)
    parser.add_argument("--development", action="store_true", help="显式开发联调；无构建来源时不能计最终验收")
    parser.add_argument("--old-binary", type=Path, help="明确 pre-Q01 真实程序；同目录另两个旧 helper 同样校验")
    parser.add_argument("--old-fixture", type=Path, help="已归档 pre-Q01 fixture.py；只复制到本轮 ignored 目录")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/network-relay/q01-first-trust/implementation")
    parser.add_argument("--case", action="append", choices=sorted({name for name, _ in CASES + ANCHOR_CASES}))
    args = parser.parse_args()
    cases = ANCHOR_CASES if args.anchor_helper else CASES
    if args.case and not set(args.case) <= {name for name, _ in cases}:
        parser.error("所选场景不属于当前普通/锚矩阵")
    selected = [(name, operation) for name, operation in cases if not args.case or name in args.case]
    if any(name.endswith("legacy_upgrade") for name, _ in selected) and not (args.old_binary and args.old_fixture):
        parser.error("旧快照升级要求显式 --old-binary 和 --old-fixture")
    artifacts = {name: getattr(args, name).resolve() for name in
                 ("binary", "permission_verifier", "receipt_signer", "anchor_helper", "old_binary", "old_fixture")
                 if getattr(args, name)}
    if args.old_binary:
        artifacts.update(old_verifier=artifacts["old_binary"].with_name("openmls-permission-verify"),
                         old_signer=artifacts["old_binary"].with_name("openmls-relay-receipt"))
    run_id = str(uuid.uuid4())
    run = args.output.resolve() / "runs" / run_id
    run.mkdir(parents=True, mode=0o700)
    report_path = run / "report.json"
    report = {"run_id": run_id, "status": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(), "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
        "scope": "Q01 named first-device registration and per-device independent trust assertions",
        "anchor_mode": bool(args.anchor_helper), "selected_cases": [name for name, _ in selected],
        "development_only": args.development,
        "artifacts": {name: str(path) for name, path in artifacts.items()}, "cases": [],
        "process_count": 0, "http_count": 0, "direct_anchor_process_count": 0,
        "full_Q01": "NOT_COMPLETE", "full_stage0": "NOT_COMPLETE",
        "pass_meaning": "named executed assertions only; unresolved anchors remain blocked",
        "limits": ["real MLS, device signatures, Service signer and loopback HTTP/SQLite",
            "synthetic business tokens and explicitly authorized delayed group bootstrap in the same database",
            "independent public objects supplied by test controller: synthetic_local, not real human identity verification",
            "file clock preserves original registration TTL; no production clock substitution",
            "copied token may fetch victim ciphertext/metadata; successful registration is only private-key possession",
            "per-device trust, no account identity anchor, no automatic group migration or old-history recovery",
            "KeyPackage-only refresh has no joint CLI; actual permission/MLS epoch update is exercised",
            "no formal SDK/Go Service, target-platform lifecycle, real power failure or global identity assurance"],
        "evidence_storage": "isolated synthetic device secrets stay in ignored mode-0700 case work directories; reports contain public objects and hashes"}
    write(report_path, report)
    try:
        report["source_sha256_before"] = sources()
        report["artifact_sha256_before"] = {name: digest(path) for name, path in artifacts.items()}
        report["artifact_provenance"] = provenance(artifacts, report["source_sha256_before"], args.development)
        for relative in report["source_sha256_before"]:
            saved = run / "source-snapshot" / relative
            saved.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, saved)
        write(report_path, report)
        for name, operation in selected:
            record = {"id": name, "group": name.split(".")[1], "status": "RUNNING"}
            report["cases"].append(record)
            write(report_path, report)
            work = run / "work" / name
            work.mkdir(parents=True, mode=0o700)
            lab = FirstTrustLab(artifacts["binary"], work, artifacts["permission_verifier"],
                                artifacts["receipt_signer"], artifacts.get("anchor_helper"))
            lab.old_binary, lab.old_fixture = artifacts.get("old_binary"), artifacts.get("old_fixture")
            try:
                lab.initialize()
                record["before"] = state(lab)
                operation(lab)
                record.update(status="PASS", verification="PASS", after=state(lab))
                print("PASS " + name, flush=True)
            except BaseException as error:
                record.update(status="FAIL", error=str(error))
                try:
                    record["after_failure"] = state(lab)
                except Exception as capture_error:
                    record["after_failure_unavailable"] = str(capture_error)
                (run / (name + "-failure.log")).write_text(traceback.format_exc())
                raise
            finally:
                lab.close()
                record["evidence"] = lab.case_evidence
                evidence_path = run / (name + "-evidence.json")
                write(evidence_path, lab.case_evidence)
                record["evidence_path"] = str(evidence_path)
                for key in ("process_count", "http_count"):
                    record[key] = getattr(lab, key)
                    report[key] += record[key]
                record["direct_anchor_process_count"] = lab.helper_process_count
                report["direct_anchor_process_count"] += lab.helper_process_count
                write(report_path, report)
        report["status"] = "DEV_PASS_SCOPED" if args.development else "PASS_SCOPED"
    except BaseException as error:
        report.update(status="FAIL", error=str(error))
        (run / "failure.log").write_text(traceback.format_exc())
        print("FAIL " + str(error), file=sys.stderr)
    finally:
        try:
            report["source_sha256_after"] = sources()
            report["artifact_sha256_after"] = {name: digest(path) for name, path in artifacts.items()}
            report["source_drift"] = sorted(key for key in
                set(report.get("source_sha256_before", {})) | set(report["source_sha256_after"])
                if report.get("source_sha256_before", {}).get(key) != report["source_sha256_after"].get(key))
            if report["source_drift"] or report.get("artifact_sha256_before") != report["artifact_sha256_after"]:
                report.update(status="FAIL", integrity_error="源码或程序在运行期间改变，原轮不可计验收")
        except Exception as error:
            report.update(status="FAIL", integrity_error=str(error))
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        write(report_path, report)
    print(json.dumps({"status": report["status"], "run_id": run_id, "cases": len(report["cases"]),
                      "report": str(report_path)}, ensure_ascii=False))
    return 0 if report["status"] in ("PASS_SCOPED", "DEV_PASS_SCOPED") else 1


if __name__ == "__main__":
    raise SystemExit(main())
