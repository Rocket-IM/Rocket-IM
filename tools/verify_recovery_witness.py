#!/usr/bin/env python3
"""执行 W1 具名用例；未实现定义及 WC12 阻断显式保留，逐轮不覆盖失败。"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sys
import traceback
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests/interop"))
from network_poc.recovery_witness_fixture import WitnessLab
from network_poc.recovery_witness_cases import CASES
from network_poc.first_trust_evidence import state
from network_poc.fixture import check
from verify_first_trust import sources, provenance, digest, write


def witness_provenance(artifacts, source, development):
    rust_artifacts = {name: path for name, path in artifacts.items() if name != "fault_library"}
    result = provenance(rust_artifacts, source, development)
    if "fault_library" in artifacts:
        library = artifacts["fault_library"]
        report = library.parent / "report.json"
        check(report.is_file(), "C 故障装置缺少独立编译记录")
        recorded = json.loads(report.read_text())
        c_source = ROOT / "tests/interop/network_poc/snapshot_faults.c"
        check(recorded["exit_code"] == 0
              and recorded["source_sha256"] == digest(c_source)
              and recorded["library_sha256"] == digest(library),
              "C 故障装置与编译来源或产物摘要不一致")
        result["fault_library"] = {
            "path": str(library), "sha256": digest(library),
            "build_report": str(report), "build_report_sha256": digest(report),
            "source": str(c_source), "source_sha256": digest(c_source),
            "role": "real atomic-snapshot syscall failure injector; separate C build"}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "permission-verifier", "receipt-signer"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("anchor-helper", "old-binary", "probe-binary", "fault-library"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--development", action="store_true")
    parser.add_argument("--case", action="append", choices=sorted(CASES))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    artifacts = {name: getattr(args, name).resolve() for name in (
        "binary", "permission_verifier", "receipt_signer", "anchor_helper", "old_binary", "probe_binary", "fault_library") if getattr(args, name)}
    run = args.output.resolve() / "runs" / str(uuid.uuid4())
    run.mkdir(parents=True, mode=0o700)
    definitions = json.loads((ROOT / "api/realtime/join-recovery-witness-vectors.json").read_text())["state_expectations"]["cases"]
    report = {"status": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat(),
        "scope": "E10C-W1 real Rust/HTTP isolated POC; WC12 never executed",
        "full_E10c": "OPEN_WC12_PLATFORM_BLOCKED", "full_stage0": "NOT_COMPLETE",
        "development_only": args.development, "source_sha256_before": sources(), "cases": [],
        "definition_coverage": {item["id"]: {"status": "NOT_EXECUTED_PLATFORM_BLOCKED"
            if item["wc"] == "WC12" else "NOT_RUN", "executed": False,
            "roles": {role: "NOT_OBSERVED" for role in ("A", "W", "T")}} for item in definitions},
        "limits": ["synthetic pinned configuration does not prove real independent control domains",
                   "no missing-update-path private candidate constructed or substituted",
                   "survivor and target results are recorded independently"]}
    for path in (Path(__file__), ROOT / "api/realtime/join-recovery-witness.schema.json",
                 ROOT / "api/realtime/join-recovery-witness-vectors.json"):
        report["source_sha256_before"][str(path.relative_to(ROOT))] = digest(path)
    report["artifact_provenance"] = witness_provenance(
        artifacts, report["source_sha256_before"], args.development)
    report["artifact_sha256_before"] = {name: digest(path) for name, path in artifacts.items()}
    for relative in report["source_sha256_before"]:
        destination = run / "source-snapshot" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)
    report_path = run / "report.json"
    write(report_path, report)
    print(report_path, flush=True)
    for name in args.case or CASES:
        work = run / "work" / name
        work.mkdir(parents=True, mode=0o700)
        anchor_helper = artifacts.get("anchor_helper")
        if name == "WC06-10-reservation-budget":
            # 合成近满状态只在首次绑定锚之前构造；用例随后真实登记锚，不移除已启用锚。
            anchor_helper = None
        lab = WitnessLab(artifacts["binary"], work, artifacts["permission_verifier"],
                         artifacts["receipt_signer"], anchor_helper)
        lab.old_binary = artifacts.get("old_binary")
        lab.probe_binary = artifacts.get("probe_binary")
        lab.fault_library = artifacts.get("fault_library")
        lab.frozen_definition = next(item for item in definitions if item["id"] == name)
        if name == "WC10-05-real-old-joined-copy" and anchor_helper is not None:
            lab.deferred_initial_anchors.add("d1")
        record = {"id": name, "status": "RUNNING", "initial_anchor_helper": str(anchor_helper)
                  if anchor_helper is not None else None,
                  "frozen_unchanged_set_refs":
                      lab.frozen_definition["expected"]["must_remain_unchanged_set_refs"]}
        report["cases"].append(record)
        write(report_path, report)
        try:
            lab.initialize()
            record["before"] = state(lab)
            record["anchors_initial"] = lab.anchor_views()
            CASES[name](lab)
            record.update(status=lab.case_evidence.get("execution_scope", "PASS_SCOPED"), after=state(lab))
        except Exception as error:
            record.update(status="FAIL", error=str(error))
            (run / (name + "-failure.log")).write_text(traceback.format_exc())
            try:
                record["after_failure"] = state(lab)
            except Exception:
                record["after_failure"] = "UNOBSERVABLE"
        finally:
            if hasattr(lab, "old_copy_lab"):
                branch = lab.old_copy_lab
                lab.case_evidence["independent_old_copy_processes"] = branch.case_evidence
                lab.process_count += branch.process_count
                lab.helper_process_count += branch.helper_process_count
            try:
                record["anchors_final"] = lab.anchor_views()
            except Exception as error:
                record["anchors_final"] = {"status": "UNOBSERVABLE", "error": str(error)}
            lab.stop()
            record.update(evidence=lab.case_evidence, roles=lab.role_results,
                          process_count=lab.process_count, http_count=lab.http_count)
            record["executed_binaries"] = sorted({item["binary"] for item in
                lab.case_evidence.get("processes", []) if "binary" in item})
            record["public_signature_probe_used"] = bool(
                lab.case_evidence.get("public_signature_fixture"))
            definition_status = lab.case_evidence.get("definition_status", record["status"])
            report["definition_coverage"][name] = {"status": definition_status,
                "executed": definition_status != "UNREACHABLE_THROUGH_NORMAL_ENTRY",
                "test_executed": True,
                "roles": {role: "OBSERVED" if results else "NOT_OBSERVED"
                          for role, results in lab.role_results.items()}}
            write(report_path, report)
        print(record["status"] + " " + name + (": " + record["error"] if "error" in record else ""), flush=True)
    report["source_drift"] = {path: digest(ROOT / path) for path, before in report["source_sha256_before"].items()
                              if digest(ROOT / path) != before}
    report["artifact_sha256_after"] = {name: digest(path) for name, path in artifacts.items()}
    report["status"] = "PASS_SCOPED" if all(item["status"].startswith("PASS_SCOPED") for item in report["cases"]) else "FAIL"
    if report["source_drift"] or report["artifact_sha256_after"] != report["artifact_sha256_before"]:
        report["status"] = "FAIL_SOURCE_DRIFT"
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    write(report_path, report)
    return 0 if report["status"] == "PASS_SCOPED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
