#!/usr/bin/env python3
"""K01—K12生命周期联合验收；每次独立运行保留来源、失败及状态证据。"""
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
from network_poc.key_package_fixture import KeyPackageLab
from network_poc.key_package_cases import CASES
from network_poc.first_trust_evidence import state
from verify_first_trust import sources, provenance, digest, write

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "permission-verifier", "receipt-signer"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--probe-binary", type=Path)
    parser.add_argument("--anchor-helper", type=Path)
    parser.add_argument("--old-binary", type=Path)
    parser.add_argument("--old-relay", type=Path)
    parser.add_argument("--development", action="store_true")
    parser.add_argument("--case", action="append", choices=sorted(CASES))
    parser.add_argument("--output", type=Path, default=ROOT / "dist/network-relay/key-package-lifecycle")
    args = parser.parse_args()
    artifacts = {name: getattr(args,name).resolve() for name in ("binary", "permission_verifier", "receipt_signer", "anchor_helper", "old_binary", "probe_binary") if getattr(args,name)}
    if args.old_binary:
        artifacts.update(old_verifier=artifacts["old_binary"].with_name("openmls-permission-verify"),
                         old_signer=artifacts["old_binary"].with_name("openmls-relay-receipt"))
    run = args.output.resolve() / "runs" / str(uuid.uuid4()); run.mkdir(parents=True, mode=0o700)
    report = {"status":"RUNNING","started_at":datetime.now(timezone.utc).isoformat(),"scope":"K01—K12 bounded native lifecycle POC",
        "development_only":args.development,"cases":[],"source_sha256_before":sources(),"full_Q01":"NOT_COMPLETE","full_stage0":"NOT_COMPLETE",
        "limits":["synthetic business registration authority and independent identity fixture","loopback HTTP, native encrypted snapshots and SQLite Relay",
                  "no formal Go Service/SDK or production directory freshness","no physical erasure or old-key cryptographic attack claim"]}
    report["source_sha256_before"][str(Path(__file__).relative_to(ROOT))]=digest(Path(__file__))
    report["artifact_provenance"]=provenance(artifacts,report["source_sha256_before"],args.development)
    report["artifact_sha256_before"]={name:digest(path) for name,path in artifacts.items()}
    for relative in report["source_sha256_before"]:
        target=run/"source-snapshot"/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/relative,target)
    path=run/"report.json";write(path,report);print(path,flush=True)
    for name,case in CASES.items():
        if args.case and name not in args.case:continue
        work=run/"work"/name;work.mkdir(parents=True,mode=0o700)
        lab=KeyPackageLab(artifacts["binary"],work,artifacts["permission_verifier"],artifacts["receipt_signer"],artifacts.get("anchor_helper"))
        lab.probe_binary=artifacts.get("probe_binary");lab.old_binary=artifacts.get("old_binary");lab.old_relay=args.old_relay.resolve() if args.old_relay else None
        record={"id":name,"status":"RUNNING"};report["cases"].append(record);write(path,report)
        try:
            lab.initialize();record["before"]=state(lab);case(lab)
            record.update(status="PASS_SCOPED",after=state(lab))
        except Exception as error:
            record.update(status="FAIL",error=str(error));(run/(name+"-failure.log")).write_text(traceback.format_exc())
            try:record["after_failure"]=state(lab)
            except Exception:pass
        finally:
            lab.stop();record["evidence"]=lab.case_evidence;record["process_count"]=lab.process_count;record["http_count"]=lab.http_count
            write(path,report)
        print(record["status"]+" "+name+(": "+record["error"] if "error" in record else ""),flush=True)
    report["status"]="PASS_SCOPED" if all(c["status"]=="PASS_SCOPED" for c in report["cases"]) else "FAIL"
    report["source_drift"]={key:digest(ROOT/key) for key,value in report["source_sha256_before"].items() if digest(ROOT/key)!=value}
    report["artifact_sha256_after"]={name:digest(path) for name,path in artifacts.items()}
    if report["source_drift"] or report["artifact_sha256_before"]!=report["artifact_sha256_after"]:report["status"]="FAIL_SOURCE_DRIFT"
    report["finished_at"]=datetime.now(timezone.utc).isoformat();write(path,report)
    return 0 if report["status"]=="PASS_SCOPED" else 1
if __name__=="__main__":raise SystemExit(main())
