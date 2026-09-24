#!/usr/bin/env python3
"""M06 独立执行器：真实写/rename错误，受控同步对象故障，保留每次运行证据。"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import traceback
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests/interop"))
from network_poc.message_io_cases import CASES
from network_poc.message_io_fixture import MessageIoLab


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources():
    paths = [ROOT / "tools/verify_message_io.py", ROOT / "poc/rust-toolchain.toml",
             ROOT / "poc/openmls-probe/Cargo.toml", ROOT / "poc/openmls-probe/Cargo.lock"]
    for folder in ("poc/openmls-probe/src", "poc/network-relay", "tests/interop/network_poc"):
        paths.extend(p for p in (ROOT / folder).rglob("*") if p.suffix in (".rs", ".py", ".c"))
    return {str(p.relative_to(ROOT)): digest(p) for p in sorted(set(paths))}


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def capture_baseline(output):
    path = output / "baseline.json"
    if path.exists():
        raise RuntimeError("基线已经存在，禁止覆盖")
    paths = [ROOT / "README.md", ROOT / "AGENTS.md"]
    for folder in ("docs", "api", "src/sdk", "poc", "tools", "tests"):
        paths.extend(p for p in (ROOT / folder).rglob("*")
                     if p.is_file() and not any(part in ("target", "node_modules", ".dart_tool", "build", "__pycache__") for part in p.parts)
                     and p.suffix in (".md", ".rs", ".py", ".c", ".json", ".toml", ".lock", ".dart", ".ts", ".mjs", ".swift", ".kt"))
    prior = []
    for folder in ("dist/network-relay/runs", "dist/network-relay/m05/runs", "dist/rebuild-sync/runs"):
        prior.extend(p for p in (ROOT / folder).glob("*") if p.is_file())
    write(path, {"created_at": datetime.now(timezone.utc).isoformat(),
                 "files": {str(p.relative_to(ROOT)): digest(p) for p in sorted(set(paths))},
                 "historical_evidence": {str(p.relative_to(ROOT)): digest(p) for p in prior}})
    print(f"Baseline: {len(paths)} inputs, {len(prior)} historical evidence files")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--anchor-helper", type=Path, help="明确指定本轮构建的独立锚程序")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/network-relay/m06")
    parser.add_argument("--case", action="append", choices=[item[0] for item in CASES])
    parser.add_argument("--capture-baseline", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if args.capture_baseline:
        capture_baseline(output)
        return 0
    if args.binary is None or args.anchor_helper is None:
        parser.error("必须以 --binary 和 --anchor-helper 指明本次验证的 Release 程序")
    binary, helper = args.binary.resolve(), args.anchor_helper.resolve()
    run_id = str(uuid.uuid4())
    run = output / "runs" / run_id
    run.mkdir(parents=True)
    report = {"run_id": run_id, "status": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat(),
              "scope": "synthetic local macOS Rust CLI and HTTP/SQLite Relay; not production SDK",
              "platform": platform.platform(), "selected_cases": args.case or "all_M06_cases",
              "sync_fault_assurance": "real kernel EBADF from macOS F_FULLFSYNC on temporary pipe descriptor; NOT real disk EIO/power loss",
              "unanchored_boundary": "no persistent guard for unsaved crypto advancement; do not retry unsaved send intent",
              "dispatch_boundary": "test host forwards successful CLI output; no autonomous SDK network worker",
              "raw_old_key_attack": "NOT_EXECUTED_ACCESS_RESTRICTED", "full_M01_M14_acceptance": "NOT_COMPLETE",
              "physical_disk_fsync_failure": "NOT_TESTED", "full_stage0": "NOT_COMPLETE",
              "source_sha256": sources(), "cases": [], "process_count": 0, "http_count": 0}
    report_path = run / "report.json"
    write(report_path, report)
    try:
        if sys.platform != "darwin":
            raise RuntimeError("当前故障装置只支持 macOS；其他平台未验收")
        library = run / "snapshot_faults.dylib"
        build = subprocess.run(["/usr/bin/cc", "-dynamiclib", "-Wall", "-Wextra", "-Werror", "-O2",
                                str(ROOT / "tests/interop/network_poc/snapshot_faults.c"), "-o", str(library)],
                               capture_output=True, text=True, timeout=60)
        (run / "fault-build.log").write_text(build.stdout + build.stderr)
        if build.returncode:
            raise RuntimeError("故障装置编译失败")
        report["artifacts"] = {str(p): digest(p) for p in (binary, helper, library)}
        for ident, execute in CASES:
            if args.case and ident not in args.case:
                continue
            record = {"id": ident, "status": "RUNNING"}
            report["cases"].append(record)
            write(report_path, report)
            with tempfile.TemporaryDirectory(prefix=ident + "-", dir=output) as temporary:
                lab = MessageIoLab(binary, Path(temporary).resolve(), helper, library)
                try:
                    lab.initialize()
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
                    for filename in ("relay.stderr.log", "syscalls.jsonl"):
                        source = lab.directory / filename
                        if source.exists():
                            shutil.copy2(source, run / (ident + "-" + filename))
                    report["process_count"] += lab.process_count + lab.helper_process_count
                    report["http_count"] += lab.http_count
                    write(report_path, report)
        report["source_sha256_after"] = sources()
        report["artifacts_after"] = {path: digest(Path(path)) for path in report["artifacts"]}
        if report["source_sha256"] != report["source_sha256_after"] or report["artifacts"] != report["artifacts_after"]:
            raise RuntimeError("运行期间源码或程序变化，不能验收")
        report["status"] = "PASS"
    except Exception as error:
        report.update(status="FAIL", error=str(error))
        print(f"FAIL {error}", file=sys.stderr)
    finally:
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        write(report_path, report)
    print(json.dumps({"status": report["status"], "run_id": run_id,
                      "cases": len(report["cases"]), "report": str(report_path)}, ensure_ascii=False))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
