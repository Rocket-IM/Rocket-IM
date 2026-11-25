#!/usr/bin/env python3
"""隔离恢复机制：独立锁定 Release、真实到期、跨进程重载及无秘密证据。"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import time
import tomllib
import uuid

from verify_first_trust import sources, digest, write

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / "dist/network-relay/expired-join-mechanism"
BINARY = "openmls-expired-join-probe"


def environment(target):
    runtime = ROOT / "dist/toolchains/rust"
    cargo = runtime / "cargo/bin/cargo"
    if not cargo.is_file():
        raise RuntimeError("缺少项目已有 Cargo，未切换工具链")
    return cargo, {**os.environ, "PATH": str(cargo.parent) + os.pathsep + os.environ.get("PATH", ""),
                   "CARGO_HOME": str(runtime / "cargo"), "RUSTUP_HOME": str(runtime / "rustup"),
                   "CARGO_TARGET_DIR": str(target)}


def locked_library():
    registry = ROOT / "dist/toolchains/rust/cargo/registry"
    crates = list((registry / "cache").glob("*/openmls-0.9.0.crate"))
    if len(crates) != 1:
        raise RuntimeError("锁定 OpenMLS 包不唯一")
    crate = crates[0]
    lock = tomllib.loads((ROOT / "poc/openmls-probe/Cargo.lock").read_text())
    item = next(p for p in lock["package"] if p["name"] == "openmls")
    if item["version"] != "0.9.0" or item["checksum"] != digest(crate):
        raise RuntimeError("OpenMLS 原件与锁文件不一致")
    source = registry / "src" / crate.parent.name
    verified = {}
    with tarfile.open(crate) as archive:
        for member in archive.getmembers():
            if member.isfile():
                original = archive.extractfile(member).read()
                local = source / member.name
                if not local.is_file() or local.read_bytes() != original:
                    raise RuntimeError("已解包 OpenMLS 与发行原件不同: " + member.name)
                verified[member.name] = hashlib.sha256(original).hexdigest()
    return {"version": item["version"], "crate_sha256": digest(crate), "verified_files": verified}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT)
    parser.add_argument("--binary", type=Path, help="复用本脚本已构建且来源完全匹配的 Release")
    args = parser.parse_args()
    run = args.output.resolve() / "runs" / str(uuid.uuid4())
    run.mkdir(parents=True, mode=0o700)
    path = run / "report.json"
    source = sources()
    source[str(Path(__file__).relative_to(ROOT))] = digest(Path(__file__))
    report = {"status": "RUNNING", "scope": "E01/E08/E09/E10/E17 mechanism subsets only",
              "started_at": datetime.now(timezone.utc).isoformat(), "phases": [],
              "source": source, "full_E01_E18": "NOT_COMPLETE", "full_Q01": "NOT_COMPLETE",
              "full_stage0": "NOT_COMPLETE", "business_recovery": "NOT_IMPLEMENTED",
              "limits": ["synthetic direct MLS actors; no HTTP recovery or authorization ledger",
                         "encrypted snapshot restart, not fault injection or independent anchor acceptance",
                         "raw SenderDataSecret AEAD positive/negative controls, not exhaustive cryptographic audit",
                         "no platform, capacity, physical erasure or compromised signing identity validation"]}
    write(path, report)
    print(path, flush=True)
    for relative in source:
        target = run / "source" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    try:
        report["locked_openmls"] = locked_library()
        rust_source = {k: v for k, v in source.items()
                       if k.startswith("poc/openmls-probe/") or k == "poc/rust-toolchain.toml"}
        if args.binary:
            binary = args.binary.resolve()
            provenance = json.loads((binary.parent / "provenance.json").read_text())
            if provenance["source"] != rust_source or provenance["binaries"][BINARY] != digest(binary):
                raise RuntimeError("Release 来源或程序摘要不匹配")
        else:
            target = run / "target"
            cargo, env = environment(target)
            manifest = run / "source/poc/openmls-probe/Cargo.toml"
            command = [str(cargo), "+1.98.1", "build", "--manifest-path", str(manifest),
                       "--locked", "--offline", "--release", "--features", "expired-join-probe,key-package-probe", "--bins"]
            with (run / "build.log").open("w") as log:
                completed = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
            report["build"] = {"command": command, "exit_code": completed.returncode}
            write(path, report)
            if completed.returncode:
                raise RuntimeError("Release 构建失败，见 build.log")
            bindir = run / "bin"
            bindir.mkdir()
            names = [BINARY, "openmls-state-lab", "openmls-permission-verify", "openmls-relay-receipt", "openmls-rollback-anchor"]
            for name in names:
                shutil.copy2(target / "release" / name, bindir / name)
            provenance = {"profile": "release", "rust": "1.98.1", "locked": True, "offline": True,
                          "features": ["expired-join-probe", "key-package-probe"], "source": rust_source,
                          "binaries": {n: digest(bindir / n) for n in names}}
            write(bindir / "provenance.json", provenance)
            binary = bindir / BINARY
        report["binary"] = str(binary)
        report["binary_sha256"] = digest(binary)
        report["provenance"] = provenance
        work = run / "work"
        work.mkdir(mode=0o700)
        for phase in ("init", "recover", "late"):
            record = {"phase": phase, "status": "RUNNING"}
            report["phases"].append(record)
            write(path, report)
            process = subprocess.run([str(binary), phase, str(work)], capture_output=True, text=True, timeout=60)
            (run / (phase + ".stdout.json")).write_text(process.stdout)
            (run / (phase + ".stderr.log")).write_text(process.stderr)
            record["exit_code"] = process.returncode
            if process.returncode:
                record["status"] = "FAIL"
                raise RuntimeError(phase + " failed: " + process.stderr.strip())
            record.update(json.loads(process.stdout))
            # 只保存加密快照；同一私有目录中的独立 key 不写入报告。
            shutil.copy2(work / "state.enc", work / (phase + ".enc"))
            write(path, report)
            print("PASS_SCOPED " + phase, flush=True)
            until = record.get("wait_until_utc_seconds", 0)
            while time.time() < until:
                time.sleep(min(0.2, until - time.time()))
        if len({p["pid"] for p in report["phases"]}) != 3:
            raise RuntimeError("未观察到三个独立进程")
        report["status"] = "PASS_SCOPED"
    except Exception as error:
        report.update(status="FAIL", error=str(error))
        print("FAIL " + str(error), flush=True)
    finally:
        report["source_drift"] = [k for k, v in source.items() if digest(ROOT / k) != v]
        if report["source_drift"]:
            report["status"] = "FAIL_SOURCE_DRIFT"
        if "binary" in report:
            report["binary_sha256_after"] = digest(Path(report["binary"]))
            if report["binary_sha256_after"] != report["binary_sha256"]:
                report["status"] = "FAIL_BINARY_DRIFT"
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        write(path, report)
    return 0 if report["status"] == "PASS_SCOPED" else 1


if __name__ == "__main__":
    sys.exit(main())
