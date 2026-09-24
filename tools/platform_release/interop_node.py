#!/usr/bin/env python3
"""同一Node桌面包与Swift或Kotlin/Flutter包的限定互通；实际移动模拟器配对。"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/interop"))
from interop import reuse_build, shutdown_endpoints, source_hashes
from interop_apple_web import accepted, prepare_swift
from interop_node_build import COMPILER, PACK_REPORT, audit, prepare
from node_pack import command, json_output, node_binary, sha, write_json
from platform_release import artifacts
from platform_release.broker import Broker
from platform_release.node_cases import run_cases
from platform_release.runtime import Runtime, SWIFT_SIMULATOR, tree_hashes


def now():
    return datetime.now(timezone.utc).isoformat()


def audit_builds(builds):
    if set(builds) == {"node", "kotlin", "flutter"}:
        from interop_node_mobile import audit as audit_mobile
        return {"node": audit(builds["node"]), **audit_mobile(builds)}
    if set(builds) != {"node", "swift"}:
        raise RuntimeError("node_build_set_mismatch")
    archive, _ = accepted("swift")
    provenance, app = artifacts.swift(builds["swift"], archive, ROOT)
    return {"node": audit(builds["node"]), "swift": {"archive_sha256": sha(archive),
            "provenance": provenance, "app": app}}


def stop_node(process, work, report):
    """正常shutdown后等待真实退出；强制回收只用于收尾，不能变成通过。"""
    forced = False
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        forced = True
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    report["node_process"] = {"pid": process.pid, "exit_code": process.returncode,
                              "forced": forced, "reaped": process.poll() is not None}
    path = work / "node-runtime.log"
    if path.stat().st_size > 1024 * 1024:
        raise RuntimeError("node_runtime_output_too_large")
    result = json.loads(path.read_text())
    report["node_result"] = result
    worker = result.get("worker", {})
    if (forced or process.returncode != 0 or result.get("status") != "PASS"
            or worker.get("exitCode") != 0 or worker.get("shutdown") is not True
            or type(worker.get("threadId")) is not int or worker["threadId"] <= 0
            or result.get("runtime") != report["node_environment"]):
        raise RuntimeError("node_worker_or_process_not_clean")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-pack-report", type=Path, default=PACK_REPORT)
    parser.add_argument("--typescript-archive", type=Path, default=COMPILER)
    parser.add_argument("--peers", choices=("swift", "mobile"), default="swift", help="mobile覆盖Kotlin及Flutter iOS/Android三组配对")
    parser.add_argument("--swift-build-report", type=Path, help="复用已核对的Swift独立应用，省略则重新构建消费应用")
    parser.add_argument("--kotlin-build-report", type=Path, help="mobile模式复用摘要匹配的Kotlin独立构建")
    args = parser.parse_args()
    if (args.peers == "mobile" and args.swift_build_report) or (args.peers == "swift" and args.kotlin_build_report):
        parser.error("构建报告必须对应选定的运行端组")
    peers = ["swift-ios"] if args.peers == "swift" else ["kotlin-android", "flutter-ios", "flutter-android"]
    endpoints = ["node-macos", *peers]
    expected_cases = 24 * len(peers)
    run_id = str(uuid.uuid4())
    work = ROOT / "dist/platform-interop/node/runs" / run_id
    work.mkdir(parents=True)
    report = {"run_id": run_id, "status": "RUNNING", "started_at": now(), "cases": [],
              "scope": "macOS Node with " + ", ".join(peers) + " pairs only", "endpoints": endpoints,
              "peer_group": args.peers, "expected_cases": expected_cases,
              "source_before": source_hashes(), "builds": {}, "host": {
                  "system": platform.system(), "release": platform.release(), "machine": platform.machine()},
              "windows_runtime": "NOT_TESTED", "physical_device_runtime": "NOT_TESTED",
              "node_with_kotlin_flutter": "NOT_TESTED", "full_stage0": "NOT_COMPLETE",
              "raw_old_key_attack": "NOT_EXECUTED_ACCESS_RESTRICTED"}
    path = work / "report.json"

    def save():
        temporary = path.with_suffix(".tmp")
        write_json(temporary, report)
        temporary.replace(path)

    broker, process = None, None
    runtime = Runtime(ROOT, work)
    phase = "environment"
    try:
        save()
        command([node_binary(), "-p", "JSON.stringify({node:process.version,platform:process.platform,"
                 "arch:process.arch,osRelease:require('node:os').release()})"], work, work / "node-environment.log")
        report["node_environment"] = json_output(work / "node-environment.log")
        if platform.system() != "Darwin" or report["node_environment"]["platform"] != "darwin":
            raise RuntimeError("macos_node_required")
        phase = "prepare_node"
        report["builds"]["node"] = prepare(work / "node", args.node_pack_report.resolve(), args.typescript_archive.resolve())
        save()
        phase = "controller"
        broker = Broker(run_id, endpoints, work)
        report["controller_url"] = broker.url
        phase = "prepare_" + args.peers
        save()
        if args.peers == "swift":
            report["builds"]["swift"] = (reuse_build("swift", args.swift_build_report) if args.swift_build_report
                                           else prepare_swift(work / "swift"))
        else:
            from interop_node_mobile import prepare as prepare_mobile
            report["builds"].update(prepare_mobile(work, broker.url, run_id, args.kotlin_build_report))
        phase = "audit_before"
        report["artifacts_before"] = audit_builds(report["builds"])
        save()
        phase = "launch_" + args.peers
        if args.peers == "swift":
            swift = report["builds"]["swift"]
            runtime.ios(SWIFT_SIMULATOR, swift["app"], swift["bundle_id"], "swift-ios", broker.url, run_id)
        else:
            from interop_node_mobile import launch
            launch(runtime, report["builds"], broker.url, run_id)
        phase = "launch_node"
        environment = {key: value for key, value in os.environ.items() if key not in {"NODE_OPTIONS", "NODE_PATH"}}
        environment.update(ROCKETS_INTEROP_URL=broker.url, ROCKETS_INTEROP_RUN_ID=run_id,
                           ROCKETS_INTEROP_ENDPOINT_ID="node-macos")
        directory = Path(report["builds"]["node"]["directory"])
        with (work / "node-runtime.log").open("w") as log:
            process = subprocess.Popen([node_binary(), "interop.mjs"], cwd=directory, env=environment,
                                       stdout=log, stderr=subprocess.STDOUT)
        phase = "ready"
        report["ready"] = broker.wait_ready(timeout=45)
        save()

        def on_case(result):
            report["cases"].append(result)
            save()
            print(result["status"], result["case_id"], flush=True)

        broker.on_case = on_case
        phase = "cases"
        results = run_cases(broker, peers)
        report["counts"] = {"total": len(results), "passed": sum(r["status"] == "PASS" for r in results)}
        report["status"] = "PASS" if report["counts"] == {"total": expected_cases, "passed": expected_cases} else "FAIL"
    except Exception as error:
        report.update(status="FAIL", error={"phase": phase, "exception_type": type(error).__name__,
                                            "origin": "harness"})
    finally:
        report["endpoint_cleanup_errors"] = shutdown_endpoints(broker) if broker else []
        report["ready"] = {name: dict(state["ready"]) for name, state in broker.states.items() if state["ready"]} if broker else {}
        report["missing_endpoints"] = [name for name in endpoints if name not in report["ready"]]
        report["cleanup_errors"] = []
        if process:
            try:
                stop_node(process, work, report)
            except Exception as error:
                report["cleanup_errors"].append({"phase": "node_exit", "exception_type": type(error).__name__})
        if broker:
            report["command_count"] = len(broker.transcript)
            report["pending_commands"] = {name: {k: state["pending"][k] for k in ("command_id", "op", "handle")}
                                           for name, state in broker.states.items() if state["pending"]}
            report["http_errors"] = list(broker.http_errors)
            try:
                broker.close()
            except Exception as error:
                report["cleanup_errors"].append({"phase": "controller_close", "exception_type": type(error).__name__})
        try:
            if args.peers == "mobile" and runtime.ios_apps:
                from interop_node_mobile import audit_installed
                report["installed_mobile_audit"] = audit_installed(runtime, report["builds"])
                report["installed_runtime_unchanged"] = True
            elif runtime.ios_apps:
                installed = runtime.command(["xcrun", "simctl", "get_app_container", SWIFT_SIMULATOR,
                                             report["builds"]["swift"]["bundle_id"], "app"]).strip()
                report["installed_swift_unchanged"] = (tree_hashes(installed)
                    == runtime.metadata["swift-ios"]["installed_app_sha256"])
                report["installed_runtime_unchanged"] = report["installed_swift_unchanged"]
        except Exception as error:
            report["cleanup_errors"].append({"phase": "installed_runtime_audit", "exception_type": type(error).__name__})
        try:
            runtime.close()
        except Exception as error:
            report["cleanup_errors"].append({"phase": "simulator_close", "exception_type": type(error).__name__})
        report["runtime"] = runtime.metadata
        report["cleanup_errors"].extend({"phase": "simulator_cleanup", "code": "harness_error"} for _ in runtime.cleanup_errors)
        try:
            report["artifacts_after"] = audit_builds(report["builds"])
            report["artifacts_stable"] = report["artifacts_before"] == report["artifacts_after"]
        except Exception:
            report["artifacts_stable"] = False
        report["source_after"] = source_hashes()
        report["source_stable"] = report["source_before"] == report["source_after"]
        if (not report["source_stable"] or not report["artifacts_stable"] or not report.get("installed_runtime_unchanged")
                or not process or any(report.get(key) for key in (
                    "missing_endpoints", "cleanup_errors", "endpoint_cleanup_errors", "pending_commands", "http_errors"))):
            report["status"] = "FAIL"
        if args.peers == "mobile":
            report["node_with_kotlin_flutter"] = report["status"]
        report["finished_at"] = now()
        save()
        print("REPORT", path, flush=True)
        print("STATUS", report["status"], flush=True)
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
