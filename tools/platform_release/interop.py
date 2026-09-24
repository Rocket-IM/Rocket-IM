#!/usr/bin/env python3
"""四端实际预编译包交叉互通；测试控制器只搬运输入，不执行密码算法。"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "dist/platform-interop"
sys.path.insert(0, str(ROOT / "tests/interop"))
ENDPOINTS = ["swift-ios", "kotlin-android", "browser", "flutter-ios", "flutter-android"]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_hashes():
    result = {}
    for name in ("src/sdk", "tests/consumers", "tests/interop/platform_release", "tools/platform_release"):
        for path in (ROOT / name).rglob("*"):
            if path.is_file() and not any(p in {"node_modules", ".dart_tool", "build", "target", ".gradle", "__pycache__"} for p in path.parts) and path.name != ".DS_Store":
                result[str(path.relative_to(ROOT))] = sha(path)
    return result


def accepted_packages():
    packages = json.loads((OUTPUT / "accepted-packages.json").read_text())
    if (not isinstance(packages, list) or len(packages) != 4
            or {p.get("platform") for p in packages} != {"swift", "browser", "kotlin", "flutter"}):
        raise RuntimeError("invalid_accepted_package_set")
    for package in packages:
        artifact = (ROOT / package["artifact"]).resolve()
        if not artifact.is_relative_to(ROOT / "dist/platform-release") or sha(artifact) != package["sha256"]:
            raise RuntimeError("accepted_package_changed")
    return packages


def verify_build_package(platform, build, packages):
    accepted = next(p for p in packages if p["platform"] == platform)
    artifact, digest = ("archive", "archive_sha256") if platform in {"swift", "browser"} else ("sdk_package", "sdk_sha256")
    if build.get(digest) != accepted["sha256"] or sha(build[artifact]) != accepted["sha256"]:
        raise RuntimeError("build_not_bound_to_accepted_package")


def reuse_build(platform, path, packages=None):
    """复用同一源码已构建的独立消费工程，重新核对输入及实际产物。"""
    from interop_apple_web import hashes, inputs
    path = path.resolve()
    if not path.is_relative_to(OUTPUT):
        raise ValueError("build_report_outside_interop_output")
    build = json.loads(path.read_text())
    verify_build_package(platform, build, packages if packages is not None else accepted_packages())
    if platform in {"swift", "browser"}:
        if build["status"] != "PASS" or build["source_sha256_before"] != inputs(platform):
            raise RuntimeError("reused_build_source_changed:" + platform)
        directory = Path(build["directory"])
        package = directory / ("Vendor/RocketsIMStage0" if platform == "swift" else "node_modules/@rockets-im/stage0")
        if hashes(package) != build["package_sha256"] or sha(build["archive"]) != build["archive_sha256"]:
            raise RuntimeError("reused_build_package_changed:" + platform)
        output = Path(build["app"]) if platform == "swift" else directory / "dist"
        if hashes(output) != build["app_sha256" if platform == "swift" else "compiled_sha256"]:
            raise RuntimeError("reused_build_artifact_changed:" + platform)
    else:
        consumer = Path(build["consumer"])
        for source in (ROOT / "tests/consumers/kotlin").rglob("*"):
            if source.is_file() and sha(source) != sha(consumer / source.relative_to(ROOT / "tests/consumers/kotlin")):
                raise RuntimeError("reused_build_source_changed:kotlin")
        if sha(build["apk"]) != build["apk_sha256"] or sha(build["sdk_package"]) != build["sdk_sha256"]:
            raise RuntimeError("reused_build_artifact_changed:kotlin")
    build["reused_report"] = str(path)
    build["reused_report_sha256"] = sha(path)
    return build


def shutdown_endpoints(broker):
    failures = []
    for endpoint, state in broker.states.items():
        if not state["ready"]:
            continue
        if state["pending"] is not None:
            failures.append({"endpoint": endpoint, "code": "harness_error", "phase": "shutdown_pending"})
            continue
        try:
            response = broker.call(endpoint, "shutdown", "", {}, timeout=10)
            if response.get("ok") is not True or response.get("value", "missing") is not None:
                failures.append({"endpoint": endpoint, "code": "harness_error", "phase": "shutdown_rejected"})
        except Exception as error:
            failures.append({"endpoint": endpoint, "code": "harness_error", "phase": "shutdown_transport",
                             "exception_type": type(error).__name__})
    return failures


def apply_final_gates(report):
    if (not report.get("source_stable") or not report.get("packages_unchanged")
            or not report.get("artifacts_stable")
            or any(report.get(key) for key in ("cleanup_errors", "endpoint_cleanup_errors", "pending_commands", "http_errors"))):
        report["status"] = "FAIL"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", help="只用于故障定位；单项通过不能代替完整矩阵")
    for platform in ("swift", "browser", "kotlin"):
        parser.add_argument("--" + platform + "-build-report", type=Path, help="复用摘要与当前源码一致的独立构建")
    parser.add_argument("--playwright-module", type=Path, default=Path.home() / ".cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright")
    args = parser.parse_args()
    from platform_release.broker import Broker
    from platform_release.artifacts import audit_artifacts
    from platform_release.cases import run_cases
    from platform_release.runtime import Runtime, SWIFT_SIMULATOR, FLUTTER_SIMULATOR
    from interop_apple_web import prepare_swift, prepare_browser
    from interop_mobile import prepare_kotlin, prepare_flutter

    run_id = str(uuid.uuid4())
    work = OUTPUT / "runs" / run_id
    work.mkdir(parents=True)
    report = {"run_id": run_id, "status": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat(),
              "scope": "five actual runtimes using four accepted precompiled packages",
              "selected_case": args.case, "cases": [], "endpoints": ENDPOINTS,
              "source_before": source_hashes(), "packages": [], "builds": {},
              "raw_old_key_attack": "NOT_EXECUTED_ACCESS_RESTRICTED", "physical_device_runtime": "NOT_TESTED"}
    path = work / "report.json"

    def save():
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        temporary.replace(path)

    broker, runtime = None, Runtime(ROOT, work)
    phase = "accepted_packages"
    try:
        save()
        packages = accepted_packages()
        report["packages"] = packages
        broker = Broker(run_id, ENDPOINTS, work)
        report["controller_url"] = broker.url
        save()
        for name, prepare in (("swift", prepare_swift), ("browser", prepare_browser), ("kotlin", prepare_kotlin)):
            phase = "prepare_" + name
            print("PREPARE", name, flush=True)
            previous = getattr(args, name + "_build_report")
            report["builds"][name] = reuse_build(name, previous, packages) if previous else prepare(work / name)
            verify_build_package(name, report["builds"][name], packages)
            save()
        print("PREPARE flutter", flush=True)
        phase = "prepare_flutter"
        report["builds"]["flutter"] = prepare_flutter(work / "flutter", broker.url, run_id)
        verify_build_package("flutter", report["builds"]["flutter"], packages)
        save()
        builds = report["builds"]
        phase = "audit_artifacts_before"
        report["artifacts_before"] = audit_artifacts(builds, ROOT)
        save()
        broker.browser_directory = Path(builds["browser"]["directory"])
        phase = "launch_swift_ios"
        runtime.ios(SWIFT_SIMULATOR, builds["swift"]["app"], builds["swift"]["bundle_id"],
                    "swift-ios", broker.url, run_id)
        phase = "launch_flutter_ios"
        runtime.ios(FLUTTER_SIMULATOR, builds["flutter"]["ios_app"], builds["flutter"]["ios_bundle_id"],
                    "flutter-ios", broker.url, run_id)
        phase = "launch_android"
        runtime.android(builds["kotlin"], builds["flutter"], broker.url, run_id)
        phase = "launch_browser"
        runtime.chrome(broker.url, run_id, args.playwright_module)
        report["runtime"] = runtime.metadata
        phase = "wait_ready"
        report["ready"] = broker.wait_ready()
        save()

        def on_case(result):
            report["cases"].append(result)
            save()
            print(result.get("status"), result.get("case_id"), flush=True)

        broker.on_case = on_case
        phase = "run_cases"
        results = run_cases(broker, ENDPOINTS, selected_case=args.case)
        report["cases"] = results
        report["counts"] = {"total": len(results), "passed": sum(r["status"] == "PASS" for r in results)}
        report["status"] = "PASS_PARTIAL" if args.case else "PASS"
        if not results or report["counts"]["passed"] != len(results) or (not args.case and len(results) != 75):
            report["status"] = "FAIL"
    except Exception as error:
        report["status"] = "FAIL"
        report["error"] = {"origin": "harness", "code": "harness_error", "phase": phase,
                           "exception_type": type(error).__name__}
    finally:
        report["ready"] = ({name: dict(state["ready"]) for name, state in broker.states.items() if state["ready"]}
                           if broker else {})
        report["missing_endpoints"] = [name for name in ENDPOINTS if name not in report["ready"]]
        if broker:
            report["endpoint_cleanup_errors"] = shutdown_endpoints(broker)
            report["command_count"] = len(broker.transcript)
            report["pending_commands"] = {name: {k: state["pending"][k] for k in ("command_id", "op", "handle")}
                                          for name, state in broker.states.items() if state["pending"]}
            try:
                broker.close()
            except Exception:
                runtime.cleanup_errors.append("broker_close_failed")
            report["http_errors"] = list(broker.http_errors)
        try:
            runtime.close()
        except Exception:
            runtime.cleanup_errors.append("runtime_close_failed")
        report["runtime"] = runtime.metadata
        cleanup_codes = {"broker_close_failed", "runtime_close_failed", "browser_runtime_error"}
        report["cleanup_errors"] = [{"origin": "harness", "code": "harness_error",
                                     "reason": error if error in cleanup_codes else "runtime_cleanup_failed"}
                                    for error in runtime.cleanup_errors]
        report["artifacts_stable"] = False
        if report.get("artifacts_before") and set(report["builds"]) == {"swift", "browser", "kotlin", "flutter"}:
            try:
                report["artifacts_after"] = audit_artifacts(report["builds"], ROOT)
                report["artifacts_stable"] = report["artifacts_before"] == report["artifacts_after"]
            except Exception as error:
                report["artifact_error"] = {"origin": "harness", "code": "harness_error", "phase": "audit_artifacts_after",
                                            "exception_type": type(error).__name__}
        try:
            report["source_after"] = source_hashes()
            report["source_stable"] = report["source_before"] == report["source_after"]
            report["packages_unchanged"] = bool(report["packages"]) and all(sha(ROOT / p["artifact"]) == p["sha256"] for p in report["packages"])
        except Exception:
            report.update(source_stable=False, packages_unchanged=False)
        apply_final_gates(report)
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        save()
        print("REPORT", path, flush=True)
        print("STATUS", report["status"], flush=True)
    return 0 if report["status"].startswith("PASS") else 1


if __name__ == "__main__":
    raise SystemExit(main())
