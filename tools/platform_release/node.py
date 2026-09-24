#!/usr/bin/env python3
"""打包Node目标SDK；在独立安装目录严格编译并真实执行Node消费者。"""

import argparse
import json
import platform
from pathlib import Path
import shutil
import sys

from node_pack import (OUTPUT, TEMPLATE, VERSION, WASM_NAME, all_hashes,
                       command, finish, json_output, node_binary, npm_command, pack, sha, start,
                       validate_package, write_json)

WORKER_CHECKS = [
    "initialization_required", "package_version", "initialization_repeat", "independent_identity",
    "same_scope_new_instance_has_distinct_identity", "empty_id_rejected", "oversize_id_rejected",
    "non_string_constructor_rejected", "encrypt_requires_group", "decrypt_requires_group",
    "identity_output_copy", "key_package_exact_retry", "key_package_output_copy", "wrong_identity_rejected",
    "wrong_identity_preserves_device", "cross_service_key_package_rejected", "grouped_key_package_rejected",
    "malformed_welcome_rejected", "malformed_welcome_preserves_package", "second_join_rejected",
    "non_bytes_encrypt_rejected", "non_bytes_decrypt_rejected", "non_string_group_rejected",
    "detached_method_rejected", "empty_plaintext_rejected", "oversize_plaintext_rejected",
    "oversize_protocol_rejected", "malformed_ciphertext_rejected", "ciphertext_differs", "unicode_round_trip",
    "binary_subarray_and_input_copy", "maximum_payload_round_trip", "wrong_conversation_rejected",
    "wrong_service_ciphertext_rejected", "validation_errors_preserve_valid_state", "tampered_ciphertext_rejected",
    "poisoned_encrypt_rejected", "poisoned_identity_rejected", "poison_isolated_to_receiver",
    "duplicate_ciphertext_rejected", "duplicate_failure_stays_poisoned", "wrong_welcome_scope_poisoned",
    "wrong_welcome_scope_stays_poisoned", "idempotent_close", "closed_object_closure_rejected",
    "closed_key_package_rejected", "closed_encrypt_rejected", "closed_decrypt_rejected",
    "close_isolated_to_owner", "other_device_usable_after_close", "poisoned_device_can_close",
]


def validate_success(record, result, runtime):
    if result["status"] != "PASS" or record["execution"]["exit_code"] != 0:
        raise RuntimeError("Node公共API消费失败")
    workers = result.get("workers")
    if not isinstance(workers, list) or len(workers) != 2:
        raise RuntimeError("未验证两个独立Node工作者")
    for worker, worker_id in zip(workers, ("worker_a", "worker_b")):
        if not isinstance(worker, dict) or worker.get("status") != "PASS" or worker.get("version") != VERSION:
            raise RuntimeError("Node工作者没有按本轮SDK版本通过")
        if worker.get("workerId") != worker_id or worker.get("exitCode") != 0 or worker.get("checks") != WORKER_CHECKS:
            raise RuntimeError("Node工作者名称、退出状态或精确API检查清单不符")
        key = worker.get("identityKey")
        if not isinstance(key, list) or len(key) != 32 or any(type(value) is not int or not 0 <= value <= 255 for value in key):
            raise RuntimeError("Node工作者没有返回有效公开身份")
    if workers[0]["identityKey"] == workers[1]["identityKey"]:
        raise RuntimeError("独立工作者未证明不同身份")
    expected = [worker_id + ":" + check for worker_id in ("worker_a", "worker_b") for check in WORKER_CHECKS]
    expected.extend(("independent_worker_identity", "two_workers_normal_exit"))
    if result["checks"] != expected:
        raise RuntimeError("Node总检查清单不符")
    reported_runtime = result.get("runtime", {})
    if any(reported_runtime.get(name) != runtime[name] for name in ("node", "platform", "arch")):
        raise RuntimeError("消费报告运行时与实际Node不符")
    record.update(status="PASS", check_count=len(expected), worker_check_count=len(WORKER_CHECKS))


def consumer_result(logfile):
    path = Path(logfile)
    if path.stat().st_size > 1024 * 1024:
        raise RuntimeError("Node消费结果超过1MiB")
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        raise RuntimeError("Node消费者没有返回结果")
    result = json.loads(lines[-1])
    if not isinstance(result, dict) or result.get("status") not in ("PASS", "FAIL"):
        raise RuntimeError("Node消费者结果不是明确PASS/FAIL")
    checks = result.get("checks")
    if not isinstance(checks, list) or not all(isinstance(check, str) for check in checks):
        raise RuntimeError("Node消费者检查记录结构错误")
    if len(checks) != len(set(checks)):
        raise RuntimeError("Node消费者检查记录重复")
    return result


def verify(args):
    run, report = start(args.output, "verify")
    report.update(cases=[], scope="Node host SDK consumption; no desktop UI",
                  host={"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
                  runtime_matrix={"macOS": "NOT_TESTED", "Windows": "NOT_TESTED"})
    installed = None
    original_package = None
    archive_before = None
    try:
        archive = args.archive.resolve()
        if not archive.is_file():
            raise RuntimeError("待安装TGZ不存在")
        archive_before = sha(archive)
        report.update(archive=str(archive), archive_sha256=archive_before)
        consumer = run / "consumer space 中文"
        shutil.copytree(TEMPLATE, consumer, ignore=shutil.ignore_patterns("node_modules", "dist"))
        report["consumer"] = str(consumer)
        command([node_binary(), "-p", "JSON.stringify({node:process.version,platform:process.platform,"
                 "arch:process.arch,execPath:process.execPath})"], consumer, run / "node-runtime.log")
        runtime = json_output(run / "node-runtime.log")
        report["runtime"] = runtime
        command(npm_command() + ["--version"], consumer, run / "npm-version.log")
        report["npm_version"] = (run / "npm-version.log").read_text(encoding="utf-8").strip()
        command(npm_command() + ["install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", str(archive)],
                consumer, run / "npm-install.log")
        installed = consumer / "node_modules/@rocket-im/stage0-node"
        original_package = validate_package(installed)
        manifest = json.loads((installed / "artifact.json").read_text(encoding="utf-8"))
        report["package_source_matches_current"] = manifest.get("source_sha256") == report["source_sha256_before"]
        if not report["package_source_matches_current"]:
            raise RuntimeError("TGZ对应源码与本次验证输入不同，不能将早期包结果归给当前源码")
        compiler = json.loads((consumer / "node_modules/typescript/package.json").read_text(encoding="utf-8"))
        if compiler.get("version") != "5.9.3":
            raise RuntimeError("独立消费者未安装固定TypeScript 5.9.3")
        command(npm_command() + ["run", "build"], consumer, run / "typescript-build.log")
        if not (consumer / "dist/consumer.js").is_file() or not (consumer / "run.mjs").is_file():
            raise RuntimeError("Node独立消费入口未生成")
        report.update(typescript="5.9.3", compiled_sha256=all_hashes(consumer / "dist"))

        def execute_case(name):
            logfile = run / (name + ".log")
            execution = command([node_binary(), "run.mjs"], consumer, logfile,
                                timeout=args.timeout_seconds, required=False)
            record = {"name": name, "execution": execution}
            report["cases"].append(record)
            write_json(run / "report.json", report)
            if execution["timed_out"] or not execution["reaped"]:
                raise RuntimeError("Node消费进程超时或未回收：" + name)
            result = consumer_result(logfile)
            record["result"] = result
            write_json(run / "report.json", report)
            return record, result

        normal, result = execute_case("public_api")
        validate_success(normal, result, runtime)

        def expect_failure(name, code):
            record, result = execute_case(name)
            if result["status"] != "FAIL" or record["execution"]["exit_code"] != 1:
                raise RuntimeError("故障消费进程未明确失败：" + name)
            if not isinstance(result.get("error"), str) or code not in result["error"]:
                raise RuntimeError("故障未返回预期初始化错误：" + name)
            if result.get("workers") != [] or result["checks"] != []:
                raise RuntimeError("初始化负例产生了成功工作者或数据检查：" + name)
            record.update(status="PASS", expected_failure=True, expected_error=code)

        wasm = installed / "dist/generated" / WASM_NAME
        hidden = wasm.with_suffix(".unavailable")
        wasm.rename(hidden)
        try:
            expect_failure("missing_wasm", "node_initialization_failed")
        finally:
            hidden.rename(wasm)
        entry = installed / "dist/index.js"
        original = entry.read_bytes()
        expected = f'export const SDK_VERSION = "{VERSION}";'.encode()
        if original.count(expected) != 1:
            raise RuntimeError("找不到唯一SDK版本常量用于故障注入")
        entry.write_bytes(original.replace(expected, b'export const SDK_VERSION = "0.0.0-invalid";'))
        try:
            expect_failure("mismatched_version", "sdk_version_mismatch")
        finally:
            entry.write_bytes(original)
        restored = validate_package(installed)
        if restored != original_package:
            raise RuntimeError("负例后消费副本未逐文件恢复")
        restored_case, result = execute_case("restored_public_api")
        validate_success(restored_case, result, runtime)
        timeout_case = command([node_binary(), "-e", "setInterval(() => {}, 1000)"], consumer,
                               run / "timeout-termination.log", timeout=1, required=False)
        record = {"name": "harness_timeout_termination", "execution": timeout_case,
                  "scope": "harness only; not SDK cancellation"}
        report["cases"].append(record)
        if not timeout_case["timed_out"] or not timeout_case["reaped"] or timeout_case["exit_code"] == 0:
            raise RuntimeError("超时装置未终止并回收Node进程")
        record["status"] = "PASS"
        report.update(status="PASS", package_sha256=restored,
                      source_dependency="仅从TGZ安装，无Rust源码、Cargo或绑定生成器",
                      wasm_loaded_from_installed_package=True)
        if runtime["platform"] == "darwin":
            report["runtime_matrix"]["macOS"] = "PASS"
        elif runtime["platform"] == "win32":
            report["runtime_matrix"]["Windows"] = "PASS"
    except Exception as error:
        report.update(status="FAIL", error=str(error))
    finally:
        try:
            if archive_before is not None:
                report["archive_sha256_after"] = sha(args.archive.resolve()) if args.archive.is_file() else None
                report["archive_stable"] = report["archive_sha256_after"] == archive_before
                if not report["archive_stable"]:
                    report.update(status="FAIL", error="验证期间TGZ变化或丢失")
            if original_package is not None:
                report["package_sha256_after"] = all_hashes(installed)
                report["package_restored"] = report["package_sha256_after"] == original_package
                if not report["package_restored"]:
                    report.update(status="FAIL", error="消费负例副本未恢复")
        except Exception as error:
            report.update(status="FAIL", error="最终摘要核对失败：" + str(error))
    return finish(run, report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    operations = parser.add_subparsers(dest="operation", required=True)
    package = operations.add_parser("pack")
    package.add_argument("--generated", type=Path, required=True)
    package.add_argument("--build-report", type=Path, required=True)
    package.add_argument("--licenses", type=Path, default=Path(__file__).resolve().parents[2] / "dist/platform-release/licenses")
    package.add_argument("--output", type=Path, default=OUTPUT)
    test = operations.add_parser("verify")
    test.add_argument("--archive", type=Path, required=True)
    test.add_argument("--output", type=Path, default=OUTPUT)
    test.add_argument("--timeout-seconds", type=float, default=60)
    args = parser.parse_args()
    if args.operation == "verify" and not 1 <= args.timeout_seconds <= 300:
        parser.error("--timeout-seconds必须介于1和300")
    return pack(args) if args.operation == "pack" else verify(args)


if __name__ == "__main__":
    sys.exit(main())
