#!/usr/bin/env python3
"""验证重建后继的新设备流授权和真实HTTP恢复同步，不改变旧重建验收入口。"""

import argparse
from datetime import datetime, timezone
from functools import partial
import hashlib
import json
from pathlib import Path
import platform
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests/interop"))

from network_poc.rebuild_sync_fixture import RebuildSyncLab
from network_poc import rebuild_sync_cases as cases
from network_poc import rebuild_sync_boundaries as boundaries
from network_poc import rebuild_sync_faults as faults


CASES = [
    ("S01", "实际Add/Welcome后新空流包含注册前排队消息并双向解密", cases.normal),
    ("S02", "20条新消息按3条分页保持双游标连续", cases.pagination),
    ("S03", "登记拉取保存页与绑定跨进程精确重试", cases.exact_retry),
    ("S04", "空页与十进制分页边界", cases.empty_and_limits),
    ("S05", "同一注册并发HTTP幂等仅一个新流", cases.concurrent_registration),
    ("S06", "完整候选克隆并发仅一份流申请获锚许可", cases.clone_request_race),
    ("S07", "尚未真正处理Welcome不能申请新流", boundaries.before_welcome),
    ("S08", "旧设备同账号另设备异账号与实例授权拒绝", boundaries.http_authorization),
    ("S09", "计划批准锚证明入群凭据签名交叉替换拒绝", boundaries.registration_evidence),
    ("S10", "真实Service签名绑定必须逐字段对应本机唯一申请", boundaries.binding_fields),
    ("S11", "旧非零游标和G1密文不能进入新流", boundaries.old_stream),
    ("S12", "签页请求范围挑战及原页摘要交叉绑定", boundaries.page_fields),
    ("S13", "真Service恶意签页仍核验原消息实际接受证明", boundaries.message_origin),
    ("S14", "普通下载及无可信锚配置不能驱动新流", boundaries.no_unsigned_or_unanchored),
    ("S15", "历史HTTP绑定不能绕过本机实时取消锚", boundaries.cancel),
    ("S16", "新页740KiB原始输入上限", boundaries.bounded_page),
    ("S17", "同挑战两个有效视图及跨页迟到重放不永久暂停", faults.delayed_pages),
]
for stage in ("after_bind", "after_download", "after_process"):
    CASES.append((f"S{len(CASES) + 1:02d}", "独立锚不回滚时完整旧快照拒绝：" + stage,
                  partial(cases.stale_snapshot, stage=stage)))
for operation in ("register", "page"):
    for hook, code in (("before_commit_exit", 86), ("after_commit_exit", 87), ("drop_after_commit", None)):
        function = faults.register_transport if operation == "register" else faults.page_transport
        CASES.append((f"S{len(CASES) + 1:02d}", "真实HTTP" + operation + "响应故障：" + hook,
                      partial(function, hook=hook, code=code)))
for operation, point, code in (("request", "before_save", 83), ("request", "after_journal", 87),
    ("bind", "before_rename", 84), ("bind", "after_finish", 88),
    ("pull", "after_save", 85), ("pull", "after_journal", 87),
    ("download", "before_save", 83), ("download", "after_journal", 87),
    ("process", "after_save", 85), ("process", "after_journal", 87)):
    CASES.append((f"S{len(CASES) + 1:02d}", "客户端" + operation + "保存退出：" + point,
                  partial(faults.client_crash, operation=operation, point=point, code=code)))
for action in ("reserve", "finish"):
    CASES.append((f"S{len(CASES) + 1:02d}", "新流拉取锚已处理后丢响应：" + action,
                  partial(faults.anchor_response, action=action)))
for kind in ("checking", "fork", "permission_pending", "access_removed"):
    CASES.append((f"S{len(CASES) + 1:02d}", "新同步保留真实前置安全状态：" + kind,
                  partial(boundaries.paused_state, kind=kind)))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_report(path, report):
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")


def inputs(args):
    paths = {name: getattr(args, name).resolve() for name in
             ("binary", "helper", "permission_verifier", "receipt_signer")}
    paths["lock"] = ROOT / "poc/openmls-probe/Cargo.lock"
    sources = [Path(__file__).resolve(), ROOT / "poc/openmls-probe/Cargo.toml", ROOT / "poc/rust-toolchain.toml"]
    for directory in ("poc/openmls-probe/src", "poc/network-relay", "tests/interop/network_poc"):
        sources.extend(p for p in (ROOT / directory).rglob("*") if p.suffix in (".rs", ".py"))
    # 包含HTTP/消息schema与api/realtime/vectors.json固定跨语言字节向量。
    sources.extend((ROOT / "api").rglob("*.json"))
    return {"binary_sha256": {name: digest(path) for name, path in paths.items()},
            "source_sha256": {str(path.relative_to(ROOT)): digest(path) for path in sorted(sources)}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    release = ROOT / "dist/crypto-probes/target/openmls/release"
    for option, name in (("binary", "state-lab"), ("helper", "rollback-anchor"),
                         ("permission-verifier", "permission-verify"), ("receipt-signer", "relay-receipt")):
        parser.add_argument("--" + option, type=Path, default=release / ("openmls-" + name))
    parser.add_argument("--case", action="append", choices=[case[0] for case in CASES])
    parser.add_argument("--output", type=Path, default=ROOT / "dist/rebuild-sync")
    args = parser.parse_args()
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=True)
    (output / "runs").mkdir(exist_ok=True)
    run_id = str(uuid.uuid4()); report_path = output / "runs" / (run_id + ".json")
    report = {"run_id": run_id, "status": "RUNNING", "executed_at": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(), "python": platform.python_version(),
        "scope": "synthetic_local bootstrap; real MLS/device/Service signatures; real localhost HTTP + SQLite + isolated Release CLI",
        "independence": "可信控制器和锚独立不回滚为假设；不同本机目录不证明生产独立故障域",
        "selected_cases": args.case or "all_rebuild_sync_cases", "http_request_count": 0,
        "process_count": 0, "direct_anchor_process_count": 0,
        "process_count_scope": "独立客户端CLI、fixture签名器及HTTP server启动；另计直接锚调用，不含嵌套helper",
        "raw_old_key_attack": "NOT_EXECUTED_ACCESS_RESTRICTED",
        "not_validated": ["生产独立保存介质与钥生命周期", "恶意Service隐瞒消息的完备性", "在线跨主机取消通知",
                          "原始旧钥攻击", "历史迁移", "四端发布与真机", "正式Go Service"], "cases": []}
    write_report(report_path, report)
    try:
        report["inputs"] = inputs(args)
        for ident, name, run_case in CASES:
            if args.case and ident not in args.case:
                continue
            record = {"id": ident, "name": name, "status": "RUNNING"}; report["cases"].append(record)
            write_report(report_path, report)
            with tempfile.TemporaryDirectory(prefix=ident + "-", dir=output) as temporary:
                lab = RebuildSyncLab(args.binary.resolve(), Path(temporary).resolve(), args.permission_verifier.resolve(),
                                     args.receipt_signer.resolve(), args.helper.resolve())
                try:
                    lab.initialize(); run_case(lab)
                    record.update(status="PASS", evidence=lab.evidence)
                    print(f"PASS {ident} {name}", flush=True)
                except Exception as error:
                    record.update(status="FAIL", error=str(error), evidence=lab.evidence)
                    raise
                finally:
                    lab.close()
                    stderr = lab.directory / "relay.stderr.log"
                    if stderr.exists() and stderr.stat().st_size:
                        log = output / "runs" / (run_id + "-" + ident + "-relay.stderr.log")
                        log.write_bytes(stderr.read_bytes()); record["relay_stderr"] = str(log)
                    report["http_request_count"] += lab.http_count
                    report["process_count"] += lab.process_count
                    report["direct_anchor_process_count"] += lab.helper_process_count
                    write_report(report_path, report)
        report["status"] = "PASS"
    except Exception as error:
        report.update(status="FAIL", error=str(error)); print(f"FAIL rebuild-sync: {error}", file=sys.stderr)
    finally:
        if "inputs" in report:
            report["inputs_after"] = inputs(args)
            report["input_digests_stable"] = report["inputs_after"] == report["inputs"]
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        write_report(report_path, report); write_report(output / "latest.json", report)
    print(f"{report['status']} {len(report['cases'])} 个本项场景；run_id={run_id}")
    print(f"报告：{report_path}")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
