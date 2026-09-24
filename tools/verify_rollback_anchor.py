#!/usr/bin/env python3
"""用已构建 Release 探针验证 Q05/Q02 外置锚；不启动 HTTP、不执行原始旧钥攻击。"""

import argparse
from datetime import datetime, timezone
from functools import partial
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests/interop"))

from network_poc.anchor_fixture import AnchorLab
from network_poc import anchor_cases as cases
from network_poc import anchor_faults as faults


CASES = [
    ("A01", "真实MLS发送、已存密文精确重试及独立设备解密", cases.ordinary_retry),
    ("A02", "完整设备目录回滚先于新密文及缓存返回阻断、精确副本恢复", cases.complete_rollback),
    ("A03", "锚不可达后持久暂停与显式恢复", cases.unavailable),
    ("A04", "实例账号设备密码身份及存储范围错配拒绝", cases.wrong_scope),
    ("A05", "固定锚钥、客户端认证钥及恢复日志钥错配拒绝", cases.wrong_key),
    ("A06", "缺失密码快照拒绝重新初始化、已有锚拒绝重建", cases.missing_state),
    ("A07", "两个完整克隆并发仅一个获准推进", cases.clone_race),
    ("A08", "已完成预约重放、伪造请求及旧签名响应拒绝", cases.signed_replay),
    ("A09", "可信配置缺失、权限及放置边界拒绝", cases.unsafe_configuration),
    ("A10", "客户端1MiB及锚32KiB输入边界", cases.bounded_input),
    ("A11", "同机控制器双边回滚不可判定的负面对照", cases.common_controller_rollback),
    ("A12", "锚恢复保留Q02检查闸", partial(cases.preserved_pause, kind="checking")),
    ("A13", "锚恢复保留真实双签后继形成的Q02分叉暂停", partial(cases.preserved_pause, kind="fork")),
    ("A14", "锚恢复保留原权限候选暂停", partial(cases.preserved_pause, kind="permission")),
]
for index, (point, code) in enumerate((("before_save", 83), ("before_rename", 84),
                                      ("after_save", 85), ("after_reserve", 86),
                                      ("after_journal", 87), ("after_finish", 88)), 15):
    CASES.append((f"A{index:02d}", "客户端受控退出：" + point,
                  partial(faults.client_crash, point=point, code=code)))
CASES.extend([
    ("A21", "reserve已接受但响应遗失时不重做密码操作", partial(faults.dropped_response, action="reserve")),
    ("A22", "finish已接受但响应遗失时精确完成已存目标", partial(faults.dropped_response, action="finish")),
    ("A23", "伪造锚响应在密码载入前拒绝", partial(faults.transport_fault, mode="tamper")),
    ("A24", "锚helper超时有界结束并持久暂停", partial(faults.transport_fault, mode="timeout")),
    ("A25", "锚helper输出超限拒绝", partial(faults.transport_fault, mode="oversize")),
    ("A26", "恢复日志篡改不能推进或部分覆盖状态", partial(faults.journal_tamper, mode="tamper")),
    ("A27", "旧恢复日志不能用于新预约", partial(faults.journal_tamper, mode="rollback")),
    ("A28", "缺失恢复日志不能以当前较大状态解锁", partial(faults.journal_tamper, mode="missing")),
    ("A29", "已消费预约精确重试不再次推进且不许可重执行", faults.exact_reservation_retry),
    ("A30", "锚状态缺失不重建、精确恢复仍需显式开闸", faults.authority_missing),
    ("A31", "独立锚目录容量达到上限时明确暂停", faults.bounded_authority_storage),
])
for index, (point, action) in enumerate((("before_save", "reserve"), ("before_rename", "reserve"),
                                        ("after_save", "reserve"), ("before_save", "finish"),
                                        ("before_rename", "finish"), ("after_save", "finish")), 32):
    CASES.append((f"A{index:02d}", f"独立锚{action}进程退出：{point}",
                  partial(faults.authority_crash, point=point, action=action)))
CASES.extend([
    ("A38", "预约通过后替换旧快照，在同次读取解密前拒绝", faults.replace_after_reserve),
    ("A39", "相同摘要纯读多次提交后旧预约仍不可重放", faults.same_head_replay),
])


def write_report(path, report):
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, help="明确指定本轮构建产物；不默认复用历史程序")
    parser.add_argument("--helper", type=Path, required=True, help="明确指定本轮构建产物；不默认复用历史程序")
    parser.add_argument("--permission-verifier", type=Path, required=True, help="明确指定本轮构建产物；不默认复用历史程序")
    parser.add_argument("--receipt-signer", type=Path, required=True, help="明确指定本轮构建产物；不默认复用历史程序")
    parser.add_argument("--case", action="append", choices=[case[0] for case in CASES])
    parser.add_argument("--output", type=Path, default=ROOT / "dist/rollback-anchor")
    args = parser.parse_args()
    run_id = str(uuid.uuid4())
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / "runs").mkdir(exist_ok=True)
    report_path = output / "runs" / (run_id + ".json")
    report = {"run_id": run_id, "status": "RUNNING", "executed_at": datetime.now(timezone.utc).isoformat(),
              "scope": "synthetic_local independent processes; real MLS and signatures; no HTTP",
              "independence": "假设可信配置及锚未与设备同时回滚；同机控制器可破坏此前提",
              "raw_old_key_attack": "NOT_EXECUTED_ACCESS_RESTRICTED", "http_request_count": 0,
              "process_count": 0, "direct_anchor_process_count": 0,
              "process_count_scope": "顶层设备CLI与fixture Service签名器；锚内部调用另未计数",
              "not_validated": ["生产硬件或独立故障域", "生产信任引导与密钥轮换部署",
                                "四端Release发布", "全账号跨群协调", "分叉裁决后重建"], "cases": []}
    write_report(report_path, report)
    try:
        for name, binary in (("binary", args.binary), ("helper", args.helper),
                             ("permission_verifier", args.permission_verifier), ("receipt_signer", args.receipt_signer)):
            report[name + "_sha256"] = digest(binary)
        report["lock_sha256"] = digest(ROOT / "poc/openmls-probe/Cargo.lock")
        sources = [Path(__file__).resolve(), ROOT / "poc/openmls-probe/Cargo.toml", ROOT / "poc/rust-toolchain.toml"]
        for directory in ("poc/openmls-probe/src", "tests/interop/network_poc"):
            sources.extend(p for p in (ROOT / directory).rglob("*") if p.suffix in (".rs", ".py"))
        report["source_sha256"] = {str(p.relative_to(ROOT)): digest(p) for p in sorted(sources)}
        for ident, name, run_case in CASES:
            if args.case and ident not in args.case:
                continue
            record = {"id": ident, "name": name, "status": "RUNNING"}
            report["cases"].append(record)
            write_report(report_path, report)
            with tempfile.TemporaryDirectory(prefix=ident + "-", dir=output) as temporary:
                lab = AnchorLab(args.binary.resolve(), Path(temporary).resolve(),
                                args.permission_verifier.resolve(), args.receipt_signer.resolve(), args.helper.resolve())
                try:
                    lab.initialize(permissions=ident in ("A12", "A13", "A14"))
                    run_case(lab)
                    record.update(status="PASS", evidence=lab.evidence)
                    print(f"PASS {ident} {name}", flush=True)
                except Exception as error:
                    record.update(status="FAIL", error=str(error))
                    raise
                finally:
                    lab.close()
                    report["process_count"] += lab.process_count
                    report["direct_anchor_process_count"] += lab.helper_process_count
                    write_report(report_path, report)
        report["status"] = "PASS"
    except Exception as error:
        report.update(status="FAIL", error=str(error))
        print(f"FAIL rollback-anchor: {error}", file=sys.stderr)
    finally:
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        write_report(report_path, report)
        write_report(output / "latest.json", report)
    print(f"{report['status']} {len(report['cases'])} 个本项场景；run_id={run_id}")
    print(f"报告：{report_path}")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
