#!/usr/bin/env python3
"""验证 Q05 未决锚的安全重建；独立真实密码进程，不启动 HTTP。"""

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

from network_poc.rebuild_fixture import RebuildLab
from network_poc import rebuild_cases as cases
from network_poc import rebuild_faults as faults


CASES = [
    ("B01", "新独立身份和授权新群真实双向通信且旧范围永久封存", cases.normal),
    ("B02", "候选仅返回原公开计划且未关联前不能使用", cases.candidate_gate),
    ("B03", "旧scope全部字段与授权交叉绑定拒绝", cases.scope_binding),
    ("B04", "伪造批准与不同实例账号新设备身份明确拒绝", cases.approval_binding),
    ("B05", "同一旧scope两个独立后继并发仅一个成功", cases.successor_race),
    ("B06", "重建后完整克隆并发仅一个获准生成新密文", cases.clone_race),
    ("B07", "重复关联不回退新密码状态与已存密文", cases.exact_link_retry),
    ("B08", "取消后旧范围与后继均不复活且不能另建后继", cases.cancel),
    ("B09", "新群不带入旧历史钥副本消息和游标", cases.history_boundary),
    ("B10", "初始登记无重建信任不可事后补授权", cases.missing_trust),
]
for index, kind in enumerate(("checking", "fork", "permission", "access_removed"), 11):
    CASES.append((f"B{index:02d}", "旧范围保留并拒绝重建：" + kind,
                  partial(cases.old_pause, kind=kind)))
for index, kind in enumerate(("checking", "fork", "permission", "access_removed"), 15):
    CASES.append((f"B{index:02d}", "独立批准端不健康明确拒绝：" + kind,
                  partial(cases.source_pause, kind=kind)))
for index, (point, code) in enumerate((("before_save", 83), ("before_rename", 84), ("after_save", 85)), 19):
    CASES.append((f"B{index:02d}", "新身份创建受控退出：" + point,
                  partial(faults.init_crash, point=point, code=code)))
for index, (point, code) in enumerate((("before_save", 83), ("before_rename", 84),
                                      ("after_save", 85), ("after_journal", 87)), 22):
    CASES.append((f"B{index:02d}", "真实Welcome提交受控退出：" + point,
                  partial(faults.join_crash, point=point, code=code)))
for index, point in enumerate(("before_save", "before_rename", "after_save"), 26):
    CASES.append((f"B{index:02d}", "独立关联保存受控退出：" + point,
                  partial(faults.link_crash, point=point)))
CASES.extend([
    ("B29", "关联已保存响应丢失后精确重试", partial(faults.link_transport, mode="drop")),
    ("B30", "伪造关联响应拒绝且可查询独立持久事实", partial(faults.link_transport, mode="tamper")),
    ("B31", "新范围输入及独立保存容量有界", cases.bounded),
])
for index, (point, code) in enumerate((("before_save", 83), ("before_rename", 84),
                                      ("after_save", 85), ("after_journal", 87), ("after_finish", 88)), 32):
    CASES.append((f"B{index:02d}", "独立批准保存受控退出：" + point,
                  partial(faults.approval_crash, point=point, code=code)))
CASES.extend([
    ("B37", "独立批准Finish丢响应后复用原持久签名结果", faults.approval_lost_response),
    ("B38", "真实Welcome已保存但缺journal时不重复消费", faults.missing_child_journal),
    ("B39", "已取消后继不能被迟到真实Welcome激活", faults.cancelled_join),
    ("B40", "独立批准设备缺可信锚启动明确拒绝", faults.source_without_anchor),
    ("B41", "原范围已有完整结果journal时保持既有精确恢复", faults.existing_old_journal),
])


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_report(path, report):
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option, name in (("binary", "state-lab"), ("helper", "rollback-anchor"),
                         ("permission-verifier", "permission-verify"), ("receipt-signer", "relay-receipt")):
        parser.add_argument("--" + option, type=Path, required=True, help="明确指定本轮构建产物；不默认复用历史程序")
    parser.add_argument("--case", action="append", choices=[c[0] for c in CASES])
    parser.add_argument("--output", type=Path, default=ROOT / "dist/anchor-rebuild")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / "runs").mkdir(exist_ok=True)
    run_id = str(uuid.uuid4())
    report_path = output / "runs" / (run_id + ".json")
    report = {"run_id": run_id, "status": "RUNNING", "executed_at": datetime.now(timezone.utc).isoformat(),
              "platform": platform.platform(), "python": platform.python_version(),
              "scope": "synthetic_local; actual MLS and device/Service signatures; isolated CLI processes; no HTTP",
              "independence": "可信控制器及锚未与旧设备共同回滚属于假设；本机不同目录不证明生产独立故障域",
              "selected_cases": args.case or "all_rebuild_cases", "http_request_count": 0,
              "raw_old_key_attack": "NOT_EXECUTED_ACCESS_RESTRICTED", "process_count": 0,
              "direct_anchor_process_count": 0,
              "process_count_scope": "客户端CLI与fixture Service签名器；另计直接锚调用；不含客户端内部helper",
              "not_validated": ["生产独立保存介质与钥生命周期", "原始旧钥攻击", "真实HTTP接受",
                                "分叉裁决后重建", "全账号跨群协调", "历史迁移", "四端发布"], "cases": []}
    write_report(report_path, report)
    try:
        for name in ("binary", "helper", "permission_verifier", "receipt_signer"):
            report[name + "_sha256"] = digest(getattr(args, name))
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
                lab = RebuildLab(args.binary.resolve(), Path(temporary).resolve(),
                                 args.permission_verifier.resolve(), args.receipt_signer.resolve(), args.helper.resolve())
                try:
                    lab.initialize()
                    run_case(lab)
                    record.update(status="PASS", evidence=lab.evidence)
                    print(f"PASS {ident} {name}", flush=True)
                except Exception as error:
                    record.update(status="FAIL", error=str(error), evidence=lab.evidence)
                    raise
                finally:
                    lab.close()
                    report["process_count"] += lab.process_count
                    report["direct_anchor_process_count"] += lab.helper_process_count
                    write_report(report_path, report)
        report["status"] = "PASS"
    except Exception as error:
        report.update(status="FAIL", error=str(error))
        print(f"FAIL anchor-rebuild: {error}", file=sys.stderr)
    finally:
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        write_report(report_path, report)
        write_report(output / "latest.json", report)
    print(f"{report['status']} {len(report['cases'])} 个本项场景；run_id={run_id}")
    print(f"报告：{report_path}")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
