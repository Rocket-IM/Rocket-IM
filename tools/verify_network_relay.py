#!/usr/bin/env python3
"""阶段 0：独立 Rust CLI + 本机 HTTP/SQLite Relay 的增量验证，无旧钥攻击。"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import tomllib
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests/interop"))
from network_poc.fixture import NetworkLab
from network_poc import (binding_cases, consistency_boundaries, consistency_cases, exchange_boundaries, exchange_cases, exchange_faults, device_join_boundaries, device_join_cases, history_boundary_cases, history_cases, join_cases, join_boundary_cases, message_cases, migration_boundaries, migration_cases, migration_faults, permission_cases, permission_recovery_cases,
                         permission_recovery_faults, recovery_cases, sent_history_cases, sent_history_boundaries)


CASES = [
    ("M01", "HTTP离线多设备收发与不透明持久化", message_cases.offline),
    ("M02", "提交后丢响应与独立CLI原字节重试", message_cases.lost_ack),
    ("M03", "20条分页、重复下载与乱序密码接收", message_cases.pagination),
    ("M04", "同尝试异头或异密文冲突", message_cases.id_conflict),
    ("M05", "身份/模式/状态绑定与原始AAD字节", message_cases.bindings),
    *binding_cases.CASES,
    ("M06", "端侧受控退出与原子快照/游标恢复", recovery_cases.interruptions),
    ("M07", "并发提交与连续分页", recovery_cases.concurrent_commit),
    ("M08", "Relay事务前后退出和重启", recovery_cases.relay_restart),
    ("M09", "在途旧尝试封口与显式替代", recovery_cases.replacement),
    ("M10", "坏消息隔离与满队列独立依赖恢复", recovery_cases.dependencies),
    ("M11", "过期投影、实例/游标隔离及同槽冲突", recovery_cases.lifecycle),
    ("M12", "重复字段、整数及密文输入限额", recovery_cases.input_limits),
    ("M13", "设备回执权限、幂等和独立已读", message_cases.receipts),
    ("M14", "设备撤销后访问和原目标集合保持", recovery_cases.revoked_access),
    ("P01", "签名群移除、R0/R1与旧尝试边界", permission_cases.signed_removal),
    ("P02", "签名/上下文篡改、越权与注入旁路拒绝", permission_cases.tampering),
    ("P03", "同账号设备签名撤销及持久访问限制", permission_cases.device_revocation),
    ("P04", "满队列独立补齐两步签名权限链", permission_cases.offline_chain),
    ("P05", "准备和应用权限变更的原子快照恢复", permission_cases.atomic_changes),
    ("P06", "并发权限变更只接受一个后继并保留冲突", permission_cases.competing_changes),
    ("P07", "公开验证器不可用时拒绝且不推进状态", permission_cases.verifier_unavailable),
    ("P08", "权限R0事务退出、丢响应及独立进程恢复", permission_cases.relay_interruptions),
    ("P09", "群移除精确排除目标账号全部设备", permission_cases.all_member_devices),
    ("R01", "竞争胜者完成原移除意图后恢复发送", permission_recovery_cases.same_intent),
    ("R02", "竞争后保留原撤销意图并重新准备", permission_recovery_cases.different_intent),
    ("R03", "过期候选签名封口与新候选恢复", permission_recovery_cases.expiry_close),
    ("R04", "接受后丢响应由封口查回原接受回执", permission_recovery_cases.accepted_close),
    ("R05", "回执篡改、错钥和已封口候选复活拒绝", permission_recovery_cases.tampered_receipts),
    ("R06", "并发提交与封口只有一个持久终态", permission_recovery_cases.submit_close_race),
    ("R07", "封口请求及恢复的端侧原子快照", permission_recovery_faults.snapshot_interruptions),
    ("R08", "封口事务退出、丢响应与多次重新准备", permission_recovery_faults.relay_interruptions),
    ("R09", "签名钥缺失或运行中替换不留下半成决议", permission_recovery_faults.signer_failure),
    ("R10", "竞争中自身被移除后持久禁止发送", permission_recovery_faults.removed_self),
    ("R11", "封口回执水位补齐前禁止重新准备", permission_recovery_faults.closed_checkpoint_floor),
    ("R12", "原意图提前完成仍须补齐全部已知水位", permission_recovery_faults.satisfied_before_floor),
    ("H01", "R1后离线补拉合法旧消息并保持当前发送状态", history_cases.offline_after_change),
    ("H02", "旧消息队列跨权限变化与原子接收恢复", history_cases.queued_atomic_receive),
    ("H03", "两个历史epoch与当前消息乱序接收和去重", history_cases.two_epochs_out_of_order),
    ("H04", "已移除发送者旧消息即使有接受签名也隔离", history_cases.removed_sender),
    ("H05", "接受签名与消息和事件ID绑定且失败不抢占去重", history_cases.receipt_binding),
    ("H06", "历史上下文与版本篡改不改变当前状态", history_cases.unknown_and_wrong_state),
    ("H07", "有效Service签名不替代旧消息的MLS完整性校验", history_boundary_cases.signed_but_corrupt),
    ("H08", "已接收撤销发送者消息只复用原接受身份", history_boundary_cases.cached_removed_sender),
    ("H09", "无历史接受证据的槽位隔离且不永久等待", history_boundary_cases.missing_history_evidence),
    ("H10", "真实未来状态与合法旧状态分别恢复", history_boundary_cases.future_then_history),
    ("H11", "被撤销接收端不能借历史证明恢复访问", history_boundary_cases.revoked_receiver),
    ("H12", "消息接受签名失败无部分记录且重试复用原证据", history_boundary_cases.message_signer_atomicity),
    ("J01", "独立新成员真实加入、离线现有成员和双向新消息", join_cases.new_member_flow),
    ("J02", "加入身份固定、群主权限和历史策略约束", join_cases.identity_and_policy),
    ("J03", "KeyPackage与Welcome篡改拒绝且失败不消耗有效材料", join_cases.altered_materials),
    ("J04", "新成员原子加入、受控退出及精确重试", join_cases.atomic_join),
    ("J05", "邀请候选与已有成员Add应用的原子恢复", join_cases.atomic_prepare),
    ("J06", "同目标并发邀请由真实胜者完成原意图", join_cases.competing_same_member),
    ("J07", "不同权限竞争保留邀请意图并重建Welcome", join_cases.competing_other_action),
    ("J08", "邀请封口后不能复活且新候选可恢复", join_cases.closed_candidate),
    ("J09", "新成员只从真实加入之后积累历史状态", join_cases.history_after_join),
    ("J10", "独立加入信任锚与公开链边界", join_boundary_cases.anchor_boundaries),
    ("J11", "加入材料仅目标可领且移除后拒绝", join_boundary_cases.material_access),
    ("J12", "签名器失败不部分接受或消耗KeyPackage", join_boundary_cases.signer_atomicity),
    ("J13", "入群接受事务前后退出与持久材料恢复", join_boundary_cases.relay_atomicity),
    ("J14", "邀请接受丢响应后的精确重试与加入", join_boundary_cases.relay_lost_ack),
    ("J15", "曾入群身份不能通过新邀请复活", join_boundary_cases.retired_identity),
    ("D01", "同账号旧设备批准新设备并双向收发未来消息", device_join_cases.future_device_flow),
    ("D02", "登录凭证和群主身份不能代替同账号旧设备批准", device_join_cases.authority_and_modes),
    ("D03", "新设备授权绑定精确身份和材料且拒绝不消耗状态", device_join_cases.bound_proof_and_material),
    ("D04", "两台旧设备批准同一新设备的真实胜者恢复", device_join_cases.same_device_competition),
    ("D05", "其他权限竞争后保持设备意图并重新绑定新状态", device_join_cases.different_action_competition),
    ("D06", "新设备候选封口后不复活且可明确重新批准", device_join_cases.closed_device_candidate),
    ("D07", "批准端、接收端和新设备入群的原子快照", device_join_boundaries.client_atomicity),
    ("D08", "旧设备所属账号被移除后迟到批准无效", device_join_boundaries.removed_authorizer),
    ("D09", "新设备撤销后原批准重放不能恢复访问", device_join_boundaries.revoke_joined_device),
    ("D10", "新设备入群后独立撤销旧设备且保留未来通信", device_join_boundaries.revoke_old_device_after_join),
    ("D11", "同账号公开群锚不扩充全局信任或加入前历史", device_join_boundaries.group_anchor_and_history),
    ("D12", "设备授权签名故障和Service事务退出完整恢复", device_join_boundaries.service_atomicity),
    ("D13", "新设备批准丢响应后精确恢复原回执和材料", device_join_boundaries.service_lost_response),
    ("X01", "同账号定向导入选中副本且保持独立密码和消息状态", migration_cases.selected_copies),
    ("X02", "迁移仅指定同账号源和目标可签署提交领取导入", migration_cases.authority),
    ("X03", "请求密文KEM签名和回执篡改失败不消耗导入状态", migration_cases.tampering),
    ("X04", "跨进程原请求和密文重试及跨迁移副本去重", migration_cases.exact_retry_and_overlap),
    ("X05", "缺少已接收正文或接受签名时拒绝并排除未确认发送队列", migration_cases.source_evidence),
    ("X06", "原消息删除过期后整包拒绝且重试重新检查可用性", migration_boundaries.availability),
    ("X07", "本地取消清理和到期拒绝及新授权去重", migration_boundaries.cancel_and_expire),
    ("X08", "当前群状态变化和未完成权限意图阻止旧迁移", migration_boundaries.current_checkpoint),
    ("X09", "源设备撤销后Service及本机拒绝旧迁移", migration_boundaries.source_revoked),
    ("X10", "目标设备撤销后迁移不能恢复访问", migration_boundaries.target_revoked),
    ("X11", "请求导出导入取消的端侧原子快照恢复", migration_faults.client_atomicity),
    ("X12", "迁移签名器失败事务退出及丢响应的原记录恢复", migration_faults.service_atomicity),
    ("S01", "原发送及接收混合历史的显式迁移且不改变原消息状态", sent_history_cases.mixed_history),
    ("S02", "丢接受响应和已准备后继时迟到原证明保持唯一接受", sent_history_cases.lost_ack_and_superseded),
    ("S03", "发送接受证明绑定原尝试和上下文且冲突保留原事实", sent_history_cases.proof_binding),
    ("S04", "封口或终态拒绝后的已接受替代才可成为发送历史", sent_history_cases.closed_then_replaced),
    ("S05", "迁移与目标正常收件保持独立副本和原去重语义", sent_history_cases.native_received_copy),
    ("S06", "发送接受记账和副本导入的原子快照恢复", sent_history_boundaries.atomic_acceptance),
    ("S07", "原发送历史删除过期后旧接受事实不能恢复迁移权限", sent_history_boundaries.unavailable_original),
    ("S08", "权限处理中和已知撤销后的接受记账不恢复发送或迁移", sent_history_boundaries.acceptance_does_not_restore_access),
    ("F01", "当前视图挑战绑定、检查闸与不可判断边界", consistency_cases.normal_and_binding),
    ("F02", "已知旧head持久暂停且只能显式恢复", consistency_cases.rollback_and_resume),
    ("F03", "只增观察水位与真实MLS补链后恢复", consistency_cases.head_floor_and_sync),
    ("F04", "独立设备同前驱接受证据识别分叉且不可原地解除", consistency_cases.independent_fork),
    ("F05", "篡改、未知前驱、重复及封口证据不能伪造分叉", consistency_cases.invalid_fork_evidence),
    ("F06", "同版本完整检查点矛盾永久暂停", consistency_cases.head_equivocation),
    ("F07", "实际补链与曾观察分支冲突原子保存", consistency_boundaries.conflict_during_recovery),
    ("F08", "检查、回滚检测及恢复的83至85受控退出", consistency_boundaries.atomic_head_and_resume),
    ("F09", "独立分叉证据导入受控退出与重启不解暂停", consistency_boundaries.atomic_fork),
    ("F10", "一致性恢复不清除原权限候选和暂停", consistency_boundaries.original_permission_pause),
    ("F11", "缓存密文、旧发送和历史迁移入口不能绕过检查闸", consistency_boundaries.cached_crypto_guards),
    ("F12", "合法旧接受记录和历史消息不冒充当前head", consistency_boundaries.history_is_not_rollback),
    ("E01", "实际持有端离线导出同支证据及原字节重试", exchange_cases.matching_and_retry),
    ("E02", "实际另一分支签署公开包并触发永久分叉暂停", exchange_cases.actual_holder_fork),
    ("E03", "交换请求和来源签名篡改与实例群双端绑定拒绝", exchange_cases.tampering_and_context),
    ("E04", "指纹和明确核验方式不可由登录或Service标签替代", exchange_boundaries.trust_required),
    ("E05", "accepted但未实际R1和未持有记录不能导出", exchange_cases.source_possession),
    ("E06", "只有来源公开证明时保持缺对照并等待实际补链", exchange_boundaries.insufficient_comparison),
    ("E07", "源端实际持有的陌生前驱不能变成本机可信锚", exchange_boundaries.missing_predecessor),
    ("E08", "已知撤销来源禁止旧包导入和缓存导出", exchange_boundaries.known_revoked_source),
    ("E09", "不可达和取消保留检查闸且迟到包不能复活", exchange_boundaries.cancellation_and_unreachable),
    ("E10", "交换开始导出取消的83至85受控退出", exchange_faults.atomic_request_export_cancel),
    ("E11", "冲突包导入的83至85受控退出和重启不解暂停", exchange_faults.atomic_import_fork),
    ("E12", "请求包分层大小限制及CLI总输入限额", exchange_boundaries.bounded_inputs),
]


def write_report(path, report):
    runs = path.parent / "runs"
    runs.mkdir(exist_ok=True)
    content = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    for destination in (runs / (report["run_id"] + ".json"), path):
        temporary = destination.with_suffix(".tmp")
        temporary.write_text(content)
        temporary.replace(destination)


def needs_permissions(ident):
    return ident == "M11" or ident.startswith(("P", "R", "H", "J", "D", "X", "S", "F", "E"))


def needs_signed_pages(ident):
    # 生命周期声明必须来自本次验证的签名页，不能用无签名的普通收发装置。
    return ident in ("M11", "P04") or ident.startswith(("R", "H", "J", "D", "X", "S", "F", "E"))


def build(binary, output):
    cargo = shutil.which("cargo")
    if cargo is None:
        raise RuntimeError("未找到 Cargo；请提供锁定工具链 PATH，或用 --binary 指定本轮已构建程序")
    version = tomllib.loads((ROOT / "poc/rust-toolchain.toml").read_text())["toolchain"]["channel"]
    with (output / "network-build.log").open("w") as log:
        completed = subprocess.run(
            [cargo, "+" + version, "build", "--locked", "--release", "--manifest-path",
             str(ROOT / "poc/openmls-probe/Cargo.toml"), "--bin", "openmls-state-lab",
             "--bin", "openmls-permission-verify", "--bin", "openmls-relay-receipt"],
            env={**os.environ, "CARGO_TARGET_DIR": str(binary.parents[1])},
            stdout=log, stderr=subprocess.STDOUT, cwd=ROOT / "poc", timeout=600)
    if completed.returncode:
        raise RuntimeError("Rust构建失败，查看 network-build.log；本次不能沿用旧PASS")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, help="明确使用已构建的本轮Rust程序")
    parser.add_argument("--permission-verifier", type=Path, help="公开权限验证程序；默认使用binary同目录产物")
    parser.add_argument("--receipt-signer", type=Path, help="Service回执签名程序；默认使用binary同目录产物")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/network-relay",
                        help="独立报告目录；逐run归档保留通过及失败记录")
    parser.add_argument("--case", choices=[case[0] for case in CASES], action="append",
                        help="只运行指定增量场景，结果会标为选定范围")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / "results.json"
    binary = (args.binary or output / "target/openmls/release/openmls-state-lab").resolve()
    verifier = (args.permission_verifier or binary.with_name("openmls-permission-verify")).resolve()
    signer = (args.receipt_signer or binary.with_name("openmls-relay-receipt")).resolve()
    report = {"status": "RUNNING", "run_id": str(uuid.uuid4()),
              "executed_at": datetime.now(timezone.utc).isoformat(),
              "scope": "synthetic trusted fixtures; Rust processes; loopback HTTP; SQLite; controlled exits; synthetic offline public evidence exchange",
              "platform": platform.platform(), "python": platform.python_version(),
              "sqlite": sqlite3.sqlite_version, "selected_cases": args.case or "all_incremental_cases",
              "raw_old_key_attack": "NOT_EXECUTED_ACCESS_RESTRICTED",
              "full_M01_M14_acceptance": "NOT_COMPLETE",
              "remaining": ["生产身份/群授权及首次核验", "真实TLS/WSS与移动/浏览器SDK",
                            "任意时刻断电和真实磁盘故障", "备份/物理删除和保留期清理",
                            "全账号跨群设备授权、重入群、附件迁移与生产恢复流程", "生产独立对照渠道及信任引导、全快照回滚防护",
                            "生产容量和完整安全模型T用例"],
              "process_count_scope": "客户端CLI、测试Service钥操作与Relay启动；不含Relay内部验证/签名子进程",
              "cases": [], "process_count": 0, "http_request_count": 0}
    public_fixtures = output / "runs" / report["run_id"] / "public-fixtures"
    report["public_fixture_directory"] = str(public_fixtures)
    write_report(report_path, report)
    try:
        if args.binary is None:
            build(binary, output)
        report["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        if args.case is None or any(needs_permissions(ident) for ident in args.case):
            report["permission_verifier_sha256"] = hashlib.sha256(verifier.read_bytes()).hexdigest()
        if args.case is None or any(needs_signed_pages(ident) for ident in args.case):
            report["receipt_signer_sha256"] = hashlib.sha256(signer.read_bytes()).hexdigest()
        report["lock_sha256"] = hashlib.sha256((ROOT / "poc/openmls-probe/Cargo.lock").read_bytes()).hexdigest()
        sources = [ROOT / "tools/verify_network_relay.py", ROOT / "poc/openmls-probe/Cargo.toml",
                   ROOT / "poc/rust-toolchain.toml"]
        for directory in ("api", "poc/network-relay", "poc/openmls-probe/src", "tests/interop/network_poc"):
            sources.extend(p for p in (ROOT / directory).rglob("*")
                           if p.is_file() and p.suffix in (".rs", ".py", ".json"))
        report["source_sha256"] = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                   for p in sorted(sources)}
        for ident, name, run_case in CASES:
            if args.case and ident not in args.case:
                continue
            record = {"id": ident, "name": name, "status": "RUNNING", "coverage": "incremental"}
            report["cases"].append(record)
            write_report(report_path, report)
            with tempfile.TemporaryDirectory(prefix=ident + "-", dir=output) as temporary:
                permissions = needs_permissions(ident)
                lab = NetworkLab(binary, Path(temporary).resolve(), verifier if permissions else None,
                                 signer if needs_signed_pages(ident) else None)
                lab.public_fixture_directory = public_fixtures
                try:
                    lab.initialize(pending_limit=1 if ident == "P04" else 1000, permissions=permissions,
                                   owner_account_id="bob" if ident in ("P09", "R10") else "alice",
                                   join_candidate=ident.startswith("J"),
                                   device_candidates=ident.startswith(("D", "X", "S")) or ident == "F11")
                    run_case(lab)
                    record["status"] = "PASS"
                    print(f"PASS {ident} {name}", flush=True)
                except Exception as error:
                    record.update(status="FAIL", error=str(error))
                    stderr = lab.directory / "relay.stderr.log"
                    if stderr.exists():
                        saved = output / "runs" / f"{report['run_id']}-{ident}-relay.stderr.log"
                        shutil.copy2(stderr, saved)
                        record["relay_stderr_path"] = str(saved)
                    raise
                finally:
                    lab.close()
                    if hasattr(lab, "case_evidence"):
                        record["evidence"] = lab.case_evidence
                    report["process_count"] += lab.process_count
                    report["http_request_count"] += lab.http_count
                    write_report(report_path, report)
        report["source_sha256_after"] = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                         for name in report["source_sha256"]}
        report["binary_sha256_after"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        if (report["source_sha256_after"] != report["source_sha256"]
                or report["binary_sha256_after"] != report["binary_sha256"]):
            raise RuntimeError("运行期间源码或Rust程序变化；本轮不能验收")
        report["status"] = "PASS"
    except Exception as error:
        report.update(status="FAIL", error=str(error))
        print(f"FAIL network: {error}", file=sys.stderr)
    finally:
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        write_report(report_path, report)
    print(f"{report['status']} {len(report['cases'])} 个增量场景；完整阶段0验收仍未完成")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
