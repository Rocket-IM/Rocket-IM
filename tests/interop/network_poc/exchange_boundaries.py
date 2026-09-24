"""Q02 交换的信任、覆盖、撤销、取消及大小边界；不读取设备秘密。"""

import base64
import copy

from .consistency_cases import assert_status, blocked, current_head, observe, send
from .exchange_cases import begin, export, fingerprint, inspect, same_branch
from .fixture import check, identity
from .permission_cases import REVOKE_A2, prepare, reject_unchanged
from .permission_recovery_cases import accept, recover


def trust_required(lab):
    common = {"source": identity("a2"), "verified_fingerprint": fingerprint(lab, "a2"),
              "verification": "synthetic_local"}
    for fields in ({**common, "verification": "service_label"},
                   {**common, "verification": "login_authenticated"},
                   {**common, "verified_fingerprint": "0" * 64},
                   {**common, "source": identity("c1")},
                   {**common, "source": identity("b1")}):
        reject_unchanged(lab, "b1", "consistency_exchange_begin", **fields)
    missing = {key: value for key, value in common.items() if key != "verified_fingerprint"}
    reject_unchanged(lab, "b1", "consistency_exchange_begin", **missing)
    lab.rust("d1", "init")
    reject_unchanged(lab, "d1", "consistency_exchange_begin", **common)
    check(inspect(lab)["active"] is None, "无可信引导失败后遗留了活动交换")
    assert_status(lab, "no_known_conflict")
    request = begin(lab)["request"]
    check(inspect(lab)["active"]["source"] == identity("a2"), "明确核验来源未被固定")
    reject_unchanged(lab, "b1", "consistency_exchange_begin", source=identity("a1"),
                     verified_fingerprint=fingerprint(lab, "a1"), verification="synthetic_local")
    check(begin(lab)["request"] == request, "异来源冲突覆盖了原活动交换")


def insufficient_comparison(lab):
    record = accept(lab, prepare(lab, "only_source_has_record")["change"])
    recover(lab, record, "a1", "a2")
    before = lab.rust("b1", "permission_inspect")
    request = begin(lab)["request"]
    package = export(lab, request, "only_source_has_record")["package"]
    result = lab.rust("b1", "consistency_exchange_import", package=package)
    check(result["outcome"] == "insufficient_comparison" and result["consistency"]["checking"],
          "仅源端证明不能冒充本机已有对照或解除检查闸")
    check(lab.rust("b1", "permission_inspect") == before, "缺对照时导入改写了本机群状态")
    blocked(lab)
    retry = lab.rust("b1", "consistency_exchange_import", package=package)
    check(retry["outcome"] == "insufficient_comparison", "重试不能隐式补造本机对照")
    lab.rust("b1", "consistency_exchange_cancel")
    cancelled_retry = lab.rust("b1", "consistency_exchange_import", package=package)
    check(cancelled_retry["duplicate"] and cancelled_retry["consistency"]["checking"],
          "已保存但缺对照的旧包在取消后消费了检查闸")
    recover(lab, record, "b1")
    observe(lab, current_head(lab))
    next_request = begin(lab)["request"]
    old = lab.rust("b1", "consistency_exchange_import", package=package)
    check(old["duplicate"] and old["outcome"] == "insufficient_comparison"
          and old["consistency"]["checking"], "旧缺对照结果重试接管了新交换")
    next_package = export(lab, next_request, "only_source_has_record")["package"]
    result = lab.rust("b1", "consistency_exchange_import", package=next_package)
    check(result["outcome"] == "matched", "真实 R1 补齐后新交换未能完成对照")
    assert_status(lab, "no_known_conflict")
    send(lab)


def missing_predecessor(lab):
    first = accept(lab, prepare(lab, "anchor_first")["change"])
    recover(lab, first, "a1", "a2")
    second = accept(lab, prepare(lab, "anchor_second", REVOKE_A2)["change"])
    recover(lab, second, "a1")
    before = lab.rust("b1", "permission_inspect")
    request = begin(lab, source="a1")["request"]
    package = export(lab, request, "anchor_second", source="a1")["package"]
    error = reject_unchanged(lab, "b1", "consistency_exchange_import", package=package)
    check(error["code"] == "consistency_coverage", "未知前驱不能由源端包自己声明为可信")
    check(lab.rust("b1", "permission_inspect") == before, "未知前驱被插入了本机权限覆盖")
    blocked(lab)
    recover(lab, first, "b1")
    result = lab.rust("b1", "consistency_exchange_import", package=package)
    check(result["outcome"] == "insufficient_comparison", "有前驱仍不等于有同前驱的本机接受证明")
    recover(lab, second, "b1")
    result = lab.rust("b1", "consistency_exchange_import", package=package)
    check(result["outcome"] == "matched", "实际补齐完整链后未能完成对照")
    assert_status(lab, "no_known_conflict")


def known_revoked_source(lab):
    same_branch(lab)
    request = begin(lab)["request"]
    package = export(lab, request, "exchange_same")["package"]
    lab.rust("b1", "consistency_exchange_import", package=package)
    pending_request = begin(lab)["request"]
    pending_package = export(lab, pending_request, "exchange_same")["package"]
    removal = accept(lab, prepare(lab, "exchange_revoke_source", REVOKE_A2)["change"])
    recover(lab, removal, "a1", "b1")
    for evidence in (pending_package, package):
        error = reject_unchanged(lab, "b1", "consistency_exchange_import", package=evidence)
        check(error["code"] == "exchange_trust_required", "已知撤销来源不能靠旧包或精确重试维持信任")
    recover(lab, removal, "a2")
    reject_unchanged(lab, "a2", "consistency_exchange_export", request=request, change_id="exchange_same")
    reject_unchanged(lab, "a2", "consistency_exchange_export", request=pending_request, change_id="exchange_same")
    blocked(lab)
    lab.rust("b1", "consistency_exchange_cancel")
    observe(lab, current_head(lab))
    reject_unchanged(lab, "b1", "consistency_exchange_begin", source=identity("a2"),
                     verified_fingerprint=fingerprint(lab, "a2"), verification="synthetic_local")
    assert_status(lab, "no_known_conflict")
    send(lab, logical="after_known_source_revocation")


def cancellation_and_unreachable(lab):
    same_branch(lab)
    request = begin(lab)["request"]
    package = export(lab, request, "exchange_same")["package"]
    observe(lab, current_head(lab))
    error = reject_unchanged(lab, "b1", "consistency_exchange_import", package=package)
    check(error["code"] == "exchange_challenge_required", "共享挑战被 head 消费后旧交换仍可首次导入")
    error = reject_unchanged(lab, "b1", "consistency_exchange_begin", source=identity("a2"),
                             verified_fingerprint=fingerprint(lab, "a2"), verification="synthetic_local")
    check(error["code"] == "exchange_challenge_required", "失效活动交换接管了新检查闸")
    lab.rust("b1", "consistency_exchange_cancel")
    request = begin(lab)["request"]
    reject_unchanged(lab, "b1", "consistency_exchange_import", package=package)
    check(begin(lab)["request"] == request, "旧交换包改变了重开请求")
    package = export(lab, request, "exchange_same")["package"]
    lab.stop()
    check(begin(lab)["request"] == request, "来源不可达/未送达期间重试改变了请求")
    blocked(lab)
    result = lab.rust("b1", "consistency_exchange_cancel")
    check(result["cancelled"] and not result["duplicate"] and result["consistency"]["checking"],
          "取消交换不能隐式证明一致性或恢复发送")
    check(inspect(lab)["active"] is None and inspect(lab)["freshness"] == "unknown",
          "取消后来源信任或未知边界不明确")
    again = lab.rust("b1", "consistency_exchange_cancel")
    check(again["duplicate"] and again["consistency"]["checking"], "重复取消改变了检查闸")
    reject_unchanged(lab, "b1", "consistency_exchange_import", package=package)
    reject_unchanged(lab, "b1", "consistency_exchange_begin", source=identity("a2"),
                     verified_fingerprint=fingerprint(lab, "a2"), verification="synthetic_local")
    blocked(lab)
    lab.start()
    observe(lab, current_head(lab))
    next_request = begin(lab)["request"]
    check(next_request != request, "取消结束后重开交换复用了旧挑战")
    reject_unchanged(lab, "b1", "consistency_exchange_import", package=package)
    next_package = export(lab, next_request, "exchange_same")["package"]
    result = lab.rust("b1", "consistency_exchange_import", package=next_package)
    check(result["outcome"] == "matched", "取消后新交换不能完成")
    assert_status(lab, "no_known_conflict")


def bounded_inputs(lab):
    same_branch(lab)
    request = begin(lab)["request"]
    package = export(lab, request, "exchange_same")["package"]
    for record, device, operation, size, fields in (
        (request, "a2", "consistency_exchange_export", 16 * 1024 + 1,
         {"change_id": "exchange_same"}),
        (package, "b1", "consistency_exchange_import", 512 * 1024 + 1, {}),
    ):
        bad = copy.deepcopy(record)
        bad["statement_bytes"] = base64.b64encode(b"x" * size).decode()
        argument = "request" if operation.endswith("export") else "package"
        error = reject_unchanged(lab, device, operation, **{argument: bad}, **fields)
        check(error["code"] == "exchange_invalid", "分层交换大小限制未明确拒绝")
    oversized = copy.deepcopy(package)
    oversized["statement_bytes"] = "A" * (1024 * 1024)
    error = reject_unchanged(lab, "b1", "consistency_exchange_import", package=oversized)
    check(error["code"] == "input_limit", "交换路径绕过 CLI 总输入限制")
    blocked(lab)
    result = lab.rust("b1", "consistency_exchange_import", package=package)
    check(result["outcome"] == "matched", "大输入拒绝影响了原有效包")
