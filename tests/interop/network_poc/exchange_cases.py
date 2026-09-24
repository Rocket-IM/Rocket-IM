"""Q02 公开证据交换：实际持有端签署导出，离线文件只承载公开材料。"""

import base64
import copy
import hashlib
import json

from .consistency_cases import (accepted_witness, assert_status, blocked, current_head,
                                mutate_bytes, observe, send)
from .fixture import CONVERSATION, SERVICE, check, identity
from .permission_cases import prepare, reject_unchanged
from .permission_recovery_cases import accept, recover


def fingerprint(lab, device):
    return hashlib.sha256(base64.b64decode(lab.public[device]["signature_key"])).hexdigest()


def begin(lab, source="a2", target="b1", **options):
    return lab.rust(target, "consistency_exchange_begin", source=identity(source),
                    verified_fingerprint=fingerprint(lab, source),
                    verification="synthetic_local", **options)


def export(lab, request, change_id, source="a2", **options):
    return lab.rust(source, "consistency_exchange_export", request=request,
                    change_id=change_id, **options)


def inspect(lab, target="b1"):
    return lab.rust(target, "consistency_exchange_inspect")


def offline_copy(lab, record, filename):
    """合成控制器的本机文件交付，不宣称生产独立渠道或人工核验已完成。"""
    path = lab.directory / filename
    original = json.dumps(record, separators=(",", ":")).encode()
    path.write_bytes(original)
    check(path.read_bytes() == original, "离线文件改变了 SignedRecord 原始字段")
    return json.loads(path.read_bytes())


def statement(record):
    return json.loads(base64.b64decode(record["statement_bytes"]))


def replace_statement(record, **fields):
    bad = copy.deepcopy(record)
    bad["statement_bytes"] = base64.b64encode(
        json.dumps({**statement(record), **fields}).encode()).decode()
    return bad


def branches(lab):
    left = accept(lab, prepare(lab, "exchange_left")["change"])
    right = accepted_witness(lab, prepare(lab, "exchange_right", device="a2")["change"])
    recover(lab, left, "a1", "b1")
    recover(lab, right, "a2")
    check(lab.rust("b1", "permission_inspect")["checkpoint"]["crypto_state_ref"]
          != lab.rust("a2", "permission_inspect")["checkpoint"]["crypto_state_ref"],
          "两端必须实际拥有不同 MLS 后继")
    return left, right


def same_branch(lab, change_id="exchange_same"):
    record = accept(lab, prepare(lab, change_id)["change"])
    recover(lab, record, "a1", "a2", "b1")
    return record


def matching_and_retry(lab):
    record = same_branch(lab)
    before = lab.rust("b1", "wire_inspect")
    request = begin(lab)["request"]
    retried = begin(lab)
    check(retried["reused"] and retried["request"] == request, "重启后请求必须复用原字节")
    active = inspect(lab)["active"]
    check(active["verification"] == "synthetic_local", "合成自动化不能冒充人工核验")
    check(active["source_fingerprint"] == fingerprint(lab, "a2")
          and active["target_fingerprint"] == fingerprint(lab, "b1"), "指纹没有绑定双端公钥")
    blocked(lab)
    http_before = lab.http_count
    lab.stop()
    public_request = offline_copy(lab, request, "exchange-request.json")
    package = export(lab, public_request, "exchange_same")["package"]
    reused = export(lab, public_request, "exchange_same")
    check(reused["reused"] and reused["package"] == package, "源端重复导出改变了签名原字节")
    public = statement(package)
    check(set(public) == {"protocol_version", "service_id", "conversation_id", "source", "target",
                          "challenge", "request_sha256", "predecessor", "record"},
          "公开交换包出现契约外字段")
    check(public["service_id"] == SERVICE and public["conversation_id"] == CONVERSATION
          and public["source"] == identity("a2") and public["target"] == identity("b1")
          and public["predecessor"] == lab.checkpoint and public["record"] == record,
          "公开交换包没有使用实际持有端的原始完整证明")
    delivered = offline_copy(lab, package, "exchange-package.json")
    result = lab.rust("b1", "consistency_exchange_import", package=delivered)
    check(result["outcome"] == "matched" and not result["duplicate"], "同支证据未明确匹配")
    assert_status(lab, "no_known_conflict")
    check(lab.rust("b1", "wire_inspect") == before, "公开证据导入修改了 MLS 或消息状态")
    check(lab.http_count == http_before, "离线交换依赖 Service HTTP 入口")
    send(lab)
    next_request = begin(lab)["request"]
    check(next_request != request, "新交换错误复用已经消费的挑战")
    retry = lab.rust("b1", "consistency_exchange_import", package=delivered)
    check(retry["duplicate"] and retry["consistency"]["checking"], "旧包重试消费了后来检查闸")
    blocked(lab)
    lab.rust("b1", "consistency_exchange_cancel")
    lab.start()
    observe(lab, current_head(lab))
    send(lab, logical="exchange_after_retry")


def actual_holder_fork(lab):
    branches(lab)
    assert_status(lab, "no_known_conflict")
    assert_status(lab, "no_known_conflict", "a2")
    send(lab)
    send(lab, "a2")
    before = lab.rust("b1", "permission_inspect")
    wire_before = lab.rust("b1", "wire_inspect")
    request = begin(lab)["request"]
    package = export(lab, offline_copy(lab, request, "fork-request.json"), "exchange_right")["package"]
    result = lab.rust("b1", "consistency_exchange_import",
                      package=offline_copy(lab, package, "holder-fork-package.json"))
    check(result["outcome"] == "fork_detected", "实际持有端冲突证明未交给 Q02 检测")
    assert_status(lab, "fork_detected")
    check(lab.rust("b1", "permission_inspect") == before
          and lab.rust("b1", "wire_inspect") == wire_before, "对照导入改写了 MLS、群权或历史授权")
    blocked(lab)
    lab.restart()
    blocked(lab)
    lab.rust("b1", "consistency_exchange_import", package=package)
    lab.rust("b1", "consistency_resume", head=current_head(lab))
    assert_status(lab, "fork_detected")
    blocked(lab)


def tampering_and_context(lab):
    same_branch(lab)
    request = begin(lab)["request"]
    for field in ("statement_bytes", "signature_bytes"):
        bad = copy.deepcopy(request)
        bad[field] = mutate_bytes(bad[field])
        reject_unchanged(lab, "a2", "consistency_exchange_export", request=bad, change_id="exchange_same")
    reject_unchanged(lab, "a1", "consistency_exchange_export", request=request, change_id="exchange_same")
    package = export(lab, request, "exchange_same")["package"]
    for field in ("statement_bytes", "signature_bytes"):
        bad = copy.deepcopy(package)
        bad[field] = mutate_bytes(bad[field])
        reject_unchanged(lab, "b1", "consistency_exchange_import", package=bad)
    for field, value in (("service_id", "other-service"), ("conversation_id", "other-group"),
                         ("source", identity("a1")), ("target", identity("a1")),
                         ("request_sha256", "0" * 64), ("challenge", "0" * 64)):
        reject_unchanged(lab, "b1", "consistency_exchange_import",
                         package=replace_statement(package, **{field: value}))
    other_request = begin(lab, target="a1")["request"]
    other_package = export(lab, other_request, "exchange_same")["package"]
    reject_unchanged(lab, "b1", "consistency_exchange_import", package=other_package)
    reject_unchanged(lab, "b1", "consistency_exchange_import", package=request)
    blocked(lab)
    result = lab.rust("b1", "consistency_exchange_import", package=package)
    check(result["outcome"] == "matched", "拒绝伪造材料消耗了合法交换")


def source_possession(lab):
    change = prepare(lab, "source_actual_record")["change"]
    record = accept(lab, change)
    request = begin(lab, source="a1")["request"]
    reject_unchanged(lab, "a1", "consistency_exchange_export", request=request,
                     change_id="source_actual_record")
    recover(lab, record, "a1", "b1")
    reject_unchanged(lab, "a1", "consistency_exchange_export", request=request, change_id="never_held")
    package = export(lab, request, "source_actual_record", source="a1")["package"]
    reject_unchanged(lab, "a1", "consistency_exchange_export", request=request, change_id="different_record")
    result = lab.rust("b1", "consistency_exchange_import", package=package)
    check(result["outcome"] == "matched", "R1 真正保存公开证明后不能正常交换")
