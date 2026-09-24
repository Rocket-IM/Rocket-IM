"""授权原字节、旧范围与恶意签页的独立边界验收。"""

import base64
import copy
import hashlib

from .fixture import SERVICE, check
from .rebuild_fixture import changed_bytes
from .rebuild_sync_cases import empty, wire
from .rebuild_sync_fixture import page_value, statement


def rejected(lab, baseline, operation, **fields):
    if operation not in ("rebuild_stream_bind", "rebuild_stream_download"):
        lab.restore_negative_baseline(baseline)
    before = lab.snapshot("successor").read_bytes()
    error = lab.rust("successor", operation, expected_exit=1, **fields)
    check(error["code"] not in ("anchor_paused", "anchor_conflict")
          and lab.snapshot("successor").read_bytes() == before,
          "前次锚暂停遮盖校验，或坏输入修改快照")
    return error["code"]


def before_welcome(lab):
    lab.join_http(apply_welcome=False)
    result = lab.registration_request(expected_exit=1)
    check(result["code"] == "rebuild_quarantined", "未实际消费Welcome的候选未被隔离门禁拒绝：" + result["code"])


def http_authorization(lab):
    lab.ready()
    request = lab.request_page()["request"]
    codes = {}
    for alias in ("a1", "source_twin", "source_peer"):
        for endpoint, fields in (("register_rebuild_stream", {"registration": lab.registration}),
                                  ("pull_rebuild_events", {"request": request})):
            error = lab.http(alias, endpoint, {"service_id": SERVICE, **fields}, expected=403)
            check(error["code"] == "rebuild_stream_denied", "错设备或旧凭证越过固定重建信任")
            codes[alias + "." + endpoint] = error["code"]
    lab.http("successor", "register_rebuild_stream", {"service_id": "other_service",
             "registration": lab.registration}, expected=403)
    lab.http("successor", "pull_rebuild_events", {"service_id": "other_service", "request": request}, expected=409)
    check(lab.register_http()["binding"] == lab.binding, "失败授权改写原绑定")
    lab.download(lab.http_page(request)); lab.process_page(); empty(wire(lab))
    lab.evidence["HTTP_wrong_credentials"] = codes


def registration_evidence(lab):
    lab.join_http(); lab.registration_request()
    variants = {}
    for field in ("request", "approval", "anchor_response"):
        bad = copy.deepcopy(lab.registration)
        bad[field]["signature_bytes"] = changed_bytes(bad[field]["signature_bytes"])
        variants[field + ".signature"] = bad
    for field in ("old_scope", "successor_scope"):
        for name in ("service", "account", "device", "identity_key", "store_id"):
            bad = copy.deepcopy(lab.registration)
            bad["plan"][field][name] = "ab" * 32 if name in ("identity_key", "store_id") else "other"
            variants["plan." + field + "." + name] = bad
    bad = copy.deepcopy(lab.registration)
    bad["join_record"]["receipt"]["signature_bytes"] = changed_bytes(bad["join_record"]["receipt"]["signature_bytes"])
    variants["join_record.receipt"] = bad
    errors = {}
    for name, bad in variants.items():
        error = lab.register_http(bad, expected=(400, 403, 409))
        errors[name] = error["code"]
    lab.register_http(); lab.bind(); lab.publish("after_bad_registration"); lab.sync()
    check(wire(lab)["inbox_count"] == 1, "坏证据占用了唯一有效流")
    lab.evidence["registration_rejections"] = errors


def binding_fields(lab):
    lab.join_http(); lab.registration_request(); lab.register_http()
    baseline = lab.negative_baseline()
    original = statement(lab.binding)
    mutations = {field: "ab" * 32 for field in ("request_sha256", "plan_sha256", "join_proof_sha256", "stream_id")}
    mutations["conversation_id"] = "G1"
    errors = {}
    for field, value in mutations.items():
        changed = copy.deepcopy(original); changed[field] = value
        errors[field] = rejected(lab, baseline, "rebuild_stream_bind", binding=lab.sign_statement(changed))
    for field in ("service", "account", "device", "identity_key", "store_id"):
        changed = copy.deepcopy(original)
        changed["successor_scope"][field] = "cd" * 32 if field in ("identity_key", "store_id") else "other"
        errors["scope." + field] = rejected(lab, baseline, "rebuild_stream_bind", binding=lab.sign_statement(changed))
    bad = copy.deepcopy(lab.binding); bad["signature_bytes"] = changed_bytes(bad["signature_bytes"])
    errors["signature"] = rejected(lab, baseline, "rebuild_stream_bind", binding=bad)
    lab.bind(); empty(wire(lab))
    lab.evidence["binding_rejections"] = errors


def old_stream(lab):
    lab.ready()
    baseline = lab.negative_baseline()
    check(rejected(lab, baseline, "wire_download", **lab.old_page) == "rebuild_sync_unavailable",
          "原普通下载入口重新放开")
    lab.restore_negative_baseline(baseline)
    error = lab.http("successor", "pull_events", {"service_id": SERVICE, "after_seq": "1",
                    "stream_id": lab.old_page["stream_id"], "limit": "3"}, expected=403)
    check(error["code"] == "rebuild_stream_denied", "旧HTTP流允许后继继承游标")
    page = lab.next_page()
    baseline = lab.negative_baseline("signed-old")
    old = copy.deepcopy(lab.old_page)
    new_stream = page_value(page)["stream_id"]
    old["stream_id"] = new_stream
    old["events"][0]["stream_id"] = new_stream
    signed = lab.signed_page(page, old)
    check(rejected(lab, baseline, "rebuild_stream_download", **signed) == "rebuild_stream_scope",
          "Service签页把旧G1消息导入新流")
    lab.download(page); lab.process_page(); empty(wire(lab))
    lab.evidence["old_stream"] = "旧非零游标、G1真实密文、普通HTTP/CLI入口均不能迁入"


def page_fields(lab):
    lab.ready(); lab.publish("page_binding")
    page = lab.next_page(); baseline = lab.negative_baseline()
    original = statement(page["receipt"])
    mutations = {field: "ab" * 32 for field in ("binding_sha256", "request_sha256", "stream_id", "challenge", "page_sha256")}
    mutations.update(service_id="other", conversation_id="G1", after_seq="1", limit="4")
    codes = {}
    for field, value in mutations.items():
        changed = copy.deepcopy(original); changed[field] = value
        if field == "service_id":
            changed["successor_scope"]["service"] = value
        codes[field] = rejected(lab, baseline, "rebuild_stream_download", page_bytes=page["page_bytes"],
                               receipt=lab.sign_statement(changed))
    for field in ("service", "account", "device", "identity_key", "store_id"):
        changed = copy.deepcopy(original)
        changed["successor_scope"][field] = "cd" * 32 if field in ("identity_key", "store_id") else "other"
        if field == "service":
            changed["service_id"] = changed["successor_scope"][field]
        codes["scope." + field] = rejected(lab, baseline, "rebuild_stream_download", page_bytes=page["page_bytes"],
                                         receipt=lab.sign_statement(changed))
    bad = copy.deepcopy(page); bad["receipt"]["signature_bytes"] = changed_bytes(bad["receipt"]["signature_bytes"])
    codes["signature"] = rejected(lab, baseline, "rebuild_stream_download", **bad)
    bad = copy.deepcopy(page); bad["page_bytes"] = changed_bytes(bad["page_bytes"])
    codes["page_bytes"] = rejected(lab, baseline, "rebuild_stream_download", **bad)
    lab.download(page); lab.process_page()
    check(wire(lab)["inbox_count"] == 1, "坏页抢占去重或游标")
    lab.evidence["page_rejections"] = codes


def message_origin(lab):
    lab.ready(); lab.publish("real_origin")
    page = lab.next_page(); value = page_value(page); baseline = lab.negative_baseline()
    variants = {}
    bad = copy.deepcopy(value); del bad["events"][0]["event"]["acceptance_receipt"]
    variants["missing_acceptance"] = bad
    bad = copy.deepcopy(value); bad["events"][0]["event"]["acceptance_id"] = "wrong_accepted"
    variants["different_acceptance"] = bad
    bad = copy.deepcopy(value)
    envelope = bad["events"][0]["event"]["envelope"]
    envelope["payload_bytes"] = changed_bytes(envelope["payload_bytes"])
    variants["different_ciphertext"] = bad
    codes = {name: rejected(lab, baseline, "rebuild_stream_download", **lab.signed_page(page, bad))
             for name, bad in variants.items()}
    check(all(code == "rebuild_stream_acceptance" for code in codes.values()), "真Service签页替代了原消息接受验证")
    lab.download(page); lab.process_page()
    check(wire(lab)["inbox_count"] == 1, "坏消息页影响原有效消息")
    lab.evidence["signed_malicious_page"] = codes


def no_unsigned_or_unanchored(lab):
    lab.ready(); page = lab.next_page()
    baseline = lab.negative_baseline()
    check(rejected(lab, baseline, "wire_download", **page_value(page)) == "rebuild_sync_unavailable",
          "有效签页被拆成普通页后仍获许可")
    lab.restore_negative_baseline(baseline)
    del lab.configs["successor"]
    error = lab.blocked("successor", "rebuild_stream_pull", limit="3")
    check(error["code"] == "rebuild_anchor_required", "失去可信锚配置后仍能驱动新流")


def cancel(lab):
    lab.ready(); lab.publish("cancelled"); page = lab.next_page()
    active = lab.backup("before-cancel-complete-client", lab.directory / "successor")
    lab.rust("a1", "anchor_rebuild_cancel", plan=lab.plan, approval=lab.approval)
    # 服务器只持历史link事实；它不被当作在线取消状态源。
    check(lab.register_http()["binding"] == lab.binding, "历史登记事实被无依据当成实时取消状态")
    codes = {}
    for operation, fields in (("rebuild_stream_bind", {"binding": lab.binding}),
        ("rebuild_stream_pull", {"limit": "3"}), ("rebuild_stream_download", page), ("wire_process", {})):
        # 只恢复取消前本机完整副本，可信锚保持已取消；每次实际到达锚，避免旧gate遮盖。
        lab.restore(active, lab.directory / "successor")
        error = lab.blocked("successor", operation, **fields)
        check(error["code"] == "anchor_conflict", "已取消后继未由实时独立锚拒绝：" + error["code"])
        codes[operation] = error["code"]
    check(lab.rust("successor", "anchor_inspect")["status"] == "cancelled", "独立锚没有永久取消诊断")
    check(lab.blocked("successor", "anchor_resume")["code"] == "anchor_sealed", "已取消后继恢复未明确拒绝")
    lab.evidence["cancellation"] = {"HTTP": "历史授权仍可读", "local_copy_restore": "当前独立锚永久阻断", "errors": codes}


def bounded_page(lab):
    lab.ready(); page = lab.next_page(); baseline = lab.negative_baseline()
    oversized = base64.b64encode(b" " * (740 * 1024 + 1)).decode()
    code = rejected(lab, baseline, "rebuild_stream_download", page_bytes=oversized, receipt=page["receipt"])
    raw = base64.b64decode(page["page_bytes"]).ljust(740 * 1024, b" ")
    claims = statement(page["receipt"]); claims["page_sha256"] = hashlib.sha256(raw).hexdigest()
    lab.download({"page_bytes": base64.b64encode(raw).decode(), "receipt": lab.sign_statement(claims)})
    lab.process_page(); empty(wire(lab))
    lab.evidence["bounded_page"] = {"accepted_raw_bytes": len(raw), "rejected_raw_bytes": 740 * 1024 + 1,
                                    "error": code, "snapshot_unchanged_on_rejection": True}


def paused_state(lab, kind):
    lab.ready(); request = lab.request_page()["request"]; page = lab.http_page(request)
    checkpoint = lab.rust("successor", "permission_inspect")["checkpoint"]
    inspect_operation = "permission_inspect"
    action = {"kind": "remove_member", "account_id": "bob"}
    if kind == "checking":
        lab.rust("successor", "consistency_challenge")
        inspect_operation = "consistency_inspect"
    elif kind == "permission_pending":
        lab.rust("successor", "permission_prepare", change_id="new_stream_pending", action=action)
    elif kind == "fork":
        left = lab.rust("successor", "permission_prepare", change_id="new_stream_left", action=action)
        right = lab.rust("source", "permission_prepare", change_id="new_stream_right", action=action)
        # 故障Service对同前驱双签接受；普通HTTP权限事务不声称会产生这种分叉。
        left_record, right_record = lab.accepted(left["change"]), lab.accepted(right["change"])
        lab.rust("successor", "permission_recover", record=left_record)
        lab.rust("source", "permission_recover", record=right_record)
        lab.rust("successor", "consistency_challenge")
        lab.rust("successor", "consistency_observe_fork", predecessor=checkpoint,
                 left=left_record, right=right_record)
        inspect_operation = "consistency_inspect"
        lab.evidence["fork_source"] = "真实设备双提案、fixture Service故障双签；非HTTP合法双接受"
    else:
        change = lab.rust("source", "permission_prepare", change_id="revoke_rebuilt",
            action={"kind": "revoke_device", **lab.identities["successor"]})
        accepted = lab.http("source", "submit_permission_change", {"service_id": SERVICE,
                            "conversation_id": "G2", "change": change["change"]})
        record = {"change": change["change"], "receipt": accepted["receipt"]}
        lab.rust("source", "permission_recover", record=record)
        lab.rust("successor", "permission_recover", record=record)
        lab.register_http(expected=403)
        lab.http_page(request, expected=403)
    prior = lab.rust("successor", inspect_operation)
    if kind == "checking":
        check(prior["checking"] and prior["paused"], "没有保存真实checking闸")
    elif kind == "fork":
        check(prior["status"] == "fork_detected" and prior["fork_evidence_count"] > 0, "未保存真实双签分叉")
    elif kind == "permission_pending":
        check(prior["pending_change"] is not None, "没有保存权限候选")
    else:
        check(prior["recovery_status"] == "access_removed", "没有实际消费撤销记录")
    before = lab.snapshot("successor").read_bytes()
    for operation, fields in (("rebuild_stream_pull", {"limit": "3"}),
                               ("rebuild_stream_bind", {"binding": lab.binding}), ("rebuild_stream_download", page)):
        error = lab.rust("successor", operation, expected_exit=1, **fields)
        check(error["code"] in ("rebuild_consistency", "rebuild_permission"), "同步入口绕过真实前置暂停：" + error["code"])
        check(lab.snapshot("successor").read_bytes() == before, "同步入口清除了真实安全状态")
    check(lab.rust("successor", inspect_operation) == prior, "已有暂停状态或证据被新同步清除")
    lab.evidence["preserved_pause"] = {"kind": kind, "state": prior}
