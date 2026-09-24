"""迁移的原消息可用性、短期授权、当前权限与已知撤销边界。"""

import time

from .fixture import ACCOUNTS, check, identity
from .history_cases import publish, receive_record
from .migration_cases import export, get, joined, prepared, request, selection, statement, submit, transfer_count
from .permission_cases import prepare, reject_unchanged
from .permission_recovery_cases import accept, close, recover


def availability(lab):
    old = joined(lab, 2)
    batch = prepared(lab, "whole_selection_required", old)
    lab.control("set_availability", acceptance_id=old[1][1]["acceptance_id"], availability="deleted")
    check(submit(lab, batch, expected=403)["code"] == "history_unavailable"
          and transfer_count(lab) == 0, "部分原消息不可用时静默缩小了选择或保存半个迁移")
    first = prepared(lab, "available_before_expiry", old[:1])
    submit(lab, first)
    lab.control("set_availability", acceptance_id=old[0][1]["acceptance_id"], availability="expired")
    lab.restart()
    check(get(lab, "available_before_expiry", expected=403)["code"] == "history_unavailable", "过期后仍领取旧迁移")
    check(submit(lab, first, expected=403)["code"] == "history_unavailable", "精确提交重试绕过原消息可用性")
    check(lab.rust("b2", "history_inspect")["imported_count"] == 0, "未领取迁移却出现历史副本")


def cancel_and_expire(lab):
    old = joined(lab)
    bundle = prepared(lab, "cancel_local_history", old)
    accepted = submit(lab, bundle)
    cancelled = lab.rust("b2", "history_cancel", transfer_id="cancel_local_history")
    check(cancelled["status"] == "cancelled" and not cancelled["duplicate"], "未记录本地取消终态")
    check(lab.rust("b2", "history_cancel", transfer_id="cancel_local_history")["duplicate"], "取消重复创建终态")
    reject_unchanged(lab, "b2", "history_import", **accepted)
    reject_unchanged(lab, "b2", "history_request", transfer_id="cancel_local_history", source=identity("b1"), selection=selection(old))
    # 一秒短授权；允许已保存成功包先导入，再证明到期后的精确重试也被拒绝。
    expiring = prepared(lab, "short_history", old, validity_secs=2)
    ready = submit(lab, expiring)
    lab.rust("b2", "history_import", **ready)
    expires = int(statement(expiring["request"])["expires_at_unix_secs"])
    time.sleep(max(0, expires - time.time()) + 0.02)
    for device, operation, fields in (("b1", "history_export", {"request": expiring["request"]}),
                                      ("b2", "history_import", ready)):
        check(reject_unchanged(lab, device, operation, **fields)["code"] == "history_expired", "已成功精确重试绕过请求期限")
    submit(lab, expiring, expected=409)
    get(lab, "short_history", expected=409)
    check(lab.rust("b2", "history_inspect")["imported_count"] == 1, "到期追溯删除了已经导入的副本")
    fresh = submit(lab, prepared(lab, "fresh_after_expiry", old))
    check(lab.rust("b2", "history_import", **fresh)["imported_count"] == 0, "新授权重放已导入原消息未去重")


def current_checkpoint(lab):
    old = joined(lab)
    bundle = prepared(lab, "before_checkpoint_change", old)
    accepted = submit(lab, bundle)
    removal = accept(lab, prepare(lab, "migration_cp_advance")["change"])
    submit(lab, bundle, expected=409)
    get(lab, "before_checkpoint_change", expected=409)
    recover(lab, removal, "a1", "a2", "b1", "b2")
    reject_unchanged(lab, "b1", "history_export", request=bundle["request"])
    reject_unchanged(lab, "b2", "history_import", **accepted)
    current = submit(lab, prepared(lab, "current_checkpoint_history", old))
    check(lab.rust("b2", "history_import", **current)["imported_count"] == 1, "当前有效检查点下无法重新请求合法历史")
    # 当前本机权限意图也必须完成，不能凭旧可用密钥先导出。
    prepare(lab, "block_source_export", {"kind": "revoke_device", "account_id": "bob", "device_id": "b2"}, "b1")
    fresh_request = request(lab, "after_checkpoint_change", old)["request"]
    check(reject_unchanged(lab, "b1", "history_export", request=fresh_request)["code"] == "permission_pending",
          "未完成权限意图仍允许迁移")
    closed = close(lab, lab.rust("b1", "permission_close_request"), "b1")
    recover(lab, closed, "b1")
    # 取消目标端请求只做私钥清理，不替代源端尚未完成的权限操作。
    lab.rust("b2", "history_cancel", transfer_id="after_checkpoint_change")
    check(lab.rust("b2", "history_inspect")["imported_count"] == 1, "失败迁移改变了已有副本")


def revoke(lab, device, actor):
    old = joined(lab)
    bundle = prepared(lab, "before_device_revoked", old)
    accepted = submit(lab, bundle)
    change = prepare(lab, "revoke_migration_" + device,
                     {"kind": "revoke_device", **identity(device)}, actor)
    removal = accept(lab, change["change"], actor)
    recover(lab, removal, *ACCOUNTS, "b2")
    lab.restart()
    submit(lab, bundle, expected=403)
    get(lab, "before_device_revoked", expected=403)
    reject_unchanged(lab, "b1", "history_export", request=bundle["request"])
    reject_unchanged(lab, "b2", "history_import", **accepted)
    check(lab.rust("b2", "history_cancel", transfer_id="before_device_revoked")["status"] == "cancelled",
          "已知失权阻止了目标本地清理待迁移私钥")
    check(lab.rust("b2", "history_inspect")["imported_count"] == 0, "已撤销端通过迁移恢复历史访问")
    receiver = "b1" if device == "b2" else "b2"
    receive_record(lab, receiver, publish(lab, "remaining_after_migration_revocation"))


def source_revoked(lab):
    revoke(lab, "b1", "b2")


def target_revoked(lab):
    revoke(lab, "b2", "b1")
