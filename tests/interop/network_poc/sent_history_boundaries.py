"""发送接受记账与历史访问分离；验证保存失败、删除和权限变化。"""

from .fixture import ACCOUNTS, check
from .migration_cases import get, joined, prepared, request, submit, transfer_count
from .migration_faults import durable
from .permission_cases import prepare, reject_unchanged
from .permission_recovery_cases import accept, recover
from .sent_history_cases import ack, accepted_count, attempt, sent


def atomic_acceptance(lab):
    own = sent(lab, "atomic_sent_acceptance", save=False)
    before = lab.rust("b1", "wire_inspect")
    result = durable(lab, "b1", "wire_accept", {"logical_message_id": "atomic_sent_acceptance", "attempt_id": "P1",
                     "acceptance_receipt": own[1]["acceptance_receipt"]})
    check(result["duplicate"] and accepted_count(lab) == 1, "接受证明保存后退出没有恢复原事实")
    after = lab.rust("b1", "wire_inspect")
    check({k: v for k, v in before.items() if k != "accepted_outbox_count"}
          == {k: v for k, v in after.items() if k != "accepted_outbox_count"}, "接受记账修改了密码、队列或游标")
    joined(lab, count=0)
    accepted = submit(lab, prepared(lab, "atomic_sent_copy", [own]))
    result = durable(lab, "b2", "history_import", accepted)
    check(result["duplicate"] and result["imported_count"] == 0
          and lab.rust("b2", "history_inspect")["imported_count"] == 1, "已发送副本的导入恢复未共同保存终态")


def unavailable_original(lab):
    old = [sent(lab, "sent_availability_" + str(i), save=False) for i in range(3)]
    for record in old[:2]:
        ack(lab, record)
    joined(lab, count=0)
    bundle = prepared(lab, "accepted_before_original_expiry", old[:2])
    submit(lab, bundle)
    lab.control("set_availability", acceptance_id=old[1][1]["acceptance_id"], availability="expired")
    check(get(lab, "accepted_before_original_expiry", expected=403)["code"] == "history_unavailable",
          "原发送者绕过整份选择的过期检查")
    submit(lab, bundle, expected=403)
    lab.control("set_availability", acceptance_id=old[2][1]["acceptance_id"], availability="deleted")
    queried = attempt(lab, "sent_availability_2")
    check(queried["outcome"] == "accepted" and queried["availability"] == "deleted"
          and "envelope" not in queried and "payload" not in queried, "删除后查询重新释放原消息载荷")
    ack(lab, (old[2][0], queried))
    blocked = prepared(lab, "deleted_sent_history", old[2:])
    check(submit(lab, blocked, expected=403)["code"] == "history_unavailable" and transfer_count(lab) == 1,
          "保存旧接受事实被误当作恢复删除内容权限")
    check(lab.rust("b2", "history_inspect")["imported_count"] == 0, "未领取迁移却导入了不可用副本")


def acceptance_does_not_restore_access(lab):
    old = [sent(lab, "ack_access_" + str(i), save=False) for i in range(2)]
    joined(lab, count=0)
    requested = request(lab, "before_ack_source_revocation", old)
    prepare(lab, "pending_before_ack", {"kind": "revoke_device", "account_id": "bob", "device_id": "b2"}, "b1")
    before = lab.rust("b1", "permission_inspect")
    ack(lab, old[0])
    check(lab.rust("b1", "permission_inspect") == before, "迟到接受证明解除尚未完成权限意图")
    reject_unchanged(lab, "b1", "wire_send", logical_message_id="while_pending", attempt_id="P1", payload="synthetic")
    reject_unchanged(lab, "b1", "history_export", request=requested["request"])
    change = prepare(lab, "target_revokes_source_before_ack",
                     {"kind": "revoke_device", "account_id": "bob", "device_id": "b1"}, "b2")
    removal = accept(lab, change["change"], "b2")
    recover(lab, removal, *ACCOUNTS, "b2")
    before = lab.rust("b1", "permission_inspect")
    check(before["recovery_status"] == "access_removed", "实验源端未进入已知失权状态")
    ack(lab, old[1])
    check(accepted_count(lab) == 2 and lab.rust("b1", "permission_inspect") == before,
          "补接受事实恢复了失权设备或遗失其他原接受记录")
    attempt(lab, "ack_access_1", expected=403)
    reject_unchanged(lab, "b1", "history_export", request=requested["request"])
    reject_unchanged(lab, "b1", "wire_send", logical_message_id="after_removed", attempt_id="P1", payload="synthetic")
    check(lab.rust("b2", "history_cancel", transfer_id="before_ack_source_revocation")["status"] == "cancelled",
          "源端失权后目标不能清理请求")
