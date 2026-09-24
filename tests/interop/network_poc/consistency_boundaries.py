"""Q02：真实补链冲突、受控退出、权限暂停及历史迁移入口。"""

from .consistency_cases import (accepted_witness, assert_status, begin, blocked, current_head,
                                fork_fixture, inspect, observe, send, sign_head)
from .fixture import check
from .permission_cases import REVOKE_A2, prepare, reject_unchanged
from .permission_recovery_cases import accept, recover


def conflict_during_recovery(lab):
    left = accept(lab, prepare(lab, "actual_left")["change"])
    right = accepted_witness(lab, prepare(lab, "observed_right", device="a2")["change"])
    recover(lab, left, "a1")
    recover(lab, right, "a2")
    right_cp = lab.rust("a2", "permission_inspect")["checkpoint"]
    observe(lab, sign_head(lab, right_cp))
    assert_status(lab, "needs_sync")
    blocked(lab)
    recover(lab, left, "b1")
    check(lab.rust("b1", "permission_inspect")["checkpoint"]
          == lab.rust("a1", "permission_inspect")["checkpoint"],
          "实际成功的 MLS 补链与一致性冲突没有一起保存")
    assert_status(lab, "fork_detected")
    blocked(lab)
    lab.rust("b1", "consistency_resume", head=current_head(lab))
    assert_status(lab, "fork_detected")


def atomic_head_and_resume(lab):
    path = lab.directory / "b1/state.enc"
    before = path.read_bytes()
    for point, code in (("before_save", 83), ("before_rename", 84)):
        lab.rust("b1", "consistency_challenge", failpoint=point, expected_exit=code)
        check(path.read_bytes() == before, "未提交检查会话改变了有效快照")
    lab.rust("b1", "consistency_challenge", failpoint="after_save", expected_exit=85)
    blocked(lab)
    head = current_head(lab)
    for point, code in (("before_save", 83), ("before_rename", 84)):
        observe(lab, head, failpoint=point, expected_exit=code)
        check(inspect(lab)["checking"], "检查结果提交前退出丢掉检查闸")
        blocked(lab)
    observe(lab, head, failpoint="after_save", expected_exit=85)
    assert_status(lab, "no_known_conflict")
    observe(lab, head)
    send(lab)
    record = accept(lab, prepare(lab, "atomic_rollback")["change"])
    recover(lab, record, "a1", "b1")
    old = sign_head(lab, lab.checkpoint)
    for point, code in (("before_save", 83), ("before_rename", 84)):
        observe(lab, old, failpoint=point, expected_exit=code)
        blocked(lab)
        check(inspect(lab)["checking"], "回滚观察保存前退出后允许越过检查")
    observe(lab, old, failpoint="after_save", expected_exit=85)
    assert_status(lab, "rollback_detected")
    blocked(lab)
    head = current_head(lab)
    for point, code in (("before_save", 83), ("before_rename", 84)):
        lab.rust("b1", "consistency_resume", head=head, failpoint=point, expected_exit=code)
        assert_status(lab, "rollback_detected")
        blocked(lab)
    lab.rust("b1", "consistency_resume", head=head, failpoint="after_save", expected_exit=85)
    lab.rust("b1", "consistency_resume", head=head)
    assert_status(lab, "no_known_conflict")
    send(lab, logical="after_atomic_resume")


def atomic_fork(lab):
    left, right, _, _ = fork_fixture(lab)
    begin(lab)
    fields = {"predecessor": lab.checkpoint, "left": left, "right": right}
    for point, code in (("before_save", 83), ("before_rename", 84)):
        lab.rust("b1", "consistency_observe_fork", **fields, failpoint=point, expected_exit=code)
        check(inspect(lab)["checking"], "分叉导入提交前退出没有保留检查闸")
        blocked(lab)
    lab.rust("b1", "consistency_observe_fork", **fields, failpoint="after_save", expected_exit=85)
    lab.rust("b1", "consistency_observe_fork", **fields)
    assert_status(lab, "fork_detected")
    blocked(lab)
    begin(lab)
    lab.rust("b1", "consistency_observe_fork", **fields)
    check(inspect(lab)["checking"], "旧分叉证据精确重试清除了新的检查请求")
    lab.restart()
    assert_status(lab, "fork_detected")
    blocked(lab)


def original_permission_pause(lab):
    first = accept(lab, prepare(lab, "before_pending")["change"])
    recover(lab, first, "a1", "b1")
    pending = prepare(lab, "original_pending", REVOKE_A2)["change"]
    observe(lab, sign_head(lab, lab.checkpoint, "a1"), "a1")
    assert_status(lab, "rollback_detected", "a1")
    blocked(lab, "a1")
    lab.rust("a1", "consistency_resume", head=current_head(lab, "a1"))
    assert_status(lab, "no_known_conflict", "a1")
    state = lab.rust("a1", "permission_inspect")
    check(state["pending_change"] == pending, "一致性恢复删除了原权限候选")
    error = reject_unchanged(lab, "a1", "wire_send", logical_message_id="still_pending",
                             attempt_id="P1", payload="synthetic-pending")
    check(error["code"] == "permission_pending", "Q02 恢复错误解除原权限暂停")
    second = accept(lab, pending)
    recover(lab, second, "a1", "b1")
    send(lab, "a1")


def cached_crypto_guards(lab):
    from .fixture import ACCOUNTS, identity
    from .migration_cases import export, joined, request, selection, submit

    records = joined(lab)
    requested = request(lab, "q02_cached_transfer", records)
    bundle = export(lab, requested["request"])
    accepted = submit(lab, bundle)
    cached_message = send(lab, logical="q02_cached_message")
    before = lab.rust("b1", "wire_inspect")
    begin(lab)
    begin(lab, "b2")
    begin(lab, "a1")
    original_peers = [{"account": ACCOUNTS[d], "device": d,
                       "signature_key": lab.public[d]["signature_key"],
                       "key_package": lab.public[d]["key_package"]} for d in ("a2", "b1", "c1")]
    candidate = {"change_id": "paused_add", "member": {**identity("a3"),
                  "signature_key": lab.public["a3"]["signature_key"]},
                 "key_package": lab.public["a3"]["key_package"], "history_policy": "from_join"}
    operations = [
        ("a1", "create", {"peers": original_peers}),
        ("b1", "wire_send", {"logical_message_id": "q02_cached_message", "attempt_id": "P1",
                             "payload": "synthetic-consistency-q02_cached_message"}),
        ("b1", "send", {"id": "legacy_send", "payload": "synthetic-legacy"}),
        ("b1", "permission_prepare", {"change_id": "paused_revoke", "action": REVOKE_A2}),
        ("a1", "permission_prepare_add", candidate),
        ("a1", "permission_prepare_device", candidate),
        ("b1", "history_export", {"request": requested["request"]}),
        ("b2", "history_request", {"transfer_id": "q02_cached_transfer", "source": identity("b1"),
                                    "selection": selection(records)}),
        ("b2", "history_import", accepted),
    ]
    # 请求参数与原记录完全相同，防止先命中缓存后绕过检查闸。
    for device, operation, fields in operations:
        error = reject_unchanged(lab, device, operation, **fields)
        check(error["code"] == "consistency_paused", operation + " 绕过了检查闸")
    check(lab.rust("b1", "wire_inspect") == before, "拒绝操作改变密码/发送状态")
    # 已有接受事实仍可记账；不会生成新密文或解除检查闸。
    acceptance = lab.submit(cached_message, device="b1")
    lab.rust("b1", "wire_accept", logical_message_id="q02_cached_message", attempt_id="P1",
             acceptance_receipt=acceptance["acceptance_receipt"])
    blocked(lab)
    observe(lab, current_head(lab))
    observe(lab, current_head(lab, "b2"), "b2")
    result = lab.rust("b2", "history_import", **accepted)
    check(result["imported_count"] == 1, "检查结束后有效历史材料被消耗或丢失")


def history_is_not_rollback(lab):
    from .history_cases import publish, receive_record

    old_message = publish(lab, "q02_legitimate_old")
    first = accept(lab, prepare(lab, "history_first")["change"])
    recover(lab, first, "a1", "b1")
    second = accept(lab, prepare(lab, "history_second", REVOKE_A2)["change"])
    recover(lab, second, "a1", "b1")
    observe(lab, current_head(lab))
    # 历史接受记录和旧 epoch 密文明确不是 Service 声称的当前 head。
    recover(lab, first, "b1")
    receive_record(lab, "b1", old_message)
    assert_status(lab, "no_known_conflict")
    send(lab)
