"""重建前已有真实权限和 Q02 暂停；不直接篡改加密快照。"""

from .fixture import check


def pause_state(lab, kind, *, source=False):
    device, twin = ("source", "source_twin") if source else ("a1", "a2")
    checkpoint = lab.trust["checkpoint"] if source else lab.old_checkpoint
    if kind == "checking":
        lab.rust(device, "consistency_challenge")
        operation = "consistency_inspect"
    elif kind == "permission":
        action = {"kind": "remove_member", "account_id": "bob" if source else "charlie"}
        lab.rust(device, "permission_prepare", change_id="pending_before_rebuild", action=action)
        operation = "permission_inspect"
    elif kind == "fork":
        action = {"kind": "remove_member", "account_id": "bob" if source else "charlie"}
        left = lab.rust(device, "permission_prepare", change_id="left_before_rebuild", action=action)
        right = lab.rust(twin, "permission_prepare", change_id="right_before_rebuild", action=action)
        left_record, right_record = lab.accepted(left["change"]), lab.accepted(right["change"])
        lab.rust(device, "permission_recover", record=left_record)
        lab.rust(twin, "permission_recover", record=right_record)
        lab.rust(device, "consistency_challenge")
        lab.rust(device, "consistency_observe_fork", predecessor=checkpoint,
                 left=left_record, right=right_record)
        operation = "consistency_inspect"
    else:
        action = {"kind": "revoke_device", "account_id": "alice",
                  "device_id": lab.identities[device]["device_id"]}
        change = lab.rust(twin, "permission_prepare", change_id="revoke_before_rebuild", action=action)
        record = lab.accepted(change["change"])
        lab.rust(twin, "permission_recover", record=record)
        lab.rust(device, "permission_recover", record=record)
        operation = "permission_inspect"
    state = lab.rust(device, operation)
    if kind == "fork":
        check(state["status"] == "fork_detected" and state["fork_evidence_count"] > 0,
              "装置未保存真实同前驱双签分叉证据")
    elif kind == "access_removed":
        check(state["recovery_status"] == "access_removed", "装置未实际撤销目标身份")
    elif kind == "checking":
        check(state["checking"] and state["paused"], "装置未实际保存 Q02 检查闸")
    else:
        check(state["pending_change"] is not None, "装置未实际保存权限候选")
    return operation, state
