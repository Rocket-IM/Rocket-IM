"""原消息终态投影与追加通知；所有操作共享调用方的显式事务。"""

from contract import ProtocolError
from storage import Store


def set_availability(db, acceptance_id, availability):
    """仅首次终态改变原投影；当前有权的原消息槽各获一次增量通知。"""
    if availability not in {"deleted", "expired"}:
        raise ProtocolError("invalid_envelope", "只支持不可逆的过期/删除投影")
    attempt = db.execute(
        "SELECT attempt_id FROM attempts WHERE acceptance_id=? "
        "AND outcome='accepted' AND availability='available'", (acceptance_id,)
    ).fetchone()
    if attempt is None:
        return
    # 先固定原槽集合：sender 的回执槽、新成员及已移除权限的旧槽都不是通知目标。
    targets = db.execute(
        "SELECT e.account,e.device,e.seq,e.event_id FROM events e "
        "JOIN members m ON m.account=e.account AND m.device=e.device "
        "JOIN devices d ON d.account=e.account AND d.device=e.device "
        "WHERE e.acceptance_id=? AND e.availability='available' "
        "AND json_extract(e.content,'$.type')='message' AND d.revoked=0 "
        "ORDER BY e.account,e.device,e.seq", (acceptance_id,)
    ).fetchall()
    db.execute(
        "UPDATE attempts SET availability=? WHERE acceptance_id=? AND availability='available'",
        (availability, acceptance_id),
    )
    # 保留旧槽原地占位语义；必须在追加前完成，避免同时遮蔽新通知。
    db.execute(
        "UPDATE events SET availability=? WHERE acceptance_id=? AND availability='available'",
        (availability, acceptance_id),
    )
    for target in targets:
        event = {"type": "message_availability", "target_event_seq": str(target["seq"]),
                 "target_event_id": target["event_id"], "acceptance_id": acceptance_id,
                 "attempt_id": attempt["attempt_id"], "availability": availability}
        # 配额不足由调用方回滚整个投影和已追加的部分扇出，不另行提交。
        Store.append_event(db, (target["account"], target["device"]), event, acceptance_id)
