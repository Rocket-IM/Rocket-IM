"""旧接受事实查询的满额恢复通道；只回滚到期投影的容量失败。"""

from contract import ProtocolError, validate_envelope
from storage import logical_key
from synchronization import project_expiration


def accepted_retry(store, db, device, operation, req, dispatch):
    if operation not in {"submit_message", "get_attempt", "close_attempt"}:
        return None
    if operation == "submit_message":
        header, _, _ = validate_envelope(req["envelope"])
        service, conversation, logical, attempt = (header[name] for name in ("service_id", "conversation_id", "logical_message_id", "attempt_id"))
    else:
        service, conversation, logical, attempt = (req[name] for name in ("service_id", "conversation_id", "logical_message_id", "attempt_id"))
    key = logical_key(service, conversation, device, logical)
    row = db.execute("SELECT outcome FROM attempts WHERE logical_key=? AND attempt_id=?", (key, attempt)).fetchone()
    if row is None or row["outcome"] != "accepted":
        return None
    # 已接受的原尝试分支只读，复用实际业务校验；改字节及范围错误仍先明确拒绝。
    return dispatch(store, db, device, req)


def project_for_request(store, db, device, operation, req, dispatch):
    original = accepted_retry(store, db, device, operation, req, dispatch)
    if original is None:
        project_expiration(db)
        return None
    db.execute("SAVEPOINT retained_acceptance_projection")
    try:
        project_expiration(db)
    except ProtocolError as error:
        db.execute("ROLLBACK TO retained_acceptance_projection")
        db.execute("RELEASE retained_acceptance_projection")
        if error.code != "resource_exhausted":
            raise
        return {**original, "lifecycle_projection_pending": True}
    db.execute("RELEASE retained_acceptance_projection")
    return None
