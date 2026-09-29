"""仅测试启动开关可用的合成控制器；与设备公开操作隔离。"""

import hmac
import threading

from contract import MAX_PAYLOAD_BYTES, ProtocolError, decode_bytes, encode_json, fields, parse_u64, validate_id, validate_state_ref
from storage import public_subject, replace_members, revoke_device, subject, token_hash
from synchronization import set_availability
from lifecycle_backfill import backfill


class TestControls:
    def __init__(self, enabled):
        self.enabled = enabled
        self.lock = threading.Lock()
        self.next_hook = None

    def take_hook(self):
        with self.lock:
            hook, self.next_hook = self.next_hook, None
            return hook

    def execute(self, store, db, token, req):
        if not self.enabled or not hmac.compare_digest(token_hash(token), store.meta(db, "controller_hash")):
            raise ProtocolError("permission_denied", "测试控制器未启用或凭证无效", status=403)
        action = req.get("action")
        if store.permission_enabled and action in {"set_state", "revoke_device", "add_control"}:
            raise ProtocolError("permission_denied", "已启用签名权限链，禁止测试控制器改写授权或控制材料", status=403)
        if action == "stats":
            fields(req, ("action",))
            return stats(db)
        if action == "backfill_lifecycle":
            return backfill(store, db, req)
        if action == "hook":
            fields(req, ("action", "hook"), ("delay_ms",))
            name = req["hook"]
            if name not in {"drop_after_commit", "before_commit_exit", "after_commit_exit", "delay_before_commit", "delay_after_commit"}:
                raise ProtocolError("invalid_envelope", "未知实验故障点")
            delay = parse_u64(req.get("delay_ms", "0"), "delay_ms")
            if delay > 5000 or (name.startswith("delay_") and delay == 0):
                raise ProtocolError("invalid_envelope", "实验延迟必须为 1—5000 毫秒")
            with self.lock:
                if self.next_hook is not None:
                    raise ProtocolError("state_conflict", "已有尚未消费的故障点", status=409)
                self.next_hook = {"name": name, "delay_ms": delay}
            return {"hook": name, "armed": True}
        if action == "set_state":
            return change_state(store, db, req)
        if action == "revoke_device":
            fields(req, ("action", "account_id", "device_id"))
            pair = subject({k: req[k] for k in ("account_id", "device_id")})
            if not db.execute("SELECT 1 FROM devices WHERE account=? AND device=?", pair).fetchone():
                raise ProtocolError("invalid_envelope", "实验设备不存在")
            revoke_device(db, pair)
            return {"revoked": True, "device": public_subject(pair)}
        if action == "set_availability":
            fields(req, ("action", "acceptance_id", "availability"))
            validate_id(req["acceptance_id"], "acceptance_id")
            if req["availability"] not in {"expired", "deleted"}:
                raise ProtocolError("invalid_envelope", "只支持不可逆的过期/删除投影")
            if not db.execute("SELECT 1 FROM attempts WHERE acceptance_id=?", (req["acceptance_id"],)).fetchone():
                raise ProtocolError("invalid_envelope", "接受记录不存在")
            set_availability(db, req["acceptance_id"], req["availability"])
            current = db.execute("SELECT availability FROM attempts WHERE acceptance_id=?", (req["acceptance_id"],)).fetchone()[0]
            return {"acceptance_id": req["acceptance_id"], "availability": current}
        if action == "add_control":
            return add_control(store, db, req)
        raise ProtocolError("unsupported_operation", "未知实验控制操作", status=404)


def change_state(store, db, req):
    fields(req, ("action", "authorization_version", "crypto_state_ref", "members"))
    version = parse_u64(req["authorization_version"], "authorization_version")
    validate_state_ref(req["crypto_state_ref"])
    if not isinstance(req["members"], list) or not 1 <= len(req["members"]) <= 6:
        raise ProtocolError("invalid_envelope", "实验成员数量必须为 1—6")
    members = [subject(m) for m in req["members"]]
    if len(set(members)) != len(members):
        raise ProtocolError("invalid_envelope", "实验成员重复")
    for pair in members:
        row = db.execute("SELECT revoked FROM devices WHERE account=? AND device=?", pair).fetchone()
        if row is None or row["revoked"]:
            raise ProtocolError("permission_denied", "不能加入未知或已撤销设备", status=403)
    current = db.execute("SELECT authorization_version FROM conversation").fetchone()[0]
    if version <= int(current):
        raise ProtocolError("state_stale", "实验权限版本必须递增", status=409)
    replace_members(db, members)
    db.execute("UPDATE conversation SET authorization_version=?,crypto_state_ref=?", (req["authorization_version"], req["crypto_state_ref"]))
    return {"authorization_version": req["authorization_version"], "crypto_state_ref": req["crypto_state_ref"], "members": req["members"]}


def add_control(store, db, req):
    fields(req, ("action", "control", "recipients", "append_events"))
    control = req["control"]
    fields(control, ("control_id", "from_state_ref", "to_state_ref", "payload_bytes"))
    validate_id(control["control_id"], "control_id")
    validate_state_ref(control["from_state_ref"])
    validate_state_ref(control["to_state_ref"])
    decode_bytes(control["payload_bytes"], "payload_bytes", MAX_PAYLOAD_BYTES)
    if control["from_state_ref"] == control["to_state_ref"] or not isinstance(req["append_events"], bool):
        raise ProtocolError("invalid_envelope", "实验控制链或事件开关无效")
    if not isinstance(req["recipients"], list) or not 1 <= len(req["recipients"]) <= 6:
        raise ProtocolError("invalid_envelope", "控制材料目标必须为 1—6 项")
    recipients = [subject(m) for m in req["recipients"]]
    if len(set(recipients)) != len(recipients) or not set(recipients) <= set(store.members(db)):
        raise ProtocolError("permission_denied", "控制材料目标缺少当前授权", status=403)
    old = db.execute("SELECT from_ref,to_ref,payload,recipients FROM controls WHERE control_id=?", (control["control_id"],)).fetchone()
    values = (control["from_state_ref"], control["to_state_ref"], control["payload_bytes"], encode_json(req["recipients"]).decode())
    if old:
        if tuple(old) != values:
            raise ProtocolError("idempotency_conflict", "控制记录不可修改", status=409)
        return {"control_id": control["control_id"], "reused": True}
    if db.execute("SELECT COUNT(*) FROM controls").fetchone()[0] >= 128:
        raise ProtocolError("resource_exhausted", "控制材料超过实验上限", status=429)
    if db.execute("SELECT 1 FROM controls WHERE from_ref=? OR to_ref=?", (control["from_state_ref"], control["to_state_ref"])).fetchone():
        raise ProtocolError("state_conflict", "控制链分叉或重复后继", status=409)
    db.execute("INSERT INTO controls VALUES (?,?,?,?,?)", (control["control_id"], *values))
    if req["append_events"]:
        for pair in recipients:
            store.append_event(db, pair, {"type": "crypto_control", "control": control})
    return {"control_id": control["control_id"], "reused": False}


def stats(db):
    from reclamation_storage import retained_stats, watermarks
    values = {"attempts": "SELECT COUNT(*) FROM attempts", "accepted": "SELECT COUNT(*) FROM attempts WHERE outcome='accepted'",
              "events": "SELECT COUNT(*) FROM events", "message_events": "SELECT COUNT(*) FROM events WHERE json_extract(content,'$.type')='message'",
              "receipts": "SELECT COUNT(*) FROM receipts", "controls": "SELECT COUNT(*) FROM controls"}
    value = {key: str(db.execute(sql).fetchone()[0]) for key, sql in values.items()}
    value.update(retained_stats(db))
    value["streams"] = [{"account_id": row["account"], "device_id": row["device"], "stream_id": row["stream_id"],
                         "watermark": str(watermarks(db, (row["account"], row["device"]))["high_watermark"]),
                         "floor": str(watermarks(db, (row["account"], row["device"]))["floor"])}
                        for row in db.execute("SELECT account,device,stream_id FROM devices ORDER BY account,device")]
    return value
