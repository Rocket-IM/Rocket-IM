"""唯一后继流的授权与签名分页；不会释放旧范围，亦不声称获知锚的实时取消。"""

import base64
import hashlib
import json
import sqlite3

from contract import ProtocolError, encode_json, fields, parse_json, parse_u64, validate_envelope, validate_id
from permission_contract import validate_proof
from permission_records import require_receipts
from receipt_contract import proof_digest
from rebuild_stream_contract import (MAX_PAGE_BYTES, signed_digest, validate_binding,
                                     validate_registration)
from rebuild_stream_storage import row_for
from synchronization import event_page


def denied(message="重建设备流授权或当前范围不匹配"):
    return ProtocolError("rebuild_stream_denied", message, status=403)


def conflict(message="重建设备流与已登记代际或原证据冲突"):
    return ProtocolError("rebuild_stream_context", message, status=409)


def target_row(db, device):
    row = row_for(db, (device["account"], device["device"]))
    if row is None:
        raise denied("此设备没有新空库固定的重建信任")
    return row


def current_access(store, db, device, successor, conversation_id):
    from permissions import checkpoint_record
    require_receipts(store)
    conv = store.context(db, device, successor["service"], conversation_id)
    if (device["account"], device["device"]) != (successor["account"], successor["device"]):
        raise denied("Bearer主体与后继签名身份不一致")
    _, checkpoint = checkpoint_record(db)
    if (any(checkpoint[name] != conv[name] for name in ("authorization_version", "crypto_state_ref"))
            or checkpoint["service_id"] != successor["service"] or checkpoint["conversation_id"] != conversation_id
            or [(m["account_id"], m["device_id"]) for m in checkpoint["members"]] != store.members(db)):
        raise conflict("持久权限检查点与当前会话投影不一致")
    key = base64.b64encode(bytes.fromhex(successor["identity_key"])).decode()
    member = {"account_id": successor["account"], "device_id": successor["device"], "signature_key": key}
    public_key = db.execute("SELECT signature_key FROM device_public_keys WHERE account=? AND device=?",
                            (device["account"], device["device"])).fetchone()
    if member not in checkpoint["members"] or public_key is None or public_key["signature_key"] != key:
        raise denied("后继缺少当前有效的精确设备公钥")


def accepted_join(db, registration, request):
    record = registration["join_record"]
    statement = validate_proof(record["change"])
    row = db.execute("SELECT p.proof,p.result,j.account,j.device,j.key_package_sha256 FROM permission_changes p JOIN join_materials j ON p.change_id=j.change_id WHERE p.change_id=?",
                     (statement["change_id"],)).fetchone()
    if (row is None or json.loads(row["proof"]) != record["change"]
            or json.loads(row["result"]).get("receipt") != record["receipt"]
            or json.loads(row["result"])["outcome"] != "accepted"
            or (row["account"], row["device"]) != (request["successor_scope"]["account"], request["successor_scope"]["device"])
            or row["key_package_sha256"] != registration["plan"]["key_package_sha256"]
            or proof_digest(record["change"]) != request["join_proof_sha256"]):
        raise denied("重建入群证明不是本库已接受的精确AddDevice记录")
    return statement


def register_rebuild_stream(store, db, device, req):
    row = target_row(db, device)
    registration = validate_registration(req["registration"])
    trusted = json.loads(row["trusted"])
    if store.permission_verifier is None:
        raise ProtocolError("permission_verifier_unavailable", "缺少重建公共验证器", status=503)
    verified = store.permission_verifier.verify_rebuild_stream(trusted, registration)
    request, digest = verified["request"], verified["request_sha256"]
    if req["service_id"] != request["successor_scope"]["service"]:
        raise denied()
    current_access(store, db, device, request["successor_scope"], request["conversation_id"])
    if trusted["trust"]["relay_receipt_key"] != store.meta(db, "relay_receipt_key"):
        raise denied("重建批准固定的Service公钥与当前实例不同")
    accepted_join(db, registration, request)
    if row["binding"] is not None:
        if row["request_sha256"] != digest or json.loads(row["registration"]) != registration:
            raise conflict()
        if device["stream_id"] != row["stream_id"]:
            raise conflict("持久设备流与原登记事实不一致")
        return {"binding": json.loads(row["binding"])}
    if db.execute("SELECT 1 FROM devices WHERE stream_id=?", (request["stream_id"],)).fetchone():
        raise conflict("新的流标识已经使用")
    statement = {"protocol_version": "rim-rebuild-stream-binding-1", "request_sha256": digest,
                 **{name: request[name] for name in ("plan_sha256", "successor_scope", "conversation_id", "stream_id", "initial_cursor", "join_proof_sha256")}}
    binding = store.receipt_signer.sign(statement)
    try:
        # 同一事务绑定唯一代际并更新投影，保留Add后已经排队的事件和序号。
        db.execute("UPDATE rebuild_streams SET registration=?,request_sha256=?,plan_sha256=?,stream_id=?,binding=? WHERE account=? AND device=?",
                   (encode_json(registration).decode(), digest, request["plan_sha256"], request["stream_id"], encode_json(binding).decode(), device["account"], device["device"]))
        db.execute("UPDATE devices SET stream_id=? WHERE account=? AND device=?", (request["stream_id"], device["account"], device["device"]))
    except sqlite3.IntegrityError:
        raise conflict("旧范围、设备、计划或流已经存在其他登记") from None
    return {"binding": binding}


def validate_event_origin(db, device, binding, join_version, slot):
    row = db.execute("SELECT content,acceptance_id FROM events WHERE account=? AND device=? AND seq=? AND event_id=?",
                     (device["account"], device["device"], int(slot["event_seq"]), slot["event_id"])).fetchone()
    if row is None:
        raise conflict("页面槽位失去原事件")
    event = json.loads(row["content"])
    acceptance_id = event.get("acceptance_id")
    original = db.execute("SELECT header,payload,result,outcome,availability FROM attempts WHERE acceptance_id=?", (acceptance_id,)).fetchone()
    if (event.get("type") not in {"message", "delivery", "read", "message_availability"} or original is None
            or original["outcome"] != "accepted" or row["acceptance_id"] != acceptance_id):
        raise conflict("后继流不接受缺少原接受记录的事件")
    header = parse_json(original["header"])
    pair = {"account_id": device["account"], "device_id": device["device"]}
    if (header["service_id"] != binding["successor_scope"]["service"]
            or header["conversation_id"] != binding["conversation_id"]
            or int(header["authorization_version"]) < join_version):
        raise conflict("原事件不属于后继加入后的新会话")
    if event["type"] == "message":
        validate_message_origin(event, original, header, pair)
    elif event["type"] == "message_availability":
        validate_availability_origin(db, device, slot, event, original, header, pair)
    elif (pair not in header["recipients"] and pair != header["sender"]
          or event.get("device") not in header["recipients"] or event.get("attempt_id") != header["attempt_id"]):
        raise conflict("回执事件不属于原消息的设备范围")


def validate_message_origin(event, original, header, pair):
    _, raw, payload = validate_envelope(event["envelope"])
    if (pair not in header["recipients"] or raw != original["header"] or payload != original["payload"]
            or event.get("acceptance_receipt") is None
            or event["acceptance_receipt"] != json.loads(original["result"]).get("acceptance_receipt")):
        raise conflict("消息事件与原信封或目标身份不一致")


def availability_target_sequence(event):
    """固定新事件的形状；关系和授权仍须从同设备原消息槽核对。"""
    try:
        fields(event, ("type", "target_event_seq", "target_event_id", "acceptance_id", "attempt_id", "availability"))
        sequence = parse_u64(event["target_event_seq"], "target_event_seq")
        for name in ("target_event_id", "acceptance_id", "attempt_id"):
            validate_id(event[name], name)
    except ProtocolError:
        raise conflict("可用性通知结构无效") from None
    if event["type"] != "message_availability" or event["availability"] not in ("deleted", "expired") or sequence == 0:
        raise conflict("可用性通知类型、终态或目标序号无效")
    return sequence


def validate_availability_origin(db, device, slot, event, original, header, pair):
    sequence = availability_target_sequence(event)
    if (sequence >= int(slot["event_seq"]) or event["attempt_id"] != header["attempt_id"]
            or original["availability"] != event["availability"]):
        raise conflict("可用性通知未绑定更早的精确接受终态")
    target = db.execute("SELECT content,acceptance_id,availability FROM events WHERE account=? AND device=? AND seq=? AND event_id=?",
                        (device["account"], device["device"], sequence, event["target_event_id"])).fetchone()
    if target is None or target["acceptance_id"] != event["acceptance_id"] or target["availability"] != event["availability"]:
        raise conflict("可用性通知没有同设备的精确原目标槽")
    message = json.loads(target["content"])
    if message.get("type") != "message" or message.get("acceptance_id") != event["acceptance_id"]:
        raise conflict("可用性通知的目标不是原接受消息")
    # 流标识由当前已签外层分页绑定；注册前排队事件不保存即将被替换的临时流ID。
    validate_message_origin(message, original, header, pair)


def pull_rebuild_events(store, db, device, req):
    row = target_row(db, device)
    if row["binding"] is None:
        raise ProtocolError("rebuild_stream_pending", "后继设备尚未完成唯一流授权", status=409)
    signed_binding = json.loads(row["binding"])
    binding = validate_binding(signed_binding)
    if store.permission_verifier is None:
        raise ProtocolError("permission_verifier_unavailable", "缺少重建公共验证器", status=503)
    verified = store.permission_verifier.verify_rebuild_pull(binding, req["request"])
    pull = verified["pull"]
    if (pull["binding_sha256"] != signed_digest(signed_binding) or req["service_id"] != pull["service_id"]
            or pull["stream_id"] != row["stream_id"] or device["stream_id"] != row["stream_id"]):
        raise conflict("分页请求未绑定本设备的唯一签名授权")
    current_access(store, db, device, pull["successor_scope"], pull["conversation_id"])
    page = event_page(store, db, device, pull, MAX_PAGE_BYTES - 512)
    registration = json.loads(row["registration"])
    join_version = int(validate_proof(registration["join_record"]["change"])["authorization_version"])
    for slot in page["events"]:
        validate_event_origin(db, device, binding, join_version, slot)
    raw = encode_json(page)
    if len(raw) > MAX_PAGE_BYTES:
        raise ProtocolError("resource_exhausted", "重建设备流原始页超过740KiB", status=429)
    statement = {"protocol_version": "rim-rebuild-stream-page-1", "binding_sha256": pull["binding_sha256"],
                 "request_sha256": verified["request_sha256"],
                 **{name: pull[name] for name in ("service_id", "conversation_id", "successor_scope", "stream_id", "after_seq", "limit", "challenge")},
                 "page_sha256": hashlib.sha256(raw).hexdigest()}
    return {"page_bytes": base64.b64encode(raw).decode(), "receipt": store.receipt_signer.sign(statement)}
