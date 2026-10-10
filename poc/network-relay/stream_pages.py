"""普通设备流签名分页；来源固定到已认证主体和原始分页字节。"""

import base64
import hashlib

from contract import ProtocolError, encode_json
from permission_records import require_receipts
from rebuild_stream_storage import authorize_operation
from stream_page_contract import MAX_PAGE_BYTES, PROTOCOL_VERSION
from synchronization import event_page


def pull_events_signed(store, db, device, req):
    authorize_operation(db, device, "pull_events_signed")
    require_receipts(store)
    page = event_page(store, db, device, req, MAX_PAGE_BYTES - 512,
                      terminal_references=req.get("include_terminal_references", False))
    raw = encode_json(page)
    if len(raw) > MAX_PAGE_BYTES:
        raise ProtocolError("resource_exhausted", "普通设备流原始页超过740KiB", status=429)
    statement = {"protocol_version": PROTOCOL_VERSION,
                 "service_id": store.meta(db, "service_id"),
                 "account_id": device["account"], "device_id": device["device"],
                 "stream_id": device["stream_id"], "after_seq": req["after_seq"],
                 "limit": req["limit"], "page_sha256": hashlib.sha256(raw).hexdigest()}
    return {"page_bytes": base64.b64encode(raw).decode(), "receipt": store.receipt_signer.sign(statement)}
