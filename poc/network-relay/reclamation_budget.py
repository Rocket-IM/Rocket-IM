"""将已回收证明和已预约计划共同计入硬预算，不借计划并发超额。"""

import json

from contract import ProtocolError, encode_json
from reclamation_storage import MAX_PROOF_BYTES


def attempt_size(row):
    # 含主键、头、终态、关系、摘要及固定标量；原payload不留在紧凑证明中。
    value = {name: row[name] for name in row.keys() if name not in {"payload", "compacted", "payload_sha256", "payload_size"}}
    if value["header"] is not None:
        value["header"] = value["header"].decode()
    return len(encode_json(value)) + 128


def event_size(row):
    value = dict(row)
    content = json.loads(value["content"])
    if content.get("type") == "message":
        content.pop("envelope", None)
    value["content"] = content
    return len(encode_json(value))


def check_proof_bytes(db, keys, ids):
    size = sum(attempt_size(row) for row in db.execute("SELECT * FROM attempts WHERE compacted=1"))
    size += sum(event_size(row) for row in db.execute("SELECT * FROM events WHERE compacted=1"))
    for key in keys:
        size += sum(attempt_size(row) for row in db.execute("SELECT * FROM attempts WHERE logical_key=? AND compacted=0", (key,)))
    for acceptance_id in ids:
        size += sum(event_size(row) for row in db.execute("SELECT * FROM events WHERE acceptance_id=? AND compacted=0", (acceptance_id,)))
    if size > MAX_PROOF_BYTES:
        raise ProtocolError("resource_exhausted", "回收证明总字节预算已满，保留原数据", status=429)
