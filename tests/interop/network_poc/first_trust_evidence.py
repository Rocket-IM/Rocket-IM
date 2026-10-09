"""Q01 无秘密摘要：原快照文件和单个显式只读事务中的完整 Relay 表。"""

from contextlib import closing
import hashlib
import json
import sqlite3


def digest(value):
    return hashlib.sha256(value).hexdigest()


def snapshot(lab, device):
    path = lab.directory / device / "state.enc"
    if not path.exists():
        return None
    value = path.read_bytes()
    return {"sha256": digest(value), "bytes": len(value)}


def database(lab):
    uri = (lab.directory / "relay.sqlite").resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, isolation_level=None)) as db:
        db.execute("BEGIN")
        try:
            tables = {}
            names = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
            for name in names:
                quoted = '"' + name.replace('"', '""') + '"'
                rows = [list(row) for row in db.execute(f"SELECT * FROM {quoted} ORDER BY rowid")]
                content = json.dumps(rows, sort_keys=True, separators=(",", ":"),
                                     default=lambda value: {"sha256": digest(value), "bytes": len(value)})
                tables[name] = {"rows": len(rows), "sha256": digest(content.encode())}
            keys = [list(row) for row in db.execute(
                "SELECT account,device,signature_key FROM device_public_keys ORDER BY account,device")]
            db.commit()
        except BaseException:
            db.rollback()
            raise
    return {"tables": tables, "public_keys": keys}


def state(lab):
    return {"snapshots": {device: snapshot(lab, device) for device in lab.public},
            "relay": database(lab)}
