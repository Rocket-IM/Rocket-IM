"""M11.a 双实例装置：同名主体、独立 Relay/MLS/回执钥/凭证/目录。"""

from contextlib import closing
import hashlib
import json
from pathlib import Path
import re
import sqlite3

from .fixture import ACCOUNTS, NetworkLab, check


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def relay_view(lab):
    """测试专用显式只读事务；只导出表计数与整体摘要，不导出凭证或行内容。"""
    uri = (lab.directory / "relay.sqlite").resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, isolation_level=None)) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        try:
            schema = db.execute("SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
            tables = {}
            for name, _ in schema:
                check(re.fullmatch(r"[a-z_][a-z_0-9]*", name) is not None, "数据库表名超出测试观察白名单")
                rows = [[{"bytes": item.hex()} if isinstance(item, bytes) else item for item in row]
                        for row in db.execute('SELECT * FROM "' + name + '"')]
                tables[name] = sorted(rows, key=lambda row: json.dumps(row, sort_keys=True))
            db.commit()
        except BaseException:
            db.rollback()
            raise
    return {"sha256": digest({"schema": schema, "tables": tables}),
            "counts": {name: len(rows) for name, rows in tables.items()}}


def client_view(lab):
    # 不解密客户端状态。包括快照、钥文件和锁文件，以发现失败路径的额外文件。
    return {device: {str(p.relative_to(lab.directory / device)): hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in sorted((lab.directory / device).rglob("*")) if p.is_file()}
            for device in ACCOUNTS}


class IsolationPair:
    def __init__(self, binary, directory, verifier, signer):
        self.directory = Path(directory)
        self.labs = {label: NetworkLab(binary, self.directory / label, verifier, signer,
                                      service="synthetic-isolation-" + label) for label in ("S1", "S2")}
        self.evidence = {}
        self.records = {label: {} for label in self.labs}

    def initialize(self):
        for lab in self.labs.values():
            lab.initialize(permissions=True)
        first, second = self.labs.values()
        check(first.process.poll() is None and second.process.poll() is None
              and first.process.pid != second.process.pid and first.url.port != second.url.port,
              "两个真实Relay必须同时运行且端口独立")
        check(first.service != second.service and first.state_ref != second.state_ref
              and first.relay_receipt_key != second.relay_receipt_key, "实例、MLS组或回执钥意外复用")
        check(set(first.tokens.values()).isdisjoint(second.tokens.values()), "跨实例复用了合成凭证")
        check(all(first.public[d]["signature_key"] != second.public[d]["signature_key"] for d in ACCOUNTS),
              "同名设备复用了密码身份")
        self.evidence["instances"] = {label: {"service": lab.service, "port": lab.url.port,
              "relay_pid": lab.process.pid, "subjects": ACCOUNTS, "crypto_state_ref": lab.state_ref,
              "receipt_public_key": lab.relay_receipt_key, "directory": label}
              for label, lab in self.labs.items()}

    def directions(self):
        for source, target in (("S1", "S2"), ("S2", "S1")):
            yield source, self.labs[source], target, self.labs[target]

    def capture(self):
        return {label: {"clients": client_view(lab), "relay": relay_view(lab)} for label, lab in self.labs.items()}

    def unchanged(self, before, label):
        after = self.capture()
        check(after == before, "拒绝/只读路径污染实例状态: " + label)
        self.evidence.setdefault("unchanged_checks", []).append({"label": label, "before_sha256": digest(before),
                                                                  "after_sha256": digest(after)})

    def restart(self):
        before = self.capture()
        for lab in self.labs.values():
            lab.restart()
        self.unchanged(before, "restart_both")

    def close(self):
        for lab in self.labs.values():
            lab.close()
