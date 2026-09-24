#!/usr/bin/env python3
"""M11 测试专用重复槽装置；原 HTTP、鉴权、消息事务及分页实现不变。"""

import argparse
import hmac
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "poc/network-relay"))

from contract import ProtocolError, encode_json, fields, parse_json, validate_id
from controls import TestControls
from permission_verifier import PermissionVerifier
from receipt_signer import ReceiptSigner
from server import RelayServer
from storage import Store, subject, token_hash
from synchronization import project_expiration


class SlotControls(TestControls):
    """一次只复制一个已有消息槽，数量仍受原 Store 总量和单设备上限约束。"""

    def execute(self, store, db, token, req):
        if req.get("action") != "duplicate_message_slot":
            return super().execute(store, db, token, req)
        if not self.enabled or not hmac.compare_digest(token_hash(token), store.meta(db, "controller_hash")):
            raise ProtocolError("permission_denied", "测试控制器未启用或凭证无效", status=403)
        fields(req, ("action", "account_id", "device_id", "event_id"))
        pair = subject({name: req[name] for name in ("account_id", "device_id")})
        validate_id(req["event_id"], "event_id")
        device = db.execute("SELECT stream_id,revoked FROM devices WHERE account=? AND device=?", pair).fetchone()
        if device is None or device["revoked"] or pair not in store.members(db):
            raise ProtocolError("permission_denied", "复制目标必须是当前未撤销成员", status=403)
        project_expiration(db)
        source = db.execute(
            "SELECT content,acceptance_id,availability FROM events WHERE account=? AND device=? AND event_id=?",
            (*pair, req["event_id"])).fetchone()
        if source is None or source["availability"] != "available":
            raise ProtocolError("test_slot_unavailable", "原消息槽不存在或已不可用", status=409)
        event = json.loads(source["content"])
        accepted = db.execute("SELECT outcome,availability FROM attempts WHERE acceptance_id=?",
                              (source["acceptance_id"],)).fetchone()
        if (event.get("type") != "message" or event.get("acceptance_id") != source["acceptance_id"]
                or accepted is None or accepted["outcome"] != "accepted" or accepted["availability"] != "available"):
            raise ProtocolError("test_slot_unavailable", "只能复制已接受且可用的原消息槽", status=409)
        # 不接收新信封、不重新签名；沿用原追加函数分配连续序号与独立事件 ID。
        store.append_event(db, pair, event, source["acceptance_id"])
        added = db.execute("SELECT seq,event_id FROM events WHERE account=? AND device=? ORDER BY seq DESC LIMIT 1",
                           pair).fetchone()
        return {"stream_id": device["stream_id"], "event_seq": str(added["seq"]),
                "event_id": added["event_id"], "source_event_id": req["event_id"],
                "acceptance_id": source["acceptance_id"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--enable-test-controls", action="store_true")
    parser.add_argument("--permission-verifier", type=Path)
    parser.add_argument("--receipt-signer", type=Path)
    parser.add_argument("--receipt-key", type=Path)
    args = parser.parse_args()
    if not args.enable_test_controls:
        parser.error("M11 包装器必须显式启用 --enable-test-controls")
    if not args.database.is_absolute() or not args.fixture.is_absolute() or not 0 <= args.port <= 65535:
        parser.error("database/fixture 必须为绝对路径，port 必须为 0—65535")
    if bool(args.receipt_signer) != bool(args.receipt_key):
        parser.error("--receipt-signer 与 --receipt-key 必须同时提供")
    fixture = parse_json(args.fixture.read_bytes())
    verifier = PermissionVerifier(args.permission_verifier) if args.permission_verifier else None
    signer = ReceiptSigner(args.receipt_signer, args.receipt_key) if args.receipt_signer else None
    store = Store(args.database, fixture, verifier, signer)
    if store.permission_enabled and verifier is None:
        parser.error("已有权限检查点必须配置 --permission-verifier")
    server = RelayServer(("127.0.0.1", args.port), store, SlotControls(True))
    print(encode_json({"status": "ready", "url": f"http://127.0.0.1:{server.server_port}",
                       "database": str(store.path)}).decode(), flush=True)
    try:
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
