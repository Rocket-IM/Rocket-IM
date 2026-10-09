#!/usr/bin/env python3
"""Q01 测试包装器：同库延后群 fixture 引导；业务注册仍走原 HTTP/验证器。"""

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "poc/network-relay"))
sys.path.insert(0, str(ROOT / "tests/interop"))

import device_registration
import server
from contract import ProtocolError, decode_bytes, encode_json, fields
from controls import TestControls
from permission_contract import validate_checkpoint
from storage import replace_members
from network_poc.expiration_relay import FileClock


class FirstTrustControls(TestControls):
    def execute(self, store, db, token, req):
        if req.get("action") != "first_trust_bootstrap":
            return super().execute(store, db, token, req)
        super().execute(store, db, token, {"action": "stats"})
        fields(req, ("action", "checkpoint", "relay_receipt_key"))
        checkpoint = validate_checkpoint(req["checkpoint"])
        key = decode_bytes(req["relay_receipt_key"], "relay_receipt_key", 32)
        if len(key) != 32:
            raise ProtocolError("permission_invalid", "测试 Service 公钥长度不符")
        conversation = db.execute("SELECT id FROM conversation").fetchone()["id"]
        if (checkpoint["service_id"] != store.meta(db, "service_id")
                or checkpoint["conversation_id"] != conversation):
            raise ProtocolError("permission_context", "测试群引导实例不匹配", status=403)
        keys = [tuple(row) for row in db.execute(
            "SELECT account,device,signature_key FROM device_public_keys ORDER BY account,device")]
        registrations = [tuple(row) for row in db.execute(
            "SELECT * FROM device_registrations ORDER BY account,device,registration_id")]
        for member in checkpoint["members"]:
            expected = (member["account_id"], member["device_id"], member["signature_key"])
            registered = db.execute("SELECT 1 FROM device_registrations WHERE account=? AND device=? AND proof_json IS NOT NULL",
                                    expected[:2]).fetchone()
            if expected not in keys or registered is None:
                raise ProtocolError("permission_denied", "测试群成员必须先完成原注册证明", status=403)
        if (db.execute("SELECT 1 FROM permission_checkpoint").fetchone()
                or db.execute("SELECT 1 FROM attempts").fetchone()
                or db.execute("SELECT 1 FROM events").fetchone()):
            raise ProtocolError("state_conflict", "测试引导仅适用于未开始消息的无群检查点库", status=409)
        encoded = encode_json(checkpoint).decode()
        db.execute("INSERT INTO permission_checkpoint VALUES (1,?,?)",
                   (checkpoint["authorization_version"], encoded))
        db.execute("INSERT INTO meta VALUES ('relay_receipt_key',?)", (req["relay_receipt_key"],))
        db.execute("UPDATE meta SET value='1' WHERE key='join_enabled'")
        pairs = [(m["account_id"], m["device_id"]) for m in checkpoint["members"]]
        replace_members(db, pairs)
        db.executemany("INSERT INTO membership_history VALUES (?,?)", pairs)
        db.execute("UPDATE conversation SET authorization_version=?,crypto_state_ref=?",
                   (checkpoint["authorization_version"], checkpoint["crypto_state_ref"]))
        assert keys == [tuple(row) for row in db.execute(
            "SELECT account,device,signature_key FROM device_public_keys ORDER BY account,device")]
        assert registrations == [tuple(row) for row in db.execute(
            "SELECT * FROM device_registrations ORDER BY account,device,registration_id")]
        store.permission_enabled = True
        return {"status": "synthetic_group_bootstrapped", "checkpoint_sha256": hashlib.sha256(encoded.encode()).hexdigest(),
                "registered_keys_preserved": True, "registration_rows_preserved": len(registrations)}


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--registration-clock-file", required=True)
    options, remaining = parser.parse_known_args()
    if "--enable-test-controls" not in remaining:
        parser.error("Q01 包装器必须显式启用测试控制器")
    clock = FileClock(options.registration_clock_file)
    device_registration.now_ms = clock
    server.TestControls = FirstTrustControls
    sys.argv = [sys.argv[0], *remaining]
    server.main()


if __name__ == "__main__":
    main()
