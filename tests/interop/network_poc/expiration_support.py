"""TTL 装置观察与断言；时钟仅影响专用 Relay 进程，不改写消息或到期判断。"""

import base64
import copy
import json

from .deletion_observer import assert_terminal_transition, relay_records
from .deletion_support import capture, unchanged
from .fixture import ACCOUNTS, check


def set_clock(lab, unix_ms):
    before = capture(lab)
    temporary = lab.clock_path.with_suffix(".tmp")
    temporary.write_text(str(unix_ms) + "\n")
    temporary.chmod(0o600)
    temporary.replace(lab.clock_path)
    unchanged(lab, before, "clock_file_only_" + str(unix_ms))
    lab.case_evidence.setdefault("clock_updates", []).append({"unix_ms": str(unix_ms)})


def assert_expired_transition(before, after, accepted):
    ident = accepted["acceptance_id"]
    attempts = [a for a in before["attempts"] if a["acceptance_id"] == ident]
    check(len(attempts) == 1 and attempts[0]["outcome"] == "accepted"
          and attempts[0]["availability"] == "available", "到期前必须有唯一可用接受记录")
    check(attempts[0]["result"] == accepted, "原接受结果已被改写")
    assert_terminal_transition(before, after, ident, "expired")


def retry_expired(lab, packet, accepted, label):
    expected = {**accepted, "availability": "expired"}
    before = capture(lab)
    for operation in ("submit_message", "get_attempt", "close_attempt"):
        value = lab.submit(packet) if operation == "submit_message" else lab.attempt(
            accepted["logical_message_id"], operation=operation)
        check(value == expected, "过期后完整接受事实变化: " + operation)
    changed = copy.deepcopy(packet)
    payload = bytearray(base64.b64decode(changed["envelope"]["payload_bytes"]))
    payload[-1] ^= 1
    changed["envelope"]["payload_bytes"] = base64.b64encode(payload).decode()
    check(lab.submit(changed, expected=409)["code"] == "idempotency_conflict",
          "过期后同尝试异密文获得接受")
    changed = copy.deepcopy(packet)
    header = json.loads(base64.b64decode(changed["envelope"]["header_bytes"]))
    header["attempt_id"] = "P2"
    changed["envelope"]["header_bytes"] = base64.b64encode(
        json.dumps(header, separators=(",", ":")).encode()).decode()
    error = lab.submit(changed, expected=409)
    check(error["code"] == "logical_message_already_accepted" and error["acceptance"] == expected,
          "新尝试绕过原过期接受事实")
    unchanged(lab, before, label)
    lab.case_evidence.setdefault("retry_results", []).append({"label": label, "result": expected,
        "changed_ciphertext": "idempotency_conflict", "new_attempt": "logical_message_already_accepted",
        "new_attempt_scope": "HTTP header negative case; no new MLS encryption"})


def check_expired_slot(slot, original):
    expected = {key: original[key] for key in ("stream_id", "event_seq", "event_id")}
    check(slot == {**expected, "availability": "expired"}, "过期槽身份改变或仍携带载荷")


def observe_final(lab, message_count):
    records = relay_records(lab)
    terminal_count = sum(row["availability"] in ("deleted", "expired") for row in records["attempts"])
    check(records["counts"] == {"attempts": message_count, "logical_messages": message_count,
          "accepted": message_count, "events": 3 * (message_count + terminal_count),
          "message_events": 3 * message_count, "receipts": 0}, "过期/重试丢失或增加了接受/事件/回执")
    lab.case_evidence["final_relay"] = records
    lab.case_evidence["final_clients"] = {d: lab.rust(d, "wire_inspect") for d in ACCOUNTS}
