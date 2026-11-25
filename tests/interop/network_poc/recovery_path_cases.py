"""E10.c合法私有Commit对照；缺路径负例受阻时不得据此关闭该项。"""

import base64
import hashlib
import time

from .fixture import ACCOUNTS, check
from .first_trust_evidence import state
from .join_review_regressions import public_record
from .key_package_fixture import decode
from .recovery_bundle_cases import stable
from .recovery_competition_cases import recovery_ledger
from .recovery_offline_cases import pair
from .recovery_watermark_cases import original_facts, resume
from .recovery_welcome_cases import not_installed, target_view


def valid_private_path(lab):
    lab.setup_expired()
    original = original_facts(lab)
    lab.case_evidence["messages"] = [{"logical": "before-recovery", "sender": lab.actor,
        "direct_receivers": [d for d in ACCOUNTS if d != lab.actor],
        "payload_sha256": hashlib.sha256(b"synthetic-first-trust-before-recovery").hexdigest(),
        "packet": lab.old_packet, "accepted": lab.old_acceptance}]
    intent, claim, allocation, bundle = lab.prepare_recovery("e10c-valid", package_ttl=300)
    raw = base64.b64decode(bundle["change"]["commit_bytes"], validate=True)
    statement = decode(bundle["change"])
    # 正常prepare内部通过真实staged Commit的精确Remove/Add及path检查。
    # 此处只观察公开帧与真实业务结果，不声称解密观察了私有Commit结构。
    check(raw[:4] == b"\x00\x01\x00\x02"
          and statement["commit_sha256"] == hashlib.sha256(raw).hexdigest(),
          "合法对照未使用真实MLS 1.0 PrivateMessage")
    accepted = lab.accept_recovery(bundle)
    record = accepted["record"]
    check(record["bundle"] == bundle and accepted["state"] == "accepted",
          "Service未接受同一公开签名及摘要原件")
    latest = decode(accepted["receipt"])["result"]["checkpoint"]
    ledger = recovery_ledger(lab)
    lab.case_evidence["prepared"] = {"intent": intent, "claim": claim,
        "allocation": allocation, "bundle": bundle, "accepted": accepted,
        "wire_format": "PrivateMessage", "wire_format_value": 2,
        "path_evidence": "normal prepare requires real staged exact inline Remove/Add and update path",
        "latest": latest, "ledger": ledger, "original_facts": original}
    for device in (*ACCOUNTS, lab.target):
        material = record if device in (lab.actor, lab.target) else public_record(record)
        result = lab.recovery(device, "observe", record=material)
        check(not result["installed"], "公开R0提前成为真实R1")
    before_target = not_installed(lab, latest)
    package_hash = decode(intent)["key_package_sha256"]
    deadline = int(before_target["packages"][package_hash]["material"]["not_after"])
    for device in ("b1", lab.target):
        resume(lab, device)
        check(lab.recovery(device, "inspect")["installed_count"] == 0,
              "合法Apply前resume提前安装R1")
        stable(lab, "before-apply-send-" + device, lambda d=device: lab.rust(d,
            "wire_send", logical_message_id="e10c-before-" + d, attempt_id="P1",
            payload="synthetic-e10c-before-r1", expected_exit=1),
            "join_required" if device == lab.target else "consistency_paused")
    check(not_installed(lab, latest) == before_target, "提前resume改变目标材料或加入状态")
    for device in (*ACCOUNTS, lab.target):
        material = record if device in (lab.actor, lab.target) else public_record(record)
        before = state(lab)
        result = lab.recovery(device, "apply", record=material)
        after = state(lab)
        check(result["installed"] and not result["duplicate"] and result["checkpoint"] == latest
              and lab.rust(device, "permission_inspect")["checkpoint"] == latest
              and lab.recovery(device, "inspect")["installed_count"] == 1
              and after["relay"] == before["relay"]
              and after["snapshots"][device] != before["snapshots"][device]
              and all(after["snapshots"][d] == v for d, v in before["snapshots"].items()
                      if d != device), "合法私有Commit/Welcome未真实安装或越界写入")
        lab.case_evidence.setdefault("role_applies", []).append({"device": device,
            "role": "target" if device == lab.target else "actor" if device == lab.actor else "survivor",
            "result": result, "before": before, "after": after})
        resume(lab, device)
    for phase in ("installed", "restarted"):
        if phase == "restarted":
            stable(lab, "restart-after-r1", lab.restart)
        for device in (*ACCOUNTS, lab.target):
            result = stable(lab, phase + "-exact-apply-" + device,
                lambda d=device: lab.recovery(d, "apply", record=record))
            check(result["installed"] and result["duplicate"], "原合法R1精确重试不幂等")
        pair(lab, "b1", "e10c-survivor-" + phase)
        pair(lab, lab.target, "e10c-target-" + phase)
        check(stable(lab, phase + "-accepted", lambda: lab.get_recovery(intent)) == accepted,
              "合法通信或重启改写接受原件")
    check(time.time() < deadline and recovery_ledger(lab) == ledger
          and original_facts(lab) == original, "合法对照到期或改写原事实/增加恢复后继")
    lab.case_evidence["completion"] = {"status": "PASS_SCOPED", "private_commit": True,
        "target": target_view(lab), "original_unchanged": True, "ledger": ledger,
        "finished_at_unix_secs": time.time(), "new_material_not_after": deadline,
        "missing_path_negative": "NOT_EXECUTED_PLATFORM_BLOCKED"}


CASES = {"E10_update_path_valid_private": valid_private_path}
