"""E10.b：仅损坏私有bundle，分别验证正常加载与真实Apply的拒绝。"""

import hashlib
import json
import shutil
import subprocess
import time

from .fixture import ACCOUNTS, check, identity
from .consistency_cases import current_head
from .first_trust_evidence import state
from .key_package_fixture import decode
from .recovery_competition_cases import recovery_ledger
from .recovery_offline_cases import pair
from .recovery_watermark_cases import checkpoint, original_facts, resume
from .recovery_welcome_cases import not_installed, target_view


def healthy(lab):
    return {d: {"group": lab.rust(d, "inspect"),
                "permission": lab.rust(d, "permission_inspect"),
                "wire": lab.rust(d, "wire_inspect"),
                "recovery": lab.recovery(d, "inspect")} for d in ACCOUNTS}


def stable(lab, name, action, code=None):
    # 格式损坏会使目标所有正常读取失败；不绕过加载校验伪造目标inspect。
    before = {"durable": state(lab), "healthy": healthy(lab)}
    result = action()
    after = {"durable": state(lab), "healthy": healthy(lab)}
    lab.case_evidence.setdefault("unchanged_steps", []).append({
        "name": name, "result": result, "before": before, "after": after})
    check(before == after, name + "改写了坏原件、有效群或Relay账本")
    if code is not None:
        check(result["code"] == code, name + "未命中指定拒绝层")
    return result


def setup(lab, mode):
    lab.setup_expired()
    lab.case_evidence["messages"] = [{"logical": "before-recovery", "sender": lab.actor,
        "direct_receivers": [d for d in ACCOUNTS if d != lab.actor],
        "payload_sha256": hashlib.sha256(b"synthetic-first-trust-before-recovery").hexdigest(),
        "packet": lab.old_packet, "accepted": lab.old_acceptance}]
    original = original_facts(lab)
    intent, _, _, bundle = lab.prepare_recovery("e10b-recovery", package_ttl=300)
    accepted = lab.accept_recovery(bundle)
    lab.install_recovery(accepted["record"], ACCOUNTS)
    latest = checkpoint(lab, lab.actor)
    check(lab.recovery(lab.target, "observe", record=accepted["record"])
          == {"duplicate": False, "installed": False}, "没有持久R0或提前安装R1")
    view = not_installed(lab, latest)
    package_hash = decode(intent)["key_package_sha256"]
    deadline = int(view["packages"][package_hash]["material"]["not_after"])
    # 留存真实挑战，损坏后测试resume请求也必须走正常加载；不另造本机状态。
    head = current_head(lab, lab.target) if mode == "corrupt_encoding" else None
    ledger = recovery_ledger(lab)
    check(len(ledger["recovery_attempts"]) == len(ledger["recovery_edges"])
          == len(ledger["recovery_roots"]) == 1 and not ledger["recovery_active"],
          "不是唯一已接受恢复起点")
    lab.case_evidence["prepared"] = {"intent": intent, "accepted": accepted,
        "latest": latest, "target_r0": view, "deadline": deadline,
        "package_hash": package_hash, "head": head, "ledger": ledger,
        "original_facts": original, "healthy": healthy(lab)}
    return intent, accepted, latest, ledger, original


def corrupt(lab, mode, package_hash):
    check(lab.bundle_fixture and lab.bundle_fixture.is_file(), "缺少显式私有bundle夹具")
    before = state(lab)
    preserved = lab.directory / "valid-target-before-corruption.enc"
    shutil.copy2(lab.directory / lab.target / "state.enc", preserved)
    preserved.chmod(0o600)
    request = {"directory": str(lab.directory / lab.target),
        "context": {"service": lab.service, "account": identity(lab.target)["account_id"],
                    "device": lab.target}, "key_package_sha256": package_hash, "mode": mode}
    process = subprocess.run([str(lab.bundle_fixture)], input=json.dumps(request),
                             text=True, capture_output=True, timeout=30)
    lab.process_count += 1
    evidence = {"mode": mode, "request": request, "exit_code": process.returncode,
                "stdout": process.stdout, "stderr": process.stderr, "before": before,
                "preserved_valid_snapshot": str(preserved)}
    lab.case_evidence["corruption"] = evidence
    check(process.returncode == 0, "私有bundle夹具失败: " + process.stdout[:400])
    result = json.loads(process.stdout)
    after = state(lab)
    evidence.update(result=result, after=after)
    check(result["synthetic"] and result["mode"] == mode
          and result["key_package_sha256"] == package_hash and result["changed_entries"] == 1
          and result["metadata_before_sha256"] == result["metadata_after_sha256"]
          and result["other_entries_before_sha256"] == result["other_entries_after_sha256"]
          and result["entry_before_sha256"] != result["entry_after_sha256"]
          and after["relay"] == before["relay"]
          and after["snapshots"][lab.target] != before["snapshots"][lab.target]
          and all(after["snapshots"][d] == v for d, v in before["snapshots"].items()
                  if d != lab.target), "夹具没有仅改变准确私有bundle条目")


def send_blocked(lab, phase, code):
    return stable(lab, phase + "-send", lambda: lab.rust(lab.target, "wire_send",
        logical_message_id=phase, attempt_id="P1", payload="synthetic-e10b-blocked",
        expected_exit=1), code)


def private_bundle(lab, mode):
    intent, accepted, latest, ledger, original = setup(lab, mode)
    prep = lab.case_evidence["prepared"]
    record = accepted["record"]
    if mode == "intact":
        before = state(lab)
        result = lab.recovery(lab.target, "apply", record=record)
        after = state(lab)
        view = target_view(lab)
        check(result["installed"] and not result["duplicate"] and result["checkpoint"] == latest
              and view["permission"]["checkpoint"] == latest and view["group"]["active"]
              and view["recovery"]["installed_count"] == 1
              and view["packages"][prep["package_hash"]]["consumed"]
              and after["relay"] == before["relay"]
              and all(after["snapshots"][d] == v for d, v in before["snapshots"].items()
                      if d != lab.target), "合法原件没有真实安装唯一R1")
        lab.case_evidence["successful_apply"] = {"result": result, "view": view,
            "before": before, "after": after, "finished_at_unix_secs": time.time()}
        resume(lab, lab.target)
        pair(lab, lab.target, "e10b-intact")
        stable(lab, "intact-restart", lab.restart)
        duplicate = stable(lab, "intact-exact-apply", lambda: lab.recovery(
            lab.target, "apply", record=record))
        check(duplicate["duplicate"] and duplicate["installed"], "合法R1重试不幂等")
        pair(lab, lab.target, "e10b-intact-restart")
    else:
        corrupt(lab, mode, prep["package_hash"])
        encoding = mode == "corrupt_encoding"
        code = "key_package_storage" if encoding else "welcome_validation"
        for phase in ("first", "after-restart"):
            if encoding:
                for operation in ("inspect", "key_package_inspect"):
                    stable(lab, phase + "-" + operation, lambda op=operation: lab.rust(
                        lab.target, op, expected_exit=1), code)
                stable(lab, phase + "-r0-inspect", lambda: lab.recovery(
                    lab.target, "inspect", expected_exit=1), code)
            else:
                check(not_installed(lab, latest) == prep["target_r0"],
                      "私钥内容损坏改变R0、公开材料或加入标记")
            started = time.time()
            error = stable(lab, phase + "-apply", lambda: lab.recovery(
                lab.target, "apply", record=record, expected_exit=1), code)
            finished = time.time()
            lab.case_evidence.setdefault("apply_rejections", []).append({"phase": phase,
                "started_at_unix_secs": started, "finished_at_unix_secs": finished,
                "error": error, "layer": "persistent_load" if encoding else "welcome_decryption"})
            check(finished < prep["deadline"], "不能用目标材料过期代替私有bundle损坏")
            if not encoding:
                check(error["message"] == "Decryption failed.", "没有进入真实Welcome秘密解密")
                duplicate = stable(lab, phase + "-observe", lambda: lab.recovery(
                    lab.target, "observe", record=record))
                check(duplicate == {"duplicate": True, "installed": False}, "R0丢失或伪完成R1")
            check(stable(lab, phase + "-query", lambda: lab.get_recovery(intent)) == accepted,
                  "私有损坏改写了Service已接受原件")
            send_blocked(lab, phase, "key_package_storage" if encoding else "join_required")
            if encoding:
                stable(lab, phase + "-resume", lambda: lab.rust(lab.target, "consistency_resume",
                    head=prep["head"], expected_exit=1), code)
            else:
                before = state(lab)
                resume(lab, lab.target)
                after = state(lab)
                check(not_installed(lab, latest) == prep["target_r0"] and after["relay"] == before["relay"]
                      and all(after["snapshots"][d] == v for d, v in before["snapshots"].items()
                              if d != lab.target), "resume把损坏私钥伪装为R1")
                lab.case_evidence.setdefault("early_resumes", []).append({
                    "phase": phase, "before": before, "after": after,
                    "target": target_view(lab), "consistency": lab.rust(lab.target, "consistency_inspect")})
            send_blocked(lab, phase + "-resumed", "key_package_storage" if encoding else "join_required")
            stable(lab, phase + "-restart", lab.restart)
        pair(lab, "b1", "e10b-healthy-after-corruption")
        send_blocked(lab, "after-healthy-communication", "key_package_storage" if encoding else "join_required")
    check(time.time() < prep["deadline"] and recovery_ledger(lab) == ledger
          and original_facts(lab) == original, "材料到期或改写原事实/产生递归恢复")
    lab.case_evidence["completion"] = {"mode": mode,
        "expected": "installed" if mode == "intact" else "rejected",
        "target_state_observable": mode != "corrupt_encoding",
        "target": target_view(lab) if mode != "corrupt_encoding" else None,
        "healthy": healthy(lab), "durable": state(lab), "ledger": recovery_ledger(lab),
        "original_unchanged": True, "no_recursive_recovery": True,
        "finished_at_unix_secs": time.time(), "target_material_still_valid": True}


CASES = {
    "E10_private_bundle_intact": lambda lab: private_bundle(lab, "intact"),
    "E10_private_bundle_encoding_corrupt": lambda lab: private_bundle(lab, "corrupt_encoding"),
    "E10_private_bundle_init_key_corrupt": lambda lab: private_bundle(lab, "corrupt_init_key"),
}
