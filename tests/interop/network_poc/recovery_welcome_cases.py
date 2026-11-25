"""E08.a：新 Welcome 先到，旧原件迟到不能首次安装或覆盖最新 R1。"""

import json
import time

from .fixture import ACCOUNTS, check
from .first_trust_evidence import state
from .join_review_regressions import public_record
from .key_package_fixture import decode
from .recovery_close_cases import attempt_facts
from .recovery_retry_cases import communicate
from .recovery_watermark_cases import checkpoint, facts, original_facts, unchanged


def target_view(lab):
    return {"group": lab.rust(lab.target, "inspect"),
            "permission": lab.rust(lab.target, "permission_inspect"),
            "recovery": lab.recovery(lab.target, "inspect"),
            "packages": lab.pool(lab.target)["packages"]}


def not_installed(lab, latest):
    view = target_view(lab)
    admission = view["permission"]["admission"]
    check(view["group"]["group_id"] is None and view["group"]["epoch"] is None
          and view["permission"]["checkpoint"] is None and admission["joined_epoch"] is None
          and admission["joined_authorization_version"] is None and admission["history_policy"] is None
          and view["recovery"]["installed_count"] == 0
          and view["recovery"]["public_head"] == latest
          and all(not p["consumed"] for p in view["packages"].values()),
          "目标在真实安装前已经产生群、加入记录或消费材料")
    return view


def reject_old(lab, phase, first, installed):
    # 两条实际入口各自验准确门禁，不能用 Lifetime/解析错误充当替代拒绝。
    unchanged(lab, phase + "-old-recovery-welcome", lambda: lab.recovery(
        lab.target, "apply", record=first, expected_exit=1), "recovery_superseded")
    unchanged(lab, phase + "-original-invitation", lambda: lab.rust(
        lab.target, "permission_join", **lab.original, expected_exit=1),
        "already_grouped" if installed else "permission_version")


def welcome_order(lab):
    lab.setup_expired()
    original = original_facts(lab)
    original_checkpoint = checkpoint(lab, lab.actor)
    first_intent, _, _, first_bundle = lab.prepare_recovery("e08-first", package_ttl=12)
    first = lab.accept_recovery(first_bundle)
    lab.install_recovery(first["record"], ACCOUNTS)
    # 目标只接收公开R0；第一次恢复的私有Welcome延迟到最新R0之后直接输入。
    first_public = public_record(first["record"])
    lab.recovery(lab.target, "observe", record=first_public)
    first_checkpoint = checkpoint(lab, lab.actor)
    first_view = not_installed(lab, first_checkpoint)
    first_reference = first_view["recovery"]["roots"]["original-add"]
    first_ledger = attempt_facts(lab, first_intent)
    first_hash = decode(first_intent)["key_package_sha256"]
    deadline = int(first_view["packages"][first_hash]["material"]["not_after"])
    check(int(time.time()) < deadline, "首次R0未在有效材料期限内建立")
    lab.case_evidence["first_r0"] = {"intent": first_intent, "accepted": first,
        "target_public_record": first_public, "target": first_view, "ledger": first_ledger}
    while int(time.time()) < deadline:
        time.sleep(.1)
    lab.case_evidence["second_recovery_precondition"] = {
        "first_material_not_after": deadline, "observed_expired_at": time.time(),
        "scope": "真实到期仅用于合法第二次恢复；后续旧Apply必须命中superseded而非expiry"}

    second_intent, _, _, second_bundle = lab.prepare_recovery("e08-latest")
    second_value = decode(second_intent)
    check(second_value["current_admission"] == first_reference
          and second_value["root_admission"] == lab.root
          and second_value["predecessor"] == {k: first_checkpoint[k]
              for k in ("authorization_version", "crypto_state_ref")}, "第二恢复未接续唯一第一后继")
    second = lab.accept_recovery(second_bundle)
    lab.install_recovery(second["record"], ACCOUNTS)
    latest = checkpoint(lab, lab.actor)
    check(int(latest["authorization_version"]) == int(original_checkpoint["authorization_version"]) + 2,
          "两次真实接受没有准确推进版本")
    observed = lab.recovery(lab.target, "observe", record=second["record"])
    check(observed == {"duplicate": False, "installed": False}, "最新完整原件没有真实保存R0")
    lab.case_evidence["latest_r0"] = {"intent": second_intent, "accepted": second,
        "target": not_installed(lab, latest)}
    for phase in ("latest-r0-before-r1", "latest-r0-after-restart"):
        if phase.endswith("after-restart"):
            unchanged(lab, "restart-before-latest-r1", lab.restart)
        reject_old(lab, phase, first["record"], installed=False)
        check(unchanged(lab, phase + "-old-public-observe", lambda: lab.recovery(
            lab.target, "observe", record=first_public)) == {"duplicate": True, "installed": False},
            "旧公共R0重复改变端点或误认R1")
        unchanged(lab, phase + "-send", lambda: lab.rust(lab.target, "wire_send",
            logical_message_id=phase, attempt_id="P1", payload="synthetic-e08-blocked",
            expected_exit=1), "join_required")
        not_installed(lab, latest)

    before = state(lab)
    result = lab.recovery(lab.target, "apply", record=second["record"])
    after = state(lab)
    installed = target_view(lab)
    second_hash = second_value["key_package_sha256"]
    admission = installed["permission"]["admission"]
    check(result["duplicate"] is False and result["installed"] is True and result["checkpoint"] == latest
          and after["relay"] == before["relay"] and after["snapshots"][lab.target] != before["snapshots"][lab.target]
          and all(after["snapshots"][d] == s for d, s in before["snapshots"].items() if d != lab.target),
          "首次最新R1未持久安装，或改写Relay/其他客户端")
    check(installed["group"]["active"] and installed["group"]["group_id"] == second_value["scope"]["group_id"]
          and str(installed["group"]["epoch"]) == result["epoch"] == admission["joined_epoch"]
          and installed["permission"]["checkpoint"] == latest
          and admission["joined_authorization_version"] is None and admission["history_policy"] is None
          and installed["recovery"]["installed_count"] == 1
          and all(p["consumed"] == (h == second_hash) for h, p in installed["packages"].items())
          and all(lab.recovery(d, "inspect")["installed_count"] == 2 for d in ACCOUNTS),
          "目标误装旧R1、覆盖加入记录，或消费了旧材料")
    lab.case_evidence["latest_r1"] = {"result": result, "before": before, "after": after, "target": installed}
    communicate(lab, "e08-before-restart")

    for phase in ("after-communication", "after-restart"):
        if phase == "after-restart":
            unchanged(lab, "restart-after-communication", lab.restart)
        reject_old(lab, phase, first["record"], installed=True)
        for suffix, record in (("full", second["record"]), ("public", public_record(second["record"]))):
            duplicate = unchanged(lab, phase + "-latest-apply-" + suffix, lambda r=record: lab.recovery(
                lab.target, "apply", record=r))
            check(duplicate == {"duplicate": True, "installed": True, "checkpoint": latest},
                  "最新原件精确重试未保持当前R1")
        check(unchanged(lab, phase + "-latest-observe", lambda: lab.recovery(lab.target, "observe",
            record=second["record"])) == {"duplicate": True, "installed": True}, "重复最新R0回退安装状态")
        check(unchanged(lab, phase + "-old-root", lambda: lab.recovery(lab.target, "root", **lab.original))
              == {"reference": lab.root, "duplicate": True}, "旧根重复回退当前端点")
        check(target_view(lab)["permission"]["admission"] == admission, "乱序输入改写实际加入记录")
    communicate(lab, "e08-after-restart")
    for name, bundle, expected in (("first", first_bundle, {**first, "head": latest}),
                                   ("latest", second_bundle, second)):
        check(unchanged(lab, name + "-accepted-exact", lambda b=bundle: lab.accept_recovery(b)) == expected,
              "旧新接受精确重试改写原件或生成第三个Commit")
    final = attempt_facts(lab, first_intent)
    check(all(final[k] == first_ledger[k] for k in ("attempt", "material", "requests"))
          and final["edges"][:1] == first_ledger["edges"] and original_facts(lab) == original,
          "新恢复或乱序输入改写旧accepted、材料、后继或原消息")
    counts = {"recovery_attempts": 2, "recovery_requests": 4, "recovery_edges": 2,
              "recovery_roots": 1, "recovery_active": 0, "permission_changes": 3,
              "permission_resolutions": 3, "kp_materials": 3}
    tables = state(lab)["relay"]["tables"]
    check(all(tables[t]["rows"] == n for t, n in counts.items())
          and final["attempt"]["state"] == final["material"]["state"] == "accepted"
          and json.loads(final["edges"][1]["current_ref"]) == first_reference
          and final["edges"][1]["recovery_id"] == second_value["request_id"]
          and final["roots"][0]["current_ref"] == final["edges"][1]["successor_ref"],
          "旧记录被关闭/释放，或接受后继不唯一")
    lab.case_evidence["completion"] = {"expected_counts": counts, "first_ledger": final,
        "original_before": original, "original_after": original_facts(lab),
        "target": target_view(lab), "final_state": facts(lab)}


CASES = {"E08_old_new_welcome_order": welcome_order}
