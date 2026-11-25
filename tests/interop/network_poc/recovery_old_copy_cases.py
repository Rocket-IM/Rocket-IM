"""E08.c：真实已加入旧副本、公开恢复记录和旧版本网络拒绝。"""

import base64
import hashlib
import json
import shutil

from .fixture import ACCOUNTS, CONVERSATION, check
from .first_trust_evidence import state
from .join_review_regressions import public_record
from .key_package_fixture import decode, transaction
from .recovery_retry_cases import communicate
from .recovery_watermark_cases import checkpoint, digest, facts, original_facts


def old_call(lab, operation, **fields):
    return lab.rust(lab.target, operation, directory=str(lab.old_copy), **fields)


def old_view(lab):
    raw = (lab.old_copy / "state.enc").read_bytes()
    return {"snapshot": {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)},
            "group": old_call(lab, "inspect"),
            "permission": old_call(lab, "permission_inspect"),
            "recovery": old_call(lab, "join_recovery", command={"kind": "inspect"}),
            "wire": old_call(lab, "wire_inspect"),
            "packages": old_call(lab, "key_package_inspect")["packages"]}


def all_facts(lab):
    return {"main": facts(lab), "old_copy": old_view(lab)}


def unchanged(lab, name, action, code=None):
    before = all_facts(lab)
    result = action()
    after = all_facts(lab)
    lab.case_evidence.setdefault("unchanged_steps", []).append({
        "name": name, "result": result, "before": before, "after": after})
    check(before == after, name + "改变主状态、旧副本或Relay账本")
    if code is not None:
        check(result["code"] == code, name + "未命中指定拒绝")
    return result


def create_joined_copy(lab):
    # 同一合成身份的独立旧副本；主目标始终未加入，不恢复或覆盖主快照。
    check(not lab.configs, "本用例不能让主副本共享独立锚")
    lab.old_copy = lab.directory / "joined-old-copy"
    before = state(lab)
    shutil.copytree(lab.directory / lab.target, lab.old_copy)
    joined = old_call(lab, "permission_join", **lab.original)
    rooted = old_call(lab, "join_recovery", command={"kind": "root", **lab.original})
    view = old_view(lab)
    admission = view["permission"]["admission"]
    cp = checkpoint(lab, lab.actor)
    lab.case_evidence["real_old_join"] = {"joined": joined, "rooted": rooted,
        "old_copy": view, "main_before": before, "main_after": state(lab)}
    check(joined["duplicate"] is False and view["group"]["active"]
          and view["group"]["group_id"] == lab.rust(lab.actor, "inspect")["group_id"]
          and str(view["group"]["epoch"]) == admission["joined_epoch"]
          and admission["joined_authorization_version"] == cp["authorization_version"]
          and admission["history_policy"] == "from_join"
          and view["permission"]["checkpoint"] == cp
          and sum(p["consumed"] for p in view["packages"].values()) == 1,
          "旧副本未真实完成普通加入或缺少原加入记录")
    check(state(lab) == before and lab.rust(lab.target, "inspect")["group_id"] is None
          and all(not p["consumed"] for p in lab.pool(lab.target)["packages"].values()),
          "创建旧副本改写主目标或消耗其私有材料")


def reject_public(lab, public, phase):
    unchanged(lab, phase + "-old-observe", lambda: old_call(lab, "join_recovery",
        command={"kind": "observe", "record": public}, expected_exit=1), "already_grouped")
    unchanged(lab, phase + "-old-apply", lambda: old_call(lab, "join_recovery",
        command={"kind": "apply", "record": public}, expected_exit=1), "recovery_observe_required")
    duplicate = unchanged(lab, phase + "-original-join-retry", lambda: old_call(
        lab, "permission_join", **lab.original))
    check(duplicate["duplicate"] is True, "旧副本原加入不再幂等")


def message_rows(lab):
    # 两张允许新增终态的表仍须逐行保护既有事实，包括原头、密文及所有列。
    with transaction(lab) as db:
        return {table: {json.dumps([row[k] for k in keys]): digest(dict(row))
                        for row in db.execute("SELECT * FROM " + table)}
                for table, keys in (("logical_messages", ("key",)),
                                    ("attempts", ("logical_key", "attempt_id")))}


def reject_stale_packet(lab, packet, latest):
    before = all_facts(lab)
    rows_before = message_rows(lab)
    rejected = lab.submit(packet, device=lab.target, expected=409)
    after = all_facts(lab)
    rows_after = message_rows(lab)
    old_tables = before["main"]["durable"]["relay"]["tables"]
    new_tables = after["main"]["durable"]["relay"]["tables"]
    changed = [t for t in old_tables if old_tables[t] != new_tables[t]]
    evidence = {"before": before, "after": after, "http_error": rejected,
        "rows_before": rows_before, "rows_after": rows_after,
        "changed_tables": changed,
        "contract": "首次仅持久拒绝终态；不是首次全表零写，精确重试须全表不变"}
    lab.case_evidence["first_service_rejection"] = evidence
    check(set(changed) == {"logical_messages", "attempts"}
          and all(new_tables[t]["rows"] == old_tables[t]["rows"] + 1 for t in changed),
          "旧版本首拒绝产生非预期写入或未保存拒绝终态")
    check(all(len(rows_after[t]) == len(rows_before[t]) + 1
              and all(rows_after[t].get(k) == v for k, v in rows_before[t].items())
              for t in rows_before), "首拒绝改写允许新增表中的既有行")
    check(before["old_copy"] == after["old_copy"]
          and before["main"]["durable"]["snapshots"] == after["main"]["durable"]["snapshots"]
          and all(before["main"][k] == after["main"][k] for k in ("permission", "consistency", "recovery")),
          "Service首拒绝改变客户端群或水位")
    check(rejected["code"] == "state_stale" and rejected["outcome"] == "rejected_final",
          "真实旧版本未被Service明确终态拒绝")
    header_raw = base64.b64decode(packet["envelope"]["header_bytes"])
    payload_raw = base64.b64decode(packet["envelope"]["payload_bytes"])
    with transaction(lab) as db:
        rows = db.execute("SELECT * FROM attempts WHERE header=?", (header_raw,)).fetchall()
        check(len(rows) == 1, "旧尝试不唯一")
        row = dict(rows[0])
        chain = dict(db.execute("SELECT * FROM logical_messages WHERE key=?", (row["logical_key"],)).fetchone())
    persisted = json.loads(row["result"])
    check(row["header"] == header_raw and row["payload"] == payload_raw
          and row["outcome"] == "rejected_final" and row["acceptance_id"] is None
          and row["successor"] is None and chain["accepted_attempt"] is None
          and row["compacted"] == 0 and row["payload_sha256"] is None and row["payload_size"] is None
          and chain["tail"] == row["attempt_id"] == "P1"
          and row["closure_id"] == rejected["closure_id"]
          and persisted == {k: v for k, v in rejected.items() if k != "message"},
          "旧尝试原字节/拒绝终态不符或意外接受")
    statement = decode(rejected["rejection_receipt"])
    check(statement["required_authorization_version"] == latest["authorization_version"]
          and statement["required_crypto_state_ref"] == latest["crypto_state_ref"],
          "拒绝证明未绑定真实最新检查点")
    for key in ("header", "payload"):
        raw = row[key]
        row[key] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    evidence.update(attempt=row, logical_chain=chain, statement=statement, persisted=persisted)
    return rejected, persisted


def old_copy(lab):
    lab.before_recovery_root = lambda: create_joined_copy(lab)
    lab.setup_expired()
    initial = old_view(lab)
    original = original_facts(lab)
    intent, _, _, bundle = lab.prepare_recovery("e08c-latest")
    accepted = lab.accept_recovery(bundle)
    lab.install_recovery(accepted["record"], ACCOUNTS)
    latest = checkpoint(lab, lab.actor)
    check(int(latest["authorization_version"]) == int(initial["permission"]["checkpoint"]["authorization_version"]) + 1,
          "恢复未产生唯一最新后继")
    page = unchanged(lab, "read-public-record", lambda: lab.http(lab.target, "get_permission_records",
        {"service_id": lab.service, "conversation_id": CONVERSATION,
         "after_version": initial["permission"]["checkpoint"]["authorization_version"], "limit": "1"}))
    public = page["records"][0]["recovery"]
    check(len(page["records"]) == 1 and public == public_record(accepted["record"])
          and set(public["bundle"]) == {"intent", "claim", "allocation", "change"},
          "未从真实HTTP取到无私有材料的公开记录")
    lab.case_evidence["latest_recovery"] = {"intent": intent, "accepted": accepted,
        "public_page": page, "checkpoint": latest}
    reject_public(lab, public, "before-latest-r1")
    check(old_view(lab) == initial and lab.rust(lab.target, "inspect")["group_id"] is None
          and lab.recovery(lab.target, "inspect")["installed_count"] == 0,
          "公开记录自动安装了任一目标R1")
    lab.install_recovery(accepted["record"], [lab.target])
    check(checkpoint(lab, lab.target) == latest
          and lab.recovery(lab.target, "inspect")["installed_count"] == 1
          and old_view(lab) == initial, "最新合法R1未安装或改写旧副本")
    reject_public(lab, public, "after-latest-r1")

    packet = old_call(lab, "wire_send", logical_message_id="e08c-real-old", attempt_id="P1",
                      payload="synthetic-e08c-old-version")
    header = json.loads(base64.b64decode(packet["envelope"]["header_bytes"]))
    old_cp = initial["permission"]["checkpoint"]
    check(not packet["reused"] and all(header[k] == old_cp[k] for k in ("authorization_version", "crypto_state_ref")),
          "旧包不是在公开恢复拒绝后由真实旧群生成")
    lab.case_evidence["real_old_packet"] = {"packet": packet, "header": header,
        "source": "旧副本正常wire_send；未改写头、密文或数据库"}
    rejected, persisted = reject_stale_packet(lab, packet, latest)
    before_proof = all_facts(lab)
    proof_result = old_call(lab, "wire_reject", logical_message_id="e08c-real-old", attempt_id="P1",
                            rejection_receipt=rejected["rejection_receipt"])
    after_proof = all_facts(lab)
    lab.case_evidence["verified_rejection"] = {"result": proof_result, "before": before_proof, "after": after_proof}
    check(proof_result["status"] == "rejected" and not proof_result["duplicate"]
          and proof_result["send_order"]["pending"]["status"] == "rejected_awaiting_checkpoint"
          and before_proof["main"] == after_proof["main"]
          and all(before_proof["old_copy"][k] == after_proof["old_copy"][k]
                  for k in ("group", "permission", "recovery", "packages")),
          "真实验签拒绝未保存、冒充R1或覆盖旧群")
    communicate(lab, "e08c-before-restart")
    for phase in ("after-communication", "after-restart"):
        if phase == "after-restart":
            unchanged(lab, "restart", lab.restart)
        reject_public(lab, public, phase)
        check(unchanged(lab, phase + "-old-submit", lambda: lab.submit(
            packet, device=lab.target, expected=409)) == rejected, "精确重试改变原拒绝")
        for operation in ("get_attempt", "close_attempt"):
            check(unchanged(lab, phase + "-" + operation, lambda op=operation: lab.http(lab.target, op,
                {"service_id": lab.service, "conversation_id": CONVERSATION,
                 "logical_message_id": "e08c-real-old", "attempt_id": "P1"})) == persisted,
                "查询或封口改写原拒绝终态")
        check(unchanged(lab, phase + "-local-rejection", lambda: old_call(lab, "wire_reject",
            logical_message_id="e08c-real-old", attempt_id="P1",
            rejection_receipt=rejected["rejection_receipt"])) == {**proof_result, "duplicate": True},
            "本地拒绝精确重试不幂等")
    communicate(lab, "e08c-after-restart")
    check(original_facts(lab) == original, "旧副本或后续消息改写原接受历史")
    final = old_view(lab)
    check(all(final[k] == initial[k] for k in ("permission", "recovery", "packages"))
          and final["recovery"]["installed_count"] == 0
          and checkpoint(lab, lab.target) == latest, "旧副本冒充最新R1或最新状态回退")
    lab.case_evidence["completion"] = {"old_copy": final, "main": facts(lab),
        "original_unchanged": True, "stage0": "NOT_COMPLETE"}


CASES = {"E08_real_joined_old_copy": old_copy}
