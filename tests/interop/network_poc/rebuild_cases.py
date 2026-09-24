"""Q05 新身份、新通信范围及唯一后继的跨进程验收。"""

import base64
import copy
from concurrent.futures import ThreadPoolExecutor
import json
import secrets

from .anchor_fixture import sha256
from .fixture import check
from .rebuild_fixture import changed_bytes
from .rebuild_states import pause_state


def prepared(lab):
    lab.unresolved(); lab.offer(); lab.approve()


def old_blocked(lab):
    before = lab.snapshot().read_bytes()
    for operation, fields in (("send", {"id": "unresolved", "payload": "synthetic-anchor-unresolved"}),
                              ("wire_send", {"logical_message_id": "old_must_block", "attempt_id": "P1",
                                             "payload": "synthetic-old-must-block"}),
                              ("anchor_resume", {})):
        lab.blocked(operation=operation, **fields)
    check(lab.snapshot().read_bytes() == before, "拒绝旧范围时修改了旧密码快照")


def normal(lab):
    lab.complete()
    plan = lab.plan
    check(plan["successor_scope"]["identity_key"] != plan["old_scope"]["identity_key"]
          and plan["successor_scope"]["device"] != plan["old_scope"]["device"]
          and plan["successor_scope"]["store_id"] != plan["old_scope"]["store_id"],
          "重建复用了旧设备身份或存储范围")
    check(plan["successor_head"] != plan["old_head"], "新密码快照错误复用旧完整状态")
    current = lab.rust("successor", "inspect")
    check(current["group_id"] != lab.old_inspect["group_id"], "Welcome 得到旧群发送状态")
    check(lab.rust("a1", "anchor_inspect")["status"] == "sealed", "旧范围缺少永久封存诊断")
    check(lab.blocked(operation="anchor_resume")["code"] == "anchor_sealed", "已封存旧范围恢复未明确拒绝")
    old_blocked(lab)
    lab.communicate(); lab.communicate("reply", sender="source", receiver="successor")
    lab.restore(lab.old_backup, lab.directory / "a1")
    old_blocked(lab)
    check(lab.snapshot().read_bytes() == lab.old_state, "恢复旧完整副本后密码文件被重建改写")
    lab.evidence["fresh_identity"] = {"device_id": plan["successor_scope"]["device"],
                                      "old_and_new_identity_distinct": True,
                                      "new_group_real_decryption": "both_directions",
                                      "old_full_snapshot_restore": "still_blocked"}


def candidate_gate(lab):
    lab.unresolved(); offered = lab.offer()
    old_blocked(lab)
    before = lab.snapshot("successor").read_bytes()
    for _ in range(2):
        check(lab.rust("successor", "rebuild_offer")["plan"] == offered["plan"],
              "候选重试没有复用原公开计划")
        check(lab.snapshot("successor").read_bytes() == before, "公开计划查询重写了密码状态")
    for operation, fields in (("init", {}), ("inspect", {}),
                              ("create", {"peers": []}),
                              ("send", {"id": "candidate", "payload": "synthetic"})):
        lab.blocked("successor", operation, **fields)
    lab.rust("successor", "rebuild_init", template=offered["plan"], expected_exit=1)
    lab.configure_successor()
    lab.blocked("successor", "wire_send", logical_message_id="not_linked", attempt_id="P1", payload="synthetic")
    check(lab.snapshot("successor").read_bytes() == before, "关联前调用改变了有效候选")


def scope_binding(lab):
    prepared(lab)
    authority = lab.materials["a1"]["authority"] / "state.enc"
    before = authority.read_bytes()
    tested = []
    for scope_name in ("old_scope", "successor_scope"):
        for field in ("service", "account", "device", "identity_key", "store_id"):
            plan = copy.deepcopy(lab.plan)
            plan[scope_name][field] = "ab" * 32 if field in ("identity_key", "store_id") else "different"
            lab.link(plan=plan, expected_exit=1)
            check(authority.read_bytes() == before, "交叉范围授权更改了独立锚")
            tested.append(scope_name + "." + field)
    for field in ("old_head", "old_txn", "anchor_public_key", "successor_head",
                  "successor_client_public_key", "key_package_sha256", "rebuild_id"):
        plan = copy.deepcopy(lab.plan); plan[field] = "cd" * 32
        lab.link(plan=plan, expected_exit=1)
        check(authority.read_bytes() == before, "交叉关联材料更改了独立锚")
        tested.append(field)
    for field, value in (("old_revision", "99"), ("old_conversation_id", "other_group"),
                         ("old_group_id", base64.b64encode(b"other-real-group").decode())):
        plan = copy.deepcopy(lab.plan); plan[field] = value
        lab.link(plan=plan, expected_exit=1)
        check(authority.read_bytes() == before, "旧群/修订号替换更改独立锚")
        tested.append(field)
    lab.link()
    lab.evidence["rejected_plan_substitutions"] = tested


def approval_binding(lab):
    prepared(lab)
    bad = copy.deepcopy(lab.approval)
    bad["signature_bytes"] = changed_bytes(bad["signature_bytes"])
    before = lab.snapshot().read_bytes()
    lab.link(approval=bad, expected_exit=1)
    source_before = lab.backup("source-invalid-input-baseline", lab.directory / "source")
    source_authority = lab.materials["source"]["authority"]
    anchor_before = lab.backup("source-anchor-invalid-input-baseline", source_authority)
    def rejected(plan):
        # 独立错误输入各用同一初始fixture，不能让前次失败的门禁遮盖本次语义校验。
        lab.restore(source_before, lab.directory / "source")
        lab.restore(anchor_before, source_authority)
        error = lab.rust("source", "rebuild_approve", plan=plan, expected_exit=1)
        check(error["code"] != "anchor_paused", "上一次暂停遮盖本次真实批准边界")
    for scope_field in ("service", "account"):
        plan = copy.deepcopy(lab.plan); plan["successor_scope"][scope_field] = "other"
        rejected(plan)
    plan = copy.deepcopy(lab.plan)
    plan["successor_scope"]["identity_key"] = plan["old_scope"]["identity_key"]
    rejected(plan)
    plan = copy.deepcopy(lab.plan)
    plan["trust"]["authorizer"]["signature_key"] = lab.public["source_peer"]["signature_key"]
    rejected(plan)
    check(lab.snapshot().read_bytes() == before, "错误批准覆盖旧状态")
    lab.link()


def successor_race(lab):
    prepared(lab)
    first = (copy.deepcopy(lab.plan), copy.deepcopy(lab.approval))
    lab.identities["second"] = {"account_id": "alice", "device_id": "rebuild_" + secrets.token_hex(16)}
    lab.offer("second"); lab.approve()
    second = (copy.deepcopy(lab.plan), copy.deepcopy(lab.approval))
    clone = lab.backup("racing-old-clone", lab.directory / "a1")
    values = ((first, "successor", lab.directory / "a1"), (second, "second", clone))
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda item: lab.raw_rust("a1", "anchor_rebuild", directory=item[2],
            plan=item[0][0], approval=item[0][1], successor_directory=str(lab.directory / item[1])), values))
    check(sum(r.returncode == 0 for r in results) == 1, "同一旧范围并发产生两个有效后继")
    winner = next(i for i, r in enumerate(results) if r.returncode == 0)
    winning, alias, _ = values[winner]
    losing, loser_alias, _ = values[1 - winner]
    lab.plan, lab.approval = winning
    lab.configure_successor(alias)
    lab.configure_successor(loser_alias, losing[0])
    lab.blocked(loser_alias, "permission_device_join_anchor", checkpoint=lab.trust["checkpoint"],
                relay_receipt_key=lab.relay_receipt_key)
    lab.rust(alias, "permission_join", **lab.joining(alias))
    lab.communicate("race_winner", sender=alias)
    lab.evidence["valid_successors"] = 1


def clone_race(lab):
    lab.complete()
    clone = lab.backup("new-clone", lab.directory / "successor")
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda p: lab.raw_rust("successor", "wire_send", directory=p,
            logical_message_id="clone_race", attempt_id="P1", payload="synthetic-clone-race"),
            (lab.directory / "successor", clone)))
    check(sum(r.returncode == 0 for r in results) == 1, "重建后两个完整克隆同时消费密码状态")
    packet = json.loads(next(r.stdout for r in results if r.returncode == 0))["result"]
    lab.rust("source", "wire_receive", **packet["envelope"])
    lab.evidence["child_clone_winners"] = 1


def exact_link_retry(lab):
    lab.complete(); packet = lab.communicate("exact_retry")
    saved = lab.snapshot("successor").read_bytes()
    authority = lab.materials["a1"]["authority"] / "state.enc"
    head = authority.read_bytes()
    for _ in range(3):
        lab.link()
        check(lab.snapshot("successor").read_bytes() == saved and authority.read_bytes() == head,
              "重复关联重置新设备状态或独立锚")
    repeated = lab.rust("successor", "wire_send", logical_message_id="exact_retry", attempt_id="P1",
                        payload="synthetic-rebuild-exact_retry")
    check(repeated["envelope"] == packet["envelope"], "关联重试导致重复生成已存密文")


def cancel(lab):
    prepared(lab)
    authority = lab.materials["a1"]["authority"] / "state.enc"
    unlinked = authority.read_bytes()
    lab.rust("a1", "anchor_rebuild_cancel", plan=lab.plan, approval=lab.approval, expected_exit=1)
    check(authority.read_bytes() == unlinked, "未关联取消创建或消耗了后继")
    lab.link(); lab.configure_successor()
    lab.rust("a1", "anchor_rebuild_cancel", plan=lab.plan, approval=lab.approval)
    check(lab.link()["cancelled"], "取消后迟到关联没有返回已取消事实")
    check(lab.rust("a1", "anchor_inspect")["status"] == "sealed", "取消后旧范围不再显示封存")
    check(lab.rust("successor", "anchor_inspect")["status"] == "cancelled", "后继缺少永久取消诊断")
    check(lab.blocked("successor", "anchor_resume")["code"] == "anchor_sealed",
          "已取消后继恢复未明确拒绝")
    old_blocked(lab)
    lab.blocked("successor", "permission_device_join_anchor", checkpoint=lab.trust["checkpoint"],
                relay_receipt_key=lab.relay_receipt_key)
    lab.restore(lab.old_backup, lab.directory / "a1")
    old_blocked(lab)
    check(lab.link()["cancelled"], "完整旧副本恢复后取消事实丢失")
    lab.identities["second"] = {"account_id": "alice", "device_id": "rebuild_" + secrets.token_hex(16)}
    lab.offer("second"); lab.approve()
    lab.link(alias="second", expected_exit=1)
    lab.configure_successor("second")
    lab.blocked("second", "permission_device_join_anchor", checkpoint=lab.trust["checkpoint"],
                relay_receipt_key=lab.relay_receipt_key)
    lab.evidence["cancel"] = "old_scope_and_only_successor_permanently_disabled"


def history_boundary(lab):
    old_packet = lab.rust("b1", "wire_send", logical_message_id="old_history", attempt_id="P1", payload="synthetic-old")
    receipt = lab.message_receipt(old_packet, "old_accepted")
    page = {"stream_id": "old_rebuild_stream", "next_after_seq": "1", "watermark": "1", "has_more": False,
            "events": [{"stream_id": "old_rebuild_stream", "event_seq": "1", "event_id": "old_event",
                        "availability": "available", "event": {"type": "message", "acceptance_id": "old_accepted",
                        "envelope": old_packet["envelope"], "acceptance_receipt": receipt}}]}
    lab.download("a1", lab.sign_test_page(page, device="a1"))
    lab.rust("a1", "wire_process")
    prior = lab.rust("a1", "wire_inspect")
    check(prior["inbox_count"] == 1 and prior["sync"]["processed_cursor"] == "1",
          "旧装置没有真实已解密消息与已推进游标")
    lab.complete()
    wire = lab.rust("successor", "wire_inspect")
    history = lab.rust("successor", "history_inspect")
    check(wire["history"]["past_epochs"] == [] and wire["inbox_count"] == 0
          and wire["outbox_count"] == 0 and wire["accepted_outbox_count"] == 0,
          "新设备自动继承了旧历史钥或消息副本")
    check(wire["sync"]["download_cursor"] == "0" and wire["sync"]["processed_cursor"] == "0",
          "新设备继承旧消息游标")
    child = lab.backup("history-negative-child", lab.directory / "successor")
    authority_path = lab.materials["a1"]["authority"]
    anchor = lab.backup("history-negative-anchor", authority_path)
    error = lab.blocked("successor", "history_request", transfer_id="no_implicit_history",
                        source=lab.identities["source"], selection=[{"acceptance_id": "old_accepted",
                        "envelope_sha256": "0" * 64}])
    check(error["code"] == "rebuild_history_disabled", "新身份隐式获得历史迁移权限")
    lab.restore(child, lab.directory / "successor")
    lab.restore(anchor, authority_path)
    lab.blocked("successor", "wire_receive", **old_packet["envelope"],
                acceptance_id="old_accepted", acceptance_receipt=receipt)
    lab.restore(child, lab.directory / "successor")
    lab.restore(anchor, authority_path)
    before = lab.snapshot("successor").read_bytes()
    error = lab.blocked("successor", "wire_download", **page)
    check(error["code"] == "rebuild_sync_unavailable" and lab.snapshot("successor").read_bytes() == before,
          "未授权的旧设备流没有明确拒绝或改变了新游标")
    lab.evidence["new_history_state"] = history
    lab.evidence["old_ciphertext"] = "rejected_without_importing_old_keys"
    lab.evidence["old_processed_cursor"] = "1"


def missing_trust(lab):
    lab.unresolved(trust=False); lab.offer(); lab.approve()
    lab.link(expected_exit=1)
    old_blocked(lab)


def old_pause(lab, kind):
    operation, state = pause_state(lab, kind)
    prepared(lab)
    before = lab.snapshot().read_bytes()
    lab.link(expected_exit=1)
    check(lab.snapshot().read_bytes() == before, "重建清除了旧 Q02/权限证据")
    old_blocked(lab)
    lab.restore(lab.old_backup, lab.directory / "a1")
    old_blocked(lab); lab.link(expected_exit=1)
    check(lab.snapshot().read_bytes() == before, "完整旧副本恢复后重建覆盖原暂停证据")
    lab.evidence["preserved_old_state"] = {"operation": operation, "value": state}


def source_pause(lab, kind):
    lab.unresolved(); lab.offer()
    operation, state = pause_state(lab, kind, source=True)
    before = lab.snapshot("source").read_bytes()
    lab.rust("source", "rebuild_approve", plan=lab.plan, expected_exit=1)
    check(lab.snapshot("source").read_bytes() == before, "失败批准改写源端已知暂停")
    check(lab.rust("source", "anchor_inspect")["paused"], "源端批准失败没有保留独立锚门禁")
    lab.evidence["preserved_source_state"] = {"operation": operation, "value": state}


def bounded(lab):
    prepared(lab)
    authority = lab.materials["a1"]["authority"] / "state.enc"
    before = authority.read_bytes()
    oversized = copy.deepcopy(lab.plan)
    oversized["rebuild_id"] = "a" * (32 * 1024)
    lab.link(plan=oversized, expected_exit=1)
    check(authority.read_bytes() == before, "超限计划更改独立锚")
    lab.link(); lab.configure_successor()
    capture = lab.forwarding_helper("capture", "inspect", "successor")
    lab.rust("successor", "anchor_inspect")
    lab.config_restore("successor")
    request = json.loads(capture.read_text())["request"]
    encoded = json.dumps(request)
    raw = encoded + " " * (32768 - len(encoded.encode()))
    accepted = lab.anchor(request, raw=raw)
    check(len(raw.encode()) == 32768 and accepted.get("response"), "合法签名请求32KiB正边界失败")
    error = lab.anchor(request, raw=raw + " ", expected_exit=1)
    check(error["code"] == "anchor_invalid", "32769字节请求未在真实输入边界拒绝")
    check(authority.stat().st_size <= 16 * 1024 + 37, "old+child 固定状态超过既定锚状态上限")
    check(len(list(authority.parent.iterdir())) <= 8, "重建创建无界独立目录文件")
    lab.evidence["bounded_anchor"] = {"state_bytes": authority.stat().st_size,
                                      "directory_entries": len(list(authority.parent.iterdir())),
                                      "valid_signed_request_32768": "PASS",
                                      "valid_signed_request_32769": "REJECTED",
                                      "oversize_rejected": True}
