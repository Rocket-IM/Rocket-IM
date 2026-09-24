"""同账号已接收历史的定向副本；复用公开设备加入和原消息接受流程。"""

import base64
import copy
import hashlib
import json
import sqlite3

from .device_join_cases import join_device, no_old_history, prepare_device, setup
from .fixture import ACCOUNTS, CONVERSATION, SERVICE, check, identity
from .history_cases import publish, receive_record
from .join_cases import accept_add, mutate_bytes
from .permission_cases import reject_unchanged
from .permission_recovery_cases import recover


def statement(record):
    return json.loads(base64.b64decode(record["statement_bytes"]))


def selection(records):
    return sorted(({"acceptance_id": accepted["acceptance_id"],
                    "envelope_sha256": statement(accepted["acceptance_receipt"])["envelope_sha256"]}
                   for _, accepted in records), key=lambda item: item["acceptance_id"])


def joined(lab, count=1, receive=True):
    old = [publish(lab, "migration_old_" + str(i)) for i in range(count)]
    if receive:
        for record in old:
            receive_record(lab, "b1", record)
    setup(lab)
    added = accept_add(lab, prepare_device(lab, "migration_device_join"), "b1")
    recover(lab, added, *ACCOUNTS)
    join_device(lab, "migration_device_join")
    return old


def request(lab, ident, records, **options):
    return lab.rust("b2", "history_request", transfer_id=ident, source=identity("b1"),
                    selection=selection(records), **options)


def export(lab, signed, **options):
    return lab.rust("b1", "history_export", request=signed, **options)


def submit(lab, bundle, device="b1", **options):
    return lab.http(device, "submit_history_transfer", {"service_id": SERVICE,
                    "conversation_id": CONVERSATION, **{k: bundle[k] for k in ("request", "package")}}, **options)


def get(lab, ident, device="b2", **options):
    return lab.http(device, "get_history_transfer", {"service_id": SERVICE,
                    "conversation_id": CONVERSATION, "transfer_id": ident}, **options)


def prepared(lab, ident, records, **options):
    return export(lab, request(lab, ident, records, **options)["request"])


def transfer_count(lab):
    with sqlite3.connect(lab.directory / "relay.sqlite") as db:
        return db.execute("SELECT COUNT(*) FROM history_transfers").fetchone()[0]


def selected_copies(lab):
    old = joined(lab, 3)
    for record in old:
        no_old_history(lab, record)
    before = {d: lab.rust(d, "wire_inspect") for d in ("b1", "b2")}
    roster = lab.rust("b2", "inspect")["roster_version"]
    stats = lab.control("stats")
    bundle = prepared(lab, "selected_history", old[:2])
    accepted = submit(lab, bundle)
    check(get(lab, "selected_history") == accepted, "定向领取改写了原请求、包或回执")
    result = lab.rust("b2", "history_import", **accepted)
    check(result["imported_count"] == 2 and not result["duplicate"], "选中历史未整体导入")
    copies = lab.rust("b2", "history_inspect")["copies"]
    expected = {"migration_old_" + str(i): hashlib.sha256(("synthetic-history-migration_old_" + str(i)).encode()).hexdigest()
                for i in range(2)}
    check({c["logical_message_id"]: c["payload_sha256"] for c in copies} == expected
          and all(c["source"] == identity("b1") and c["provenance"] == "source_authenticated_copy" for c in copies),
          "副本越过选择范围或错误声明为原发送者证明")
    check(lab.control("stats") == stats and all(lab.rust(d, "wire_inspect") == before[d] for d in before)
          and lab.rust("b2", "inspect")["roster_version"] == roster,
          "导入副本改变了原流、游标、密码状态或全局设备信任")
    with sqlite3.connect(lab.directory / "relay.sqlite") as db:
        persisted = json.dumps(db.execute("SELECT request,package,receipt FROM history_transfers").fetchall())
    check("synthetic-history-migration_old" not in persisted, "Service 迁移记录包含明文")
    checkpoint = lab.rust("b1", "permission_inspect")["checkpoint"]
    lab.public_fixture_directory.mkdir(parents=True, exist_ok=True)
    (lab.public_fixture_directory / "history-transfer-public-fixture.json").write_text(json.dumps(
        {"checkpoint": checkpoint, **accepted}, indent=2))
    receive_record(lab, "a1", publish(lab, "after_copy_new_device", "b2"))
    receive_record(lab, "b2", publish(lab, "after_copy_existing_device"))


def authority(lab):
    old = joined(lab)
    for device, source in (("b2", "b2"), ("b2", "a1"), ("a1", "b1"), ("a3", "a1")):
        reject_unchanged(lab, device, "history_request", transfer_id="invalid_target",
                         source=identity(source), selection=selection(old))
    bundle = prepared(lab, "bound_authority", old)
    for device in ("a1", "a2", "b2", "c1"):
        submit(lab, bundle, device, expected=403)
    for device in ("a1", "a2", "b2", "c1"):
        reject_unchanged(lab, device, "history_export", request=bundle["request"])
    for name, value in (("service_id", "other_service"), ("conversation_id", "other_group")):
        fields = {"service_id": SERVICE, "conversation_id": CONVERSATION,
                  "request": bundle["request"], "package": bundle["package"], name: value}
        lab.http("b1", "submit_history_transfer", fields, expected=(403, 409))
    check(transfer_count(lab) == 0, "越权请求部分保存了迁移记录")
    accepted = submit(lab, bundle)
    for device in ("a1", "a2", "b1", "c1"):
        get(lab, "bound_authority", device, expected=403)
        reject_unchanged(lab, device, "history_import", **accepted)
    lab.rust("b2", "history_import", **get(lab, "bound_authority"))


def tampering(lab):
    old = joined(lab)
    bundle = prepared(lab, "tamper_history", old)
    variants = []
    for kind, fields in (("request", ("signature_bytes", "statement_bytes")),
                        ("package", ("signature_bytes", "statement_bytes", "kem_output", "ciphertext"))):
        for field in fields:
            bad = copy.deepcopy(bundle)
            bad[kind][field] = mutate_bytes(bad[kind][field])
            variants.append(bad)
            submit(lab, bad, expected=(400, 403, 409))
    check(transfer_count(lab) == 0, "失败的证明或密文留下 Service 接受记录")
    accepted = submit(lab, bundle)
    for bad in variants:
        reject_unchanged(lab, "b2", "history_import", request=bad["request"],
                         package=bad["package"], receipt=accepted["receipt"])
    bad = copy.deepcopy(accepted)
    bad["receipt"]["signature_bytes"] = mutate_bytes(bad["receipt"]["signature_bytes"])
    reject_unchanged(lab, "b2", "history_import", **bad)
    second = submit(lab, prepared(lab, "different_history_request", old))
    reject_unchanged(lab, "b2", "history_import", **{**accepted, "request": second["request"]})
    reject_unchanged(lab, "b2", "history_import", **{**accepted, "receipt": second["receipt"]})
    check(lab.rust("b2", "history_inspect")["imported_count"] == 0, "拒绝前部分写入副本")
    check(lab.rust("b2", "history_import", **accepted)["imported_count"] == 1, "错误包消耗了有效接收钥")


def exact_retry_and_overlap(lab):
    old = joined(lab, 3)
    first = request(lab, "stable_history", old[:2])
    check(request(lab, "stable_history", old[:2]) == {**first, "reused": True}, "请求重试更换了密钥或原字节")
    reject_unchanged(lab, "b2", "history_request", transfer_id="stable_history", source=identity("b1"), selection=selection(old))
    bundle = export(lab, first["request"])
    check(export(lab, first["request"]) == {**bundle, "reused": True}, "导出重试重新加密了副本")
    accepted = submit(lab, bundle)
    reordered = {name: dict(reversed(list(bundle[name].items()))) for name in ("request", "package")}
    lab.restart()
    check(submit(lab, reordered) == accepted, "JSON容器字段顺序改变了原字节重试语义")
    result = lab.rust("b2", "history_import", **accepted)
    retry = lab.rust("b2", "history_import", **accepted)
    check(result["imported_count"] == 2 and retry["duplicate"] and retry["imported_count"] == 0,
          "完整导入重试增加了副本或错误报告新增数")
    overlap = submit(lab, prepared(lab, "overlap_history", old[1:]))
    check(lab.rust("b2", "history_import", **overlap)["imported_count"] == 1
          and lab.rust("b2", "history_inspect")["imported_count"] == 3, "跨迁移原消息没有去重")
    check(transfer_count(lab) == 2, "精确重试创建了额外迁移记录")


def source_evidence(lab):
    old = joined(lab, 2, receive=False)
    signed = request(lab, "missing_received_content", old)["request"]
    reject_unchanged(lab, "b1", "history_export", request=signed)
    # 跨 epoch 收取尚未接收的旧消息必须提供原接受签名。
    reject_unchanged(lab, "b1", "wire_receive", **old[0][0]["envelope"])
    for record in old:
        receive_record(lab, "b1", record)
    accepted = submit(lab, export(lab, signed))
    lab.rust("b2", "history_import", **accepted)
    current = publish(lab, "receipt_to_attach")
    lab.receive("b1", current[0])
    missing = request(lab, "attach_acceptance_evidence", [current])["request"]
    reject_unchanged(lab, "b1", "history_export", request=missing)
    check(lab.rust("b1", "history_inspect")["missing_receipt_count"] == 1, "无签名接收凭空产生接受证明")
    check(receive_record(lab, "b1", current)["duplicate"], "精确重放补接受证明生成了重复消息")
    lab.rust("b2", "history_import", **submit(lab, export(lab, missing)))
    own = publish(lab, "source_sent_not_received", "b1")
    signed_own = request(lab, "sent_queue_excluded", [own])["request"]
    reject_unchanged(lab, "b1", "history_export", request=signed_own)
    check(lab.rust("b2", "history_inspect")["imported_count"] == 3, "发送队列自动成为可导出历史")
