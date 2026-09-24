"""M11.a：双方先合法收发，再双向交叉凭证、实例、游标、回执及密码材料。"""

from .fixture import ACCOUNTS, CONVERSATION, check
from .isolation_storage_cases import storage
from .isolation_support import reject_http, reject_rust, round_trip
from .slot_support import delivery_for
from .sync_support import TARGETS

LOGICAL = "shared_message"


def credentials(pair):
    for source_label, source, target_label, target in pair.directions():
        own = pair.records[target_label][LOGICAL]
        for device in ACCOUNTS:
            for operation, fields in (("pull_events", {"service_id": target.service, "after_seq": "0", "limit": "100"}),
                                      ("get_attempt", {"service_id": target.service, "conversation_id": CONVERSATION,
                                                       "logical_message_id": LOGICAL, "attempt_id": "P1"})):
                reject_http(pair, target, device, operation, fields, status=401, code="unauthenticated",
                            token=source.tokens[device], label=f"{source_label}->{target_label}:{device}:token:{operation}")
        reject_http(pair, target, "a1", "submit_message", {"envelope": own["packet"]["envelope"]},
                    status=401, code="unauthenticated", token=source.tokens["a1"], label=f"{target_label}:foreign_token_submit")
        for device in TARGETS:
            candidate = delivery_for(own["slots"][device])
            reject_http(pair, target, device, "report_delivery", {"service_id": target.service, **candidate},
                        status=401, code="unauthenticated", token=source.tokens[device], label=f"{target_label}:{device}:foreign_token_delivery")


def service_scope(pair):
    for source_label, source, target_label, target in pair.directions():
        foreign = pair.records[source_label][LOGICAL]
        for device in ACCOUNTS:
            reject_http(pair, target, device, "pull_events", {"service_id": source.service, "after_seq": "0", "limit": "100"},
                        status=403, code="permission_denied", label=f"{target_label}:{device}:foreign_service")
        for operation in ("get_attempt", "close_attempt"):
            reject_http(pair, target, "a1", operation, {"service_id": source.service, "conversation_id": CONVERSATION,
                        "logical_message_id": LOGICAL, "attempt_id": "P1"}, status=403, code="permission_denied",
                        label=f"{target_label}:foreign_service:{operation}")
        reject_http(pair, target, "a1", "submit_message", {"envelope": foreign["packet"]["envelope"]},
                    status=403, code="permission_denied", label=f"{target_label}:foreign_envelope_submit")
        before = pair.capture()
        # 同名查询应该返回自己的记录；不能要求合法的相同字符串ID一律被拒。
        value = target.attempt(LOGICAL)
        check(value == pair.records[target_label][LOGICAL]["accepted"] and value != foreign["accepted"],
              "同名ID查询串入外实例接受事实")
        pair.unchanged(before, f"{target_label}:same_name_query_own_result")


def cursors(pair):
    for source_label, source, target_label, target in pair.directions():
        for device in ACCOUNTS:
            foreign_page = source.pull(device)
            reject_http(pair, target, device, "pull_events", {"service_id": target.service,
                        "stream_id": foreign_page["stream_id"], "after_seq": "0", "limit": "100"},
                        status=409, code="cursor_invalid", label=f"{target_label}:{device}:foreign_stream_http")
            reject_rust(pair, target, device, "wire_download_signed", foreign_page.signed_input(), code="stream_page_signature",
                        label=f"{target_label}:{device}:foreign_page_bound_stream")
            before = pair.capture()
            cursor = target.rust(device, "wire_inspect")["sync"]["download_cursor"]
            own = target.pull(device, cursor)
            check(own["events"] == [] and own["next_after_seq"] == cursor
                  and own["stream_id"] != foreign_page["stream_id"], "同值序号未按本实例流解释")
            pair.unchanged(before, f"{target_label}:{device}:numeric_cursor_uses_own_stream")


def receipts(pair):
    for source_label, source, target_label, target in pair.directions():
        foreign = pair.records[source_label][LOGICAL]
        own = pair.records[target_label][LOGICAL]
        for device in TARGETS:
            original = delivery_for(own["slots"][device])
            for variant, candidate in (("foreign_acceptance", delivery_for(foreign["slots"][device])),
                                       ("foreign_event", {**original, "event_id": foreign["slots"][device]["event_id"]})):
                reject_http(pair, target, device, "report_delivery", {"service_id": target.service, **candidate},
                            status=403, code="permission_denied", label=f"{target_label}:{device}:{variant}")
            reject_http(pair, target, device, "report_read", {"service_id": target.service,
                        "acceptance_ids": [own["accepted"]["acceptance_id"], foreign["accepted"]["acceptance_id"]]},
                        status=403, code="permission_denied", label=f"{target_label}:{device}:mixed_read_batch_atomic")


def crypto_material(pair):
    for source_label, source, target_label, target in pair.directions():
        foreign = pair.records[source_label][LOGICAL]
        own = pair.records[target_label][LOGICAL]
        fields = {**own["packet"]["envelope"], "acceptance_id": own["accepted"]["acceptance_id"],
                  "acceptance_receipt": own["accepted"]["acceptance_receipt"]}
        for device in TARGETS:
            variations = (
                ("foreign_envelope", {**foreign["packet"]["envelope"], "acceptance_id": foreign["accepted"]["acceptance_id"],
                                      "acceptance_receipt": foreign["accepted"]["acceptance_receipt"]}, "identity_mismatch"),
                ("foreign_signature", {**fields, "acceptance_receipt": foreign["accepted"]["acceptance_receipt"]}, "acceptance_signature"),
                ("foreign_acceptance_id", {**fields, "acceptance_id": foreign["accepted"]["acceptance_id"]}, "acceptance_conflict"),
                ("foreign_ciphertext", {**fields, "payload_bytes": foreign["packet"]["envelope"]["payload_bytes"]}, "acceptance_conflict"),
            )
            for variant, request, code in variations:
                reject_rust(pair, target, device, "wire_receive", request, code=code,
                            label=f"{target_label}:{device}:{variant}")
        reject_rust(pair, target, "a1", "wire_accept", {"logical_message_id": LOGICAL, "attempt_id": "P1",
                    "acceptance_receipt": foreign["accepted"]["acceptance_receipt"]}, code="acceptance_signature",
                    label=f"{target_label}:foreign_send_acceptance")


def execute_isolation(pair, operation):
    round_trip(pair, LOGICAL)
    operation(pair)
    pair.restart()
    operation(pair)
    # 失败输入与两次独立重载后，双方继续用相同新ID正常收发。
    round_trip(pair, "shared_after_restart")
    pair.restart()
    for label, lab in pair.labs.items():
        before = pair.capture()
        for logical, record in pair.records[label].items():
            check(lab.attempt(logical) == record["accepted"], "重启改变本实例完整接受结果")
            for device, slot in record["slots"].items():
                observed = lab.rust(device, "wire_slot_inspect", event_seq=slot["event_seq"])
                check(observed["slot"] == slot and observed["result"]["message"]["payload_sha256"] == record["payload_sha256"],
                      "最终重载的原槽或消息摘要串实例")
        pair.unchanged(before, f"{label}:final_readback")
    pair.evidence["final_state"] = pair.capture()


CASES = [("M11.isolation." + name, operation) for name, operation in (
    ("credentials", credentials), ("service_scope", service_scope), ("cursors", cursors),
    ("receipts", receipts), ("crypto_material", crypto_material), ("storage", storage))]
