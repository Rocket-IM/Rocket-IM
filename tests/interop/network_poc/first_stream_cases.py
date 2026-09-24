"""M11 普通首流：来源、原页完整性及正常分页恢复。"""

import base64
import copy

from .fixture import ACCOUNTS, check
from .first_stream_support import (alter_unsigned, download, encode, process, publish,
                                   pull, reject, sign_test_page, statement, unpack)


def source_scopes(pair):
    for lab in pair.labs.values():
        publish(lab, "first_source")
    for source_label, source, target_label, target in pair.directions():
        foreign = pull(source, "b1")
        own = pull(target, "b1")
        reject(pair, target, "b1", foreign, "stream_page_signature", source_label + "_foreign_key")
        for field, value in (("service_id", source.service), ("account_id", "alice"),
                             ("device_id", "b2"), ("stream_id", "wrong_stream")):
            forged = sign_test_page(target, own, claims={field: value})
            reject(pair, target, "b1", forged, "stream_page_context", target_label + "_" + field)
        reject(pair, target, "b1", pull(target, "a2"), "stream_page_context",
               target_label + "_actual_other_account")
        reject(pair, target, "a2", pull(target, "a1"), "stream_page_context",
               target_label + "_actual_same_account_other_device")
        reject(pair, target, "b1", unpack(own), "stream_source_required",
               target_label + "_raw_downgrade", operation="wire_download")
        pair.restart()
        reject(pair, target, "b1", foreign, "stream_page_signature", target_label + "_restart_foreign")
        for device in ("a2", "b1", "c1"):
            download(target, device, pull(target, device))
            process(target, device, 1)
    pair.evidence["accepted_after_rejection"] = "both instances, all three message recipients"


def page_integrity(pair):
    for label, lab in pair.labs.items():
        publish(lab, "integrity_one")
        publish(lab, "integrity_two")
        wrapper = pull(lab, "b1")
        original = unpack(wrapper)
        changes = {
            "stream_id": "another_stream", "next_after_seq": "1", "watermark": "3",
            "has_more": True, "events": original["events"][:1],
        }
        for field, value in changes.items():
            page = copy.deepcopy(original)
            page[field] = value
            reject(pair, lab, "b1", alter_unsigned(wrapper, page), "stream_page_digest", label + "_alter_" + field)
        invalid_signature = copy.deepcopy(wrapper)
        invalid_signature["receipt"]["signature_bytes"] = base64.b64encode(bytes(64)).decode()
        reject(pair, lab, "b1", invalid_signature, "stream_page_signature", label + "_signature")
        claims = statement(wrapper)
        claims["account_id"] = "alice"
        changed_claims = copy.deepcopy(wrapper)
        changed_claims["receipt"]["statement_bytes"] = base64.b64encode(encode(claims)).decode()
        reject(pair, lab, "b1", changed_claims, "stream_page_signature", label + "_claims_unsigned")
        for field, value in (("after_seq", "1"), ("limit", "1")):
            reject(pair, lab, "b1", sign_test_page(lab, wrapper, claims={field: value}),
                   "stream_page_range", label + "_signed_" + field)
        reject(pair, lab, "b1", sign_test_page(lab, wrapper, claims={"page_sha256": "0" * 64}),
               "stream_page_digest", label + "_signed_digest")
        shifted = copy.deepcopy(original)
        shifted["events"] = shifted["events"][1:]
        reject(pair, lab, "b1", sign_test_page(lab, wrapper, page=shifted),
               "stream_page_range", label + "_signed_gap")
        for suffix, raw in (("json", b"{"), ("duplicate", encode(original)[:-1] + b',"has_more":false}')):
            reject(pair, lab, "b1", sign_test_page(lab, wrapper, raw=raw),
                   "stream_page_invalid", label + "_signed_invalid_" + suffix)
        download(lab, "b1", wrapper)
        process(lab, "b1", 2)
    pair.restart()
    pair.evidence["integrity"] = "original bytes, five page fields, signature, claims, range and duplicate JSON fields"


def pagination_restart(pair):
    for label, lab in pair.labs.items():
        for device in ACCOUNTS:
            empty = pull(lab, device)
            check(unpack(empty)["events"] == [], "空流预置状态不为空")
            download(lab, device, empty)
            process(lab, device, 0)
        pair.restart()
        for index in range(3):
            publish(lab, "pagination_" + str(index))
        for device in ("a2", "b1", "c1"):
            first = pull(lab, device, limit="1")
            result = download(lab, device, first)
            check(result["sync"]["download_cursor"] == "1", "第一小页越过未下载事件")
            pair.restart()
            first_processed = process(lab, device, 1)
            download(lab, device, first)
            replay = process(lab, device, 1)
            check(replay["results"] == [] and replay["deliveries"] == first_processed["deliveries"],
                  "首页精确重放重复发布结果或改变送达候选")
            overlap = pull(lab, device, limit="2")
            download(lab, device, overlap)
            processed = process(lab, device, 2)
            check(len(processed["deliveries"]) == 2, "交叠页重复生成业务送达候选")
            last = pull(lab, device, after="2", limit="1")
            download(lab, device, last)
            pair.restart()
            final = process(lab, device, 3)
            check(final["sync"]["processed_cursor"] == "3" and len(final["deliveries"]) == 3,
                  "尾页重启未恢复完整处理")
            check(lab.rust(device, "wire_process")["results"] == [], "重载重复发布处理结果")
            pair.evidence.setdefault("pagination", []).append({"service": label, "device": device,
                "inbox": 3, "download_cursor": "3", "processed_cursor": "3", "delivery_candidates": 3})


CASES = [
    ("M11.first_stream.source_scopes", source_scopes),
    ("M11.first_stream.page_integrity", page_integrity),
    ("M11.first_stream.pagination_restart", pagination_restart),
]
