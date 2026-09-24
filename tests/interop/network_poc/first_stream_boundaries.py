"""签名来源不替代原消息校验；旧快照、冲突和可用性投影的明确边界。"""

import hashlib
import json
import subprocess

from .fixture import check, identity
from .first_stream_support import (alter_unsigned, download, process, publish,
                                   pull, reject, sign_test_page, unpack)


def old_snapshot_migration(pair):
    legacy = pair.legacy_binary
    # 固定上一轮实测旧程序，真实生成没有来源字段的加密快照，不直接改写快照明文。
    check(hashlib.sha256(legacy.read_bytes()).hexdigest()
          == "1c5a6f3afccff4cdf2ededad4542a683363052a0a0f60ccb83ff14687947926f",
          "旧程序不是 M11 槽位补证记录的构建")
    for label, lab in pair.labs.items():
        publish(lab, "legacy_queued")
        wrapper = pull(lab, "b1")
        request = {"directory": str(lab.directory / "b1"), "service": lab.service,
                   "account": "bob", "device": "b1", "operation": "wire_download", **unpack(wrapper)}
        output = subprocess.run([str(legacy)], input=json.dumps(request), text=True,
                                capture_output=True, timeout=30)
        lab.process_count += 1
        check(output.returncode == 0 and json.loads(output.stdout)["result"]["status"] == "downloaded",
              "旧程序未创建真实未认证待处理页")
        for phase in ("before_restart", "after_restart"):
            reject(pair, lab, "b1", wrapper, "source_migration_required", label + "_" + phase)
            reject(pair, lab, "b1", {}, "source_migration_required", label + "_process_" + phase,
                   operation="wire_process")
            observed = lab.rust("b1", "wire_inspect")
            check(observed["inbox_count"] == 0 and observed["sync"]["pending_count"] == 1,
                  "旧未认证槽被追认或消费")
            pair.restart()
        download(lab, "a2", pull(lab, "a2"))
        process(lab, "a2", 1)
    pair.evidence["migration"] = "old encrypted snapshots remain blocked; no automatic trust or data deletion"


def trusted_slot_conflict(pair):
    for label, lab in pair.labs.items():
        publish(lab, "slot_first")
        first = pull(lab, "b1")
        download(lab, "b1", first)
        original = lab.rust("b1", "wire_slot_inspect", event_seq="1")
        publish(lab, "slot_suffix")
        wrapper = pull(lab, "b1")
        changed = unpack(wrapper)
        changed["events"][0]["event_id"] = "conflicting_event"
        reject(pair, lab, "b1", alter_unsigned(wrapper, changed), "stream_page_digest", label + "_unsigned_conflict")
        signed = sign_test_page(lab, wrapper, page=changed)
        result = lab.rust("b1", "wire_download_signed", **signed)
        check(result["status"] == "stream_conflict" and result["sync"]["halted"],
              "可信来源同槽冲突未停止流")
        check(lab.rust("b1", "wire_slot_inspect", event_seq="1") == original,
              "冲突覆盖了原待处理槽")
        check(not lab.rust("b1", "wire_slot_inspect", event_seq="2")["found"],
              "冲突页部分保存了合法后缀")
        pair.restart()
        reject(pair, lab, "b1", wrapper, "stream_conflict", label + "_persisted_halt")
        reject(pair, lab, "b1", {}, "stream_conflict", label + "_halted_processing", operation="wire_process")
    pair.evidence["conflict"] = "unsigned alteration rejected without halt; authentic conflict persists halt, original slot and absent suffix"


def availability_projection(pair):
    for label, lab in pair.labs.items():
        publish(lab, "availability")
        for device, availability, processed in (("b1", "deleted", True), ("a2", "expired", False),
                                                 ("c1", "deleted", False)):
            original = pull(lab, device)
            download(lab, device, original)
            if processed:
                process(lab, device, 1)
            projected = unpack(original)
            projected["events"][0]["availability"] = availability
            del projected["events"][0]["event"]
            download(lab, device, sign_test_page(lab, original, page=projected))
            result = process(lab, device, int(processed))
            check(len(result["deliveries"]) == int(processed), "不可用投影制造或移除既有业务成功")
            if not processed:
                check(result["results"][0]["result"] == {"status": "unavailable", "availability": availability},
                      "待处理不可用槽没有明确结果")
            old = lab.rust(device, "wire_download_signed", **original)
            check(old["status"] == "stream_conflict" and old["sync"]["halted"], "旧 available 签页复活了不可用槽")
            pair.restart()
            slot = lab.rust(device, "wire_slot_inspect", event_seq="1")
            check(slot["slot"]["availability"] == availability, "重启恢复了旧 available 状态")
            pair.evidence.setdefault("projections", []).append({"service": label, "device": device,
                "availability": availability, "was_processed": processed, "old_available_replay": "stream_conflict"})
    pair.evidence["projection_limit"] = "explicit synthetic Service signed projection; no real delete or wall-clock TTL acceptance"


def receipt_slots(pair):
    for label, lab in pair.labs.items():
        accepted = publish(lab, "receipt_source")
        download(lab, "a2", pull(lab, "a2"))
        result = process(lab, "a2", 1)
        lab.http("a2", "report_delivery", {"service_id": lab.service, **result["deliveries"][0]})
        lab.http("a2", "report_read", {"service_id": lab.service, "acceptance_ids": [accepted["acceptance_id"]]})
        wrapper = pull(lab, "a1")
        page = unpack(wrapper)
        check([s["event"]["type"] for s in page["events"]] == ["delivery", "read"],
              "没有取得真实提交的送达/已读页")
        for slot in page["events"]:
            check(slot["event"]["device"] == identity("a2"), "回执报告设备错误")
        reject(pair, lab, "b1", wrapper, "stream_page_context", label + "_foreign_receipt_page")
        download(lab, "a1", wrapper)
        recorded = process(lab, "a1", 0)
        check([v["result"] for v in recorded["results"]] == [{"status": "receipt_recorded"}] * 2
              and recorded["deliveries"] == [], "来源认证改变了原回执槽语义")
        pair.restart()
        check(lab.rust("a1", "wire_process")["results"] == [], "回执槽重启重复处理")
    pair.evidence["receipt_limit"] = "whole-page Service origin authenticated; client receipt business model remains receipt_recorded"


CASES = [
    ("M11.first_stream.old_snapshot_migration", old_snapshot_migration),
    ("M11.first_stream.trusted_slot_conflict", trusted_slot_conflict),
    ("M11.first_stream.availability_projection", availability_projection),
    ("M11.first_stream.receipt_slots", receipt_slots),
]
