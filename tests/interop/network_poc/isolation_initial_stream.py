"""M11 首流来源回归；保留历史限制报告，当前装置必须在保存前拒绝外页。"""

import hashlib

from .fixture import check
from .slot_support import check_message_result, check_message_slot, digest, inspect_slot
from .sync_support import TARGETS, relay_receipts


def verify_initial_source(pair):
    check(set(pair.labs) == {"S1", "S2"}, "首流回归需要两个明确命名的独立实例")
    logical = "m11_initial_stream_source"
    evidence = {"classification": "PASS_SCOPED", "accepted": {}, "targets": {}}
    pair.evidence["initial_stream"] = evidence
    publications, pages, server_before = {}, {}, {}
    for label, lab in pair.labs.items():
        packet = lab.prepare(logical, payload="synthetic-M11-initial-" + label)
        accepted = lab.submit(packet)
        check(bool(accepted.get("acceptance_receipt")), "首流回归缺少本实例真实签名接受记录")
        publications[label] = (packet, accepted)
        evidence["accepted"][label] = accepted
        pages[label] = {}
        for device in TARGETS:
            state = lab.rust(device, "wire_inspect")
            check(state["inbox_count"] == 0 and state["sync"]["stream_id"] is None
                  and state["sync"]["slot_count"] == 0
                  and state["sync"]["download_cursor"] == state["sync"]["processed_cursor"] == "0",
                  "首流回归必须使用未接收、未下载的新设备存储")
            page = lab.pull(device)
            check(len(page["events"]) == 1 and page["next_after_seq"] == page["watermark"] == "1"
                  and not page["has_more"], "独立服务初页不是唯一真实消息")
            check_message_slot(page["events"][0], packet, accepted, 1)
            pages[label][device] = page
        server_before[label] = relay_receipts(lab)

    for source_label, source, target_label, target in pair.directions():
        targets = evidence["targets"].setdefault(target_label, {})
        for device in TARGETS:
            foreign = pages[source_label][device]
            own = pages[target_label][device]
            check(own["stream_id"] != foreign["stream_id"], "双实例真实设备流意外相同")
            errors = {}
            for kind, operation, fields, code in (
                ("raw_bypass", "wire_download", dict(foreign), "stream_source_required"),
                ("foreign_signed", "wire_download_signed", foreign.signed_input(), "stream_page_signature"),
            ):
                before = pair.capture()
                error = target.rust(device, operation, expected_exit=1, **fields)
                check(error["code"] == code, "首流来源拒绝错误码不符")
                pair.unchanged(before, f"{source_label}->{target_label}:{device}:initial:{kind}")
                errors[kind] = error
            check(inspect_slot(target, device, 1)["found"] is False, "拒绝外页却保存了首槽")
            targets[device] = {"own_page": own, "foreign_signed_input": foreign.signed_input(),
                               "rejections": errors, "state_after_rejections": target.rust(device, "wire_inspect")}

    pair.restart()
    for label, lab in pair.labs.items():
        for device in TARGETS:
            target = evidence["targets"][label][device]
            check(lab.rust(device, "wire_inspect") == target["state_after_rejections"], "重载改变空白首流状态")
            page = lab.pull(device)
            check(page == target["own_page"], "重启改变本实例原消息页")
            downloaded = lab.download(device, page)
            check(downloaded["status"] == "downloaded" and downloaded["sync"]["stream_id"] == page["stream_id"],
                  "来源拒绝后无法正常绑定本设备流")
            processed = lab.rust(device, "wire_process")
            check(len(processed["results"]) == 1 and len(processed["deliveries"]) == 1,
                  "拒绝后的合法初页未独立成功处理")
            payload_hash = hashlib.sha256(("synthetic-M11-initial-" + label).encode()).hexdigest()
            check_message_result(processed["results"][0]["result"], page["events"][0], logical, payload_hash, False)
            target.update(downloaded=downloaded, processed=processed,
                          stored_slot=inspect_slot(lab, device, 1), state_after_valid=lab.rust(device, "wire_inspect"))
        check(relay_receipts(lab) == server_before[label], "首流来源回归意外改变服务端事件或回执")
        check(lab.attempt(logical) == publications[label][1], "首流来源回归改变原接受事实")
    pair.restart()
    for label, lab in pair.labs.items():
        for device in TARGETS:
            target = evidence["targets"][label][device]
            check(lab.rust(device, "wire_inspect") == target["state_after_valid"], "重载丢失验证过的来源或消息结果")
            inspect_slot(lab, device, 1, target["stored_slot"])
            lab.download(device, lab.pull(device))
            repeated = lab.rust(device, "wire_process")
            check(repeated["results"] == [] and repeated["deliveries"] == target["processed"]["deliveries"],
                  "来源绑定恢复后重复发布旧消息")
            target["restart_replay"] = repeated
    evidence["server_view_unchanged"] = True
    evidence["server_view_sha256"] = {label: digest(value) for label, value in server_before.items()}
