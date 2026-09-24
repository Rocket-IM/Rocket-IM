"""M03 原消息乱序后的持久恢复；不改变 MLS 窗口、业务实现或已隔离槽。"""

import hashlib

from .deletion_observer import relay_records
from .fixture import check
from .slot_support import digest, inspect_slot


def _unchanged_target(lab, device, target):
    current = lab.rust(device, "wire_inspect")
    check(current == target["state"], "恢复改变目标公开状态、隔离数量或双游标")
    slots = [inspect_slot(lab, device, saved["event_seq"], saved)
             for saved in target["stored_slots"]]
    return {"state": current, "stored_slots_sha256": digest(slots)}


def _idle_process(lab, device, target):
    result = lab.rust(device, "wire_process")
    check(result["results"] == [] and result["deliveries"] == target["candidates"],
          "恢复重复处理原槽、改变送达候选或复活已隔离消息")
    check(result["sync"] == target["state"]["sync"], "空处理改变双游标或隔离状态")
    return result


def _retry_quarantined(lab, device, target, by_acceptance, evidence):
    retries = []
    evidence["quarantined_direct_retries"][device] = retries
    for saved in target["stored_slots"]:
        if saved["result"]["status"] != "quarantined":
            continue
        event = saved["slot"]["event"]
        record = by_acceptance[event["acceptance_id"]]
        check(event["envelope"] == record["packet"]["envelope"]
              and event["acceptance_receipt"] == record["accepted"]["acceptance_receipt"],
              "隔离槽不是本轮原消息及签名接受事实")
        path = lab.directory / device / "state.enc"
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        error = lab.receive(device, record["packet"], expected_exit=1,
                            acceptance_id=record["accepted"]["acceptance_id"],
                            acceptance_receipt=record["accepted"]["acceptance_receipt"])
        after = hashlib.sha256(path.read_bytes()).hexdigest()
        # 保存实际底层错误文本；只接收原 Rust 公共错误，不写入原合成正文。
        retries.append({"event_seq": saved["event_seq"], "event_id": saved["slot"]["event_id"],
                        "logical_message_id": record["logical"], "error": error,
                        "state_sha256_before": before, "state_sha256_after": after})
        check(error["code"] == "decryption_failed", "原隔离消息的直接重试未保持解密失败")
        check(before == after, "失败的直接重试修改了目标加密快照")
        inspect_slot(lab, device, saved["event_seq"], saved)
    evidence["after_direct_retry"][device] = {
        "process": _idle_process(lab, device, target),
        **_unchanged_target(lab, device, target),
    }


def recover(lab, packets, order, targets):
    """所有调用使用新 CLI 或真实 HTTP；签页重复不触发新的解密，直接重试单独取证。"""
    evidence = lab.case_evidence.setdefault("recovery", {})
    evidence.update(sender_retries=[], target_replays={}, quarantined_direct_retries={},
                    after_direct_retry={}, scope="synthetic_local_reordering_recovery",
                    encryption_measurement="NOT_INSTRUMENTED")
    check(len(order) == len(set(order)) and set(order) <= packets.keys(), "恢复顺序包含重复或未知消息")
    before_rows = relay_records(lab)
    before_sender = lab.rust("a1", "wire_inspect")
    before_targets = {device: _unchanged_target(lab, device, target) for device, target in targets.items()}
    lab.restart()
    check(relay_records(lab) == before_rows and lab.rust("a1", "wire_inspect") == before_sender,
          "正常 Relay 重启或新 CLI 改变消息记录及发送状态")
    after_targets = {device: _unchanged_target(lab, device, target) for device, target in targets.items()}
    check(after_targets == before_targets, "重启改变目标原槽持久结果")
    evidence["restart"] = {"relay_before": before_rows, "relay_sha256_after": digest(relay_records(lab)),
                           "sender": before_sender, "targets": after_targets, "normal_restart_count": 1}

    for send_index in order:
        record = packets[send_index]
        restored = lab.prepare(record["logical"], payload=record["payload"])
        check(restored["reused"] is True and restored["envelope"] == record["packet"]["envelope"],
              "重新加载的发送尝试未复用已保存的原字节")
        submitted = lab.submit(restored)
        found = lab.attempt(record["logical"])
        check(submitted == found == record["accepted"], "重试或查询改变完整 HTTP 接受事实")
        check(relay_records(lab) == before_rows, "原字节重试新增或修改 Relay 消息相关记录")
        evidence["sender_retries"].append({
            "send_index": send_index, "logical_message_id": record["logical"], "reused": True,
            "original_envelope_sha256": digest(record["packet"]["envelope"]),
            "restored_envelope_sha256": digest(restored["envelope"]),
            "submit": submitted, "get_attempt": found, "relay_unchanged": True,
        })
    check(lab.rust("a1", "wire_inspect") == before_sender, "原字节重试改变发送者公开状态")

    by_acceptance = {packets[index]["accepted"]["acceptance_id"]: packets[index] for index in order}
    check(len(by_acceptance) == len(order), "不同原消息共享了接受标识")
    for device, target in targets.items():
        rounds = []
        evidence["target_replays"][device] = rounds
        for number in (1, 2):
            page = lab.pull(device, "0", "100")
            check(page == target["full_page"] and page.wrapper == target["full_page"].wrapper,
                  "重启或重复完整补拉改变原槽、水位或原签页字节")
            downloaded = lab.download(device, page)
            check(downloaded["status"] == "downloaded", "重复完整签页未成功保存")
            result = _idle_process(lab, device, target)
            current = _unchanged_target(lab, device, target)
            check(relay_records(lab) == before_rows, "重复补拉改变 Relay 已提交消息记录")
            rounds.append({"round": number, "signed_page_sha256": digest(page.wrapper),
                           "download": downloaded, "process": result, **current})
        _retry_quarantined(lab, device, target, by_acceptance, evidence)
        check(relay_records(lab) == before_rows, "客户端隔离重试改变 Relay 消息记录")
    evidence["final_relay_sha256"] = digest(relay_records(lab))
    evidence["direct_retry_count"] = sum(len(rows) for rows in evidence["quarantined_direct_retries"].values())
