"""M12.c：默认Rust、真实签页和Node HTTP间的大事件序号正向往返。"""

import hashlib

from .deletion_observer import relay_records
from .fixture import check
from .sequence_support import BASE, SEQUENCES, inspect, node, pull, record, relocate, snapshot, unchanged


def initialize(lab):
    empty = lab.pull("b1")
    check(empty["events"] == [] and empty["watermark"] == "0", "初始签页不为空")
    lab.download("b1", empty)
    before = inspect(lab, 0, 0, 0, 0)
    seed = {"stream_id": empty["stream_id"], "base_seq": str(BASE)}
    before_files, before_rows = snapshot(lab), relay_records(lab)
    error = lab.rust("b1", "wire_sequence_seed", expected_exit=1, **seed)
    check(error["code"] == "invalid_request", "默认构建暴露了实验起点操作")
    unchanged(lab, before_files, before_rows)
    default_binary = lab.binary
    try:
        lab.binary = lab.seed_binary
        seeded = lab.rust("b1", "wire_sequence_seed", **seed)
    finally:
        lab.binary = default_binary
    after = inspect(lab, BASE, BASE, 0, 0)
    expected = {**before, "sync": {**before["sync"], "download_cursor": str(BASE), "processed_cursor": str(BASE)}}
    check(after == expected, "测试种子改变了双游标以外的公开状态")
    record(lab, "synthetic_client_sequence_seed", empty_signed_page=empty.wrapper, response=seeded,
           default_rejection=error, default_reload=after,
           default_program_resumed=True, historical_prefix="NOT_EXECUTED")
    packets = []
    for index in range(3):
        text = "synthetic-M12-message-" + str(index)
        packet = lab.prepare("m12_" + str(index), payload=text)
        accepted = lab.submit(packet)
        packets.append({"packet": packet, "accepted": accepted, "payload_sha256": hashlib.sha256(text.encode()).hexdigest()})
    relocate(lab)
    return packets


def process(lab, page, packets, seen, candidates):
    result = lab.rust("b1", "wire_process")
    check([row["event_seq"] for row in result["results"]] == [slot["event_seq"] for slot in page["events"]],
          "Rust输出的处理序号丢精度或遗漏")
    for slot, item in zip(page["events"], result["results"]):
        index = SEQUENCES.index(slot["event_seq"])
        expected = packets[index]
        message = item["result"]
        check(index not in seen and item["event_id"] == slot["event_id"]
              and message["status"] == "valid" and message["message"]["duplicate"] is False
              and message["message"]["payload_sha256"] == expected["payload_sha256"]
              and slot["event"]["envelope"] == expected["packet"]["envelope"]
              and slot["event"]["acceptance_id"] == expected["accepted"]["acceptance_id"],
              "大序号槽身份、原密文或实际解密结果不符")
        saved = lab.rust("b1", "wire_slot_inspect", event_seq=slot["event_seq"])
        check(saved["found"] and saved["slot"] == slot and saved["result"] == message and not saved["waiting"],
              "新默认CLI未精确读取保存的大序号原槽")
        seen.add(index)
        candidates.append({"acceptance_id": slot["event"]["acceptance_id"], "attempt_id": "P1", "event_id": slot["event_id"]})
    check(result["deliveries"] == candidates, "大序号处理遗漏或重复送达候选")
    record(lab, "default_rust_process", result=result)


def roundtrip(lab, limit, boundary_check=None):
    packets = initialize(lab)
    if boundary_check is not None:
        boundary_check(lab)
    cursor, seen, candidates = BASE, set(), []
    pages = []
    while cursor < BASE + 3:
        reply = pull(lab, cursor, limit)
        page = reply["page"]
        expected_seqs = SEQUENCES[len(seen):len(seen) + limit]
        check(reply["sequences"] == expected_seqs and page["next_after_seq"] == expected_seqs[-1]
              and page["watermark"] == SEQUENCES[-1]
              and page["has_more"] == (expected_seqs[-1] != SEQUENCES[-1]), "实际Node分页未精确返回连续大序号")
        downloaded = lab.rust("b1", "wire_download_signed", **reply["wrapper"])
        check(downloaded["status"] == "downloaded", "默认Rust拒绝合法大序号签页")
        saved = inspect(lab, int(expected_seqs[-1]), cursor, len(seen), len(seen) + len(expected_seqs))
        if not pages:
            before_rows = relay_records(lab)
            lab.restart()
            check(lab.rust("b1", "wire_inspect") == saved and relay_records(lab) == before_rows,
                  "排队重启改变大序号或消息相关记录")
            record(lab, "restart_after_first_download", state=saved)
        process(lab, page, packets, seen, candidates)
        cursor = int(page["next_after_seq"])
        inspect(lab, cursor, cursor, len(seen), len(seen))
        pages.append(reply)
    final = inspect(lab, BASE + 3, BASE + 3, 3, 3)
    check(final["sync"]["pending_count"] == 0 and len({item["event_id"] for item in candidates}) == 3,
          "处理末尾仍有等待或序号碰撞")
    # 两个会被Number混同的请求，必须实际经HTTP获得不同结果。
    second = pull(lab, SEQUENCES[1], 1)
    third = pull(lab, SEQUENCES[2], 1)
    check(second["sequences"] == [SEQUENCES[2]] and third["sequences"] == [], "相邻大游标被请求舍入混同")
    entire = pull(lab, BASE, 100)
    check(entire["sequences"] == SEQUENCES, "完整签页未保持三个独立序号")
    js_roundtrip = node(lab, "validate_page", page=entire["page"])
    check(js_roundtrip["roundtrip_page"] == entire["page"] and js_roundtrip["sequences"] == SEQUENCES,
          "JS JSON往返损失序号或原槽")
    stored = [lab.rust("b1", "wire_slot_inspect", event_seq=seq) for seq in SEQUENCES]
    before_rows = relay_records(lab)
    lab.restart()
    for _ in range(2):
        again = pull(lab, BASE, 100)
        check(again["wrapper"] == entire["wrapper"] and again["page"] == entire["page"], "重启/重复补拉修改大序号签页")
        lab.rust("b1", "wire_download_signed", **again["wrapper"])
        result = lab.rust("b1", "wire_process")
        check(result["results"] == [] and result["deliveries"] == candidates
              and lab.rust("b1", "wire_inspect") == final, "重复大页重新处理或改变精确游标")
        check([lab.rust("b1", "wire_slot_inspect", event_seq=seq) for seq in SEQUENCES] == stored,
              "重复大页改写原槽身份或持久结果")
        check(relay_records(lab) == before_rows, "只读分页改变Relay消息记录")
        record(lab, "repeat_full_signed_page", result=result, state=final)
    check(before_rows["receipts"] == [], "只消费和保存消息不应隐式报告回执")
    lab.case_evidence.update(final_state=final, final_relay=before_rows, successful_candidates=candidates,
                             sequences=SEQUENCES, default_processing=True, page_limit=str(limit),
                             node_roundtrip=js_roundtrip,
                             limit="synthetic high checkpoint; no historical prefix, allocator or receipt append acceptance")


def boundaries(lab):
    from .sequence_boundaries import input_boundaries
    roundtrip(lab, 2, input_boundaries)


CASES = [("M12_page_1", lambda lab: roundtrip(lab, 1)),
         ("M12_page_2", lambda lab: roundtrip(lab, 2)),
         ("M12_page_3", lambda lab: roundtrip(lab, 3)),
         ("M12_input_boundaries", boundaries)]
