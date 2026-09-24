"""下载与处理分离的跨进程断言；只记录合成密文及正文摘要。"""

import base64
import hashlib
import json

from receive_support import (advanced, check_message, committed, execute, failure,
                             inspect as receive_inspect, metrics, received,
                             success, summary_only, unchanged)
from support import require


def record(sequence, envelope):
    return {"sequence": str(sequence), "envelope": envelope}


def download(probe, records, fault="none"):
    return probe.request("download", request={"records": records, "fault": fault})


def process(probe, sequence, request_id="process-request", fault="none"):
    return probe.request("process", request_id=request_id, sequence=str(sequence), fault=fault)


def inspect(probe):
    result = receive_inspect(probe)
    require("download_cursor" in result and "downloads" in result, "缺少独立下载状态")
    require(int(result["processed_cursor"]) <= int(result["download_cursor"]), "处理游标超过下载游标")
    require(len(result["downloads"]) == int(result["download_cursor"]), "下载游标与连续记录数量不符")
    require([row["sequence"] for row in result["downloads"]]
            == [str(i) for i in range(1, len(result["downloads"]) + 1)], "下载记录不连续")
    summary_only(result["downloads"])
    require(all("envelope" not in row and "ciphertext" not in row for row in result["downloads"]),
            "下载摘要意外返回完整密文")
    return result


def saved(response, cursor, processed, added):
    value = success(response)
    require(value == {"download_cursor": str(cursor), "processed_cursor": str(processed),
                      "added": added, "cached": added == 0}, "下载结果或游标不符")
    metrics(response)
    events = response.get("events")
    if added:
        require(isinstance(events, list) and len(events) == 1 and events[0].get("kind") == "download",
                "下载提交没有唯一下载事件")
        require(events[0].get("scope") == {"service": "local-service", "account": "alice",
                                          "device": "alice-device"}, "下载事件归属不符")
    else:
        require(events == [], "已下载批次重试重复发布事件")
    trace = response.get("trace") or []
    require(trace and trace[-1] == "COMMIT", "下载成功前没有结束显式事务")
    return value


def downloaded(before, after, records):
    for key in before:
        if key not in ("download_cursor", "downloads"):
            require(after[key] == before[key], f"仅下载意外改变了 {key}")
    require(int(after["download_cursor"]) == int(before["download_cursor"]) + len(records),
            "下载游标没有与新增记录共同推进")
    require(after["downloads"][:len(before["downloads"])] == before["downloads"], "已有下载摘要变化")
    fields = ("service", "conversation", "senderAccount", "senderDevice", "messageId", "ciphertext")
    for item, row in zip(records, after["downloads"][len(before["downloads"]):]):
        envelope = {key: item["envelope"][key] for key in fields}
        encoded = json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode()
        require(row["sequence"] == item["sequence"], "下载序号保存不符")
        require(row["envelope_hash"] == hashlib.sha256(encoded).hexdigest(), "下载 envelope 摘要不符")
        require(row["ciphertext_hash"] == hashlib.sha256(base64.b64decode(envelope["ciphertext"])).hexdigest(),
                "原始下载密文摘要不符")


def processed(before, after, sequence, duplicate=False):
    advanced(before, after, sequence, duplicate)
    require(after["download_cursor"] == before["download_cursor"] and after["downloads"] == before["downloads"],
            "处理改写或删除了已经保存的原始下载记录")


def pending_blocked(probe, records, before):
    """即便下载精确重放或已处理命中缓存，也必须先检查未决预约。"""
    requests = [("download", {"request": {"records": records, "fault": "none"}}),
                ("download", {"request": {"records": [record(int(before["download_cursor"]) + 1,
                                                             records[-1]["envelope"])], "fault": "none"}}),
                ("process", {"request_id": "process-request", "sequence": records[0]["sequence"], "fault": "none"}),
                ("process", {"request_id": "new-retry", "sequence": records[0]["sequence"], "fault": "none"}),
                ("process", {"request_id": "new-sequence", "sequence": records[-1]["sequence"], "fault": "none"}),
                ("execute", {"request": {"request_id": "initialize", "action": {"op": "initialize"},
                                          "fault": "none"}})]
    for operation, values in requests:
        response = probe.request(operation, **values)
        failure(response, "crypto_pending", paused=True)
        metrics(response)
        require(inspect(probe) == before, "未决预约门禁改变了已下载数据或处理状态")
    return len(requests)
