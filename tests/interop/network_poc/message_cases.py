"""真实 Rust 加解密通过 HTTP 传输的消息、身份和回执验收。"""

import base64
import copy
import hashlib
import http.client
import json

from .fixture import SERVICE, check


def header(packet):
    return json.loads(base64.b64decode(packet["envelope"]["header_bytes"]))


def changed_header(packet, **changes):
    modified = copy.deepcopy(packet)
    value = header(packet)
    value.update(changes)
    modified["envelope"]["header_bytes"] = base64.b64encode(
        json.dumps(value, separators=(",", ":")).encode()).decode()
    return modified


def offline(lab):
    packet = lab.prepare("offline")
    accepted = lab.submit(packet)
    check(bool(accepted["acceptance_id"]), "缺少接受标识")
    for device in ("a2", "b1", "c1"):
        page = lab.pull(device)
        check(len(page["events"]) == 1, "每个初始目标应只有一个消息槽位")
        incoming = page["events"][0]["event"]["envelope"]
        check(incoming == packet["envelope"], "Relay 改写了原始信封")
        received = lab.receive(device, {"envelope": incoming})
        check(received["payload_sha256"] == hashlib.sha256(b"synthetic-network-offline").hexdigest(),
              "设备解密摘要不符")
    stats = lab.control("stats")
    check(stats["accepted"] == "1" and stats["message_events"] == "3", "接受/完整扇出不一致")
    for path in lab.directory.glob("relay.sqlite*"):
        check(b"synthetic-network-offline" not in path.read_bytes(), "Relay 存在合成正文")


def lost_ack(lab):
    packet = lab.prepare("lost_ack")
    lab.control("hook", hook="drop_after_commit")
    try:
        lab.submit(packet)
        raise AssertionError("故障装置没有丢弃接受响应")
    except (http.client.RemoteDisconnected, ConnectionResetError):
        pass
    again = lab.prepare("lost_ack")
    check(again["reused"] and again["envelope"] == packet["envelope"], "重启CLI后没有复用原字节")
    result = lab.submit(again)
    queried = lab.attempt("lost_ack")
    check(queried["acceptance_id"] == result["acceptance_id"], "重试接受标识不稳定")
    check(lab.control("stats")["message_events"] == "3", "ACK 丢失造成重复扇出")


def pagination(lab):
    for i in range(20):
        lab.submit(lab.prepare("page_" + str(i)))
    cursor = "0"
    seen = []
    first_page = None
    while True:
        page = lab.pull("b1", cursor, "3")
        first_page = first_page or page
        seqs = [slot["event_seq"] for slot in page["events"]]
        check(seqs == [str(n) for n in range(int(cursor) + 1, int(cursor) + len(seqs) + 1)],
              "分页不是已提交连续前缀")
        lab.download("b1", page)
        # 原页重复下载不得重复建业务消息。
        lab.download("b1", page)
        lab.rust("b1", "wire_process")
        seen.extend(seqs)
        cursor = page["next_after_seq"]
        if not page["has_more"]:
            break
    check(seen == [str(n) for n in range(1, 21)], "20 条消息补拉有遗漏")
    check(first_page["next_after_seq"] == "3" and first_page["watermark"] == "20",
          "分页错误地跳到高水位")
    state = lab.rust("b1", "wire_inspect")
    check(state["inbox_count"] == 20 and state["sync"]["download_cursor"] == "20"
          and state["sync"]["processed_cursor"] == "20", "双游标或去重计数错误")
    # 网络到达次序可反转；密码处理仍使用同一份持久记录。
    packets = [lab.prepare("reorder_" + str(i)) for i in range(2)]
    for packet in reversed(packets):
        lab.receive("b1", packet)
    check(lab.receive("b1", packets[0])["duplicate"], "乱序后的重复没有去重")


def id_conflict(lab):
    packet = lab.prepare("conflict")
    accepted = lab.submit(packet)
    different = changed_header(packet, authorization_version="2")
    error = lab.submit(different, expected=409)
    check(error["code"] == "idempotency_conflict", "同键异头没有明确冲突")
    different = copy.deepcopy(packet)
    bytes_ = bytearray(base64.b64decode(different["envelope"]["payload_bytes"]))
    bytes_[-1] ^= 1
    different["envelope"]["payload_bytes"] = base64.b64encode(bytes_).decode()
    check(lab.submit(different, expected=409)["code"] == "idempotency_conflict", "异密文覆盖原请求")
    check(lab.attempt("conflict")["acceptance_id"] == accepted["acceptance_id"], "原接受被修改")
    check(lab.control("stats")["message_events"] == "3", "冲突追加了投递")


def bindings(lab):
    variants = [dict(service_id="S2"), dict(conversation_id="G2"),
                dict(sender={"account_id": "bob", "device_id": "b1"}),
                dict(security_mode="server_readable"), dict(protocol_version="rim-poc-2"),
                dict(authorization_version="99"), dict(crypto_state_ref="0" * 64),
                dict(recipients=[{"account_id": "bob", "device_id": "b1"}])]
    for i, change in enumerate(variants):
        packet = lab.prepare("binding_" + str(i))
        altered = changed_header(packet, **change)
        before = (lab.directory / "b1/state.enc").read_bytes()
        lab.receive("b1", altered, expected_exit=1)
        check((lab.directory / "b1/state.enc").read_bytes() == before, "错误上下文改变了有效密码状态")
        check(not lab.receive("b1", packet)["duplicate"], "坏消息抢占了逻辑去重")
    # 语义相同但原始 AAD 字节不同也必须拒绝。
    packet = lab.prepare("aad_order")
    altered = copy.deepcopy(packet)
    altered["envelope"]["header_bytes"] = base64.b64encode(
        json.dumps(header(packet), sort_keys=True, indent=1).encode()).decode()
    lab.receive("b1", altered, expected_exit=1)
    lab.receive("b1", packet)


def receipts(lab):
    packet = lab.prepare("receipts")
    accepted = lab.submit(packet)
    a2slot = lab.pull("a2")["events"][0]
    bpage = lab.pull("b1")
    bslot = bpage["events"][0]
    lab.receive("a2", packet)
    report = {"service_id": SERVICE, "acceptance_id": accepted["acceptance_id"],
              "attempt_id": "P1", "event_id": bslot["event_id"]}
    check(lab.http("a2", "report_delivery", report, expected=403)["code"] == "permission_denied",
          "A2 可以代 B1 报告送达")
    report["event_id"] = a2slot["event_id"]
    lab.http("a2", "report_delivery", report)
    check(lab.control("stats")["receipts"] == "1", "A2 送达被扩大为其他设备送达")
    lab.download("b1", bpage)
    processed = lab.rust("b1", "wire_process")
    for item in processed["deliveries"]:
        lab.http("b1", "report_delivery", {"service_id": SERVICE, **item})
        lab.http("b1", "report_delivery", {"service_id": SERVICE, **item})
    check(lab.control("stats")["receipts"] == "2", "重复送达报告没有幂等")
    before_read = lab.pull("a1")
    check(all(slot["event"]["type"] == "delivery" for slot in before_read["events"]),
          "接收被自动报告为已读")
    read = {"service_id": SERVICE, "acceptance_ids": [accepted["acceptance_id"]]}
    first_read = lab.http("b1", "report_read", read)
    check(first_read == lab.http("b1", "report_read", read), "重复已读结果不一致")
    check(first_read["receipts"][0]["read"], "实际阅读后没有更新已读状态")
    after_read = lab.pull("a1")
    read_events = [slot["event"] for slot in after_read["events"] if slot["event"]["type"] == "read"]
    check(len(read_events) == 1 and read_events[0]["device"]["device_id"] == "b1",
          "已读通知重复或关联到错误设备")
