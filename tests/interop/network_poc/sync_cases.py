"""M03真实20消息的交叠分页、提示顺序与迟到页边界。"""

from functools import partial

from .fixture import check
from .sync_support import Receiver, TARGETS, add_messages


def receive_notifications(lab, packets, *, limit, overlap, process_every, restart_midway):
    receivers = {}
    # 仅测试调度输入：没有WSS传输、SDK通知入口或自动同步worker。
    hints = [value for number in range(20, 0, -1) for value in (number, number)]
    lab.case_evidence["notification_scope"] = "synthetic reverse/duplicate hints trigger real HTTP pulls from Rust-persisted cursor; not WSS/SDK worker"
    for device in TARGETS:
        receiver = Receiver(lab, device, packets)
        receivers[device] = receiver
        restarted = False
        for index, hint in enumerate(hints):
            state = lab.rust(device, "wire_inspect")
            before = int(state["sync"]["download_cursor"])
            check(before == receiver.cursor, "调度未使用Rust持久游标")
            after = max(0, before - overlap) if before < 20 else before
            page = lab.pull(device, str(after), str(limit))
            receiver.download(page, after, limit, high=20)
            receiver.trace.append({"operation": "synthetic_notification", "hint": str(hint),
                                   "persisted_cursor_before": str(before), "requested_after": str(after)})
            if (index + 1) % process_every == 0 or receiver.cursor == 20:
                receiver.process()
            if restart_midway and not restarted and 0 < receiver.cursor < 20:
                lab.restart()
                receiver.trace.append({"operation": "relay_restart", "at_download_cursor": str(receiver.cursor)})
                restarted = True
        receiver.process()
        check(receiver.cursor == 20 and receiver.seen == set(packets), "反序提示调度没有完整恢复20条")
        check(len(receiver.slots) == len(receiver.candidates()) == 20, "交叠页重复建槽或重复确认候选")
    return receivers


def final_messages(lab, packets, receivers):
    lab.restart()
    for device, receiver in receivers.items():
        page = lab.pull(device)
        check(page["events"] == [receiver.slots[seq] for seq in range(1, 21)], "重启改变原消息槽位/密文")
        receiver.download(page, 0, 100, high=20)
        receiver.process()
    for logical, (saved, accepted) in packets.items():
        check(lab.attempt(logical) == accepted and lab.submit(saved) == accepted, "原消息重投改变接受结果")
    stats = lab.control("stats")
    check(stats["accepted"] == stats["attempts"] == "20" and stats["message_events"] == stats["events"] == "60"
          and stats["receipts"] == "0", "下载/处理自动生成了回执或重复消息")
    lab.case_evidence["final_stats"] = stats


def overlapping_notifications(lab, *, limit, overlap, process_every):
    packets = {}
    add_messages(lab, packets)
    receivers = receive_notifications(lab, packets, limit=limit, overlap=overlap,
                                      process_every=process_every, restart_midway=True)
    final_messages(lab, packets, receivers)


def delayed_pages(lab):
    packets = {}
    add_messages(lab, packets, stop=10)
    old_watermark_pages = {device: lab.pull(device, "0", "10") for device in TARGETS}
    add_messages(lab, packets, start=10)
    lab.case_evidence["delayed_scope"] = "delayed application of actual returned HTTP pages; not delayed network responses"
    receivers = {}
    for device in TARGETS:
        receiver = Receiver(lab, device, packets)
        receivers[device] = receiver
        future = lab.pull(device, "5", "5")
        receiver.reject(future, "future page would skip slots 1..5")
        receiver.process()
        first = lab.pull(device, "0", "5")
        receiver.download(first, 0, 5, high=20)
        receiver.process()
        overlap = lab.pull(device, "3", "7")
        receiver.download(overlap, 3, 7, high=20)
        receiver.process()
        receiver.download(future, 5, 5, high=20)
        receiver.process()
        tail = lab.pull(device, "8", "12")
        receiver.download(tail, 8, 12, high=20)
        receiver.process()
        receiver.reject(first, "next=5 behind persisted cursor=20 while watermark=20")
        receiver.reject(old_watermark_pages[device], "old watermark=10 behind persisted cursor=20")
        # 从原持久游标继续，不回滚游标、不丢弃已有记录、不伪造成功。
        fresh = lab.pull(device, "20", "3")
        receiver.download(fresh, 20, 3, high=20)
        receiver.process()
        check(receiver.seen == set(packets), "迟到页拒绝后合法消息遗漏")
    final_messages(lab, packets, receivers)


CASES = [
    ("M03.overlap.process_each_page", partial(overlapping_notifications, limit=5, overlap=2, process_every=1)),
    ("M03.overlap.deferred_process", partial(overlapping_notifications, limit=7, overlap=3, process_every=2)),
    ("M03.pages.delayed_application", delayed_pages),
]
