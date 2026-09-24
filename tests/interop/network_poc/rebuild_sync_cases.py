"""重建新流的真实入群、HTTP分页与独立进程重试。"""

from concurrent.futures import ThreadPoolExecutor
import json

from .fixture import SERVICE, check
from .rebuild_sync_fixture import page_value, statement


def wire(lab):
    return lab.rust("successor", "wire_inspect")


def empty(state):
    check(state["inbox_count"] == 0 and state["outbox_count"] == 0
          and state["sync"]["download_cursor"] == "0" and state["sync"]["processed_cursor"] == "0",
          "后继继承了旧消息或非零游标")


def normal(lab):
    lab.publish("before_add")
    lab.join_http()
    empty(wire(lab))
    for index in range(2):
        lab.publish("before_binding_" + str(index))
    lab.registration_request(); lab.register_http()
    bound = lab.bind()
    check(bound["sync"]["download_cursor"] == "0", "新流绑定跳过了注册前排队的消息")
    lab.publish("after_binding")
    pages, _ = lab.sync()
    events = [event for page in pages for event in page_value(page)["events"]]
    check([event["event_seq"] for event in events] == ["1", "2", "3"], "注册前后事件不连续")
    state = wire(lab)
    check(state["inbox_count"] == 3 and state["sync"]["processed_cursor"] == "3",
          "新授权流没有实际解密全部消息")
    sent, _ = lab.publish("successor_reply", device="successor")
    page = lab.http("source_peer", "pull_events", {"service_id": SERVICE, "after_seq": "0", "limit": "100"})
    target = next(e for e in page["events"] if e["event"]["envelope"] == sent["envelope"])
    received = lab.rust("source_peer", "wire_receive", **target["event"]["envelope"],
                        acceptance_id=target["event"]["acceptance_id"],
                        acceptance_receipt=target["event"]["acceptance_receipt"])
    check(not received["duplicate"], "后继回复未被另一真实设备解密")
    check(lab.plan["old_scope"]["device"] != lab.plan["successor_scope"]["device"], "重建复用旧设备")
    check(state["history"]["past_epochs"] == [], "新流携带旧历史钥")
    lab.evidence["http_decryption"] = {"incoming": 3, "reply": 1, "before_add_excluded": True,
                                        "old_processed_cursor": "1", "new_initial_cursor": "0"}


def pagination(lab):
    lab.ready()
    for index in range(20):
        lab.publish("page_" + str(index))
    pages, _ = lab.sync("3")
    values = [page_value(page) for page in pages]
    seen = [slot["event_seq"] for page in values for slot in page["events"]]
    check(len(pages) == 7 and seen == [str(n) for n in range(1, 21)], "20条/3条分页有遗漏或重复")
    check(values[0]["watermark"] == "20" and values[0]["next_after_seq"] == "3", "页游标跳到高水位")
    state = wire(lab)
    check(state["inbox_count"] == 20 and state["sync"]["download_cursor"] == "20"
          and state["sync"]["processed_cursor"] == "20", "双游标或实际消息数不一致")
    lab.evidence["pagination"] = {"messages": 20, "limit": "3", "pages": 7, "processed_cursor": "20"}


def exact_retry(lab):
    lab.join_http()
    first = lab.registration_request()["registration"]
    check(lab.registration_request()["registration"] == first, "新进程重试重新生成申请或stream_id")
    original = lab.register_http()["binding"]
    lab.restart()
    check(lab.register_http()["binding"] == original, "Relay重启重签或替换原绑定")
    lab.bind(); lab.publish("retry")
    first_request = lab.request_page()["request"]
    check(lab.request_page()["request"] == first_request, "活动拉取重新生成挑战")
    page = lab.http_page(first_request)
    lab.download(page); lab.process_page()
    saved = wire(lab)
    next_request = lab.request_page()["request"]
    check(next_request != first_request and statement(next_request)["after_seq"] == "1", "下一页未固定新挑战和游标")
    repeated = lab.download(page)
    check(repeated["duplicate"] and repeated["sync"] == saved["sync"], "保存页重试回退状态")
    check(lab.request_page()["request"] == next_request, "原页精确重试清除了后来活动挑战")
    rebound = lab.bind()
    check(rebound["duplicate"] and rebound["sync"] == saved["sync"], "重复授权重置新流")
    lab.evidence["exact_retry"] = ["registration", "HTTP binding after restart", "active pull", "saved page", "late bind"]


def empty_and_limits(lab):
    lab.ready()
    for limit in ("1", "100"):
        page = lab.next_page(limit)
        check(page_value(page)["events"] == [] and page_value(page)["next_after_seq"] == "0", "空页跳过游标")
        lab.download(page); lab.process_page()
    empty(wire(lab))
    codes = {}
    for limit in ("0", "101", "-1", "1.5", "01", "18446744073709551616"):
        before = lab.snapshot("successor").read_bytes()
        error = lab.request_page(limit, expected_exit=1)
        check(error["code"] != "anchor_paused" and lab.snapshot("successor").read_bytes() == before,
              "无效页大小未真实校验或改变快照")
        codes[limit] = error["code"]
    request = lab.request_page("3")["request"]
    before = lab.snapshot("successor").read_bytes()
    error = lab.request_page("4", expected_exit=1)
    check(error["code"] == "rebuild_stream_conflict" and lab.snapshot("successor").read_bytes() == before,
          "活动拉取修改limit未拒绝或修改快照")
    check(lab.request_page("3")["request"] == request, "limit拒绝后丢失原活动请求")
    lab.publish("after_invalid_limits"); lab.download(lab.http_page(request)); lab.process_page()
    check(wire(lab)["inbox_count"] == 1, "输入预检错误永久暂停后继")
    lab.evidence["limit_rejections"] = codes


def concurrent_registration(lab):
    lab.join_http(); lab.registration_request()
    with ThreadPoolExecutor(max_workers=2) as pool:
        answers = list(pool.map(lambda _: lab.register_http(), range(2)))
    check(answers[0] == answers[1], "并发相同注册生成两个绑定")
    lab.bind(); lab.publish("concurrent_registration"); lab.sync()
    check(wire(lab)["inbox_count"] == 1, "并发注册重置或重复流事件")


def clone_request_race(lab):
    lab.join_http()
    clone = lab.backup("request-clone", lab.directory / "successor")
    fields = dict(plan=lab.plan, approval=lab.approval, anchor_request=lab.link_result["anchor_request"],
                  anchor_response=lab.link_result["anchor_response"])
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda directory: lab.raw_rust("successor", "rebuild_stream_request",
                          directory=directory, **fields), (lab.directory / "successor", clone)))
    check(sum(r.returncode == 0 for r in results) == 1, "同锚的完整克隆同时生成不同流申请")
    lab.evidence["clone_request_winners"] = 1
    lab.registration = json.loads(next(r.stdout for r in results if r.returncode == 0))["result"]["registration"]
    lab.register_http()


def stale_snapshot(lab, stage):
    lab.ready()
    if stage == "after_download":
        lab.publish("rollback_first"); lab.download(lab.next_page())
    if stage == "after_process":
        lab.publish("rollback_first"); lab.sync()
    stale = lab.backup("stale-complete-client", lab.directory / "successor")
    lab.publish("rollback_next"); lab.sync()
    lab.restore(stale, lab.directory / "successor")
    before = lab.snapshot("successor").read_bytes()
    for operation, fields in (("rebuild_stream_pull", {"limit": "3"}), ("wire_process", {}),
                               ("rebuild_stream_bind", {"binding": lab.binding}), ("anchor_resume", {})):
        lab.blocked("successor", operation, **fields)
    check(lab.snapshot("successor").read_bytes() == before, "旧完整快照重放后重新消费或覆盖消息")
    lab.evidence["snapshot_rollback"] = {"stage": stage, "authority_unchanged": True, "result": "paused"}
