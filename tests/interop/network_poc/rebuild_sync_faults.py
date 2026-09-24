"""真实进程退出、丢HTTP响应和锚恢复窗口。"""

import http.client

from .fixture import check
from .rebuild_sync_cases import wire
from .rebuild_sync_fixture import page_value


def interrupted(action):
    try:
        action()
        raise AssertionError("故障装置未丢弃真实HTTP响应")
    except (http.client.RemoteDisconnected, ConnectionResetError):
        pass


def register_transport(lab, hook, code):
    lab.join_http(); lab.registration_request(); lab.publish("queued_before_failure")
    lab.control("hook", hook=hook)
    interrupted(lab.register_http)
    if code:
        check(lab.process.wait(timeout=10) == code, "HTTP登记退出点不符")
    lab.restart()
    one = lab.register_http(); two = lab.register_http()
    check(one == two, "HTTP登记失去响应后生成不同授权")
    lab.bind(); lab.sync()
    check(wire(lab)["inbox_count"] == 1, "登记保存故障漏掉注册前事件")
    lab.evidence["register_transport"] = {"hook": hook, "actual_exit": code, "recovered_messages": 1}


def page_transport(lab, hook, code):
    lab.ready(); lab.publish("first_page_failure")
    request = lab.request_page()["request"]
    lab.control("hook", hook=hook)
    interrupted(lambda: lab.http_page(request))
    if code:
        check(lab.process.wait(timeout=10) == code, "签页HTTP退出点不符")
    lab.restart(); lab.publish("queued_after_lost_page")
    check(lab.request_page()["request"] == request, "HTTP丢页导致本机重新生成活动挑战")
    page = lab.http_page(request)
    check([e["event_seq"] for e in page_value(page)["events"]] == ["1", "2"], "丢响应后新事务视图跳过旧事件")
    lab.download(page); lab.process_page()
    check(wire(lab)["inbox_count"] == 2, "响应丢失重试未完整实际解密")
    lab.evidence["page_transport"] = {"hook": hook, "actual_exit": code, "view_growth_preserved": True}


def delayed_pages(lab):
    lab.ready(); lab.publish("first")
    request = lab.request_page()["request"]
    shorter = lab.http_page(request)
    lab.publish("arrived_between_retries")
    longer = lab.http_page(request)
    check(shorter != longer, "装置没有构造同挑战的两个有效事务视图")
    lab.download(shorter); lab.process_page()
    before = lab.snapshot("successor").read_bytes()
    error = lab.download(longer, expected_exit=1)
    check(error["code"] not in ("anchor_paused", "anchor_conflict")
          and lab.snapshot("successor").read_bytes() == before, "迟到视图改变已保存页")
    lab.sync()
    check(wire(lab)["inbox_count"] == 2, "拒绝迟到页后不能继续补拉")
    lab.publish("third"); lab.sync()
    before = lab.snapshot("successor").read_bytes()
    lab.download(shorter, expected_exit=1)
    check(lab.snapshot("successor").read_bytes() == before, "跨两页旧重放回退快照")
    lab.publish("fourth"); lab.sync()
    check(wire(lab)["inbox_count"] == 4, "跨页旧重放永久暂停了后继")
    lab.evidence["delayed_views"] = {"same_challenge_different_valid_pages": True,
                                     "old_response_rejected_without_pause": True, "final_messages": 4}


def client_crash(lab, operation, point, code):
    lab.join_http()
    actions = {"request": lab.registration_request, "bind": lab.bind, "pull": lab.request_page,
               "download": None, "process": lab.process_page}
    if operation != "request":
        lab.registration_request(); lab.register_http()
    if operation not in ("request", "bind"):
        lab.bind()
    if operation in ("download", "process"):
        lab.publish("client_crash")
        page = lab.next_page()
        actions["download"] = lambda **options: lab.download(page, **options)
        if operation == "process":
            lab.download(page)
    before = lab.snapshot("successor").read_bytes()
    options = {"env": {"RIM_ANCHOR_FAILPOINT": point}} if code >= 86 else {"failpoint": point}
    actions[operation](expected_exit=code, **options)
    saved = lab.snapshot("successor").read_bytes()
    check((saved != before) == (code in (85, 87, 88)), "客户端实际保存退出窗口不符")
    lab.blocked("successor", "rebuild_stream_pull", limit="3")
    if code in (87, 88):
        lab.resume("successor")
        check(lab.snapshot("successor").read_bytes() == saved, "anchor_resume重写了完整已保存结果")
        result = actions[operation]()
        if operation in ("request", "bind", "pull", "download"):
            check(result.get("duplicate", False), "已保存结果未精确重用")
        again = actions[operation]()
        if operation == "request":
            check(result["registration"] == again["registration"], "恢复重试生成另一流申请")
        elif operation == "pull":
            check(result["request"] == again["request"], "恢复重试重签活动挑战")
        else:
            check(result == again, "恢复后原业务结果或游标改变")
        if operation == "process":
            check(result["results"] == [] and wire(lab)["inbox_count"] == 1, "恢复后重复处理已提交消息")
        if operation == "request":
            lab.register_http(); lab.bind()
        if operation in ("request", "bind", "pull"):
            lab.publish("after_recovery")
        lab.sync()
        check(wire(lab)["inbox_count"] >= 1, "完整journal恢复后无法实际解密")
    else:
        lab.blocked("successor", "anchor_resume")
        check(lab.snapshot("successor").read_bytes() == saved, "缺完整journal却重跑密码操作")
    lab.evidence["client_crash"] = {"operation": operation, "point": point, "exit": code,
                                    "outcome": "exact_saved_result" if code in (87, 88) else "safely_paused"}


def anchor_response(lab, action):
    lab.ready(); lab.publish("anchor_transport")
    lab.forwarding_helper("drop", action, "successor")
    lab.request_page(expected_exit=1)
    saved = lab.snapshot("successor").read_bytes()
    lab.config_restore("successor")
    if action == "finish":
        lab.resume("successor")
        check(lab.snapshot("successor").read_bytes() == saved, "锚恢复重写了已保存挑战")
        one, two = lab.request_page(), lab.request_page()
        check(one["duplicate"] and one["request"] == two["request"], "已完成锚丢响应后重签新挑战")
        lab.sync(); check(wire(lab)["inbox_count"] == 1, "锚精确恢复后未完成同步")
    else:
        lab.blocked("successor", "anchor_resume")
        lab.blocked("successor", "rebuild_stream_pull", limit="3")
    lab.evidence["anchor_response_drop"] = action
