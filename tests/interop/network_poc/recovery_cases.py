"""事务、进程中断、状态依赖与设备流恢复的跨组件验证。"""

import base64
import copy
from concurrent.futures import ThreadPoolExecutor
import http.client
import time

from .fixture import CONVERSATION, SERVICE, check, identity


def interruptions(lab):
    for point, code in (("before_save", 83), ("before_rename", 84), ("after_save", 85)):
        logical = "crash_send_" + point
        lab.rust("a1", "wire_send", logical_message_id=logical, attempt_id="P1",
                 payload="synthetic-crash", failpoint=point, expected_exit=code)
        packet = lab.prepare(logical, payload="synthetic-crash")
        check(packet["reused"] == (point == "after_save"), "发送提交边界与复用结果错误")
        accepted = lab.submit(packet)
        check(bool(accepted["acceptance_id"]), "恢复发送没有接受结果")
        before = (lab.directory / "b1/state.enc").read_bytes()
        lab.receive("b1", packet, failpoint=point, expected_exit=code)
        check(((lab.directory / "b1/state.enc").read_bytes() != before) == (point == "after_save"),
              "接收提交前改变了持久状态")
        result = lab.receive("b1", packet)
        check(result["duplicate"] == (point == "after_save"), "接收崩溃后去重不一致")
    page = lab.pull("b1")
    lab.download("b1", page, failpoint="before_rename", expected_exit=84)
    check(lab.rust("b1", "wire_inspect")["sync"]["download_cursor"] == "0",
          "页面落盘失败推进了下载游标")
    lab.download("b1", page)
    lab.rust("b1", "wire_process")
    check(lab.rust("b1", "wire_inspect")["sync"]["processed_cursor"] == page["next_after_seq"],
          "恢复后处理进度不一致")


def concurrent_commit(lab):
    first, second = lab.prepare("tx_first"), lab.prepare("tx_second")
    lab.control("hook", hook="delay_before_commit", delay_ms="1200")
    with ThreadPoolExecutor(max_workers=3) as pool:
        one = pool.submit(lab.submit, first)
        time.sleep(0.15)
        two = pool.submit(lab.submit, second)
        page = lab.pull("b1", "0", "1")
        one.result(timeout=10)
        two.result(timeout=10)
    check(page["next_after_seq"] == "1", "并发页错误地跳过未返回槽位")
    rest = lab.pull("b1", "1", "100")
    check([x["event_seq"] for x in rest["events"]] == ["2"], "并发提交导致序号空洞或遗漏")
    check(lab.control("stats")["accepted"] == "2", "并发提交未原子接受")


def relay_restart(lab):
    old_stream = lab.pull("b1")["stream_id"]
    for i, (hook, exit_code) in enumerate((("before_commit_exit", 86), ("after_commit_exit", 87))):
        packet = lab.prepare("relay_restart_" + str(i))
        before = int(lab.control("stats")["accepted"])
        lab.control("hook", hook=hook)
        try:
            lab.submit(packet)
            raise AssertionError("服务端退出故障未触发")
        except (http.client.RemoteDisconnected, ConnectionResetError):
            pass
        check(lab.process.wait(timeout=10) == exit_code, "Relay 退出点不符")
        lab.restart()
        after = int(lab.control("stats")["accepted"])
        check(after == before + (hook == "after_commit_exit"), "Relay 持久事务提交边界错误")
        accepted = lab.submit(packet)
        check(lab.attempt("relay_restart_" + str(i))["acceptance_id"] == accepted["acceptance_id"],
              "重启后接受标识变化")
        page = lab.pull("b1")
        check(page["stream_id"] == old_stream, "正常重启更换了设备流")
    check(lab.control("stats")["message_events"] == "6", "崩溃恢复出现部分或重复扇出")


def replacement(lab):
    old = lab.prepare("replace")
    closed = lab.attempt("replace", operation="close_attempt")
    check(closed["outcome"] == "cancelled_before_accept", "旧尝试没有被持久封口")
    error = lab.submit(old, expected=409)
    check(error["code"] == "attempt_closed", "迟到旧包复活")
    new = lab.prepare("replace", "P2", replaces_attempt_id="P1", closure_id=closed["closure_id"])
    # 省略封口参数不能把后继当成初始尝试接受。
    error = lab.submit(new, expected=409)
    check(error["code"] == "attempt_chain_conflict", "新 ID 绕过了尝试链")
    accepted = lab.submit(new, replaces_attempt_id="P1", closure_id=closed["closure_id"])
    same = lab.attempt("replace", "P2", operation="close_attempt")
    check(same["acceptance_id"] == accepted["acceptance_id"], "封口撤回了已接受消息")
    check(lab.control("stats")["accepted"] == "1", "替代产生两条接受记录")
    lab.receive("b1", new)
    lab.prepare("unknown_successor")
    first_closed = lab.attempt("unknown_successor", operation="close_attempt")
    second = lab.prepare("unknown_successor", "P2", replaces_attempt_id="P1",
                         closure_id=first_closed["closure_id"])
    # P2 尚未到服务端时，也能携带当前链尾证明封口。
    second_closed = lab.http("a1", "close_attempt", {
        "service_id": SERVICE, "conversation_id": CONVERSATION,
        "logical_message_id": "unknown_successor", "attempt_id": "P2",
        "replaces_attempt_id": "P1", "closure_id": first_closed["closure_id"]})
    check(second_closed["outcome"] == "cancelled_before_accept", "未知后继无法封口")
    check(lab.submit(second, replaces_attempt_id="P1", closure_id=first_closed["closure_id"],
                     expected=409)["code"] == "attempt_closed", "已封口未知后继在迟到时复活")


def dependencies(lab):
    # 第一条有效信封被传输装置损坏，后续合法消息仍可处理。
    invalid = lab.prepare("bad_payload")
    broken = copy.deepcopy(invalid)
    payload = bytearray(base64.b64decode(broken["envelope"]["payload_bytes"]))
    payload[-1] ^= 1
    broken["envelope"]["payload_bytes"] = base64.b64encode(payload).decode()
    lab.submit(broken)
    good = lab.prepare("after_bad")
    lab.submit(good)
    page = lab.pull("b1")
    lab.download("b1", page)
    result = lab.rust("b1", "wire_process")
    check(result["sync"]["quarantined_count"] == 1 and len(result["deliveries"]) == 1,
          "坏消息应隔离且不能报告送达，后续合法消息应成功")
    old_state_packet = lab.prepare("old_state_pending")
    previous = lab.state_ref
    removal = lab.rust("a1", "remove", id="remove_c", member="c1")
    current = lab.rust("a1", "wire_inspect")["crypto_state_ref"]
    lab.rust("a1", "wire_configure", conversation_id=CONVERSATION, authorization_version="2")
    lab.control("set_state", authorization_version="2", crypto_state_ref=current,
                members=[identity(d) for d in ("a1", "a2", "b1")])
    rejected = lab.submit(old_state_packet, expected=409)
    check(rejected["code"] == "state_stale" and rejected["outcome"] == "rejected_final",
          "权限变更后首次提交旧状态未被终态拒绝")
    control = {"control_id": "remove_c", "from_state_ref": previous,
               "to_state_ref": current, "payload_bytes": removal["commit"]}
    lab.control("add_control", control=control, recipients=[identity("b1")], append_events=False)
    lab.rust("b1", "wire_configure", conversation_id=CONVERSATION,
             authorization_version="1", pending_limit=1)
    lab.submit(lab.prepare("wait_dependency"))
    page = lab.pull("b1", "2")
    lab.download("b1", page)
    waiting = lab.rust("b1", "wire_process")
    check(waiting["sync"]["processed_cursor"] == "2", "缺依赖时处理游标越过等待事件")
    dependencies_ = lab.http("b1", "get_crypto_dependencies", {
        "service_id": SERVICE, "conversation_id": CONVERSATION,
        "from_state_ref": previous, "to_state_ref": current, "limit": "32"})
    check(len(dependencies_["controls"]) == 1, "满队列无法取得独立控制依赖")
    for item in dependencies_["controls"]:
        lab.rust("b1", "wire_apply_dependency", control=item)
        lab.rust("b1", "wire_apply_dependency", control=item)
    lab.rust("b1", "wire_configure", conversation_id=CONVERSATION, authorization_version="2")
    lab.rust("b1", "wire_process")
    state = lab.rust("b1", "wire_inspect")
    check(state["sync"]["processed_cursor"] == "3" and state["inbox_count"] == 2
          and state["sync"]["applied_control_count"] == 1, "依赖恢复后重复应用或消息未恢复")


def lifecycle(lab):
    packet = lab.prepare("expired")
    accepted = lab.submit(packet)
    page = lab.pull("b1")
    lab.download("b1", page)
    lab.rust("b1", "wire_process")
    lab.control("set_availability", acceptance_id=accepted["acceptance_id"], availability="expired")
    unavailable = lab.pull("b1")
    check(unavailable["events"][0]["availability"] == "expired", "未返回过期占位")
    check(unavailable["events"][0]["event_id"] == page["events"][0]["event_id"], "过期改变了槽位身份")
    lab.download("b1", unavailable)
    lab.rust("b1", "wire_process")
    check(lab.submit(packet)["acceptance_id"] == accepted["acceptance_id"], "过期旧消息重新接受")
    error = lab.http("b1", "pull_events", {"service_id": "S2", "after_seq": "0", "limit": "1"}, expected=403)
    check(error["code"] == "permission_denied", "实例隔离失效")
    error = lab.http("b1", "pull_events", {"service_id": SERVICE, "stream_id": "wrong_stream",
                                           "after_seq": "0", "limit": "1"}, expected=409)
    check(error["code"] == "cursor_invalid", "失效游标被默默重置")
    conflict = copy.deepcopy(page)
    conflict["events"][0]["event_id"] = "replaced_slot"
    conflict = lab.sign_test_page(conflict)
    result = lab.download("b1", conflict)
    check(result["status"] == "stream_conflict", "同槽异身份被覆盖")
    check(lab.rust("b1", "wire_inspect")["sync"]["halted"], "流冲突停止状态未持久化")


def input_limits(lab):
    packet = lab.prepare("limits")
    body = b'{"service_id":"synthetic-network","after_seq":"0","after_seq":"1","limit":"1"}'
    error = lab.http("b1", "pull_events", {}, raw=body, expected=400)
    check(error["code"] == "invalid_envelope", "重复 JSON 键未被拒绝")
    error = lab.http("b1", "pull_events", {"service_id": SERVICE, "after_seq": 0, "limit": "1"}, expected=400)
    check(error["code"] == "invalid_envelope", "数字冒充字符串游标")
    lab.pull("b1")
    error = lab.pull("b1", "9007199254740993", expected=409)
    check(error["code"] == "cursor_invalid", "大整数没有无损进入游标边界判断")
    error = lab.pull("b1", "18446744073709551616", expected=400)
    check(error["code"] == "invalid_envelope", "u64 溢出没有拒绝")
    invalid = copy.deepcopy(packet)
    invalid["envelope"]["payload_bytes"] = base64.b64encode(b"a" * (512 * 1024 + 1)).decode()
    check(lab.submit(invalid, expected=400)["code"] == "invalid_envelope", "超长密文未在输入边界拒绝")
    # 实际 Rust 密文组成的大页必须截断后仍能通过原CLI的1MiB入口。
    for i in range(12):
        lab.submit(lab.prepare("large_" + str(i), payload="z" * (64 * 1024)))
    cursor = "0"
    count = 0
    truncated = False
    while True:
        page = lab.pull("b1", cursor)
        truncated = truncated or page["has_more"]
        lab.download("b1", page)
        lab.rust("b1", "wire_process")
        count += len(page["events"])
        cursor = page["next_after_seq"]
        if not page["has_more"]:
            break
    check(count == 12 and truncated, "大页未按字节截断或补拉遗漏")


def revoked_access(lab):
    packet = lab.prepare("before_revoke")
    accepted = lab.submit(packet)
    old_targets = copy.deepcopy(accepted["recipients"])
    lab.control("revoke_device", **identity("c1"))
    error = lab.pull("c1", expected=403)
    check(error["code"] == "device_revoked", "已撤销设备仍可补拉")
    again = lab.submit(packet)
    check(again["acceptance_id"] == accepted["acceptance_id"] and again["recipients"] == old_targets,
          "重试改写了原目标或接受结果")
    check(lab.pull("b1")["events"][0]["event"]["envelope"] == packet["envelope"],
          "仍有权的原目标不能读取原记录")
