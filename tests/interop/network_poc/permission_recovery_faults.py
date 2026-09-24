"""权限恢复的磁盘提交点、Service 终态事务及身份失权边界。"""

import http.client

from .fixture import check
from .permission_cases import REMOVE_CHARLIE, REVOKE_A2, prepare, reject_unchanged, submit, version
from .permission_recovery_cases import accept, close, communicate, inspect, pause, receipt_statement, records, recover


def snapshot_interruptions(lab):
    change = prepare(lab, "recovery_atomic")["change"]
    for point, code in (("before_save", 83), ("before_rename", 84)):
        before = (lab.directory / "a1/state.enc").read_bytes()
        lab.rust("a1", "permission_close_request", failpoint=point, expected_exit=code)
        check((lab.directory / "a1/state.enc").read_bytes() == before, "封口请求保存失败破坏了候选")
    lab.rust("a1", "permission_close_request", failpoint="after_save", expected_exit=85)
    request = lab.rust("a1", "permission_close_request")
    check(request["change"] == change, "重启后封口引用了不同候选")
    closed = close(lab, request)
    for point, code in (("before_save", 83), ("before_rename", 84)):
        before = (lab.directory / "a1/state.enc").read_bytes()
        recover(lab, closed, "a1", failpoint=point, expected_exit=code)
        check((lab.directory / "a1/state.enc").read_bytes() == before, "关闭恢复失败留下部分意图状态")
        check(inspect(lab)["pending_change"] == change, "恢复未提交就丢失了旧候选")
    recover(lab, closed, "a1", failpoint="after_save", expected_exit=85)
    recover(lab, closed, "a1")
    check(inspect(lab)["recovery_status"] == "needs_reprepare", "候选结束后遗失待完成意图")
    pause(lab)
    second = prepare(lab, "recovery_atomic_next")["change"]
    accepted = accept(lab, second)
    for device in ("a1", "b1"):
        for point, code in (("before_save", 83), ("before_rename", 84)):
            before = (lab.directory / device / "state.enc").read_bytes()
            recover(lab, accepted, device, failpoint=point, expected_exit=code)
            check((lab.directory / device / "state.enc").read_bytes() == before,
                  "接受恢复未提交就改变了密码或业务状态")
        recover(lab, accepted, device, failpoint="after_save", expected_exit=85)
        recover(lab, accepted, device)
        check(version(lab, device) == "2", "恢复接受结果重复推进了权限版本")
    communicate(lab, "snapshot_recovery_done")


def relay_interruptions(lab):
    for index, (hook, exit_code) in enumerate((("before_commit_exit", 86), ("after_commit_exit", 87),
                                              ("drop_after_commit", None))):
        change = prepare(lab, "close_crash_" + str(index))["change"]
        request = lab.rust("a1", "permission_close_request")
        lab.control("hook", hook=hook)
        try:
            close(lab, request)
            raise AssertionError("封口故障点不应返回 HTTP 成功")
        except (http.client.RemoteDisconnected, ConnectionResetError):
            pass
        if exit_code is not None:
            check(lab.process.wait(timeout=10) == exit_code, "封口事务退出点不匹配")
        lab.restart()
        terminal = close(lab, request)
        check(receipt_statement(terminal)["outcome"] == "closed", "重启后无法取得持久封口结果")
        check(close(lab, request) == terminal, "同一次封口返回不同原回执")
        check(submit(lab, change, expected=409)["code"] == "permission_closed", "封口在重启后丢失")
        recover(lab, terminal, "a1")
        pause(lab)
        check(records(lab)["records"] == [], "封口不应伪造权限接受链")
    final = prepare(lab, "after_close_crashes")["change"]
    accepted = accept(lab, final)
    recover(lab, accepted, "a1", "b1")
    communicate(lab, "relay_recovery_done")


def signer_failure(lab):
    change = prepare(lab, "signer_atomic")["change"]
    request = lab.rust("a1", "permission_close_request")
    saved = lab.receipt_key.with_suffix(".saved")
    lab.receipt_key.rename(saved)
    try:
        error = close(lab, request, expected=503)
        check(error["code"] == "receipt_signer_unavailable", "丢失服务签名器不能发布伪终态")
        check(inspect(lab)["pending_change"] == change, "Service 失败改变了客户端候选")
        # 运行中换钥也必须拒绝；这是装置自己的临时 Service key，不接触用户密钥。
        replacement_key = lab.relay_key("init")["signature_key"]
        check(replacement_key != lab.relay_receipt_key, "换钥装置未产生独立身份")
        close(lab, request, expected=503)
        submit(lab, change, expected=503)
        check(records(lab)["records"] == [] and records(lab)["authorization_version"] == "1",
              "签名失败部分提交了接受/权限状态")
    finally:
        if lab.receipt_key.exists():
            lab.receipt_key.unlink()
        saved.rename(lab.receipt_key)
    accepted = accept(lab, change)
    check(receipt_statement(close(lab, request))["outcome"] == "accepted",
          "失败的封口不应留下阻止后续有效接受的墓碑")
    recover(lab, accepted, "a1", "b1")
    communicate(lab, "after_signer_recovery")


def removed_self(lab):
    prepare(lab, "intent_before_access_loss", REVOKE_A2)
    winner = prepare(lab, "owner_removes_alice", {"kind": "remove_member", "account_id": "alice"},
                     device="b1")["change"]
    accepted = accept(lab, winner, "b1")
    recover(lab, accepted, "b1", "c1", "a1", "a2")
    for device in ("a1", "a2"):
        state = inspect(lab, device)
        check(state["recovery_status"] == "access_removed", "本机已移除不能标为恢复就绪")
        check(state["checkpoint"]["authorization_version"] == "1", "被移除端不能冒充完成后继 R1")
        pause(lab, device)
        reject_unchanged(lab, device, "permission_prepare", change_id="unauthorized_again", action=REMOVE_CHARLIE)
    communicate(lab, "remaining_after_access_loss", sender="b1", receiver="c1")


def closed_checkpoint_floor(lab):
    prepare(lab, "behind_revoke", REVOKE_A2)
    winner = prepare(lab, "ahead_remove", device="a2")["change"]
    accepted = accept(lab, winner, "a2")
    recover(lab, accepted, "a2")
    request = lab.rust("a1", "permission_close_request")
    closed = close(lab, request)
    check(receipt_statement(closed)["authorization_version"] == "2", "封口未绑定当时服务检查点")
    recover(lab, closed, "a1")
    check(version(lab, "a1") == "1", "Service 检查点不能直接冒充已验证 MLS 状态")
    reject_unchanged(lab, "a1", "permission_prepare", change_id="before_chain", action=REVOKE_A2)
    chain = records(lab, device="a1", limit="1")
    recover(lab, chain["records"][0], "a1", "b1")
    check(inspect(lab)["recovery_status"] == "needs_reprepare", "补链不能丢失原撤销意图")
    pause(lab)
    second = prepare(lab, "after_chain_revoke", REVOKE_A2)["change"]
    terminal = accept(lab, second)
    recover(lab, terminal, "a1", "b1")
    communicate(lab, "after_floor_sync")


def satisfied_before_floor(lab):
    prepare(lab, "original_remove_charlie")
    first = accept(lab, prepare(lab, "winner_remove_charlie", device="a2")["change"], "a2")
    recover(lab, first, "a2")
    second = accept(lab, prepare(lab, "winner_remove_bob", {"kind": "remove_member", "account_id": "bob"},
                                device="a2")["change"], "a2")
    recover(lab, second, "a2")
    closed = close(lab, lab.rust("a1", "permission_close_request"))
    check(receipt_statement(closed)["authorization_version"] == "3", "装置未产生两步后继水位")
    recover(lab, closed, "a1")
    page = records(lab, device="a1", limit="1")
    check(page["records"] == [first] and page["has_more"], "未取得首个真实接受记录")
    recover(lab, page["records"][0], "a1")
    check(version(lab, "a1") == "2" and inspect(lab)["recovery_status"] == "needs_reprepare",
          "原意图提前完成时遗失了尚未补齐的服务水位")
    pause(lab)
    reject_unchanged(lab, "a1", "permission_prepare", change_id="early_release", action=REMOVE_CHARLIE)
    next_page = records(lab, device="a1", after="2", limit="1")
    check(next_page["records"] == [second], "两步链没有连续取回")
    recover(lab, next_page["records"][0], "a1")
    check(version(lab, "a1") == "3" and inspect(lab)["recovery_status"] == "ready",
          "意图和水位均满足后没有恢复发送")
    communicate(lab, "satisfied_after_full_chain", receiver="a2")
