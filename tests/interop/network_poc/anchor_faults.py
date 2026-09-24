"""预约、密码快照与恢复日志之间的故障边界；不通过重做密码操作恢复。"""

import base64
import json
import time

from .fixture import check


def client_crash(lab, point, code):
    lab.enable()
    before = lab.snapshot().read_bytes()
    options = ({"failpoint": point} if code < 86
               else {"env": {"RIM_ANCHOR_FAILPOINT": point}})
    lab.send("interrupted", expected_exit=code, **options)
    saved = lab.snapshot().read_bytes()
    check((saved != before) == (code in (85, 87, 88)), "中断后的快照提交边界错误")
    lab.blocked(id="interrupted", payload="synthetic-anchor-interrupted")
    if code in (87, 88):
        lab.resume()
        check(lab.snapshot().read_bytes() == saved, "恢复执行了新的密码状态转移")
        cached = lab.send("interrupted")
        check(cached["reused"], "有认证日志的精确恢复重新生成密文")
        repeated = lab.send("interrupted")
        check(cached["ciphertext"] == repeated["ciphertext"], "恢复重试没有返回同一已存密文")
        lab.rust("b1", "receive", id="interrupted", ciphertext=cached["ciphertext"])
    else:
        lab.blocked(operation="anchor_resume")
        lab.blocked(id="interrupted", payload="synthetic-anchor-interrupted")
    lab.evidence["crash"] = {"point": point, "exit": code, "snapshot_saved": saved != before,
                             "recovery": "exact_saved_target" if code in (87, 88) else "safely_paused"}


def dropped_response(lab, action):
    lab.enable()
    before = lab.snapshot().read_bytes()
    lab.forwarding_helper("drop", action)
    result = lab.raw_rust("a1", "send", id="lost", payload="synthetic-anchor-lost")
    check(result.returncode == 1, "丢锚响应却返回业务成功")
    saved = lab.snapshot().read_bytes()
    check((saved != before) == (action == "finish"), "丢响应发生在错误的密码提交边界")
    lab.config_restore()
    lab.blocked(id="lost", payload="synthetic-anchor-lost")
    if action == "finish":
        lab.resume()
        packet = lab.send("lost")
        check(packet["reused"], "finish响应遗失后重做了密码操作")
        lab.rust("b1", "receive", id="lost", ciphertext=packet["ciphertext"])
    else:
        lab.blocked(operation="anchor_resume")


def transport_fault(lab, mode):
    lab.enable()
    before = lab.snapshot().read_bytes()
    lab.forwarding_helper(mode)
    started = time.monotonic()
    error = lab.blocked()
    elapsed = time.monotonic() - started
    check(lab.snapshot().read_bytes() == before, "helper失效前生成并保存了新密文")
    if mode == "timeout":
        check(elapsed < 6, "helper调用未按3秒预算有界结束")
    lab.evidence["helper_fault"] = {"mode": mode, "elapsed_seconds": round(elapsed, 3),
                                    "error_code": error["code"]}
    lab.config_restore()
    if mode == "tamper":
        lab.blocked(operation="anchor_resume")
    else:
        lab.resume()
        lab.send("after_helper_fault")


def journal_tamper(lab, mode):
    lab.enable()
    lab.send("journal_one", expected_exit=87, env={"RIM_ANCHOR_FAILPOINT": "after_journal"})
    journal = lab.directory / "a1/anchor-journal.enc"
    first = journal.read_bytes()
    if mode == "rollback":
        lab.resume()
        lab.send("journal_two", expected_exit=87, env={"RIM_ANCHOR_FAILPOINT": "after_journal"})
        journal.write_bytes(first)
    elif mode == "tamper":
        altered = bytearray(first)
        altered[-1] ^= 1
        journal.write_bytes(altered)
    else:
        journal.unlink()
    lab.blocked(operation="anchor_resume")
    lab.blocked()


def exact_reservation_retry(lab):
    lab.enable()
    capture = lab.forwarding_helper()
    lab.send("reserved", expected_exit=86, env={"RIM_ANCHOR_FAILPOINT": "after_reserve"})
    request = json.loads(capture.read_text())["request"]
    authority = lab.materials["a1"]["authority"] / "state.enc"
    before = authority.read_bytes()
    for _ in range(3):
        response = lab.anchor(request)
        signed = response.get("response", response)
        statement = json.loads(base64.b64decode(signed["statement_bytes"]))
        check(statement["status"] == "reserved_duplicate", "精确预约重试未返回同一已消费预约")
        check(authority.read_bytes() == before, "预约精确重试修改锚状态")
    lab.config_restore()
    lab.blocked()
    lab.blocked(operation="anchor_resume")


def authority_crash(lab, point, action):
    lab.enable()
    before = lab.snapshot().read_bytes()
    lab.forwarding_helper("crash_" + point, action)
    result = lab.raw_rust("a1", "send", id="authority_crash", payload="synthetic-anchor-authority_crash")
    check(result.returncode == 1, "独立锚异常退出却返回业务成功")
    saved = lab.snapshot().read_bytes()
    check((saved != before) == (action == "finish"), "锚退出与本机密码保存次序错误")
    lab.config_restore()
    if action == "finish" or point in ("before_save", "before_rename"):
        lab.resume()
        packet = lab.send("authority_crash")
        check(packet["reused"] == (action == "finish"), "锚故障恢复是否复用密文与实际保存状态不符")
        lab.rust("b1", "receive", id="authority_crash", ciphertext=packet["ciphertext"])
    else:
        lab.blocked(operation="anchor_resume")


def authority_missing(lab):
    lab.enable()
    authority = lab.materials["a1"]["authority"]
    backup = lab.backup("authority-missing", authority)
    (authority / "state.enc").unlink()
    lab.blocked()
    check(not (authority / "state.enc").exists(), "锚状态缺失被静默重建")
    lab.restore(backup, authority)
    lab.blocked()
    lab.resume()
    lab.send("authority_restored")


def bounded_authority_storage(lab):
    lab.enable()
    authority = lab.materials["a1"]["authority"]
    capture = lab.forwarding_helper(action="inspect")
    lab.rust("a1", "anchor_inspect")
    lab.config_restore()
    request = json.loads(capture.read_text())["request"]
    before = (authority / "state.enc").read_bytes()
    for count in (5, 6):
        for index in range(count):
            file = authority / (f".snapshot-{index:032x}.tmp")
            file.write_bytes(b"synthetic")
            file.chmod(0o600)
        check(len(list(authority.iterdir())) == count + 3, "容量装置总项数错误")
        if count == 5:
            response = lab.anchor(request)
            statement = json.loads(base64.b64decode(response["response"]["statement_bytes"]))
            check(statement["status"] == "inspected" and len(list(authority.iterdir())) == 3,
                  "总项8的合法临时残留未被清理并正常读取")
        else:
            check(lab.blocked()["code"] == "anchor_unavailable", "总项9未阻断客户端业务")
            check(lab.anchor(request, expected_exit=1)["code"] == "anchor_capacity",
                  "总项9的合法临时文件未在实际容量边界拒绝")
            check(len(list(authority.iterdir())) == 9, "超限拒绝改变或增加了锚目录文件")
        check((authority / "state.enc").read_bytes() == before, "容量验证改变有效锚状态")
    lab.evidence["anchor_directory_boundary"] = {"total_8": "CLEANED_AND_INSPECTED",
                                                "total_9": "anchor_capacity",
                                                "valid_temporary_names": True}


def replace_after_reserve(lab):
    lab.enable()
    old = lab.backup("before-later-state", lab.directory / "a1") / "state.enc"
    lab.send("advanced")
    lab.forwarding_helper("replace_snapshot", replacement=old)
    result = lab.raw_rust("a1", "send", id="must_not_use_old", payload="synthetic-must-not-use-old")
    check(result.returncode == 1, "预约当前摘要后换旧快照，仍成功生成密文")
    error = json.loads(result.stdout)["error"]
    check(error["code"] == "snapshot_load" and "commitment" in error["message"].lower(),
          "更换的密码快照没有在已预约摘要绑定处拒绝")
    check(lab.snapshot().read_bytes() == old.read_bytes(), "已替换旧快照又被密码操作覆盖")
    lab.config_restore()
    lab.blocked()
    lab.blocked(operation="anchor_resume")


def same_head_replay(lab):
    lab.enable()
    capture = lab.forwarding_helper()
    before = lab.snapshot().read_bytes()
    lab.rust("a1", "inspect")
    old_request = json.loads(capture.read_text())["request"]
    lab.config_restore()
    for _ in range(3):
        lab.rust("a1", "inspect")
    check(lab.snapshot().read_bytes() == before, "装置未形成相同head的纯读提交")
    response = lab.anchor(old_request)
    signed = response.get("response", response)
    statement = json.loads(base64.b64decode(signed["statement_bytes"]))
    check(statement["status"] == "conflict", "相同head的更旧预约在后续提交后复活")
