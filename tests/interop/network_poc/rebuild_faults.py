"""安全重建的保存窗口、真实子进程退出与传输失效。"""

import json
import sys

from .fixture import check
from .rebuild_cases import old_blocked, prepared


def link_helper(lab, mode):
    trusted = lab.materials["a1"]["trusted"]
    script = trusted / "rebuild-transport.py"
    capture = trusted / "rebuild-transport.json"
    settings = {"helper": str(lab.helper), "capture": str(capture), "mode": mode}
    source = '''import base64, json, pathlib, subprocess, sys
settings = SETTINGS
data = json.load(sys.stdin)
chosen = data["op"] == "rebuild"
if chosen and settings["mode"].startswith("crash_"):
    data["failpoint"] = settings["mode"][6:]
result = subprocess.run([settings["helper"]], input=json.dumps(data), text=True, capture_output=True)
if chosen:
    capture = pathlib.Path(settings["capture"])
    capture.write_text(json.dumps({"request": data, "response": result.stdout, "returncode": result.returncode}))
    capture.chmod(0o600)
if chosen and settings["mode"] == "drop":
    sys.exit(0)
if chosen and settings["mode"] == "tamper" and result.returncode == 0:
    reply = json.loads(result.stdout)
    signed = reply.get("result", reply)
    if "response" in signed: signed = signed["response"]
    raw = bytearray(base64.b64decode(signed["signature_bytes"]))
    raw[-1] ^= 1
    signed["signature_bytes"] = base64.b64encode(raw).decode()
    sys.stdout.write(json.dumps(reply)); sys.exit(0)
sys.stdout.write(result.stdout)
sys.exit(result.returncode)
'''
    script.write_text("#!" + sys.executable + "\n" + source.replace("SETTINGS", repr(settings)))
    script.chmod(0o700)
    lab.config_change(helper_path=str(script))
    return capture


def init_crash(lab, point, code):
    lab.unresolved()
    template = lab.template()
    lab.offer(template=template, failpoint=point, expected_exit=code)
    state = lab.snapshot("successor")
    check(state.exists() == (code == 85), "新身份保存边界与受控退出不符")
    if code == 85:
        saved = state.read_bytes()
        recovered = lab.rust("successor", "rebuild_offer")
        check(state.read_bytes() == saved, "查询已保存新身份重新生成或改写密码状态")
        lab.plan, lab.public["successor"] = recovered["plan"], recovered["identity"]
        lab.rust("successor", "rebuild_init", template=template, expected_exit=1)
    else:
        lab.offer(template=template)
    lab.approve(); lab.link(); lab.configure_successor()
    lab.rust("successor", "permission_join", **lab.joining())
    lab.communicate("identity_crash_recovered")
    old_blocked(lab)
    lab.evidence["identity_crash"] = {"point": point, "exit": code, "saved": code == 85}


def join_crash(lab, point, code):
    prepared(lab); lab.link(); lab.configure_successor()
    bundle = lab.joining()
    before = lab.snapshot("successor").read_bytes()
    options = {"env": {"RIM_ANCHOR_FAILPOINT": point}} if code >= 86 else {"failpoint": point}
    lab.rust("successor", "permission_join", **bundle, expected_exit=code, **options)
    saved = lab.snapshot("successor").read_bytes()
    check((saved != before) == (code in (85, 87)), "Welcome 保存边界不符")
    lab.blocked("successor", "wire_send", logical_message_id="interrupted_join", attempt_id="P1", payload="synthetic")
    if code == 87:
        lab.resume("successor")
        check(lab.rust("successor", "permission_join", **bundle)["duplicate"],
              "完整已存 Welcome 恢复重试重复消费了 KeyPackage")
        lab.communicate("joined_after_saved_journal")
    else:
        lab.blocked("successor", "anchor_resume")
        check(lab.snapshot("successor").read_bytes() == saved, "缺少完整journal却重新执行Welcome")
    old_blocked(lab)
    lab.evidence["welcome_crash"] = {"point": point, "exit": code,
                                      "outcome": "exact_saved_result" if code == 87 else "safely_paused"}


def link_crash(lab, point):
    prepared(lab)
    old = lab.snapshot().read_bytes()
    child = lab.snapshot("successor").read_bytes()
    authority = lab.materials["a1"]["authority"] / "state.enc"
    prior = authority.read_bytes()
    capture = link_helper(lab, "crash_" + point)
    lab.link(expected_exit=1)
    result = json.loads(capture.read_text())
    check(result["returncode"] != 0, "独立关联进程未实际退出")
    check((authority.read_bytes() != prior) == (point == "after_save"), "独立关联持久化退出窗口不符")
    check(lab.snapshot().read_bytes() == old and lab.snapshot("successor").read_bytes() == child,
          "独立关联失败部分覆盖端侧密码状态")
    lab.config_restore()
    lab.link(); lab.configure_successor()
    lab.rust("successor", "permission_join", **lab.joining())
    lab.communicate("link_crash_recovered")
    old_blocked(lab)
    lab.evidence["link_crash"] = {"point": point, "actual_helper_exit": result["returncode"]}


def link_transport(lab, mode):
    prepared(lab)
    capture = link_helper(lab, mode)
    lab.link(expected_exit=1)
    recorded = json.loads(capture.read_text())
    check(recorded["returncode"] == 0, "传输故障未发生在真实关联已接受之后")
    lab.config_restore()
    lab.link(); lab.configure_successor()
    lab.rust("successor", "permission_join", **lab.joining())
    lab.communicate("link_transport_recovered")
    old_blocked(lab)
    lab.evidence["link_transport"] = {"mode": mode, "actual_link_saved": True,
                                      "retry": "same_successor"}


def approval_crash(lab, point, code):
    lab.unresolved(); lab.offer()
    before = lab.snapshot("source").read_bytes()
    options = {"env": {"RIM_ANCHOR_FAILPOINT": point}} if code >= 86 else {"failpoint": point}
    lab.rust("source", "rebuild_approve", plan=lab.plan, expected_exit=code, **options)
    saved = lab.snapshot("source").read_bytes()
    check((saved != before) == (code in (85, 87, 88)), "批准结果保存边界错误")
    lab.blocked("source", "rebuild_approve", plan=lab.plan)
    if code in (87, 88):
        lab.resume("source")
        one = lab.approve()
        two = lab.approve()
        check(one == two and lab.snapshot("source").read_bytes() == saved,
              "恢复未复用完整已存批准结果")
        lab.link(); lab.configure_successor()
        lab.rust("successor", "permission_join", **lab.joining())
        lab.communicate("approved_after_crash")
    else:
        lab.blocked("source", "anchor_resume")
        check(lab.snapshot("source").read_bytes() == saved, "缺完整批准结果时重新执行签名")
    old_blocked(lab)
    lab.evidence["approval_crash"] = {"point": point, "exit": code,
                                       "result": "saved_exact_result" if code in (87, 88) else "paused"}


def approval_lost_response(lab):
    lab.unresolved(); lab.offer()
    lab.forwarding_helper("drop", "finish", "source")
    lab.rust("source", "rebuild_approve", plan=lab.plan, expected_exit=1)
    saved = lab.snapshot("source").read_bytes()
    lab.config_restore("source"); lab.resume("source")
    one = lab.approve(); two = lab.approve()
    check(one == two and lab.snapshot("source").read_bytes() == saved,
          "批准响应遗失后重写已存结果")
    lab.link(); lab.configure_successor()
    lab.rust("successor", "permission_join", **lab.joining())
    lab.communicate("approved_after_lost_response")


def missing_child_journal(lab):
    prepared(lab); lab.link(); lab.configure_successor()
    lab.rust("successor", "permission_join", **lab.joining(), expected_exit=87,
             env={"RIM_ANCHOR_FAILPOINT": "after_journal"})
    saved = lab.snapshot("successor").read_bytes()
    (lab.directory / "successor/anchor-journal.enc").unlink()
    lab.blocked("successor", "anchor_resume")
    lab.blocked("successor", "permission_join", **lab.bundle)
    check(lab.snapshot("successor").read_bytes() == saved, "新设备缺journal后重复消费一次性Welcome")
    old_blocked(lab)


def cancelled_join(lab):
    prepared(lab); lab.link(); lab.configure_successor()
    bundle = lab.joining()
    lab.rust("a1", "anchor_rebuild_cancel", plan=lab.plan, approval=lab.approval)
    before = lab.snapshot("successor").read_bytes()
    lab.blocked("successor", "permission_join", **bundle)
    check(lab.snapshot("successor").read_bytes() == before, "取消后迟到真实Welcome激活了新群")
    old_blocked(lab)


def source_without_anchor(lab):
    lab.unresolved(); lab.offer()
    del lab.configs["source"]
    error = lab.blocked("source", "rebuild_approve", plan=lab.plan)
    check(error["code"] == "rebuild_anchor_required", "未由可信锚启动的源设备仍能批准")


def existing_old_journal(lab):
    lab.unresolved(point="after_journal", code=87)
    lab.offer(); lab.approve()
    saved = lab.snapshot().read_bytes()
    lab.link(expected_exit=1)
    check(lab.snapshot().read_bytes() == saved, "原完整结果被重建覆盖")
    lab.resume()
    cached = lab.rust("a1", "wire_send", logical_message_id="unresolved", attempt_id="P1",
                       payload="synthetic-anchor-unresolved")
    check(cached["reused"], "完整原结果未沿既有恢复入口精确复用")
    lab.rust("b1", "wire_receive", **cached["envelope"])
