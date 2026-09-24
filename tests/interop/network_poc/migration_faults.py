"""同一加密快照和Service单事务的真实进程退出恢复。"""

import http.client

from .fixture import check, identity
from .migration_cases import get, joined, prepared, request, selection, submit, transfer_count


def durable(lab, device, operation, fields):
    before = (lab.directory / device / "state.enc").read_bytes()
    for point, code in (("before_save", 83), ("before_rename", 84)):
        lab.rust(device, operation, **fields, failpoint=point, expected_exit=code)
        check((lab.directory / device / "state.enc").read_bytes() == before, operation + "失败却部分改变快照")
    lab.rust(device, operation, **fields, failpoint="after_save", expected_exit=85)
    return lab.rust(device, operation, **fields)


def client_atomicity(lab):
    old = joined(lab, 2)
    req = durable(lab, "b2", "history_request", {"transfer_id": "atomic_history", "source": identity("b1"), "selection": selection(old)})
    check(req["reused"], "保存后退出未复用目标原请求")
    bundle = durable(lab, "b1", "history_export", {"request": req["request"]})
    check(bundle["reused"], "保存后退出未复用原密文包")
    accepted = submit(lab, bundle)
    result = durable(lab, "b2", "history_import", accepted)
    check(result["duplicate"] and result["imported_count"] == 0
          and lab.rust("b2", "history_inspect")["imported_count"] == 2, "导入恢复没有共同提交副本、去重和请求消耗")
    request(lab, "atomic_cancel", old)
    check(durable(lab, "b2", "history_cancel", {"transfer_id": "atomic_cancel"})["duplicate"], "取消终态没有原子保存")


def service_atomicity(lab):
    old = joined(lab)
    bundle = prepared(lab, "service_history_atomic", old)
    saved = lab.receipt_key.with_suffix(".saved")
    lab.receipt_key.rename(saved)
    try:
        check(submit(lab, bundle, expected=503)["code"] == "receipt_signer_unavailable"
              and transfer_count(lab) == 0, "签名失败留下半成迁移")
    finally:
        saved.rename(lab.receipt_key)
    for hook, code in (("before_commit_exit", 86), ("after_commit_exit", 87)):
        lab.control("hook", hook=hook)
        try:
            submit(lab, bundle)
            raise AssertionError("受控退出却返回成功")
        except (http.client.RemoteDisconnected, ConnectionResetError):
            pass
        check(lab.process.wait(timeout=10) == code, "Service迁移事务退出点不符")
        lab.restart()
        check(transfer_count(lab) == (0 if code == 86 else 1), "迁移事务没有全有或全无")
        if code == 86:
            get(lab, "service_history_atomic", expected=403)
    accepted = get(lab, "service_history_atomic")
    check(submit(lab, bundle) == accepted, "提交后退出重新生成了Service回执")
    lab.rust("b2", "history_import", **accepted)
    lost = prepared(lab, "history_response_lost", old)
    lab.control("hook", hook="drop_after_commit")
    try:
        submit(lab, lost)
        raise AssertionError("丢响应装置没有生效")
    except (http.client.RemoteDisconnected, ConnectionResetError):
        pass
    original = get(lab, "history_response_lost")
    lab.restart()
    check(submit(lab, lost) == original and get(lab, "history_response_lost") == original,
          "丢响应重启改变了原迁移事实")
    check(lab.rust("b2", "history_import", **original)["imported_count"] == 0 and transfer_count(lab) == 2,
          "响应恢复重复展示了相同原消息")
