"""新成员的信任锚、材料访问和真实 HTTP 接受事务边界。"""

import copy
import http.client

from .fixture import check
from .join_cases import accept_add, join, material, member, prepare_add, setup, submit_add
from .permission_cases import prepare, reject_unchanged, version
from .permission_recovery_cases import accept, communicate, records, recover


def _finish(lab, ident):
    bundle = material(lab, ident)
    recover(lab, bundle["record"], "a1", "b1")
    join(lab, bundle)
    check(version(lab, "d1") == version(lab, "a1"), "新成员和原成员没有共同进入已接受状态")
    communicate(lab, "after_" + ident, sender="d1", receiver="b1")
    return bundle


def anchor_boundaries(lab):
    setup(lab)
    altered = copy.deepcopy(lab.checkpoint)
    altered["owner_account_id"] = "bob"
    for checkpoint, key in ((lab.checkpoint, lab.relay_receipt_key),
                            (altered, lab.relay_receipt_key),
                            (lab.checkpoint, lab.public["b1"]["signature_key"])):
        reject_unchanged(lab, "d1", "permission_join_anchor", checkpoint=checkpoint,
                         relay_receipt_key=key)
    predecessor = accept(lab, prepare(lab, "before_join_anchor_advance")["change"])
    recover(lab, predecessor, "a1", "a2", "b1")
    advanced = lab.rust("d1", "permission_join_advance", record=predecessor)
    check(advanced["checkpoint"] is None
          and advanced["admission"]["public_checkpoint"]["authorization_version"] == "2"
          and lab.rust("d1", "inspect")["group_id"] is None,
          "公开权限链被误当成已经完成的 MLS 入群状态")
    check(lab.rust("d1", "permission_join_advance", record=predecessor)["duplicate"],
          "已验证公开链的精确重放不幂等")
    reject_unchanged(lab, "d1", "permission_join_anchor", checkpoint=lab.checkpoint,
                     relay_receipt_key=lab.relay_receipt_key)
    ident = "join_after_public_chain"
    candidate = prepare_add(lab, ident)
    accepted = accept_add(lab, candidate)
    reject_unchanged(lab, "d1", "permission_join_advance", record=accepted)
    reject_unchanged(lab, "d1", "permission_recover", record=accepted)
    bundle = _finish(lab, ident)
    state = lab.rust("d1", "wire_inspect")
    check(state["history"]["past_epochs"] == [] and version(lab, "d1") == "3",
          "通过公共链加入后制造了入群前历史或回退了权限版本")
    reject_unchanged(lab, "d1", "permission_join_advance", record=predecessor)
    check(join(lab, bundle)["duplicate"], "成功加入不能精确重报原结果")


def signer_atomicity(lab):
    setup(lab)
    ident = "join_signer_failure"
    candidate = prepare_add(lab, ident)
    before = (lab.directory / "a1/state.enc").read_bytes()
    saved = lab.receipt_key.with_suffix(".saved")
    lab.receipt_key.rename(saved)
    try:
        error = submit_add(lab, candidate, expected=503)
        check(error["code"] == "receipt_signer_unavailable", "入群签名失败没有明确失败")
        page = records(lab)
        check(page["records"] == [] and page["authorization_version"] == "1",
              "签名失败留下了半成入群权限或接受记录")
        material(lab, ident, expected=403)
        check((lab.directory / "a1/state.enc").read_bytes() == before,
              "Service 签名失败修改了发起端的有效候选")
    finally:
        saved.rename(lab.receipt_key)
    accepted = submit_add(lab, candidate)
    check(submit_add(lab, candidate) == accepted, "签名恢复后的同一入群接受不幂等")
    bundle = _finish(lab, ident)
    check(bundle["join"] == candidate["join"] and bundle["record"]["receipt"] == accepted["receipt"],
          "签名失败消耗了 KeyPackage 或改变了可领取材料")


def relay_atomicity(lab):
    setup(lab)
    ident = "join_transaction_recovery"
    candidate = prepare_add(lab, ident)
    for hook, expected_exit in (("before_commit_exit", 86), ("after_commit_exit", 87)):
        lab.control("hook", hook=hook)
        try:
            submit_add(lab, candidate)
            raise AssertionError("入群事务故障点错误地返回成功")
        except (http.client.RemoteDisconnected, ConnectionResetError):
            pass
        check(lab.process.wait(timeout=10) == expected_exit, "入群事务退出点不匹配")
        lab.restart()
        page = records(lab)
        if expected_exit == 86:
            check(page["records"] == [] and page["authorization_version"] == "1",
                  "提交前退出留下权限、KeyPackage 占用或接受链")
            material(lab, ident, expected=403)
        else:
            check(len(page["records"]) == 1 and page["authorization_version"] == "2",
                  "提交后退出丢失或重复了入群接受")
    accepted = submit_add(lab, candidate)
    bundle = _finish(lab, ident)
    check(bundle["record"] == {"change": candidate["change"], "receipt": accepted["receipt"]}
          and bundle["join"] == candidate["join"], "重启后的入群材料与接受证明不一致")


def relay_lost_ack(lab):
    setup(lab)
    ident = "join_lost_acceptance"
    candidate = prepare_add(lab, ident)
    lab.control("hook", hook="drop_after_commit")
    try:
        submit_add(lab, candidate)
        raise AssertionError("已设置丢响应却收到入群成功")
    except (http.client.RemoteDisconnected, ConnectionResetError):
        pass
    check(lab.process.poll() is None, "丢响应装置不应结束 Relay")
    original = material(lab, ident)
    lab.restart()
    check(material(lab, ident) == original, "重启后已接受入群的材料或回执变了")
    accepted = submit_add(lab, candidate)
    check(accepted["receipt"] == original["record"]["receipt"]
          and records(lab)["records"] == [original["record"]], "丢响应重试接受了第二次加入")
    _finish(lab, ident)


def material_access(lab):
    setup(lab)
    ident = "join_target_only_material"
    candidate = prepare_add(lab, ident)
    material(lab, ident, expected=403)
    accepted = accept_add(lab, candidate)
    for device in ("a1", "a2", "b1", "c1"):
        material(lab, ident, device=device, expected=403)
    bundle = _finish(lab, ident)
    check(bundle["record"] == accepted and bundle["join"] == candidate["join"],
          "目标没有取得原始入群材料")
    removal = prepare(lab, "remove_material_target", {"kind": "remove_member", "account_id": "david"})["change"]
    terminal = accept(lab, removal)
    material(lab, ident, expected=403)
    recover(lab, terminal, "a1", "b1", "d1")
    lab.restart()
    material(lab, ident, expected=403)
    reject_unchanged(lab, "d1", "wire_send", logical_message_id="removed_join_target",
                     attempt_id="P1", payload="synthetic-access-removed")
    communicate(lab, "remaining_after_join_target_removed")


def retired_identity(lab):
    setup(lab)
    ident = "join_before_retirement"
    candidate = prepare_add(lab, ident)
    accepted = submit_add(lab, candidate)
    _finish(lab, ident)
    removal = prepare(lab, "retire_joined_identity", {"kind": "remove_member", "account_id": "david"})["change"]
    terminal = accept(lab, removal)
    recover(lab, terminal, "a1", "b1", "d1")
    lab.restart()
    reject_unchanged(lab, "a1", "permission_prepare_add", change_id="must_not_rejoin",
                     member=member(lab), key_package=lab.public["d1"]["key_package"],
                     history_policy="from_join")
    reject_unchanged(lab, "d1", "permission_join_anchor", checkpoint=lab.checkpoint,
                     relay_receipt_key=lab.relay_receipt_key)
    check(submit_add(lab, candidate) == accepted, "旧加入的精确查询改写了原接受事实")
    material(lab, ident, expected=403)
    page = records(lab)
    check(len(page["records"]) == 2 and page["authorization_version"] == "3",
          "旧加入重放复活了账号或制造了新的权限变更")
    packet = lab.prepare("after_retired_join_retry")
    result = lab.submit(packet)
    check(all(target["device_id"] != "d1" for target in result["recipients"]),
          "已移除的新成员被原加入记录重新授权")
    lab.receive("b1", packet)
