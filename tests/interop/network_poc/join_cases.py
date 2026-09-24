"""真实 Add/Welcome 的独立进程联调；身份锚仍由可信合成装置提供。"""

import base64
import copy
import json

from .fixture import ACCOUNTS, CONVERSATION, SERVICE, check, identity
from .history_cases import publish, receive_record
from .permission_cases import REMOVE_CHARLIE, prepare, reject_unchanged, version
from .permission_recovery_cases import accept, close, inspect, pause, records, recover


def member(lab):
    return {**identity("d1"), "signature_key": lab.public["d1"]["signature_key"]}


def setup(lab, devices=tuple(ACCOUNTS)):
    for device in devices:
        lab.rust(device, "permission_pin_member", member=member(lab))
    lab.rust("d1", "permission_join_anchor", checkpoint=lab.checkpoint,
             relay_receipt_key=lab.relay_receipt_key)


def prepare_add(lab, ident, device="a1", **fields):
    request = {"change_id": ident, "member": member(lab),
               "key_package": lab.public["d1"]["key_package"], "history_policy": "from_join"}
    request.update(fields)
    return lab.rust(device, "permission_prepare_add", **request)


def submit_add(lab, candidate, device="a1", expected=200):
    return lab.http(device, "submit_permission_change", {"service_id": SERVICE,
                    "conversation_id": CONVERSATION, "change": candidate["change"],
                    "join": candidate["join"]}, expected=expected)


def accept_add(lab, candidate, device="a1"):
    accepted = submit_add(lab, candidate, device)
    check(accepted["outcome"] == "accepted" and "receipt" in accepted, "入群接受缺少签名终态")
    return {"change": candidate["change"], "receipt": accepted["receipt"]}


def material(lab, ident, device="d1", expected=200):
    return lab.http(device, "get_join_material", {"service_id": SERVICE,
                    "conversation_id": CONVERSATION, "change_id": ident}, expected=expected)


def join(lab, bundle, **options):
    return lab.rust("d1", "permission_join", **bundle, **options)


def statement(candidate):
    return json.loads(base64.b64decode(candidate["change"]["statement_bytes"]))


def mutate_bytes(value):
    raw = bytearray(base64.b64decode(value)); raw[-1] ^= 1
    return base64.b64encode(raw).decode()


def assert_no_old_history(lab, old):
    packet, accepted = old
    reject_unchanged(lab, "d1", "wire_receive", **packet["envelope"],
                     acceptance_id=accepted["acceptance_id"], acceptance_receipt=accepted["acceptance_receipt"])


def new_member_flow(lab):
    setup(lab)
    old = publish(lab, "before_join")
    late = lab.prepare("unaccepted_before_join")
    lab.http("d1", "get_permission_records", {"service_id": SERVICE, "conversation_id": CONVERSATION,
             "after_version": "1", "limit": "32"}, expected=403)
    candidate = prepare_add(lab, "first_join")
    record = accept_add(lab, candidate)
    check(version(lab, "a1") == "1", "R0 服务接受冒充发起端完成 R1")
    reject_unchanged(lab, "d1", "wire_send", logical_message_id="not_joined", attempt_id="P1", payload="synthetic")
    check(lab.submit(late, expected=409)["outcome"] == "rejected_final", "加入后首次提交旧目标集未拒绝")
    recover(lab, record, "a1", "a2", "c1")
    current = publish(lab, "after_join_before_welcome")
    bundle = material(lab, "first_join")
    check(bundle == {"record": record, "join": candidate["join"]}, "加入材料与接受原证据不一致")
    join(lab, bundle)
    state = lab.rust("d1", "wire_inspect")
    check(state["history"]["past_epochs"] == [] and version(lab, "d1") == "2", "入群制造了加入前历史")
    page = lab.pull("d1")
    check(len(page["events"]) == 1 and page["events"][0]["event"]["acceptance_id"] == current[1]["acceptance_id"],
          "新成员应仅收到加入后原目标包含自己的消息")
    assert_no_old_history(lab, old)
    check(receive_record(lab, "d1", current)["duplicate"] is False, "新成员未成功解密新消息")
    check(receive_record(lab, "d1", current)["duplicate"] is True, "新成员重复接收未去重")
    recover(lab, record, "b1")
    check(receive_record(lab, "b1", old)["historical"] is True, "已有离线成员的合法旧历史被破坏")
    receive_record(lab, "b1", current)
    reply = publish(lab, "new_member_reply", "d1")
    receive_record(lab, "a1", reply)
    check(lab.submit(old[0]) == old[1], "加入改写了旧接受结果或目标集合")
    check(records(lab)["records"] == [record], "公开权限链没有保持原三段证明和回执结构")
    lab.restart()
    check(material(lab, "first_join") == bundle, "重启没有保持原入群材料")


def identity_and_policy(lab):
    request = {"change_id": "without_pin", "member": member(lab),
               "key_package": lab.public["d1"]["key_package"], "history_policy": "from_join"}
    reject_unchanged(lab, "a1", "permission_prepare_add", **request)
    setup(lab)
    for device, changes in (("b1", {}), ("a1", {"history_policy": "all_history"}),
                            ("a1", {"key_package": lab.public["c1"]["key_package"]})):
        reject_unchanged(lab, device, "permission_prepare_add", **(request | changes))
    wrong_member = member(lab) | {"signature_key": lab.public["b1"]["signature_key"]}
    reject_unchanged(lab, "a1", "permission_pin_member", member=wrong_member)
    same_account = {**identity("a2"), "signature_key": lab.public["a2"]["signature_key"]}
    reject_unchanged(lab, "a1", "permission_prepare_add", **(request | {
        "member": same_account, "key_package": lab.public["a2"]["key_package"]}))
    candidate = prepare_add(lab, "valid_after_rejections")
    record = accept_add(lab, candidate)
    recover(lab, record, "a1", "a2", "b1", "c1")
    join(lab, material(lab, "valid_after_rejections"))
    receive_record(lab, "d1", publish(lab, "valid_identity"))


def altered_materials(lab):
    setup(lab)
    candidate = prepare_add(lab, "bound_join")
    for field in ("key_package", "welcome"):
        bad = copy.deepcopy(candidate); bad["join"][field] = mutate_bytes(bad["join"][field])
        submit_add(lab, bad, expected=(400, 403))
    check(records(lab)["records"] == [], "坏加入材料留下了接受或成员投影")
    submit_add(lab, candidate, device="b1", expected=403)
    record = accept_add(lab, candidate)
    bundle = material(lab, "bound_join")
    for field in ("key_package", "welcome"):
        bad = copy.deepcopy(bundle); bad["join"][field] = mutate_bytes(bad["join"][field])
        reject_unchanged(lab, "d1", "permission_join", **bad)
    bad = copy.deepcopy(bundle)
    bad["record"]["receipt"]["signature_bytes"] = mutate_bytes(bad["record"]["receipt"]["signature_bytes"])
    reject_unchanged(lab, "d1", "permission_join", **bad)
    recover(lab, record, "a1", "a2", "b1", "c1")
    join(lab, bundle)
    receive_record(lab, "d1", publish(lab, "after_invalid_welcome"))


def atomic_join(lab):
    setup(lab)
    candidate = prepare_add(lab, "atomic_join")
    record = accept_add(lab, candidate)
    bundle = material(lab, "atomic_join")
    recover(lab, record, "a1", "a2", "b1", "c1")
    before = (lab.directory / "d1/state.enc").read_bytes()
    for point, code in (("before_save", 83), ("before_rename", 84)):
        join(lab, bundle, failpoint=point, expected_exit=code)
        check((lab.directory / "d1/state.enc").read_bytes() == before, "入群失败却消耗 KeyPackage 或部分提交群状态")
    join(lab, bundle, failpoint="after_save", expected_exit=85)
    join(lab, bundle)
    receive_record(lab, "d1", publish(lab, "after_join_crash"))
    before = lab.rust("d1", "wire_inspect")
    join(lab, bundle)
    check(lab.rust("d1", "wire_inspect") == before, "精确入群重放覆盖了已有效接收的群状态")


def atomic_prepare(lab):
    setup(lab)
    before = (lab.directory / "a1/state.enc").read_bytes()
    for point, code in (("before_save", 83), ("before_rename", 84)):
        prepare_add(lab, "atomic_add", failpoint=point, expected_exit=code)
        check((lab.directory / "a1/state.enc").read_bytes() == before, "准备未提交却改变成员或密码状态")
    prepare_add(lab, "atomic_add", failpoint="after_save", expected_exit=85)
    candidate = prepare_add(lab, "atomic_add")
    check(prepare_add(lab, "atomic_add") == candidate, "重启 CLI 后没有复用精确 Commit/Welcome")
    record = accept_add(lab, candidate)
    for device in ("a1", "b1"):
        before = (lab.directory / device / "state.enc").read_bytes()
        recover(lab, record, device, failpoint="before_rename", expected_exit=84)
        check((lab.directory / device / "state.enc").read_bytes() == before, "Add应用失败留下部分权限状态")
        recover(lab, record, device)
    join(lab, material(lab, "atomic_add"))
    receive_record(lab, "d1", publish(lab, "after_add_crash"))


def competing_same_member(lab):
    setup(lab)
    loser = prepare_add(lab, "add_loser")
    winner = prepare_add(lab, "add_winner", device="a2")
    record = accept_add(lab, winner, "a2")
    submit_add(lab, loser, expected=409)
    recover(lab, record, "a2", "a1", "b1", "c1")
    check(inspect(lab)["recovery_status"] == "ready", "相同身份的有效 Add 胜者没有完成原意图")
    reject_unchanged(lab, "d1", "permission_join", record=record, join=loser["join"])
    join(lab, material(lab, "add_winner"))
    receive_record(lab, "d1", publish(lab, "same_add_winner"))


def competing_other_action(lab):
    setup(lab)
    original = prepare_add(lab, "add_before_competitor")
    winner = accept(lab, prepare(lab, "remove_competitor", device="a2")["change"], "a2")
    recover(lab, winner, "a2", "a1", "b1")
    check(inspect(lab)["recovery_status"] == "needs_reprepare", "其他权限变化丢掉了邀请意图")
    pause(lab)
    candidate = prepare_add(lab, "add_after_competitor")
    before, after = statement(original)["action"], statement(candidate)["action"]
    check(before["member"] == after["member"] and before["key_package_sha256"] == after["key_package_sha256"]
          and before["welcome_sha256"] != after["welcome_sha256"], "重准备未保持目标，或错误复用旧 Welcome")
    record = accept_add(lab, candidate)
    recover(lab, record, "a1", "a2", "b1")
    lab.rust("d1", "permission_join_advance", record=winner)
    reject_unchanged(lab, "d1", "permission_join", record=record, join=original["join"])
    join(lab, material(lab, "add_after_competitor"))
    receive_record(lab, "d1", publish(lab, "different_competitor_done"))


def closed_candidate(lab):
    setup(lab)
    original = prepare_add(lab, "closed_add")
    closed = close(lab, lab.rust("a1", "permission_close_request"))
    recover(lab, closed, "a1")
    pause(lab)
    check(submit_add(lab, original, expected=409)["code"] == "permission_closed", "封口后加入材料复活")
    reject_unchanged(lab, "d1", "permission_join", record=closed, join=original["join"])
    candidate = prepare_add(lab, "after_closed_add")
    record = accept_add(lab, candidate)
    recover(lab, record, "a1", "a2", "b1", "c1")
    join(lab, material(lab, "after_closed_add"))
    receive_record(lab, "d1", publish(lab, "closed_add_recovered"))


def history_after_join(lab):
    setup(lab)
    old = publish(lab, "before_real_join")
    candidate = prepare_add(lab, "history_join")
    record = accept_add(lab, candidate)
    recover(lab, record, "a1", "a2", "b1", "c1")
    join(lab, material(lab, "history_join"))
    own_history = publish(lab, "after_real_join")
    removal = accept(lab, prepare(lab, "after_join_remove")["change"])
    recover(lab, removal, "a1", "a2", "b1", "d1")
    history = lab.rust("d1", "wire_inspect")["history"]["past_epochs"]
    check(len(history) == 1 and history[0]["authorization_version"] == "2", "新成员历史越过真实加入边界")
    assert_no_old_history(lab, old)
    check(receive_record(lab, "d1", own_history)["historical"] is True, "加入后合法旧消息不能恢复")
    receive_record(lab, "d1", publish(lab, "current_after_join_history"))
