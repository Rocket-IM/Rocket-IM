"""旧密文确定性拒绝与锚状态、真实签页隔离和连续同步的联合回归。"""
import base64
import copy

from .fixture import ACCOUNTS, check
from .first_trust_evidence import state
from .history_cases import signed_for_packet
from .join_review_regressions import enable_anchor, reject_ready
from .sync_support import relay_receipts


def setup(lab):
    lab.setup_expired()
    _, _, _, bundle = lab.prepare_recovery()
    lab.install_recovery(lab.accept_recovery(bundle)["record"])
    enable_anchor(lab, "d1")


def reject_old(lab):
    reject_ready(lab, "d1", "wire_receive", "history_unavailable",
                 **lab.old_packet["envelope"], acceptance_id=lab.old_acceptance["acceptance_id"],
                 acceptance_receipt=lab.old_acceptance["acceptance_receipt"])


def download_pair(lab):
    logical = "after-history-rejection"
    packet = lab.prepare(logical)
    accepted = lab.submit(packet)
    lab.rust("a1", "wire_accept", logical_message_id=logical, attempt_id="P1",
             acceptance_receipt=accepted["acceptance_receipt"])
    page = lab.pull("d1")
    check([s["event"]["acceptance_id"] for s in page["events"]] ==
          [lab.old_acceptance["acceptance_id"], accepted["acceptance_id"]],
          "测试签页必须包含队首旧密文及后续新密文")
    lab.download("d1", page)
    lab.case_evidence["signed_page"] = page.wrapper
    return page, packet, accepted


def assert_processed(lab, processed, page, accepted, *, resumed=False):
    lab.case_evidence["processed"] = processed
    expected = [{"acceptance_id": accepted["acceptance_id"], "attempt_id": "P1",
                 "event_id": page["events"][1]["event_id"]}]
    check(processed["deliveries"] == expected, "隔离旧消息产生错误送达或阻塞新消息")
    if resumed:
        check(processed["results"] == [], "恢复重新执行了已提交的批次")
    else:
        results = [item["result"] for item in processed["results"]]
        check(len(results) == 2 and results[0] == {"status": "quarantined", "code": "history_unavailable"}
              and results[1]["status"] == "valid"
              and results[1]["acceptance_id"] == accepted["acceptance_id"],
              "旧消息未隔离或新消息未解密")
    wire = lab.rust("d1", "wire_inspect")
    check(wire["inbox_count"] == 1 and wire["sync"]["pending_count"] == 0
          and wire["sync"]["processed_cursor"] == page["next_after_seq"]
          and wire["sync"]["download_cursor"] == page["next_after_seq"],
          "拒绝旧消息污染成功去重或未推进连续游标")
    old = lab.rust("d1", "wire_slot_inspect", event_seq=page["events"][0]["event_seq"])
    check(old["slot"] == page["events"][0] and not old["waiting"]
          and old["result"] == {"status": "quarantined", "code": "history_unavailable"},
          "隔离改写原消息槽或丢失拒绝原因")
    lab.case_evidence.update(processed=processed, wire=wire, old_slot=old)
    for delivery in processed["deliveries"]:
        lab.http("d1", "report_delivery", {"service_id": lab.service, **delivery})
    rows = [r for r in relay_receipts(lab)["receipts"] if r["device"]["device_id"] == "d1"]
    check(len(rows) == 1 and rows[0]["acceptance_id"] == accepted["acceptance_id"]
          and rows[0]["delivered"] and not rows[0]["read"], "旧消息被误报送达或后台同步自动已读")
    check(lab.rust("d1", "wire_read_pending")["pending_count"] == 0, "隔离产生阅读意图")
    lab.restart()
    lab.download("d1", page)
    repeated = lab.rust("d1", "wire_process")
    check(repeated["results"] == [] and repeated["deliveries"] == expected,
          "重启重放再次处理隔离消息或丢失新消息回执")
    lab.continued("continued-after-quarantine", sender="d1", recipients=(*ACCOUNTS, "d1"))


def continued_sync(lab, direct=True):
    setup(lab)
    if direct:
        for _ in range(2):
            reject_old(lab)
            lab.restart()
    page, _, accepted = download_pair(lab)
    assert_processed(lab, lab.rust("d1", "wire_process"), page, accepted)
    if direct:
        reject_old(lab)


def process_fault(lab, point):
    setup(lab)
    page, _, accepted = download_pair(lab)
    before = state(lab)
    code = {"after_reserve": 86, "after_journal": 87, "after_finish": 88}[point]
    lab.rust("d1", "wire_process", env={"RIM_ANCHOR_FAILPOINT": point}, expected_exit=code)
    if point == "after_reserve":
        check(state(lab) == before, "预约后中断却提交了消息或游标")
        for _ in range(2):
            reject_old(lab)
            error = lab.rust("d1", "anchor_resume", expected_exit=1)
            check(error["code"] == "anchor_unresolved", "缺失结果日志的预约被释放")
            check(lab.rust("d1", "wire_process", expected_exit=1)["code"] == "anchor_paused",
                  "未决预约被旧密文预检绕过")
            lab.restart()
        check(state(lab) == before, "未决恢复改变快照或 Relay")
        lab.case_evidence["unresolved"] = lab.rust("d1", "anchor_inspect")
        return
    lab.restart()
    lab.resume("d1")
    anchor = lab.rust("d1", "anchor_inspect")
    lab.resume("d1")
    check(lab.rust("d1", "anchor_inspect") == anchor, "重复恢复推进锚")
    assert_processed(lab, lab.rust("d1", "wire_process"), page, accepted, resumed=True)


def retained_history(lab):
    lab.setup_expired()
    old = lab.prepare("retained-unseen")
    accepted = lab.submit(old)
    lab.rust("a1", "wire_accept", logical_message_id="retained-unseen", attempt_id="P1",
             acceptance_receipt=accepted["acceptance_receipt"])
    _, _, _, bundle = lab.prepare_recovery()
    lab.install_recovery(lab.accept_recovery(bundle)["record"])
    enable_anchor(lab, "b1")
    reject_ready(lab, "b1", "wire_receive", "historical_acceptance_required", **old["envelope"])
    bad = copy.deepcopy(accepted["acceptance_receipt"])
    raw = bytearray(base64.b64decode(bad["signature_bytes"]))
    raw[0] ^= 1
    bad["signature_bytes"] = base64.b64encode(raw).decode()
    reject_ready(lab, "b1", "wire_receive", "acceptance_signature", **old["envelope"],
                 acceptance_id=accepted["acceptance_id"], acceptance_receipt=bad)
    fields = {"acceptance_id": accepted["acceptance_id"], "acceptance_receipt": accepted["acceptance_receipt"]}
    check(lab.receive("b1", old, **fields)["historical"], "预检阻止合法保留历史解密")
    check(lab.receive("b1", old, **fields)["duplicate"], "预检破坏历史去重")
    reject_ready(lab, "b1", "wire_receive", "acceptance_signature", **old["envelope"],
                 acceptance_id=accepted["acceptance_id"], acceptance_receipt=bad)
    lab.continued("after-retained-history", sender="b1", recipients=(*ACCOUNTS, "d1"))


def crypto_failure(lab):
    setup(lab)
    _, packet, accepted = download_pair(lab)
    bad = copy.deepcopy(packet)
    raw = bytearray(base64.b64decode(bad["envelope"]["payload_bytes"]))
    raw[-1] ^= 1
    bad["envelope"]["payload_bytes"] = base64.b64encode(raw).decode()
    before = state(lab)
    error = lab.receive("d1", bad, acceptance_id=accepted["acceptance_id"],
                        acceptance_receipt=signed_for_packet(lab, bad, accepted), expected_exit=1)
    check(error["code"] == "decryption_failed" and state(lab) == before, "错误密文未走真实密码拒绝")
    for _ in range(2):
        reject_old(lab)
        check(lab.rust("d1", "anchor_resume", expected_exit=1)["code"] == "anchor_unresolved",
              "密码失败被无条件释放")
        check(lab.rust("d1", "wire_process", expected_exit=1)["code"] == "anchor_paused",
              "密码处理失败后跳过未决保护")
        lab.restart()
    check(state(lab) == before, "密码失败重试改变快照或 Relay")
    lab.case_evidence["crypto_rejection"] = error
    lab.case_evidence["unresolved"] = lab.rust("d1", "anchor_inspect")


CASES = {
    "H01_reject_old_then_sync": continued_sync,
    "H02_quarantine_then_sync": lambda l: continued_sync(l, False),
    "H03_history_after_journal": lambda l: process_fault(l, "after_journal"),
    "H04_history_after_finish": lambda l: process_fault(l, "after_finish"),
    "H05_history_unresolved": lambda l: process_fault(l, "after_reserve"),
    "H06_retained_history": retained_history,
    "H07_crypto_failure_paused": crypto_failure,
}
