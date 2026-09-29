"""锚日志、整快照与签名 Read 的精确绑定；合成破坏明确记录，原件单独保留。"""

import base64
from copy import deepcopy
from functools import partial
import hashlib
import json

from .deletion_observer import relay_records
from .fixture import check
from .read_anchor_faults import recover, setup, unresolved
from .read_anchor_fixture import anchor_state, assert_blocked, state
from .read_support import finish, inspect, load_messages, mark, pending, publish, report, snapshot, synchronize


def journal_binding(lab, *, defect):
    records, ids, operation, fields, before, page = setup(lab, "process")
    journal = lab.directory / "b1/anchor-journal.enc"
    previous_snapshot = lab.snapshot("b1").read_bytes()
    # 同一设备、同一 head 的更早预约，仍不能代替本次完整日志。
    lab.rust("b1", "wire_read_pending", expected_exit=87, env={"RIM_ANCHOR_FAILPOINT": "after_journal"})
    stale = journal.read_bytes()
    lab.resume("b1")
    if defect == "foreign_scope":
        lab.rust("a2", "wire_read_pending", expected_exit=87, env={"RIM_ANCHOR_FAILPOINT": "after_journal"})
        foreign = (lab.directory / "a2/anchor-journal.enc").read_bytes()
        lab.resume("a2")
    rows = relay_records(lab)
    lab.rust("b1", operation, **fields, expected_exit=87, env={"RIM_ANCHOR_FAILPOINT": "after_journal"})
    exact, target = journal.read_bytes(), lab.snapshot("b1").read_bytes()
    if defect == "missing":
        journal.unlink()
    elif defect == "tampered":
        altered = bytearray(exact)
        altered[-1] ^= 1
        journal.write_bytes(altered)
    elif defect == "stale":
        journal.write_bytes(stale)
    elif defect == "foreign_scope":
        journal.write_bytes(foreign)
    else:
        lab.snapshot("b1").write_bytes(previous_snapshot)
    unresolved(lab, operation, fields, rows)
    lab.case_evidence["journal_rejection"] = {
        "defect": defect, "rejected_anchor": lab.case_evidence["unresolved_anchor"],
        "exact_journal_sha256": hashlib.sha256(exact).hexdigest(),
        "original_target_sha256": hashlib.sha256(target).hexdigest(),
        "stale_journal_sha256": hashlib.sha256(stale).hexdigest(),
        "restoration": "controller_restores_only_exact_captured_journal_and_target_bytes"}
    journal.write_bytes(exact)
    journal.chmod(0o600)
    lab.snapshot("b1").write_bytes(target)
    recover(lab, "process", records, ids, before, page, saved=True, rows=rows)


def snapshot_rollback(lab, *, confirmed):
    records = publish(lab)
    ids = load_messages(lab, records)
    old = lab.backup("before-read", lab.directory / "b1")
    mark(lab, ids)
    if confirmed:
        report(lab)
        synchronize(lab)
    committed, rows = state(lab), relay_records(lab)
    exact = lab.backup("exact-read", lab.directory / "b1")
    lab.restore(old, lab.directory / "b1")
    for _ in range(2):
        check(anchor_state(lab)["status"] == "rollback_detected", "完整旧目录回滚未被锚发现")
        assert_blocked(lab, "wire_read_pending", {})
        assert_blocked(lab, "anchor_resume", {}, code="anchor_rollback")
        lab.restart()
    lab.restore(exact, lab.directory / "b1")
    lab.resume("b1")
    check(state(lab) == committed and relay_records(lab) == rows, "精确副本恢复丢失原阅读事实")
    if not confirmed:
        report(lab)
        synchronize(lab)
    lab.case_evidence["rollback"] = {"phase": "confirmed" if confirmed else "pending",
        "old_snapshot_sha256": hashlib.sha256((old / "state.enc").read_bytes()).hexdigest(),
        "exact_snapshot_sha256": committed["snapshot_sha256"], "restored": committed}
    finish(lab, records)


def old_read(lab):
    records = publish(lab, 2)
    ids = load_messages(lab, records)
    mark(lab, ids[:1])
    report(lab)
    old_page = lab.pull("b1", after="2")
    synchronize(lab)
    lab.rust("b1", "wire_read", event_ids=ids[1:], expected_exit=87,
             env={"RIM_ANCHOR_FAILPOINT": "after_journal"})
    lab.resume("b1")
    before, rows = inspect(lab), relay_records(lab)
    check(before["pending_count"] == before["confirmed_count"] == 1, "新待办与旧确认前置不符")
    for _ in range(2):
        lab.download("b1", old_page)
        result = lab.rust("b1", "wire_process")
        check(result["read_confirmed_count"] == 0 and result["results"] == []
              and inspect(lab) == before and relay_records(lab) == rows, "旧精确 Read 错清新消息待办")
        lab.restart()
    lab.case_evidence["old_read"] = {"signed_page": old_page.wrapper, "retained": before}
    report(lab)
    result = synchronize(lab)
    check(sum(p["read_confirmed_count"] for p in result) == 1, "当前本人 Read 没有且仅确认一次")
    finish(lab, records)


def wrong_read(lab, *, field):
    records, ids, _, _, before, page = setup(lab, "download")
    altered = deepcopy(page)
    event = altered["events"][-1]["event"]
    if field in ("account_id", "device_id"):
        event["device"][field] = "alice" if field == "account_id" else "b2"
    else:
        event[field] = "synthetic-unrelated"
    signed = lab.sign_test_page(altered)
    rows = relay_records(lab)
    lab.download("b1", signed)
    lab.rust("b1", "wire_process", expected_exit=87, env={"RIM_ANCHOR_FAILPOINT": "after_journal"})
    lab.resume("b1")
    for _ in range(2):
        check(lab.rust("b1", "wire_process")["read_confirmed_count"] == 0
              and inspect(lab) == before["reads"] and pending(lab) == before["pending"]
              and relay_records(lab) == rows, "跨范围签名 Read 或恢复误清本人待办")
        lab.restart()
    lab.case_evidence.update(progress="PENDING_UNRELATED_SIGNED_READ",
        synthetic_read={"field": field, "construction": "fixture_service_resigns_altered_read_only",
                        "original_signed_page": page.wrapper, "altered_signed_page": signed.wrapper},
        final_read_state=inspect(lab), final_relay=rows)


def wrong_page(lab, *, field):
    records, ids, _, _, before, page = setup(lab, "download")
    wrapper = page.signed_input()
    expected = "stream_page_context"
    if field == "signature":
        raw = bytearray(base64.b64decode(wrapper["receipt"]["signature_bytes"]))
        raw[-1] ^= 1
        wrapper["receipt"]["signature_bytes"] = base64.b64encode(raw).decode()
        expected = "stream_page_signature"
    else:
        claims = json.loads(base64.b64decode(wrapper["receipt"]["statement_bytes"]))
        claims[field] = "synthetic-other-scope"
        if field == "stream_id":
            # 页体与声明共同改成另一合法流；验证本机绑定，不能只靠内部不一致拒绝。
            body = dict(deepcopy(page))
            body["stream_id"] = claims[field]
            for slot in body["events"]:
                slot["stream_id"] = claims[field]
            raw = json.dumps(body, separators=(",", ":")).encode()
            wrapper["page_bytes"] = base64.b64encode(raw).decode()
            claims["page_sha256"] = hashlib.sha256(raw).hexdigest()
            expected = "cursor_invalid"
        wrapper["receipt"] = lab.relay_key("sign", expected_signature_key=lab.relay_receipt_key,
                                          statement=claims)["receipt"]
    anchored, rows = anchor_state(lab), relay_records(lab)
    error = lab.rust("b1", "wire_download_signed", **wrapper, expected_exit=1)
    current = anchor_state(lab)
    check(error["code"] == expected and current == anchored and state(lab) == before
          and relay_records(lab) == rows, "错误签页未在预约前拒绝或改变原状态")
    lab.case_evidence["page_rejection"] = {"field": field, "error": error,
        "anchor_before": anchored, "anchor_after": current, "signed_input": wrapper}
    synchronize(lab)
    finish(lab, records)


def unchanged_head(lab, *, point):
    records = publish(lab)
    ids = load_messages(lab, records)
    mark(lab, ids)
    before, rows = state(lab), relay_records(lab)
    journal = lab.directory / "b1/anchor-journal.enc"
    if point == "stale_journal":
        lab.rust("b1", "wire_read_pending", expected_exit=87,
                 env={"RIM_ANCHOR_FAILPOINT": "after_journal"})
        old = journal.read_bytes()
        lab.resume("b1")
    injected = "after_reserve" if point == "after_reserve" else "after_journal"
    lab.rust("b1", "wire_read_pending", expected_exit=86 if injected == "after_reserve" else 87,
             env={"RIM_ANCHOR_FAILPOINT": injected})
    check(snapshot(lab) == before["snapshot_sha256"], "纯读诊断写入新快照")
    if point == "after_reserve":
        unresolved(lab, "wire_read_pending", {}, rows)
        return
    if point == "stale_journal":
        exact = journal.read_bytes()
        journal.write_bytes(old)
        unresolved(lab, "wire_read_pending", {}, rows)
        journal.write_bytes(exact)
        lab.case_evidence["same_head_old_journal_rejected"] = True
    lab.resume("b1")
    check(state(lab) == before and relay_records(lab) == rows,
          "相同摘要的精确日志恢复改变阅读或服务事实")
    lab.case_evidence.update(recovery="EXACT_UNCHANGED_TARGET", state_after_resume=before)
    report(lab)
    results = synchronize(lab)
    check(sum(p["read_confirmed_count"] for p in results) == 1, "恢复后本人精确签页未仅确认一次")
    finish(lab, records)


CASES = [("M13.anchor.journal." + d, partial(journal_binding, defect=d))
         for d in ("missing", "tampered", "stale", "foreign_scope", "wrong_target")]
CASES += [("M13.anchor.rollback." + p, partial(snapshot_rollback, confirmed=p == "confirmed"))
          for p in ("pending", "confirmed")]
CASES += [("M13.anchor.old_read", old_read)]
CASES += [("M13.anchor.read." + f, partial(wrong_read, field=f))
          for f in ("account_id", "device_id", "acceptance_id", "attempt_id")]
CASES += [("M13.anchor.page." + f, partial(wrong_page, field=f))
          for f in ("service_id", "account_id", "device_id", "stream_id", "signature")]
CASES += [("M13.anchor.unchanged_head." + p, partial(unchanged_head, point=p))
          for p in ("after_reserve", "after_journal", "stale_journal")]
