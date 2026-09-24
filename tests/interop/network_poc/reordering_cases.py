"""M03 同发送者同 epoch 的固定到达顺序；仅补证，不改变密码窗口。"""

from functools import partial
import hashlib

from .fixture import check, identity
from .reordering_recovery import recover
from .reordering_support import receive_targets, report_successes
from .slot_support import digest
from .sync_support import TARGETS


def run(lab, *, order, page_limit, quarantined=()):
    # 序号是本装置的首次发送顺序；不声称已直接读取加密 SenderData。
    lab.case_evidence = {
        "scope": "synthetic_local_same_sender_same_epoch_reordering",
        "created_message_count": 9, "submitted_send_indices": order,
        "page_limit": page_limit, "expected_quarantined_send_indices": list(quarantined),
        "generation_basis": "inferred from consecutive first wire_send calls and locked OpenMLS source; encrypted SenderData not exported",
        "default_out_of_order_tolerance": 5, "default_maximum_forward_distance": 1000,
        "ratchet_configuration_changed": False, "sender": "a1",
        "prepared": [], "acceptances": [], "targets": {},
    }
    packets = {}
    for index in range(9):
        logical = f"reordering_{index:02}"
        payload = "synthetic-M03-window-" + logical
        packet = lab.prepare(logical, payload=payload)
        check(packet["reused"] is False, "首次发送意外命中旧尝试")
        payload_hash = hashlib.sha256(payload.encode()).hexdigest()
        packets[index] = {"logical": logical, "payload": payload, "packet": packet,
                          "payload_sha256": payload_hash}
        lab.case_evidence["prepared"].append({
            "send_index": index, "logical_message_id": logical, "reused": False,
            "envelope_sha256": digest(packet["envelope"]), "payload_sha256": payload_hash,
        })
    for index in order:
        accepted = lab.submit(packets[index]["packet"])
        check(accepted["outcome"] == "accepted" and accepted["acceptance_receipt"]
              and accepted["recipients"] == [identity(d) for d in TARGETS], "原消息未完整接受")
        packets[index]["accepted"] = accepted
        lab.case_evidence["acceptances"].append({"send_index": index, "result": accepted})
    targets = receive_targets(lab, packets, order, page_limit, quarantined)
    recover(lab, packets, order, targets)
    report_successes(lab, packets, order, targets, quarantined)
    lab.case_evidence.update(
        accepted_messages=len(order), successful_messages_per_target=len(order) - len(quarantined),
        quarantined_messages_per_target=len(quarantined),
        behavioral_gap="REPRODUCED_NOT_FIXED" if quarantined else "CONTROL_CASE",
        quarantine_recovery="UNAVAILABLE_IN_TESTED_PATHS" if quarantined else "NOT_APPLICABLE",
        full_stage0="NOT_COMPLETE")


CASES = [
    ("M03_window_ordered", partial(run, order=list(range(9)), page_limit=3)),
    ("M03_window_reproduce_full", partial(run, order=[0, 1, 4, 6, 3, 7, 5, 2, 8],
                                          page_limit=100, quarantined=(2,))),
    ("M03_window_reproduce_pages", partial(run, order=[0, 1, 4, 6, 3, 7, 5, 2, 8],
                                           page_limit=1, quarantined=(2,))),
    ("M03_window_inside", partial(run, order=[7, 4, 8], page_limit=1)),
    ("M03_window_edge", partial(run, order=[7, 3, 8], page_limit=1)),
    ("M03_window_outside", partial(run, order=[7, 2, 3, 8], page_limit=1, quarantined=(2,))),
]
