"""普通拒绝不能消耗锚预约；使用真实进程、独立锚和后续合法密码操作验收。"""

import copy

from anchor_support import download, execute, metrics, process, snapshot, status, success
from crypto_support import committed, failure, send_action
from download_support import saved
from receive_support import committed as received_commit
from support import require

PREFLIGHT_CASES = (
    "rejection_missing_download", "rejection_receive_gap", "rejection_duplicate_group",
    "rejection_request_conflict", "rejection_attempt_conflict", "rejection_message_conflict",
    "rejection_download_gap", "rejection_download_scope", "rejection_download_conflict",
    "rejection_download_capacity", "rejection_result_capacity",
)


class PreflightCases:
    def preflight_rejection(self, name):
        if name in ("rejection_download_capacity", "rejection_result_capacity"):
            return self.capacity_rejection(name)
        self.bootstrap()
        with self.peer() as peer:
            with self.probe() as client:
                setup = self.setup(client, peer)
                saved(download(client, setup["records"]), 2, 0, 2)
                original = send_action("existing-attempt", "existing-message")
                envelope = committed(execute(client, "existing-request", original), "send")
                success(peer.request("peer_receive", envelope=envelope))
                records = copy.deepcopy(setup["records"])
                calls = {
                    "rejection_missing_download": ("download_not_found", lambda: process(client, 3)),
                    "rejection_receive_gap": ("receive_gap", lambda: process(client, 2)),
                    "rejection_duplicate_group": ("crypto_already_grouped", lambda: execute(client, "duplicate-group", self.group)),
                    "rejection_request_conflict": ("crypto_request_conflict", lambda: execute(client, "existing-request", send_action())),
                    "rejection_attempt_conflict": ("crypto_attempt_conflict", lambda: execute(client, "attempt-conflict", send_action("existing-attempt"))),
                    "rejection_message_conflict": ("crypto_message_conflict", lambda: execute(client, "message-conflict", send_action("new-attempt", "existing-message"))),
                    "rejection_download_gap": ("download_gap", lambda: download(client, [dict(records[0], sequence="4")])),
                    "rejection_download_scope": ("crypto_scope_mismatch", lambda: download(client, records)),
                    "rejection_download_conflict": ("download_sequence_conflict", lambda: download(client, records)),
                }
                if name == "rejection_download_scope":
                    records[0]["envelope"]["service"] = "other-service"
                elif name == "rejection_download_conflict":
                    records[0]["envelope"]["messageId"] = "other-message"
                before, anchor = snapshot(client), status(client)
                code, operation = calls[name]
                response = operation()
                # 先保留所有实际结果，再断言，失败轮也有锚和后续正常请求证据。
                after = snapshot(client)
                observed_anchor = success(client.request("status"))
                following = execute(client, "after-rejection", send_action())
                failure(response, code=code, paused=False)
                metrics(response)
                require(after == before and observed_anchor == anchor, "确定性拒绝改变业务状态或锚预约")
                envelope = committed(following, "send")
                success(peer.request("peer_receive", envelope=envelope))
                stable, stable_anchor = snapshot(client), status(client)
            with self.probe() as reopened:
                require(snapshot(reopened) == stable and status(reopened) == stable_anchor,
                        "重启改变拒绝后的健康状态")
                received_commit(process(reopened), "receive")
                status(reopened)
        return {"error": code, "zero_crypto_calls_on_rejection": True,
                "business_and_anchor_unchanged": True, "send_then_restart_receive": True}

    def capacity_rejection(self, name):
        self.bootstrap()
        with self.peer() as peer:
            with self.probe() as client:
                setup = self.setup(client, peer, records=1)
                record = setup["records"][0]
                if name == "rejection_download_capacity":
                    # 同一真实密文占不同下载槽；不冒充 128 条独立消息或容量性能验收。
                    for first in range(1, 129, 16):
                        saved(download(client, [dict(record, sequence=str(n))
                                                for n in range(first, first + 16)]), first + 15, 0, 16)
                    operation = lambda: download(client, [dict(record, sequence="129")])
                    count_key, count = "downloads", 128
                else:
                    # 初始化和建群已占两条结果；用真实发送把结果表填到既定 128 上限。
                    for number in range(126):
                        action = send_action(f"attempt-{number}", f"message-{number}")
                        envelope = committed(execute(client, f"send-{number}", action), "send")
                        success(peer.request("peer_receive", envelope=envelope))
                    operation = lambda: execute(client, "over-capacity", send_action())
                    count_key, count = "result_count", 128
                before, anchor = snapshot(client), status(client)
                measured = len(before[count_key]) if count_key == "downloads" else before[count_key]
                require(measured == count, "未实际触及既定容量")
                response = operation()
                failure(response, "crypto_limit", paused=False)
                metrics(response)
                require(snapshot(client) == before and status(client) == anchor,
                        "满额拒绝消耗预约或改写业务状态")
            with self.probe() as reopened:
                require(snapshot(reopened) == before and status(reopened) == anchor,
                        "满额拒绝后重启改变状态")
                if name == "rejection_download_capacity":
                    envelope = committed(execute(reopened, "valid-send", send_action()), "send")
                    success(peer.request("peer_receive", envelope=envelope))
                    received_commit(process(reopened), "receive")
                else:
                    committed(execute(reopened, "send-0", send_action("attempt-0", "message-0")),
                              "send", cached=True)
                    saved(download(reopened, [record]), 1, 0, 1)
                status(reopened)
        return {"error": "crypto_limit", "full_table": count_key, "count": count,
                "zero_crypto_calls_on_rejection": True, "anchor_unchanged": True,
                "supported_operations_after_restart": True, "capacity_reclaimed": False}
