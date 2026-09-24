"""密码存储实验的控制器与断言；日志只保留合成正文和私密状态摘要。"""

import base64
import hashlib

from support import Probe, require

METRICS = ("provider_news", "provider_restores", "candidate_sends", "candidate_receives")


def digest(value):
    encoded = value.encode() if isinstance(value, str) else value
    return {"sha256": hashlib.sha256(encoded).hexdigest(), "bytes": len(encoded)}


def redact(value):
    if isinstance(value, dict):
        return {key: digest(item) if key in ("text", "provider", "provider_blob")
                and isinstance(item, (str, bytes)) else redact(item)
                for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


class CryptoProbe(Probe):
    def __init__(self, *args, device="alice-device", flags=(), **kwargs):
        # 普通控制器的可选参数位置正好位于 account 之后；复用其限时、限输出和清理。
        super().__init__(*args, flags=(device, *flags), **kwargs)

    def record(self, direction, payload):
        super().record(direction, redact(payload))


def success(response):
    require(response.get("ok") is True and response.get("error") is None,
            f"预期成功：{redact(response)}")
    return response.get("result")


def metrics(response, news=0, restores=0, sends=0, receives=0):
    expected = dict(zip(METRICS, (news, restores, sends, receives)))
    require(response.get("metrics") == expected,
            f"密码调用次数不符：{response.get('metrics')}，预期 {expected}")


def failure(response, code=None, sqlite_code=None, paused=None):
    error = response.get("error") or {}
    require(response.get("ok") is False and response.get("result") is None,
            "失败仍返回成功结果")
    require(response.get("events") == [], "失败仍发布成功事件")
    if code is not None:
        require(error.get("code") == code, f"错误类别不符：{error}")
    if sqlite_code is not None:
        require(error.get("sqlite_code") == sqlite_code, f"SQLite 错误码不符：{error}")
    if paused is not None:
        require(error.get("paused") is paused, f"暂停状态不符：{error}")
    return error


def inspect(probe):
    response = probe.request("inspect")
    result = success(response)
    require(response.get("events") == [], "读取发布了写入事件")
    metrics(response)
    trace = response.get("trace") or []
    require(trace and trace[0] == "BEGIN" and trace[-1] == "COMMIT",
            f"读取未完成显式事务：{trace}")
    require("provider" not in result and "provider_blob" not in result, "公开接口泄露 provider")
    return result


def execute(probe, request_id, action, fault="none"):
    return probe.request("execute", request={"request_id": request_id,
                         "action": action, "fault": fault})


def committed(response, operation, cached=False):
    outcome = success(response)
    require(outcome.get("kind") == operation and outcome.get("cached") is cached,
            "操作种类或缓存标记不符")
    events = response.get("events")
    if cached:
        require(events == [], "缓存重试重复发布提交事件")
        metrics(response)
    else:
        require(isinstance(events, list) and len(events) == 1, "新提交没有唯一成功事件")
        require(events[0].get("revision") == outcome["revision"], "事件版本与提交不一致")
        metrics(response, news=int(operation == "initialize"),
                restores=int(operation != "initialize"), sends=int(operation == "send"))
        require(response.get("crypto_thread") != response.get("worker_thread"),
                "密码计算占用了 SQLite 工作线程")
        trace = response.get("trace") or []
        require(trace and trace[-1] == "COMMIT", "成功事件之前没有完成事务")
    return outcome["value"]


def send_action(attempt="attempt-one", message="message-one", text="合成消息🙂\u0000one"):
    return {"op": "send", "attempt_id": attempt, "message_id": message, "text": text}


def unchanged(before, after, pending=False):
    require({key: value for key, value in before.items() if key != "pending"}
            == {key: value for key, value in after.items() if key != "pending"},
            "失败改变了持久化 provider、密文、版本或结果记录")
    require((after.get("pending") is not None) is pending, "未决预约状态不符")


def encrypted_state(before, after, envelope):
    require(int(after["revision"]) == int(before["revision"]) + 1, "新消息未推进一次版本")
    require(int(after["encryptions"]) == int(before["encryptions"]) + 1, "加密计数不是一次")
    require(after["provider_hash"] != before["provider_hash"], "密码状态未推进")
    require(len(after["outbox"]) == len(before["outbox"]) + 1, "待发送密文没有共同提交")
    ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
    expected = hashlib.sha256(ciphertext).hexdigest()
    matching = [entry for entry in after["outbox"] if entry["message_id"] == envelope["messageId"]]
    require(len(matching) == 1 and matching[0]["ciphertext_hash"] == expected,
            "待发送摘要与返回密文不一致")
    require(after["pending"] is None, "成功提交未删除预约")
