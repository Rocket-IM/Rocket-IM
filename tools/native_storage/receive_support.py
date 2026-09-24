"""原生接收事务的断言；正文只在内存比较，落盘记录沿用递归摘要。"""

from crypto_support import (CryptoProbe, digest, execute, failure, redact, success,
                            unchanged)
from support import require

METRICS = ("provider_news", "provider_restores", "candidate_sends", "candidate_receives")


def metrics(response, news=0, restores=0, sends=0, receives=0):
    expected = dict(zip(METRICS, (news, restores, sends, receives)))
    require(response.get("metrics") == expected,
            f"密码调用次数不符：{response.get('metrics')}，预期 {expected}")


def summary_only(value):
    """摘要可以包含 text_hash；任何层级都不得包含正文或私密快照字段。"""
    if isinstance(value, dict):
        require(not {"text", "provider", "provider_blob"}.intersection(value), "状态摘要泄露私密字段")
        for item in value.values():
            summary_only(item)
    elif isinstance(value, list):
        for item in value:
            summary_only(item)


def inspect(probe):
    response = probe.request("inspect")
    result = success(response)
    metrics(response)
    require(response.get("events") == [], "状态查询产生消息事件")
    trace = response.get("trace") or []
    require(trace and trace[0] == "BEGIN" and trace[-1] == "COMMIT", "状态查询没有完成显式事务")
    require(not {"provider", "provider_blob", "text"}.intersection(result), "状态查询泄露私密数据")
    for name in ("processed_cursor", "decryptions", "inbox", "receipt_count"):
        require(name in result, f"缺少接收状态：{name}")
    summary_only(result["inbox"])
    return result


def received(probe, sequence, expected=None):
    response = probe.request("received", sequence=str(sequence))
    metrics(response)
    require(response.get("events") == [], "已提交消息查询产生事件")
    trace = response.get("trace") or []
    endings = ("COMMIT", "ROLLBACK") if expected is None else ("COMMIT",)
    require(trace and trace[0] == "BEGIN" and trace[-1] in endings, "消息查询没有结束显式事务")
    if expected is None:
        failure(response, "receive_not_found", paused=False)
        return None
    result = success(response)
    require(result == expected, "重启或查询后的消息与已提交结果不一致")
    return result


def committed(response, operation, cached=False, duplicate=False):
    outcome = success(response)
    require(outcome.get("kind") == operation and outcome.get("cached") is cached,
            "提交种类或缓存标记不符")
    events = response.get("events")
    if cached or duplicate:
        metrics(response)
        require(events == [], "缓存或已处理消息重复发布事件")
    else:
        metrics(response, news=int(operation == "initialize"),
                restores=int(operation != "initialize"), sends=int(operation == "send"),
                receives=int(operation == "receive"))
        require(isinstance(events, list) and len(events) == 1, "首次提交缺少唯一事件")
        require(events[0].get("revision") == outcome["revision"], "事件版本不等于提交版本")
        require(response.get("crypto_thread") != response.get("worker_thread"),
                "密码处理在数据库工作线程执行")
    trace = response.get("trace") or []
    require(trace and trace[-1] == "COMMIT", "成功结果交付前没有完成显式事务")
    value = outcome["value"]
    if operation == "receive":
        require(value.get("duplicate") is duplicate, "接收去重标记不符")
    return value


def receive_action(sequence, envelope):
    return {"op": "receive", "sequence": str(sequence), "envelope": envelope}


def check_message(value, sequence, envelope, text, duplicate=False):
    require(value["sequence"] == str(sequence) and value["duplicate"] is duplicate,
            "接收结果序号或去重标记不符")
    require(value["message"] == {"messageId": envelope["messageId"],
                                 "senderAccount": "bob", "text": text}, "已提交消息正文或身份错误")


def advanced(before, after, sequence, duplicate=False):
    require(after["pending"] is None and after["processed_cursor"] == str(sequence),
            "提交没有共同清除预约和更新游标")
    require(int(after["revision"]) == int(before["revision"]) + 1, "提交版本没有仅推进一次")
    require(after["receipt_count"] == before["receipt_count"] + 1, "接收凭据没有共同提交")
    require(after["result_count"] == before["result_count"] + 1, "结果记录没有共同提交")
    require(int(after["decryptions"]) == int(before["decryptions"]) + int(not duplicate),
            "解密计数与去重状态不一致")
    require(len(after["inbox"]) == len(before["inbox"]) + int(not duplicate),
            "消息、去重记录与游标没有共同提交")
    require((after["provider_hash"] == before["provider_hash"]) is duplicate,
            "密码状态推进与去重状态不一致")
    for key in ("scope", "identity", "conversation", "encryptions", "outbox"):
        require(after[key] == before[key], f"接收意外改变了 {key}")
    if duplicate:
        require(after["provider_bytes"] == before["provider_bytes"] and after["inbox"] == before["inbox"],
                "重复消息重新写入密码状态或消息")
