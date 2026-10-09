"""M12 回收联合装置；只编排原 Rust/HTTP 操作并只读观察隔离数据库。"""

from contextlib import closing
import hashlib
import json
import sqlite3
import subprocess

from .fixture import NetworkLab, check, identity
from .read_anchor_fixture import ReadAnchorLab

DEVICES = ("a1", "a2", "b1", "c1")
PAYLOAD = "q" * (64 * 1024)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def snapshot(lab, device):
    content = (lab.directory / device / "state.enc").read_bytes()
    return {"bytes": len(content), "sha256": digest(content)}


class PreparedRequest(dict):
    """保留 Rust 保存的原编码，HTTP 发送不能由宿主重新排序。"""

    def __init__(self, result):
        super().__init__(result["request"])
        self.request_json = result["request_json"]
        check(json.loads(self.request_json) == self, "保存的请求编码与字段不一致")


class ReclamationHTTP:
    def http(self, device, operation, fields, **options):
        if operation == "confirm_reclaim" and isinstance(fields, PreparedRequest):
            options.setdefault("raw", fields.request_json.encode())
        return super().http(device, operation, fields, **options)


class ReclamationLab(ReclamationHTTP, NetworkLab):
    def raw_rust(self, device, operation, **fields):
        request = {"directory": str(self.directory / device), "service": self.service,
                   "account": identity(device)["account_id"], "device": device,
                   "operation": operation, **fields}
        process = subprocess.Popen([str(self.binary)], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.process_count += 1
        trace = {"device": device, "operation": operation, "pid": process.pid,
                 "failpoint": fields.get("failpoint")}
        self.case_evidence.setdefault("processes", []).append(trace)
        try:
            stdout, stderr = process.communicate(json.dumps(request), timeout=30)
        except BaseException:
            process.kill()
            stdout, stderr = process.communicate(timeout=5)
            trace.update(interrupted=True, exit_code=process.returncode)
            raise
        trace.update(exit_code=process.returncode, stdout_sha256=digest(stdout.encode()),
                     stderr_sha256=digest(stderr.encode()))
        return subprocess.CompletedProcess([str(self.binary)], process.returncode, stdout, stderr)

    def rust(self, device, operation, *, expected_exit=0, **fields):
        result = self.raw_rust(device, operation, **fields)
        check(result.returncode == expected_exit,
              f"{operation}: exit {result.returncode}, expected {expected_exit}; {result.stdout[:400]}")
        if expected_exit in range(83, 89):
            check(not result.stdout.strip(), "提交响应前退出却输出结果")
            return None
        reply = json.loads(result.stdout)
        check(reply["ok"] == (expected_exit == 0), "退出码与业务结果不一致")
        return reply["result"] if reply["ok"] else reply["error"]


class ReclamationAnchorLab(ReclamationHTTP, ReadAnchorLab):
    pass


def raw_command(lab, device, operation, **fields):
    before = snapshot(lab, device)
    result = lab.raw_rust(device, operation, **fields)
    check(result.returncode in (0, 1), "容量探索发生非业务退出")
    reply = json.loads(result.stdout)
    check(reply["ok"] == (result.returncode == 0), "退出码与业务状态不符")
    if not reply["ok"]:
        after = snapshot(lab, device)
        lab.case_evidence.setdefault("business_rejections", []).append({"device": device,
            "operation": operation, "error": reply["error"], "before": before, "after": after})
        check("result" not in reply and after == before,
              "拒绝输出成功或改变加密快照")
    return reply


def database(lab):
    """同一个显式只读事务采集表摘要；不让宿主执行业务清理。"""
    uri = (lab.directory / "relay.sqlite").resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, isolation_level=None)) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN")
        try:
            tables = {}
            for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
                name = row[0]
                quoted = '"' + name.replace('"', '""') + '"'
                values = [list(value) for value in db.execute(f"SELECT * FROM {quoted} ORDER BY rowid")]
                encoded = json.dumps(values, sort_keys=True, separators=(",", ":"),
                                     default=lambda value: {"bytes_sha256": digest(value), "bytes": len(value)})
                tables[name] = {"rows": len(values), "sha256": digest(encoded.encode())}
            attempts = []
            for row in db.execute("SELECT * FROM attempts ORDER BY logical_key,attempt_id"):
                value = dict(row)
                attempts.append({"acceptance_id": value["acceptance_id"], "attempt_id": value["attempt_id"],
                    "outcome": value["outcome"], "availability": value["availability"],
                    "payload_is_null": value["payload"] is None,
                    "payload_bytes": len(value["payload"]) if value["payload"] is not None else 0,
                    "payload_sha256": digest(value["payload"]) if value["payload"] is not None else None,
                    "compacted": value.get("compacted", 0)})
            watermarks = ([dict(row) for row in db.execute("SELECT * FROM stream_watermarks ORDER BY account,device")]
                          if "stream_watermarks" in tables else [])
            message_events = []
            for row in db.execute("SELECT * FROM events ORDER BY account,device,seq"):
                content = json.loads(row["content"])
                if content["type"] == "message":
                    message_events.append({"acceptance_id": row["acceptance_id"], "account": row["account"],
                        "device": row["device"], "seq": row["seq"], "has_envelope": "envelope" in content,
                        "compacted": row["compacted"]})
            db.commit()
        except BaseException:
            db.rollback()
            raise
    return {"tables": tables, "attempts": attempts, "watermarks": watermarks, "message_events": message_events}


def publish(lab, logical, payload="synthetic-reclamation", sender="a1"):
    packet = lab.rust(sender, "wire_send", logical_message_id=logical, attempt_id="P1", payload=payload)
    accepted = lab.submit(packet, device=sender)
    lab.rust(sender, "wire_accept", logical_message_id=logical, attempt_id="P1",
             acceptance_receipt=accepted["acceptance_receipt"])
    return {"logical": logical, "sender": sender, "payload": payload, "packet": packet,
            "accepted": accepted, "payload_sha256": digest(payload.encode())}


def synchronize(lab, device, *, report_delivery=False):
    outcomes = []
    while True:
        cursor = lab.rust(device, "wire_inspect")["sync"]["download_cursor"]
        page = lab.pull(device, after=cursor)
        lab.download(device, page)
        processed = lab.rust(device, "wire_process")
        outcomes.append(processed)
        if report_delivery:
            for candidate in processed["deliveries"]:
                result = lab.http(device, "report_delivery", {"service_id": lab.service, **candidate})
                check(result["delivered"], "真实处理后的送达报告未保存")
        lab.case_evidence.setdefault("synchronization", []).append({"device": device,
            "after": cursor, "page_end": page["next_after_seq"], "slots": len(page["events"]),
            "page_sha256": digest(page.wrapper["page_bytes"].encode()),
            "results": [{"event_seq": item["event_seq"], "status": item["result"]["status"]}
                        for item in processed["results"]], "sync": processed["sync"]})
        if not page["has_more"]:
            break
    return outcomes


def terminal_candidate(lab, *, payload="synthetic-reclamation", availability="deleted", logical="candidate"):
    record = publish(lab, logical, payload)
    record["old_page"] = lab.pull("b1")
    for device in DEVICES[1:]:
        outcomes = synchronize(lab, device, report_delivery=True)
        messages = [item["result"]["message"] for result in outcomes for item in result["results"]
                    if item["result"]["status"] == "valid"]
        check(len(messages) == 1 and messages[0]["payload_sha256"] == record["payload_sha256"],
              "回收候选未真实成功解密")
    for device in DEVICES:
        synchronize(lab, device)
    lab.control("set_availability", acceptance_id=record["accepted"]["acceptance_id"],
                availability=availability)
    for device in DEVICES:
        synchronize(lab, device)
    lab.case_evidence.setdefault("candidates", []).append({"logical": record["logical"],
        "acceptance_id": record["accepted"]["acceptance_id"], "payload_bytes": len(payload.encode()),
        "payload_sha256": record["payload_sha256"], "availability": availability,
        "real_decryptions": 3, "terminal_source": "authenticated_test_controller_set_availability"})
    return record


def prepare_requests(lab, records, plan="plan-1"):
    selected = sorted(record["accepted"]["acceptance_id"] for record in records)
    requests = {}
    for device in DEVICES:
        before = snapshot(lab, device)
        result = lab.rust(device, "wire_reclaim_request", plan_id=plan, acceptance_ids=selected)
        saved = snapshot(lab, device)
        check(result["status"] == "prepared" and not result["duplicate"] and saved != before,
              "首次准备没有原子保存固定请求")
        repeated = lab.rust(device, "wire_reclaim_request", plan_id=plan, acceptance_ids=selected)
        check(repeated["duplicate"] and repeated["request_json"] == result["request_json"]
              and snapshot(lab, device) == saved, "精确准备重试改写了请求或快照")
        request = PreparedRequest(result)
        check(request["acceptance_ids"] == selected and request["plan_id"] == plan,
              "本机回收请求未保持精确选择")
        requests[device] = request
        lab.case_evidence.setdefault("preparations", []).append({"device": device,
            "plan_id": plan, "before": before, "after": saved, "request_json": request.request_json})
    lab.case_evidence.setdefault("plans", []).append({"plan_id": plan, "requests": requests})
    return requests


def approve(lab, requests):
    for index, device in enumerate(DEVICES):
        response = lab.http(device, "confirm_reclaim", requests[device])
        check(response["status"] == ("ready" if index == len(DEVICES) - 1 else "pending"),
              "Relay在所有原参与者确认前发放许可或漏发许可")
    receipts = {}
    for device in DEVICES:
        response = lab.http(device, "confirm_reclaim", requests[device])
        check(response["status"] == "ready" and "receipt" in response, "原回收确认无法恢复许可")
        receipts[device] = response["receipt"]
    lab.case_evidence.setdefault("permits", []).append(receipts)
    return receipts


def apply(lab, receipts):
    results = {}
    for device in DEVICES:
        before = snapshot(lab, device)
        result = lab.rust(device, "wire_reclaim", receipt=receipts[device])
        check(result["status"] == "reclaimed" and result["reclaimed_count"] > 0,
              "合法回收没有产生持久紧凑记录")
        results[device] = result
        lab.case_evidence.setdefault("local_reclamation", []).append({"device": device,
            "before": before, "after": snapshot(lab, device), "result": result,
            "wire": lab.rust(device, "wire_inspect")})
    return results


def finish(lab, results):
    for index, device in enumerate(DEVICES):
        response = lab.http(device, "finish_reclaim", results[device]["finish_request"])
        check(response["status"] == ("complete" if index == len(DEVICES) - 1 else "pending"),
              "Relay提前删除载荷或全体完成后没有回收")
    after = database(lab)
    lab.case_evidence["relay_after_finish"] = after
    return after


def require_budget_error(reply):
    check(not reply["ok"] and reply["error"]["code"] == "snapshot_save"
          and "oversize" in reply["error"]["message"].lower(),
          f"实际容量探索没有触及快照字节预算: {reply.get('error')}")


def reject_old_binary(lab, device="b1"):
    if lab.old_binary is None:
        lab.case_evidence["legacy_binary"] = {"status": "NOT_EXECUTED_NO_EXPLICIT_OLD_BINARY"}
        return
    before, rows = snapshot(lab, device), database(lab)
    request = {"directory": str(lab.directory / device), "service": lab.service,
               "account": identity(device)["account_id"], "device": device, "operation": "wire_inspect"}
    options = {"env": lab.environment(device)} if hasattr(lab, "environment") else {}
    result = subprocess.run([str(lab.old_binary)], input=json.dumps(request), text=True,
                            capture_output=True, timeout=30, **options)
    lab.process_count += 1
    response = json.loads(result.stdout)
    lab.case_evidence["legacy_binary"] = {"path": str(lab.old_binary),
        "sha256": digest(lab.old_binary.read_bytes()), "exit_code": result.returncode,
        "response": response, "snapshot_before": before, "snapshot_after": snapshot(lab, device),
        "stdout_sha256": digest(result.stdout.encode()), "stderr_sha256": digest(result.stderr.encode())}
    check(result.returncode == 1 and not response["ok"] and response["error"]["code"] == "state_decoding",
          "真实旧程序没有明确拒绝新回收快照")
    check(snapshot(lab, device) == before and database(lab) == rows,
          "旧程序只读重载改变新回收状态")
