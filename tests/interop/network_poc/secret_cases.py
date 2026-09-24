"""正常MLS保密观测、拒绝输入不回显、主动明文载荷的真实负面对照。"""

import base64
from copy import deepcopy
import hashlib
import secrets

from .deletion_observer import relay_records
from .fixture import check
from .secret_support import credential_checks, hit_surfaces, sample_devices, scan


def marker(prefix):
    return prefix + secrets.token_hex(24)


def finish_observation(lab, phase):
    sample_devices(lab, phase)
    lab.stop()
    lab.case_evidence.setdefault("server_observations", []).append(lab.collect_server(phase))


def encrypted_messages(lab):
    sample_devices(lab, "initial")
    payloads = [marker("M01_ASCII_"), '正文/引号"/换行\n/🚀/' + marker("M01_UTF8_"),
                marker("M01_LONG_") + "0123456789" * 200]
    records = []
    for index, payload in enumerate(payloads):
        logical = f"private-{index}"
        packet = lab.prepare(logical, payload=payload)
        accepted = lab.submit(packet)
        lab.rust("a1", "wire_accept", logical_message_id=logical, attempt_id="P1",
                 acceptance_receipt=accepted["acceptance_receipt"])
        check(lab.submit(packet) == accepted and lab.attempt(logical) == accepted,
              "原消息重复提交/查询改变接受记录")
        records.append({"logical_message_id": logical, "payload_sha256": hashlib.sha256(payload.encode()).hexdigest(),
                        "accepted": accepted})
    decrypted = []
    for device in ("a2", "b1", "c1"):
        page = lab.pull(device)
        lab.download(device, page)
        result = lab.rust(device, "wire_process")
        messages = [v["result"] for v in result["results"] if v["result"]["status"] == "valid"]
        check(len(messages) == 3 and [v["message"]["payload_sha256"] for v in messages]
              == [r["payload_sha256"] for r in records], "实际目标没有解密原三条正文")
        for candidate in result["deliveries"]:
            lab.http(device, "report_delivery", {"service_id": lab.service, **candidate})
        lab.download(device, page)
        duplicate = lab.rust(device, "wire_process")
        check(duplicate["results"] == [], "重复页导致重新解密")
        decrypted.append({"device": device, "messages": 3, "payload_sha256": [r["payload_sha256"] for r in records]})
        if device == "b1":
            lab.rust(device, "wire_read", event_ids=[v["event_id"] for v in messages])
            request = lab.rust(device, "wire_read_pending")["request"]
            lab.http(device, "report_read", request)
    lab.case_evidence["server_observations"] = [lab.collect_server("before-restart")]
    before = relay_records(lab)
    old_pid = lab.process.pid
    lab.restart()
    check(lab.process.pid != old_pid and relay_records(lab) == before, "Relay重启改变已提交内容")
    for record in records:
        check(lab.attempt(record["logical_message_id"]) == record["accepted"], "重启后原接受记录丢失")
    page = lab.pull("b1", after="3")
    lab.download("b1", page)
    lab.rust("b1", "wire_process")
    check(lab.rust("b1", "wire_read_inspect")["confirmed_count"] == 3, "本人已读签页未恢复确认")
    lab.case_evidence.update(decrypted=decrypted, message_payload_hashes=[r["payload_sha256"] for r in records],
        restart={"old_pid": old_pid, "new_pid": lab.process.pid}, final_relay=relay_records(lab))
    finish_observation(lab, "final")
    observed = scan(lab, "normal-message-client-secrets", lab.surfaces, plaintexts=payloads)
    check(not hit_surfaces(observed), "正常Rust加密链在服务器观测面出现正文或客户端秘密")
    credential_checks(lab)
    lab.case_evidence["conclusion"] = "NO_MATCH_IN_SELECTED_NORMAL_MESSAGE_SURFACES"


def rejected_inputs(lab):
    sample_devices(lab, "initial")
    canary = marker("M01_REJECTED_INPUT_")
    packet = lab.prepare("rejected")
    requests = [("unknown_field", {"envelope": packet["envelope"], "private_value": canary}, {}),
                ("malformed_json", {}, {"raw": ('{"private":"' + canary).encode()}),
                ("invalid_base64", {"envelope": {**packet["envelope"], "payload_bytes": canary + "!"}}, {}),
                ("invalid_bearer", {"envelope": packet["envelope"]}, {"token": canary, "expected": 401})]
    before = relay_records(lab)
    errors = []
    for name, body, options in requests:
        error = lab.http("a1", "submit_message", body, **{"expected": 400, **options})
        check(error["code"] == ("unauthenticated" if name == "invalid_bearer" else "invalid_envelope"),
              "非预期拒绝")
        check(relay_records(lab) == before, "拒绝输入部分写入服务器")
        errors.append({"case": name, "code": error["code"]})
    lab.restart()
    check(relay_records(lab) == before, "拒绝输入在重启后复活")
    lab.case_evidence.update(rejected=errors, final_relay=before)
    finish_observation(lab, "final")
    outputs = [s for s in lab.surfaces if s["kind"] not in {"http_request", "http_request_body"}]
    observed = scan(lab, "rejected-input-no-reflection", outputs, plaintexts=[canary])
    check(not hit_surfaces(observed), "拒绝输入泄漏到HTTP响应/数据库/日志/备份")
    requests = [s for s in lab.surfaces if s["kind"] == "http_request"]
    inputs = scan(lab, "rejected-input-actual-presence", requests, plaintexts=[canary])
    check(len(hit_surfaces(inputs, "plaintext")) == 4, "四个实际请求未检出有意输入的正文标记")
    check(all(h["category"] == "plaintext" for s in inputs["surfaces"] for h in s["hits"]),
          "拒绝输入请求包含客户端秘密")
    credential_checks(lab)
    lab.case_evidence["conclusion"] = "REJECTED_INPUT_OBSERVED_AT_INGRESS_NOT_REFLECTED_OR_PERSISTED"


def opaque_payload_control(lab):
    sample_devices(lab, "initial")
    canary = marker("M01_INTENTIONAL_PLAINTEXT_")
    packet = deepcopy(lab.prepare("opaque", payload="legitimate-client-plaintext-control"))
    packet["envelope"]["payload_bytes"] = base64.b64encode(canary.encode()).decode()
    accepted = lab.submit(packet)
    page = lab.pull("b1")
    lab.download("b1", page)
    processed = lab.rust("b1", "wire_process")
    check(processed["results"][0]["result"]["status"] == "quarantined"
          and processed["deliveries"] == [] and lab.rust("b1", "wire_inspect")["inbox_count"] == 0,
          "主动明文载荷被客户端误当成有效MLS消息")
    lab.restart()
    check(lab.attempt("opaque") == accepted, "负对照接受事实未持久保存")
    lab.pull("b1")
    lab.case_evidence.update(accepted=accepted, processed=processed, final_relay=relay_records(lab))
    finish_observation(lab, "final")
    observed = scan(lab, "intentional-plaintext-detected", lab.surfaces, plaintexts=[canary])
    hits = hit_surfaces(observed)
    kinds = {s["label"]: s["kind"] for s in lab.surfaces}
    detected = {kinds[s["label"]] for s in hits}
    check({"http_request", "http_response", "server_database", "server_database_dump",
           "server_backup", "server_backup_dump"} <= detected, "负对照没有在实际传输/持久化/备份检出")
    check(all(h["category"] == "plaintext" for s in hits for h in s["hits"]), "负对照出现客户端秘密")
    check(not detected.intersection({"relay_stdout", "relay_stderr"}), "主动载荷被记入日志")
    credential_checks(lab)
    lab.case_evidence.update(detected_kinds=sorted(detected),
        conclusion="OBSERVED_LIMITATION_AUTHORIZED_CALLER_CAN_SUBMIT_PLAINTEXT_AS_OPAQUE_PAYLOAD")


CASES = [("M01.secrets.normal_messages", encrypted_messages),
         ("M01.secrets.rejected_inputs", rejected_inputs),
         ("M01.secrets.opaque_payload_control", opaque_payload_control)]
