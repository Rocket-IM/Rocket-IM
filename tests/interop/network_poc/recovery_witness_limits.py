"""真实 W1 wire/保留预算/最终时钟边界；不解释或修改 MLS 私有材料。"""

import base64
import copy
import json
import subprocess
import time

from .fixture import check, identity
from .first_trust_evidence import state
from .key_package_fixture import decode
from .join_review_regressions import enable_anchor
from .recovery_capacity_cases import fixture as capacity_fixture
from .recovery_witness_fixture import canonical_envelopes, encoded, json_bytes, sha
from .recovery_witness_lifecycle import prepared


def padded_proof(lab, device, kind, original, decoded_length):
    """只给正常公开声明追加合法 JSON 空白，并用测试设备重签。"""
    raw = base64.b64decode(original["statement_bytes"])
    check(len(raw) < decoded_length, "合法公开声明已经大于目标长度")
    padded = raw + b" " * (decoded_length - len(raw))
    check(json.loads(padded) == json.loads(raw), "填充改变公开声明语义")
    before = state(lab)
    anchors_before = lab.anchor_views()
    normal = lab.binary
    try:
        lab.binary = lab.probe_binary
        result = lab.rust(device, "join_recovery_witness_sign_probe",
                         kind=kind, statement_bytes=encoded(padded))
    finally:
        lab.binary = normal
    check(state(lab) == before, "公开原件签名夹具改变设备或 Relay 状态")
    anchors_after = lab.anchor_views()
    proof = result["proof"]
    wire = json_bytes(canonical_envelopes(proof))
    lab.case_evidence.setdefault("wire_size_materials", []).append({
        "kind": kind, "decoded_bytes": len(padded), "wire_bytes": len(wire),
        "statement_sha256": sha(padded), "envelope_sha256": sha(wire), "proof": proof,
        "preparation_anchors_before": anchors_before,
        "preparation_anchors_after": anchors_after,
        "rejection_baseline_is_sampled_after_preparation": True,
        "same_decoded_statement": True,
        "scope": "public test signature with trailing JSON whitespace; original MLS bytes untouched"})
    return proof


def request_size(lab):
    record, request = prepared(lab)
    lab.observed("A", "exact-public-r0-accepted-before-size-check", record)
    oversized = padded_proof(lab, lab.target, "request", request, 6046)
    check(len(json_bytes(canonical_envelopes(oversized))) == 8195,
          "不是最邻近可表达的 8 KiB 越界封装")
    lab.unchanged("W", "8195-byte-original-request-rejected-before-state",
        lambda: lab.respond(record, oversized, expected_exit=1), "w1_resource_exhausted")
    delivery = lab.respond(record, request)["delivery"]
    lab.observed("W", "original-sized-request-still-accepted", delivery)
    installed = lab.install(record, request, delivery)
    check(installed["installed"], "原合法请求无法安装")
    lab.observed("T", "normal-control-after-request-limit-rejection", installed)
    lab.case_evidence["discrete_wire_boundary"] = {
        "limit": 8192, "greatest_canonical_within": 8191, "least_canonical_exceeding": 8195,
        "frozen_8193_is_not_encodable": "fixed envelope plus padded standard Base64 changes in 4-byte steps"}


def response_size(lab):
    record, request = prepared(lab)
    lab.observed("A", "exact-public-r0-accepted-before-size-check", record)
    delivery = lab.respond(record, request)["delivery"]
    lab.observed("W", "normal-independent-witness-response", delivery)
    oversized = copy.deepcopy(delivery)
    oversized["response"] = padded_proof(
        lab, lab.witness, "response", delivery["response"], 12190)
    check(len(json_bytes(canonical_envelopes(oversized["response"]))) == 16387,
          "不是最邻近可表达的 16 KiB 越界封装")
    lab.unchanged("T", "16387-byte-original-response-rejected-before-state",
        lambda: lab.install(record, request, oversized, expected_exit=1), "w1_resource_exhausted")
    installed = lab.install(record, request, delivery)
    check(installed["installed"], "原合法响应无法安装")
    lab.observed("T", "normal-control-after-response-limit-rejection", installed)
    lab.case_evidence["discrete_wire_boundary"] = {
        "limit": 16384, "greatest_canonical_within": 16383, "least_canonical_exceeding": 16387,
        "frozen_16385_is_not_encodable": "fixed envelope plus padded standard Base64 changes in 4-byte steps"}


def reservation_budget(lab):
    lab.setup_w1()
    _, accepted = lab.accepted()
    record = accepted["record"]
    lab.observed("A", "exact-public-r0-accepted-before-capacity-check", record)
    check(lab.target not in lab.configs, "容量夹具要求先于独立锚绑定")
    result = capacity_fixture(lab, lab.target, "witness_bytes")
    lab.case_evidence["synthetic_capacity"] = result
    lab.case_evidence["capacity_scope"] = (
        "legitimate self-signed public requests and duplicated already verified observations; "
        "synthetic near-full state, not naturally accumulated or production capacity")
    inspection = lab.witness_command(lab.target, "inspect")
    enable_anchor(lab, lab.target)
    anchor = lab.rust(lab.target, "anchor_inspect")
    lab.observed("T", "normal-release-reloads-synthetic-near-full-snapshot", inspection)
    lab.unchanged("T", "full-reservation-rejected-before-new-challenge",
        lambda: lab.witness_request(record, expected_exit=1), "w1_resource_exhausted")
    rejected_anchor = lab.rust(lab.target, "anchor_inspect")
    lab.case_evidence["budget_rejection_anchor"] = {
        "before": anchor, "after": rejected_anchor,
        "sampled_before_subsequent_ordinary_inspection": True,
    }
    check(rejected_anchor == anchor, "满额拒绝消耗独立锚预约")
    after = lab.witness_command(lab.target, "inspect")
    check(after == inspection, "预算失败淘汰历史或新建活动挑战")


def final_sample_deadline(lab):
    lab.setup_w1()
    _, accepted = lab.accepted()
    record = accepted["record"]
    lab.observed("A", "exact-public-r0-accepted-before-final-sample", record)
    request = lab.witness_request(record, ttl="8")["request"]
    delivery = lab.respond(record, request)["delivery"]
    lab.observed("W", "normal-independent-witness-response-before-deadline", delivery)
    deadline = int(decode(delivery["response"])["expires_at_unix_secs"])
    barrier = (lab.directory / "w1-final-sample-barrier").resolve()
    barrier.mkdir()
    device = lab.target
    payload = {"directory": str(lab.directory / device), "service": lab.service,
        "account": identity(device)["account_id"], "device": device,
        "operation": "join_recovery",
        "command": {"kind": "witness_apply", "record": record,
                    "request": request, "delivery": delivery}}
    raw = json_bytes(canonical_envelopes(payload)).decode()
    before = state(lab)
    anchor_before = lab.rust(device, "anchor_inspect") if device in lab.configs else None
    started = time.time()
    process = subprocess.Popen([str(lab.probe_binary)], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env=lab.environment(device, {"RIM_WITNESS_FINAL_SAVE_BARRIER": str(barrier)}))
    lab.process_count += 1
    trace = {"device": device, "operation": "join_recovery", "pid": process.pid,
        "request_sha256": sha(raw.encode()), "binary": str(lab.probe_binary),
        "scope": "default-disabled barrier immediately before final real-clock sample"}
    lab.case_evidence.setdefault("processes", []).append(trace)
    try:
        process.stdin.write(raw)
        process.stdin.close()
        process.stdin = None
        while not (barrier / "arrived").exists():
            check(process.poll() is None, "最终屏障之前进程已经退出")
            check(time.time() - started < 15, "没有抵达临时 provider 验证后的最终屏障")
            time.sleep(.01)
        arrived = time.time()
        check(int(arrived) < deadline, "装置未在有效期内抵达最终屏障")
        # 屏障只延后真实取样；绝不替换系统时间或 OpenMLS Lifetime。
        while int(time.time()) < deadline:
            time.sleep(.02)
        released = time.time()
        (barrier / "release").write_text("continue actual final clock check\n")
        stdout, stderr = process.communicate(timeout=15)
    except BaseException:
        process.kill()
        stdout, stderr = process.communicate(timeout=5)
        trace.update(interrupted=True, exit_code=process.returncode,
                     stdout_sha256=sha(stdout.encode()), stderr_sha256=sha(stderr.encode()))
        raise
    trace.update(exit_code=process.returncode, stdout_sha256=sha(stdout.encode()),
                 stderr_sha256=sha(stderr.encode()))
    reply = json.loads(stdout)
    after = state(lab)
    anchor_after = lab.rust(device, "anchor_inspect") if device in lab.configs else None
    event = {"label": "real-final-sample-crosses-deadline", "before": before, "after": after,
        "result": reply, "started_at": started, "arrived_after_temporary_validation_at": arrived,
        "expires_at_unix_secs": deadline, "released_at": released,
        "actual_clock_only": True, "default_disabled_probe": True,
        "anchor_before": anchor_before, "anchor_after": anchor_after}
    lab.role_results["T"].append(event)
    check(process.returncode == 1 and reply.get("ok") is False and
          reply["error"]["code"] == "w1_deadline_expired", "最终真实取样没有拒绝过期")
    check(before == after, "最终取样失败改变快照、材料、挑战或 Relay")
    check(anchor_after == anchor_before, "最终到期拒绝留下独立锚预约/暂停，违反冻结 U-APPLY-FAIL")
    check(lab.recovery(lab.target, "inspect")["installed_count"] == 0,
          "失败后新进程误报已安装")
    refreshed = lab.witness_request(record, ident="w1-final-sample-refresh")["request"]
    fresh_delivery = lab.respond(record, refreshed)["delivery"]
    installed = lab.install(record, refreshed, fresh_delivery)
    check(installed["installed"], "最终取样失败后不能用新挑战正常恢复")
    lab.observed("T", "normal-fresh-challenge-after-final-sample-failure", installed)


CASES = {
    "WC06-08-request-size": request_size,
    "WC06-09-response-size": response_size,
    "WC06-10-reservation-budget": reservation_budget,
    "WC07-07-deadline-at-final-sample": final_sample_deadline,
}
