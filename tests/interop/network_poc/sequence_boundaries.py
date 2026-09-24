"""M12.c：类型、u64溢出和舍入后重复序号在HTTP/Rust/JS边界明确拒绝。"""

import copy

from .deletion_observer import relay_records
from .first_stream_support import sign_test_page
from .fixture import check
from .sequence_support import BASE, SEQUENCES, node, pull, record, snapshot, unchanged


def field(page, name, value):
    changed = copy.deepcopy(page)
    if name == "event_seq":
        changed["events"][0][name] = value
    else:
        changed[name] = value
    return changed


def input_boundaries(lab):
    original = pull(lab, BASE, 100)
    files, rows = snapshot(lab), relay_records(lab)
    invalid = [("number", int(SEQUENCES[-1])), ("null", None), ("boolean", True),
               ("overflow", "18446744073709551616"), ("leading_zero", "09007199254740993"), ("negative", "-1")]
    for label, value in invalid:
        error = lab.http("b1", "pull_events_signed", {"service_id": lab.service,
                         "stream_id": lab.streams["b1"], "after_seq": value, "limit": "1"}, expected=400)
        check(error["code"] == "invalid_envelope", "HTTP错误类型或溢出没有在解析边界拒绝")
        unchanged(lab, files, rows)
        record(lab, "http_invalid_cursor", label=label, requested=value, error=error)
    maximum = lab.http("b1", "pull_events_signed", {"service_id": lab.service,
                       "stream_id": lab.streams["b1"], "after_seq": "18446744073709551615", "limit": "1"}, expected=409)
    check(maximum["code"] == "cursor_invalid", "合法u64最大值应明确拒绝超水位，不能称SQLite正向支持")
    unchanged(lab, files, rows)
    record(lab, "http_u64_max_above_watermark", error=maximum, positive_storage_tested=False)
    for name in ("event_seq", "next_after_seq", "watermark"):
        for label, value in invalid:
            malformed = field(original["page"], name, value)
            js_error = node(lab, "validate_page", expected=1, page=malformed)
            check(js_error["code"] == "invalid_envelope", "JS没有拒绝错误类型或u64表示")
            # 明确的恶意Service签页负例：保持有效签名，以触达Rust类型/数值校验。
            signed = sign_test_page(lab, original["wrapper"], page=malformed)
            rust_error = lab.rust("b1", "wire_download_signed", expected_exit=1, **signed)
            expected = "stream_page_invalid" if label in ("number", "null", "boolean") else "invalid_envelope"
            check(rust_error["code"] == expected, "Rust签页输入未在预期类型/整数边界拒绝")
            unchanged(lab, files, rows)
            record(lab, "signed_page_and_js_invalid_sequence", field=name, label=label,
                   js_error=js_error, rust_error=rust_error, snapshot_unchanged=True,
                   source="explicit_synthetic_service_resigning")
    collided = copy.deepcopy(original["page"])
    collided["events"][2]["event_seq"] = SEQUENCES[1]
    js_error = node(lab, "validate_page", expected=1, page=collided)
    check(js_error["code"] == "cursor_invalid", "JS未识别舍入后的重复序号")
    signed = sign_test_page(lab, original["wrapper"], page=collided)
    rust_error = lab.rust("b1", "wire_download_signed", expected_exit=1, **signed)
    check(rust_error["code"] == "cursor_invalid", "Rust未识别舍入后的重复序号")
    unchanged(lab, files, rows)
    record(lab, "rounded_sequence_collision_rejected", js_error=js_error, rust_error=rust_error)
    for label, value in invalid[:4]:
        error = lab.rust("b1", "wire_slot_inspect", event_seq=value, expected_exit=1)
        expected = "invalid_envelope" if label == "overflow" else "invalid_request"
        check(error["code"] == expected, "原槽查询接受错误类型或溢出")
        unchanged(lab, files, rows)
        record(lab, "slot_query_invalid_sequence", label=label, error=error)
