"""普通签页的真实 HTTP 输入与显式恶意 Service 测试材料；不自动重签改动页。"""

import base64
import copy
import hashlib
import json

from .fixture import check


def encode(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()


def unpack(wrapper):
    return json.loads(base64.b64decode(wrapper["page_bytes"], validate=True))


def statement(wrapper):
    return json.loads(base64.b64decode(wrapper["receipt"]["statement_bytes"], validate=True))


def pull(lab, device, after="0", limit="100"):
    request = {"service_id": lab.service, "after_seq": after, "limit": limit}
    if device in lab.streams:
        request["stream_id"] = lab.streams[device]
    wrapper = lab.http(device, "pull_events_signed", request)
    page = unpack(wrapper)
    claims = statement(wrapper)
    check(set(wrapper) == {"page_bytes", "receipt"}, "签页响应字段超出契约")
    check(claims["after_seq"] == after and claims["limit"] == limit,
          "Service 声明没有绑定实际分页请求")
    check(claims["stream_id"] == page["stream_id"], "签名流与原页不一致")
    lab.streams[device] = page["stream_id"]
    return wrapper


def alter_unsigned(wrapper, page):
    """攻击者改原页而保持原签名；必须被 Rust 拒绝。"""
    result = copy.deepcopy(wrapper)
    result["page_bytes"] = base64.b64encode(encode(page)).decode()
    return result


def sign_test_page(lab, wrapper, *, page=None, claims=None, raw=None):
    """显式使用合成 Service 钥制造来源真实但语义错误的页，仅用于负例。"""
    original = base64.b64decode(wrapper["page_bytes"], validate=True)
    raw = raw if raw is not None else (encode(page) if page is not None else original)
    signed = statement(wrapper)
    signed["page_sha256"] = hashlib.sha256(raw).hexdigest()
    signed.update(claims or {})
    receipt = lab.relay_key("sign", statement=signed,
                            expected_signature_key=lab.relay_receipt_key)["receipt"]
    return {"page_bytes": base64.b64encode(raw).decode(), "receipt": receipt}


def reject(pair, lab, device, wrapper, code, label, *, operation="wire_download_signed"):
    before = pair.capture()
    error = lab.rust(device, operation, expected_exit=1, **wrapper)
    check(error["code"] == code, f"{label}: {error}, expected {code}")
    pair.unchanged(before, label)
    pair.evidence.setdefault("rejections", []).append({"label": label, "code": code})


def download(lab, device, wrapper):
    result = lab.rust(device, "wire_download_signed", **wrapper)
    check(result["status"] == "downloaded", "合法签页未保存")
    return result


def publish(lab, logical):
    packet = lab.prepare(logical)
    accepted = lab.submit(packet)
    check(bool(accepted["acceptance_receipt"]), "Service 未返回消息接受签名")
    lab.rust("a1", "wire_accept", logical_message_id=logical, attempt_id="P1",
             acceptance_receipt=accepted["acceptance_receipt"])
    return accepted


def process(lab, device, count):
    result = lab.rust(device, "wire_process")
    inspect = lab.rust(device, "wire_inspect")
    check(inspect["inbox_count"] == count and not inspect["sync"]["halted"],
          "合法签页处理后消息数或流状态不符")
    return result
