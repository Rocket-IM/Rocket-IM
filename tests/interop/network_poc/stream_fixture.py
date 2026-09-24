"""普通签名页的测试适配；保留 HTTP 原件，测试重签必须显式调用。"""

import base64
import copy
import hashlib
import json


class StreamPage(dict):
    def __init__(self, wrapper):
        self.wrapper = copy.deepcopy(wrapper)
        raw = base64.b64decode(wrapper["page_bytes"], validate=True)
        super().__init__(json.loads(raw))

    def signed_input(self):
        original = json.loads(base64.b64decode(self.wrapper["page_bytes"], validate=True))
        if self != original:
            raise AssertionError("已修改捕获的签名页；必须明确测试原件篡改拒绝或调用 sign_test_page")
        return copy.deepcopy(self.wrapper)


def sign_test_page(lab, page, *, device=None, after="0", limit="100"):
    """仅合成 Service 作恶装置：调用者明确要求后，使用实验钥重新签署页。"""
    if not hasattr(lab, "relay_receipt_key"):
        return page
    if isinstance(page, StreamPage):
        claims = json.loads(base64.b64decode(page.wrapper["receipt"]["statement_bytes"], validate=True))
    else:
        if device is None:
            raise AssertionError("人工构造签名页必须明确目标设备")
        from .fixture import identity
        recipient = getattr(lab, "identities", {}).get(device) or identity(device)
        claims = {"protocol_version": "RIM-STREAM-PAGE-POC-1", "service_id": lab.service,
                  **recipient, "stream_id": page["stream_id"], "after_seq": after, "limit": limit}
    raw = json.dumps(page, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode()
    claims["page_sha256"] = hashlib.sha256(raw).hexdigest()
    receipt = lab.relay_key("sign", expected_signature_key=lab.relay_receipt_key,
                            statement=claims)["receipt"]
    return StreamPage({"page_bytes": base64.b64encode(raw).decode(), "receipt": receipt})
