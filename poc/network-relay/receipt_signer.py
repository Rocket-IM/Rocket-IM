"""显式配置的 Service 自有签名器；从不读取用户解密私钥。"""

import os
import subprocess
from pathlib import Path

from bounded_helper import run_helper
from contract import ProtocolError, decode_bytes, encode_json, fields, parse_json
from receipt_contract import (validate_consistency_head, validate_message_acceptance,
                              validate_message_closure, validate_message_rejection, validate_receipt)
from history_contract import validate_history_receipt
from rebuild_stream_contract import validate_binding, validate_page_receipt
from stream_page_contract import validate_stream_page_receipt


def unavailable():
    return ProtocolError("receipt_signer_unavailable", "Service 凭证签名器不可用或密钥不匹配", status=503)


class ReceiptSigner:
    def __init__(self, path, key_path):
        self.path, self.key_path = Path(path), Path(key_path)
        if not self.path.is_absolute() or not self.path.is_file() or not os.access(self.path, os.X_OK):
            raise ValueError("receipt-signer 必须是可执行文件的绝对路径")
        if not self.key_path.is_absolute():
            raise ValueError("receipt-key 必须是预先初始化密钥的绝对路径")
        self.signature_key = None

    def _call(self, request):
        try:
            output, code = run_helper(self.path, encode_json({**request, "key_path": str(self.key_path)}), 3.0, 64 * 1024, unavailable)
            value = parse_json(output)
            fields(value, ("ok", "result"))
            if code != 0 or value["ok"] is not True:
                raise unavailable()
            return value["result"]
        except (ProtocolError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            raise unavailable() from None

    def public_key(self):
        result = self._call({"operation": "public_key"})
        try:
            fields(result, ("signature_key",))
            if len(decode_bytes(result["signature_key"], "signature_key", 32)) != 32:
                raise unavailable()
            return result["signature_key"]
        except ProtocolError:
            raise unavailable() from None

    def sign(self, statement):
        if self.signature_key is None:
            raise unavailable()
        validator = {"rim-permission-receipt-1": validate_receipt,
                     "rim-message-acceptance-1": validate_message_acceptance,
                     "rim-message-closure-1": validate_message_closure,
                     "rim-message-rejection-1": validate_message_rejection,
                     "rim-history-receipt-1": validate_history_receipt,
                     "rim-rebuild-stream-binding-1": validate_binding,
                     "rim-rebuild-stream-page-1": validate_page_receipt,
                     "RIM-STREAM-PAGE-POC-1": validate_stream_page_receipt,
                     "rim-consistency-head-1": validate_consistency_head}.get(statement.get("protocol_version"))
        if validator is None:
            raise unavailable()
        result = self._call({"operation": "sign", "statement": statement, "expected_signature_key": self.signature_key})
        try:
            fields(result, ("receipt",))
            if validator(result["receipt"]) != statement:
                raise unavailable()
            return result["receipt"]
        except ProtocolError:
            raise unavailable() from None
