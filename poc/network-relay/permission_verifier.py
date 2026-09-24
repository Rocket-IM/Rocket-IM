"""有界调用显式配置的 Rust 公共证据验证器；不访问任何客户端目录。"""

import os
import subprocess
from pathlib import Path

from bounded_helper import run_helper
from contract import MAX_REQUEST_BYTES, ProtocolError, encode_json, fields, parse_json
from permission_contract import JOIN_ACTIONS, validate_checkpoint, validate_statement
from receipt_contract import validate_close

MAX_OUTPUT = 64 * 1024
VERIFIER_TIMEOUT = 3.0
ERROR_STATUS = {"invalid_permission": 400, "permission_denied": 403, "permission_conflict": 409,
                "permission_signature": 403, "permission_context": 403, "permission_version": 409,
                "permission_commit": 403, "resource_exhausted": 429,
                "invalid_join_material": 400, "join_identity": 403, "join_material_mismatch": 400,
                "history_invalid": 400, "history_signature": 403, "history_context": 409, "history_denied": 403,
                "rebuild_stream_invalid": 400, "rebuild_stream_context": 409, "rebuild_stream_signature": 403,
                "rebuild_stream_denied": 403, "anchor_invalid": 400, "anchor_signature": 403,
                "anchor_rebuild_denied": 403, "anchor_response_binding": 409}


def unavailable():
    return ProtocolError("permission_verifier_unavailable", "公共权限验证器不可用或返回无效结果", status=503)


class PermissionVerifier:
    def __init__(self, path):
        self.path = Path(path)
        if not self.path.is_absolute() or not self.path.is_file() or not os.access(self.path, os.X_OK):
            raise ValueError("permission-verifier 必须为可执行文件的绝对路径")

    def _call(self, request):
        raw = encode_json(request)
        if len(raw) > MAX_REQUEST_BYTES:
            raise ProtocolError("resource_exhausted", "公共验证器完整输入超过 1 MiB", status=429)
        try:
            output, return_code = self._run(raw)
            value = parse_json(output)
            fields(value, ("ok",), ("result", "error"))
            if value["ok"] is False and return_code == 1:
                fields(value, ("ok", "error"))
                fields(value["error"], ("code", "message"))
                code = value["error"]["code"]
                if code not in ERROR_STATUS:
                    raise unavailable()
                raise ProtocolError(code, "权限证据未通过公共验证", status=ERROR_STATUS[code])
            if value["ok"] is not True or return_code != 0:
                raise unavailable()
            fields(value, ("ok", "result"))
            return value["result"]
        except ProtocolError as error:
            if error.code in ERROR_STATUS or error.code == "permission_verifier_unavailable":
                raise
            raise unavailable() from None
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            raise unavailable() from None

    def verify(self, checkpoint, change, statement, join=None):
        request = {"checkpoint": checkpoint, "change": change}
        if join is not None:
            request["join"] = join
        validated = self._call(request)
        try:
            fields(validated, ("checkpoint", "statement"))
            validate_checkpoint(validated["checkpoint"])
            validate_statement(validated["statement"])
            if validated["statement"] != statement:
                raise unavailable()
            expected = {**checkpoint, "authorization_version": statement["authorization_version"],
                        "crypto_state_ref": statement["to_state_ref"]}
            action = statement["action"]
            if action["kind"] in JOIN_ACTIONS:
                expected["members"] = sorted([*checkpoint["members"], action["member"]], key=lambda member: (member["account_id"], member["device_id"]))
            else:
                expected["members"] = [member for member in checkpoint["members"]
                                       if not (member["account_id"] == action["account_id"] and
                                               (action["kind"] == "remove_member" or member["device_id"] == action["device_id"]))]
            if validated["checkpoint"] != expected:
                raise unavailable()
            return validated
        except (ProtocolError, KeyError, TypeError):
            raise unavailable() from None

    def verify_close(self, checkpoint, change, close):
        validated = self._call({"checkpoint": checkpoint, "change": change, "close": close})
        try:
            fields(validated, ("statement",))
            if validated["statement"] != validate_close(close):
                raise unavailable()
            return validated
        except (ProtocolError, KeyError, TypeError):
            raise unavailable() from None

    def verify_history_transfer(self, checkpoint, request, package):
        from history_contract import (ciphertext_digest, package_digest, request_digest,
                                      validate_history_package, validate_history_request)
        validated = self._call({"operation": "verify_history_transfer", "checkpoint": checkpoint,
                                "request": request, "package": package})
        try:
            expected = {"request": validate_history_request(request), "package": validate_history_package(package),
                        "request_sha256": request_digest(request), "package_sha256": package_digest(package)}
            if (validated != expected or expected["package"]["request_sha256"] != expected["request_sha256"]
                    or expected["package"]["ciphertext_sha256"] != ciphertext_digest(package)
                    or expected["request"]["transfer_id"] != expected["package"]["transfer_id"]):
                raise unavailable()
            return validated
        except (ProtocolError, KeyError, TypeError):
            raise unavailable() from None

    def _run(self, raw):
        return run_helper(self.path, raw, VERIFIER_TIMEOUT, MAX_OUTPUT, unavailable)

    def verify_rebuild_stream(self, trusted, registration):
        from rebuild_stream_contract import signed_digest, validate_stream_request
        from receipt_contract import signed_statement
        result = self._call({"operation": "verify_rebuild_stream", "trusted": trusted, "registration": registration})
        expected = {"request": validate_stream_request(signed_statement(registration["request"])),
                    "request_sha256": signed_digest(registration["request"])}
        if result != expected:
            raise unavailable()
        return result

    def verify_rebuild_pull(self, binding, request):
        from rebuild_stream_contract import signed_digest, validate_pull
        from receipt_contract import signed_statement
        result = self._call({"operation": "verify_rebuild_pull", "binding": binding, "request": request})
        expected = {"pull": validate_pull(signed_statement(request)), "request_sha256": signed_digest(request)}
        if result != expected:
            raise unavailable()
        return result
