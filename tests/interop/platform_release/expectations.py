"""跨端验收的响应断言与资源归属；不实现任何密码算法。"""
import base64
from dataclasses import dataclass
import hashlib
import uuid


ERROR_CODES = {
    "invalid_argument", "invalid_encoding", "identity_mismatch", "scope_mismatch",
    "already_grouped", "group_required", "closed", "poisoned", "crypto_failure",
    "limit_exceeded",
}
BYTE_OPERATIONS = {"identity", "key_package", "create_group", "encrypt", "decrypt"}


def encoded(value):
    return base64.b64encode(value).decode("ascii")


def summary(value):
    return {"length": len(value), "sha256": hashlib.sha256(value).hexdigest()}


class CaseFailure(Exception):
    def __init__(self, details):
        super().__init__(details.get("check") or details.get("kind", "verification_failed"))
        self.details = details


def require(condition, name):
    if not condition:
        raise CaseFailure({"kind": "assertion", "check": name})


def error_summary(error):
    """不复制 SDK 或装置的未知异常正文，避免原参数进入验收报告。"""
    if not isinstance(error, dict):
        return {"origin": "malformed", "code": "malformed_error"}
    origin = error.get("origin")
    code = error.get("code")
    return {
        "origin": origin if origin in ("sdk", "harness") else "unknown",
        "code": code if isinstance(code, str) and code in ERROR_CODES else "unknown",
        "device_poisoned": error.get("device_poisoned") if type(error.get("device_poisoned")) is bool else None,
    }


@dataclass(repr=False)
class Device:
    endpoint: str
    handle: str
    account: str
    device: str
    identity: bytes = b""
    key_package: bytes = b""


class Case:
    def __init__(self, client, case_id):
        self.client = client
        self.case_id = case_id
        self.prefix = uuid.uuid4().hex[:12]
        self.devices = []
        self.details = {"operations": [], "checks": []}

    def call(self, device, operation, args=None):
        try:
            result = self.client.call(device.endpoint, operation, device.handle, args or {})
        except Exception as error:
            raise CaseFailure({"kind": "transport_or_harness", "operation": operation,
                               "endpoint": device.endpoint, "exception_type": type(error).__name__}) from None
        if not isinstance(result, dict) or type(result.get("ok")) is not bool:
            raise CaseFailure({"kind": "malformed_response", "operation": operation,
                               "endpoint": device.endpoint})
        return result

    def ok(self, device, operation, **args):
        result = self.call(device, operation, args)
        record = {"endpoint": device.endpoint, "operation": operation}
        if not result["ok"]:
            raise CaseFailure({"kind": "unexpected_rejection", **record,
                               "error": error_summary(result.get("error"))})
        require("value" in result, "success_response_has_value")
        value = result["value"]
        if operation in BYTE_OPERATIONS:
            require(isinstance(value, str), "byte_response_is_base64_string")
            try:
                data = base64.b64decode(value, validate=True)
            except (ValueError, TypeError):
                raise CaseFailure({"kind": "invalid_response_base64", **record}) from None
            require(encoded(data) == value, "response_base64_is_canonical")
            require(0 < len(data) <= (65536 if operation == "decrypt" else 262144), "response_size_bound")
            if operation == "identity":
                require(len(data) == 32, "identity_key_size")
            record["value"] = summary(data)
            value = data
        else:
            require(value is None, "unit_response_is_null")
        self.details["operations"].append({**record, "status": "PASS"})
        return value

    def rejected(self, device, operation, code, poisoned=False, **args):
        require(code in ERROR_CODES, "known_expected_sdk_error")
        result = self.call(device, operation, args)
        actual = error_summary(result.get("error"))
        expected = {"origin": "sdk", "code": code, "device_poisoned": poisoned}
        record = {"endpoint": device.endpoint, "operation": operation,
                  "expected_error": expected, "actual_error": actual}
        if result["ok"] or actual != expected:
            raise CaseFailure({"kind": "wrong_rejection", **record, "actual_ok": result["ok"]})
        self.details["operations"].append({**record, "status": "PASS"})

    def new(self, endpoint, service="interop-service"):
        index = len(self.devices)
        handle = f"h{self.prefix}_{index}"
        device = Device(endpoint, handle, f"account-{index}", f"device-{self.prefix}-{index}")
        # 先登记所有权，即使响应丢失也会尝试drop，绝不重做有状态new。
        self.devices.append(device)
        require(sum(d.endpoint == endpoint for d in self.devices) <= 32, "endpoint_handle_limit")
        self.ok(device, "new", service_id=service, account_id=device.account, device_id=device.device)
        device.identity = self.ok(device, "identity")
        device.key_package = self.ok(device, "key_package")
        return device

    def unchanged(self, device):
        require(self.ok(device, "identity") == device.identity, "preflight_preserves_identity")
        require(self.ok(device, "key_package") == device.key_package, "preflight_preserves_key_package")
        self.details["checks"].append("preflight_preserves_identity_and_key_package")

    def cleanup(self):
        failures = []
        for device in reversed(self.devices):
            try:
                self.ok(device, "drop")
            except CaseFailure as error:
                failures.append(error.details)
            except Exception as error:
                failures.append({"kind": "cleanup_harness", "exception_type": type(error).__name__})
        self.details["cleanup"] = {"attempted_handles": len(self.devices), "failures": failures}
        return failures
