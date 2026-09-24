"""本机测试控制器：仅传递公开API输入/输出，不执行任何密码操作。"""
import base64
from collections import deque
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import threading
import time
from urllib.parse import urlsplit

from .expectations import ERROR_CODES

VERSION = "0.1.0-stage0.1"
LIMIT = 1024 * 1024
BYTE_FIELDS = {"peer_identity_key", "creator_identity_key", "key_package", "welcome", "plaintext", "ciphertext"}
BYTE_OPERATIONS = {"identity", "key_package", "create_group", "encrypt", "decrypt"}
ARGUMENTS = {
    "new": {"service_id", "account_id", "device_id"}, "identity": set(), "key_package": set(),
    "create_group": {"conversation_id", "peer_account_id", "peer_device_id", "peer_identity_key", "key_package"},
    "join_group": {"conversation_id", "creator_account_id", "creator_device_id", "creator_identity_key", "welcome"},
    "encrypt": {"plaintext"}, "decrypt": {"ciphertext"}, "close": set(), "drop": set(), "shutdown": set(),
}


class ProtocolError(ValueError):
    """仅包含由控制器生成的固定错误码。"""


def summarize(value):
    if not isinstance(value, str):
        raise ProtocolError("invalid_base64_type")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise ProtocolError("invalid_base64") from None
    if base64.b64encode(raw).decode("ascii") != value:
        raise ProtocolError("noncanonical_base64")
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def validate_result(body, command):
    """白名单映射先于保存；未知字段、错误正文都不能进入日志或返回状态。"""
    result = {key: body[key] for key in ("run_id", "endpoint_id", "command_id")}
    if type(body.get("ok")) is not bool:
        raise ProtocolError("invalid_result_status")
    result["ok"] = body["ok"]
    if body["ok"]:
        if "value" not in body or body.get("error") is not None:
            raise ProtocolError("invalid_success_shape")
        value = body["value"]
        if command["op"] in BYTE_OPERATIONS:
            size = summarize(value)["bytes"]
            if not 0 < size <= (65536 if command["op"] == "decrypt" else 262144):
                raise ProtocolError("invalid_result_size")
            if command["op"] == "identity" and size != 32:
                raise ProtocolError("invalid_identity_size")
        elif value is not None:
            raise ProtocolError("invalid_unit_result")
        result["value"] = value
    else:
        error = body.get("error")
        if (not isinstance(error, dict) or error.get("origin") not in ("sdk", "harness")
                or type(error.get("device_poisoned")) is not bool
                or not isinstance(error.get("code"), str)
                or not isinstance(error.get("message"), str) or len(error["message"]) > 512
                or body.get("value") is not None):
            raise ProtocolError("invalid_error_shape")
        if error["origin"] == "sdk" and error["code"] not in ERROR_CODES:
            raise ProtocolError("unknown_sdk_error_code")
        result["error"] = {"origin": error["origin"],
                           "code": error["code"] if error["origin"] == "sdk" else "harness_error",
                           "device_poisoned": error["device_poisoned"], "message": ""}
    return result


class Broker:
    def __init__(self, run_id, endpoints, output):
        self.run_id, self.output = run_id, Path(output)
        self.condition = threading.Condition()
        self.states = {name: {"ready": None, "pending": None, "delivered": False,
                              "response": None, "timed_out": False} for name in endpoints}
        self.sequence, self.transcript = 0, []
        self.connection_sequence = 0
        self.http_errors = deque(maxlen=32)
        self.closing = False
        self.browser_directory = None
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.handler())
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_port}"

    def record_http_error(self, error):
        with self.condition:
            if not self.closing:
                self.http_errors.append({"origin": "harness", "code": "harness_error",
                                         "reason": str(error) if isinstance(error, ProtocolError) else "invalid_request_or_connection"})

    def record_control_event(self, event, endpoint, command_id=None, transport=None):
        """仅记录已校验的控制标识和时序，不保存请求、响应或异常正文。"""
        with self.condition:
            with (self.output / "control-events.jsonl").open("a") as stream:
                stream.write(json.dumps({"time_epoch": time.time(), "event": event,
                                         "endpoint": endpoint, "command_id": command_id,
                                         "transport": transport}) + "\n")

    def handler(self):
        broker = self

        class Handler(SimpleHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def setup(self):
                super().setup()
                self.connection.settimeout(15)
                with broker.condition:
                    broker.connection_sequence += 1
                    self.control_connection_id = broker.connection_sequence

            def control(self, event, endpoint, command_id=None):
                connection = self.headers.get("Connection", "absent").lower()
                broker.record_control_event(event, endpoint, command_id, {
                    "connection_id": self.control_connection_id,
                    "request_version": self.request_version if self.request_version in {"HTTP/1.0", "HTTP/1.1"} else "other",
                    "request_connection": connection if connection in {"close", "keep-alive", "absent"} else "other",
                    "response_version": self.protocol_version})

            def send_json(self, status, body=None):
                data = b"" if body is None else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                # 本控制器每请求关闭HTTP/1.0连接，明确通知Android客户端不要将该连接返池。
                self.send_header("Connection", "close")
                self.end_headers()
                if data:
                    self.wfile.write(data)

            def route(self):
                parts = urlsplit(self.path).path.split("/")
                if len(parts) != 5 or parts[1] != "interop" or parts[2] != broker.run_id:
                    raise ProtocolError("unknown_test_route")
                name, action = parts[3:]
                if name not in broker.states:
                    raise ProtocolError("unknown_endpoint")
                return name, action

            def do_GET(self):
                if urlsplit(self.path).path.startswith("/browser/") and broker.browser_directory:
                    self.directory = str(broker.browser_directory)
                    self.path = self.path.removeprefix("/browser")
                    return super().do_GET()
                try:
                    name, action = self.route()
                    if action != "next":
                        raise ProtocolError("invalid_action")
                    self.control("poll_received", name)
                    deadline = time.monotonic() + 10
                    with broker.condition:
                        state = broker.states[name]
                        while not broker.closing and not (state["pending"] and not state["delivered"] and not state["timed_out"]):
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                break
                            broker.condition.wait(remaining)
                        command = None
                        if not broker.closing and state["pending"] and not state["delivered"] and not state["timed_out"]:
                            state["delivered"] = True
                            command = state["pending"]
                            self.control("command_delivered", name, command["command_id"])
                    self.send_json(200, command) if command else self.send_json(204)
                    if command:
                        self.control("command_written", name, command["command_id"])
                except (ValueError, OSError) as error:
                    broker.record_http_error(error)
                    if isinstance(error, ValueError):
                        self.send_json(400, {"error": "invalid_control_request"})

            def do_POST(self):
                try:
                    name, action = self.route()
                    if action in {"ready", "result"}:
                        self.control("post_received", name)
                    length = int(self.headers.get("Content-Length", "-1"))
                    if not 0 <= length <= LIMIT:
                        raise ProtocolError("invalid_content_length")
                    body = json.loads(self.rfile.read(length))
                    if not isinstance(body, dict) or body.get("run_id") != broker.run_id or body.get("endpoint_id") != name:
                        raise ProtocolError("response_scope_mismatch")
                    with broker.condition:
                        state = broker.states[name]
                        command_id = None
                        if broker.closing:
                            raise ProtocolError("broker_closed")
                        if action == "ready":
                            if (state["ready"] is not None or body.get("sdk_version") != VERSION
                                    or body.get("platform") != name):
                                raise ProtocolError("invalid_ready_identity_version_or_duplicate")
                            state["ready"] = {key: body[key] for key in ("run_id", "endpoint_id", "sdk_version", "platform")}
                        elif action == "result":
                            command = state["pending"]
                            if (not command or not state["delivered"] or state["timed_out"]
                                    or body.get("command_id") != command["command_id"] or state["response"] is not None):
                                raise ProtocolError("unexpected_or_duplicate_result")
                            state["response"] = validate_result(body, command)
                            command_id = command["command_id"]
                            self.control("result_received", name, command_id)
                        else:
                            raise ProtocolError("invalid_action")
                        broker.condition.notify_all()
                    self.send_json(200, {"ok": True})
                    self.control("ack_written", name, command_id)
                except (ValueError, OSError) as error:
                    broker.record_http_error(error)
                    if isinstance(error, ValueError):
                        self.send_json(400, {"error": "invalid_control_request"})

        return Handler

    def wait_ready(self, timeout=120):
        deadline = time.monotonic() + timeout
        with self.condition:
            while not all(s["ready"] for s in self.states.values()):
                remaining = deadline - time.monotonic()
                if remaining <= 0 or self.closing:
                    raise TimeoutError("endpoints_not_ready")
                self.condition.wait(remaining)
            return {name: dict(state["ready"]) for name, state in self.states.items()}

    def record(self, item):
        self.transcript.append(item)
        with (self.output / "commands.jsonl").open("a") as stream:
            stream.write(json.dumps(item, ensure_ascii=False) + "\n")

    def call(self, endpoint, op, handle, args, timeout=30):
        if (op not in ARGUMENTS or not isinstance(args, dict) or set(args) != ARGUMENTS[op]
                or not all(isinstance(v, str) for v in args.values())
                or not isinstance(handle, str) or not (op == "shutdown" and handle == "" or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", handle))):
            raise ProtocolError("invalid_command_shape")
        metadata = {k: summarize(v) if k in BYTE_FIELDS else {"bytes": len(v.encode()), "sha256": hashlib.sha256(v.encode()).hexdigest()}
                    for k, v in args.items()}
        started = time.monotonic()
        with self.condition:
            state = self.states[endpoint]
            if self.closing or not state["ready"] or state["pending"]:
                raise RuntimeError("endpoint_unready_or_busy")
            self.sequence += 1
            command = {"run_id": self.run_id, "command_id": f"cmd{self.sequence:06d}", "op": op, "handle": handle, "args": args}
            if len(json.dumps(command).encode()) > LIMIT:
                raise ProtocolError("test_command_too_large")
            item = {"command_id": command["command_id"], "endpoint": endpoint, "op": op, "handle": handle, "args": metadata}
            state.update(pending=command, delivered=False, response=None, timed_out=False)
            self.condition.notify_all()
            while state["response"] is None:
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0 or self.closing:
                    state["timed_out"] = True
                    self.record({**item, "status": "TIMEOUT"})
                    raise TimeoutError("command_timeout")
                self.condition.wait(remaining)
            response = state["response"]
            state.update(pending=None, delivered=False, response=None, timed_out=False)
        item.update(ok=response["ok"], milliseconds=round((time.monotonic() - started) * 1000, 2))
        if response["ok"]:
            item["result"] = summarize(response["value"]) if op in BYTE_OPERATIONS else None
        else:
            item["error"] = {k: response["error"][k] for k in ("origin", "code", "device_poisoned")}
        self.record(item)
        return response

    def close(self):
        with self.condition:
            self.closing = True
            self.condition.notify_all()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
