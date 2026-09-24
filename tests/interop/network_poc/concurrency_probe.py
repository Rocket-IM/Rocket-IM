"""M07 专用内存屏障与有界时序证据；不属于公开 Relay 协议。"""

import copy
import re
import secrets
import threading
from contextlib import contextmanager

from contract import ProtocolError


def invalid(message="事务测试控制参数无效"):
    return ProtocolError("test_transaction_invalid", message)


class TransactionProbe:
    def __init__(self, controller_token, enabled, gate_timeout=5):
        if not 0 < gate_timeout <= 5:
            raise ValueError("事务测试屏障必须在 5 秒内结束")
        self.controller_token = controller_token
        self.enabled = enabled
        self.gate_timeout = gate_timeout
        self.condition = threading.Condition()
        self.local = threading.local()
        self.labels = {}
        self.events = []
        self.key = None
        self.control_count = 0
        self.closed = False

    def execute(self, token, req):
        if not self.enabled or not isinstance(token, str) or not secrets.compare_digest(
                token.encode("utf-8"), self.controller_token.encode("utf-8")):
            raise ProtocolError("permission_denied", "事务屏障仅供已启用的测试控制器使用", status=403)
        with self.condition:
            self.control_count += 1
            if self.control_count > 512:
                raise ProtocolError("resource_exhausted", "事务测试控制请求超过上限", status=429)
            if not isinstance(req, dict):
                raise invalid()
            action = req.get("action")
            if action == "arm":
                return self.arm(req)
            if action == "status" and set(req) == {"action"}:
                return {"events": copy.deepcopy(self.events), "labels": [
                    {"label": label, "claimed": item["claimed"], "finished": item["finished"]}
                    for label, item in self.labels.items()]}
            if action == "release":
                return self.release(req)
            raise invalid()

    def arm(self, req):
        if set(req) != {"action", "labels"} or not isinstance(req["labels"], list) or not 1 <= len(req["labels"]) <= 8:
            raise invalid()
        if self.key is not None or self.closed:
            raise ProtocolError("state_conflict", "每个测试 Relay 只允许配置一次事务计划", status=409)
        labels = {}
        for spec in req["labels"]:
            if not isinstance(spec, dict) or set(spec) - {"label", "hold_before_begin", "hold_before_commit"}:
                raise invalid()
            label = spec.get("label")
            if not isinstance(label, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,31}", label) is None or label in labels:
                raise invalid()
            gates = {}
            for point in ("before_begin", "before_commit"):
                hold = spec.get("hold_" + point, False)
                if type(hold) is not bool:
                    raise invalid()
                if hold:
                    gates[point] = {"waiting": False, "decision": None}
            labels[label] = {"claimed": False, "finished": False, "gates": gates}
        self.labels = labels
        self.key = secrets.token_urlsafe(32)
        return {"key": self.key}

    def release(self, req):
        if set(req) != {"action", "label", "point", "decision"}:
            raise invalid()
        if not all(isinstance(req[field], str) for field in ("label", "point", "decision")):
            raise invalid()
        item = self.labels.get(req["label"])
        gate = item and item["gates"].get(req["point"])
        decisions = {"continue"} if req["point"] == "before_begin" else {"commit", "rollback"}
        if gate is None or req["decision"] not in decisions:
            raise invalid()
        if not gate["waiting"] or gate["decision"] is not None or item["finished"]:
            raise ProtocolError("state_conflict", "事务屏障未等待或已经释放", status=409)
        gate["decision"] = req["decision"]
        self.record(req["label"], req["point"] + "_released", decision=req["decision"])
        self.condition.notify_all()
        return {"released": True, "label": req["label"], "point": req["point"]}

    @contextmanager
    def bind(self, headers):
        labels = headers.get_all("X-RIM-Test-Transaction", [])
        keys = headers.get_all("X-RIM-Test-Key", [])
        if not labels and not keys:
            yield
            return
        if len(labels) != 1 or len(keys) != 1 or len(keys[0]) > 128:
            raise invalid("事务测试标签和密钥必须各提供一次")
        label = labels[0]
        with self.condition:
            if not self.enabled or self.key is None or not secrets.compare_digest(
                    keys[0].encode("utf-8"), self.key.encode("utf-8")):
                raise ProtocolError("permission_denied", "事务测试密钥无效", status=403)
            item = self.labels.get(label)
            if item is None or item["claimed"] or self.closed:
                raise ProtocolError("state_conflict", "事务标签未配置或已经消费", status=409)
            item["claimed"] = True
        self.local.label = label
        try:
            yield
        finally:
            with self.condition:
                item["finished"] = True
                self.condition.notify_all()
            del self.local.label

    def current_label(self):
        return getattr(self.local, "label", None)

    def record(self, label, stage, **details):
        with self.condition:
            # 8 个单次标签每个至多 14 个事件；溢出表示装置自身有错误。
            if len(self.events) >= 128:
                raise RuntimeError("事务测试时序事件超过上限")
            self.events.append({"index": len(self.events) + 1, "label": label, "stage": stage, **details})
            self.condition.notify_all()

    def checkpoint(self, label, point, pending=None):
        with self.condition:
            gate = self.labels[label]["gates"].get(point)
            if gate is None:
                return
            gate["waiting"] = True
            self.record(label, point + "_waiting", **({"pending": pending} if pending is not None else {}))
            ready = self.condition.wait_for(lambda: gate["decision"] is not None or self.closed,
                                            timeout=self.gate_timeout)
            gate["waiting"] = False
            if not ready or self.closed:
                self.record(label, point + "_cancelled" if self.closed else point + "_timeout")
                raise ProtocolError("test_transaction_timeout", "事务测试屏障超时或已停止", status=503)
            if gate["decision"] == "rollback":
                raise ProtocolError("test_transaction_rollback", "测试控制器要求回滚当前事务", status=503)

    def close(self):
        with self.condition:
            self.closed = True
            self.condition.notify_all()
