"""首次使用的期限在事务即将提交时再检查；精确旧结果不重新受TTL控制。"""
import time
from contract import ProtocolError

class TimedResult(dict):
    def __init__(self, value, not_after, not_before=0, code="key_package_expired"):
        super().__init__(value)
        self.not_after = int(not_after)
        self.not_before = int(not_before)
        self.code = code

def before_commit(value):
    if isinstance(value, TimedResult) and not value.not_before <= int(time.time()) < value.not_after:
        raise ProtocolError(value.code, "材料在首次使用提交前已到期", status=409)
