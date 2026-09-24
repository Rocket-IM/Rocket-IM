"""M01 合成秘密观察装置：采集真实 HTTP、日志和服务端存储，不修改 Relay。"""

import base64
from contextlib import closing
import hashlib
import http.client
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import time
from urllib.parse import urlparse

from .fixture import NetworkLab, check


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _identifier(name):
    return '"' + name.replace('"', '""') + '"'


def _value(value):
    if isinstance(value, bytes):
        return {"sqlite_blob_base64": base64.b64encode(value).decode("ascii")}
    return value


def _database_contents(db):
    """由调用方持有显式只读事务；保留所有 schema、列及字段值。"""
    schema = [dict(zip(("type", "name", "table", "sql"), row)) for row in db.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")]
    tables = {}
    for item in schema:
        if item["type"] != "table":
            continue
        name = _identifier(item["name"])
        columns = [list(row) for row in db.execute(f"PRAGMA table_info({name})")]
        rows = [[_value(value) for value in row] for row in db.execute(f"SELECT * FROM {name}")]
        rows.sort(key=_json_bytes)
        tables[item["name"]] = {"columns": columns, "rows": rows}
    return {"schema": schema, "tables": tables}


def _readonly(path):
    return sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True,
                           isolation_level=None)


class SecretLab(NetworkLab):
    def __init__(self, binary, directory, permission_verifier=None, receipt_signer=None):
        super().__init__(binary, directory, permission_verifier, receipt_signer)
        self.surfaces = []
        self.surface_directory = self.directory / "surfaces"
        self.surface_directory.mkdir(mode=0o700)
        self._stdout_log = None
        self._starts = 0

    def _surface(self, label, kind, suffix=".bin"):
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", label)[:100]
        path = self.surface_directory / f"{len(self.surfaces):04d}-{safe}{suffix}"
        path.touch(mode=0o600, exist_ok=False)
        entry = {"label": label, "path": str(path), "kind": kind}
        self.surfaces.append(entry)
        return path

    def capture(self, label, data: bytes, kind):
        """仅保存本 case 的合成原字节，返回不含内容的摘要。"""
        check(isinstance(data, bytes), "M01 采集输入必须是原字节")
        path = self._surface(label, kind)
        path.write_bytes(data)
        return {"label": label, "path": str(path), "kind": kind,
                "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    def _safe_result(self, operation, call):
        # 基类失败可能包含 stdout 前段；失败报告只保存摘要，不改变正常返回值。
        try:
            return call()
        except Exception as error:
            if hasattr(self, "case_evidence"):
                self.case_evidence.setdefault("protected_failures", []).append({
                    "operation": operation, "exception_type": type(error).__name__,
                    "error_sha256": hashlib.sha256(str(error).encode(
                        "utf-8", errors="backslashreplace")).hexdigest()})
            raise AssertionError("实验子进程请求失败；原错误仅保留摘要") from None

    def rust(self, device, operation, *, expected_exit=0, **fields):
        return self._safe_result("rust:" + operation, lambda: super(SecretLab, self).rust(
            device, operation, expected_exit=expected_exit, **fields))

    def relay_key(self, operation, **fields):
        return self._safe_result("relay_key:" + operation,
                                 lambda: super(SecretLab, self).relay_key(operation, **fields))

    def start(self):
        check(self.process is None, "Relay 已在运行")
        self._starts += 1
        stdout_path = self._surface(f"relay-{self._starts}-stdout", "relay_stdout", ".log")
        stderr_path = self._surface(f"relay-{self._starts}-stderr", "relay_stderr", ".log")
        self._stdout_log = stdout_path.open("wb")
        self.server_log = stderr_path.open("wb")
        command = [sys.executable, "-B", str(self.relay_entrypoint),
                   "--database", str(self.directory / "relay.sqlite"),
                   "--fixture", str(self.fixture_path), "--port", "0", "--enable-test-controls"]
        if self.permission_verifier:
            command.extend(["--permission-verifier", str(self.permission_verifier)])
        if self.receipt_signer:
            command.extend(["--receipt-signer", str(self.receipt_signer),
                            "--receipt-key", str(self.receipt_key)])
        command.extend(self.relay_args)
        self.process = subprocess.Popen(command, stdout=self._stdout_log, stderr=self.server_log)
        self.process_count += 1
        deadline = time.monotonic() + 15
        line = b""
        while time.monotonic() < deadline:
            with stdout_path.open("rb") as stdout:
                line = stdout.readline()
            if line.endswith(b"\n") or self.process.poll() is not None:
                break
            time.sleep(0.01)
        check(line.endswith(b"\n"), "Relay 未输出完整就绪行；原日志已保留")
        try:
            ready = json.loads(line)
        except (ValueError, UnicodeError):
            raise AssertionError("Relay 就绪行不是有效 JSON；原日志已保留") from None
        check(ready.get("status") == "ready", "Relay 未就绪；原日志已保留")
        self.url = urlparse(ready["url"])
        check(self.url.hostname == "127.0.0.1", "实验必须仅监听本机")

    def stop(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
            self.process = None
        for log in (self._stdout_log, self.server_log):
            if log is not None:
                log.close()
        self._stdout_log = self.server_log = None

    def _request(self, label, path, body, auth, expected):
        connection = http.client.HTTPConnection(self.url.hostname, self.url.port, timeout=10)
        sent = []
        original_send = connection.send

        def send(data):
            # request 的 body 明确为 bytes；这里记录 HTTPConnection 实际交给 send 的字节。
            check(isinstance(data, (bytes, bytearray, memoryview)), "HTTP 采集遇到非字节输入")
            original_send(data)
            sent.append(bytes(data))

        connection.send = send
        self.http_count += 1
        label = f"http-{self.http_count}-{label}"
        try:
            self.capture(label + "-request-body", body, "http_request_body")
            connection.request("POST", path, body=body,
                               headers={"Authorization": "Bearer " + auth,
                                        "Content-Type": "application/json"})
            response = connection.getresponse()
            self.capture(label + "-metadata", _json_bytes({
                "version": response.version, "status": response.status,
                "reason": response.reason, "headers": response.getheaders()}),
                "http_response_metadata")
            payload = response.read(2 * 1024 * 1024)
            self.capture(label + "-body", payload, "http_response")
            statuses = expected if isinstance(expected, tuple) else (expected,)
            check(response.status in statuses,
                  f"HTTP 状态 {response.status} 不符合预期；原响应已保留")
            try:
                reply = json.loads(payload)
            except (ValueError, UnicodeError):
                raise AssertionError("HTTP 响应不是有效 JSON；原响应已保留") from None
            return reply["result"] if reply["ok"] else reply["error"]
        finally:
            self.capture(label + "-request", b"".join(sent), "http_request")
            connection.close()

    def http(self, device, operation, fields, *, expected=200, raw=None, token=None):
        body = json.dumps(fields).encode() if raw is None else raw
        auth = self.tokens[device] if token is None else token
        return self._request(operation, "/v1/" + operation, body, auth, expected)

    def control(self, action, *, expected=200, **fields):
        return self._request("control-" + action, "/_test/control",
                             json.dumps({"action": action, **fields}).encode(),
                             self.controller_token, expected)

    def collect_server(self, label):
        """全表只读观察与 SQLite 真实备份比对；不包含任何客户端目录。"""
        start = len(self.surfaces)
        source = self.directory / "relay.sqlite"
        backup_path = self._surface(label + "-backup", "server_backup", ".sqlite")
        with closing(_readonly(source)) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            try:
                contents = _database_contents(db)
                with closing(sqlite3.connect(backup_path, isolation_level=None)) as backup:
                    db.backup(backup)
                self.capture(label + "-database", source.read_bytes(), "server_database")
                for suffix, kind in (("-wal", "server_wal"), ("-shm", "server_shm")):
                    sidecar = source.with_name(source.name + suffix)
                    if sidecar.exists():
                        self.capture(label + suffix, sidecar.read_bytes(), kind)
                db.commit()
            except BaseException:
                db.rollback()
                raise
        with closing(_readonly(backup_path)) as backup:
            backup.execute("PRAGMA query_only=ON")
            backup.execute("BEGIN")
            try:
                backup_contents = _database_contents(backup)
                backup.commit()
            except BaseException:
                backup.rollback()
                raise
        self.capture(label + "-database-dump", _json_bytes(contents), "server_database_dump")
        self.capture(label + "-backup-dump", _json_bytes(backup_contents), "server_backup_dump")
        check(contents == backup_contents, "SQLite 备份的 schema 或完整字段值不同")
        self.capture(label + "-fixture", self.fixture_path.read_bytes(), "server_fixture")
        if self.receipt_key.exists():
            self.capture(label + "-service-key", self.receipt_key.read_bytes(), "service_key")
        files = []
        for item in self.surfaces[start:]:
            data = Path(item["path"]).read_bytes()
            files.append({**item, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        return {"files": files, "table_counts": {name: len(table["rows"])
                for name, table in contents["tables"].items()},
                "table_columns": {name: [column[1] for column in table["columns"]]
                for name, table in contents["tables"].items()},
                "backup_matches_all_tables": True, "source_transaction": "explicit_readonly",
                "backup_method": "sqlite3.Connection.backup",
                "scope": "synthetic_local_service_database_copy_not_deployment_restore"}
