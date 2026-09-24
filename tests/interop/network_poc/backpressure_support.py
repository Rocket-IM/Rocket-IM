"""M12.e真实socket装置：100 Continue确认占槽，外部日志确认原线程释放。"""

import hashlib
import http.client
import json
import socket
import struct
import time

from .deletion_observer import relay_records
from .fixture import check


def record(lab, operation, **fields):
    lab.case_evidence.setdefault("trace", []).append({"operation": operation, **fields})


def events(lab):
    path = lab.directory / "backpressure.events.jsonl"
    # 只读取已完整换行的记录，避免与独立进程追加最后一行竞争。
    return [json.loads(line) for line in path.read_text().splitlines(keepends=True) if line.endswith("\n")]


def wait_events(lab, ports, stage, timeout=3, since_ns=0):
    deadline = time.monotonic() + timeout
    while True:
        found = [e for e in events(lab) if e["stage"] == stage and e["client_port"] in ports
                 and e["monotonic_ns"] >= since_ns]
        if set(e["client_port"] for e in found) == set(ports):
            return found
        check(lab.process.poll() is None, "Relay在等待线程证据时退出")
        check(time.monotonic() < deadline, "等待原线程事件超时: " + stage)
        time.sleep(0.005)


class HeldRequest:
    def __init__(self, lab, operation, fields):
        self.started_ns = time.monotonic_ns()
        self.body = json.dumps(fields).encode()
        self.socket = socket.create_connection((lab.url.hostname, lab.url.port), timeout=3)
        self.port = self.socket.getsockname()[1]
        self.reader = self.socket.makefile("rb", buffering=0)
        self.closed = False
        lab.http_count += 1
        try:
            headers = (f"POST /v1/{operation} HTTP/1.1\r\nHost: localhost\r\n"
                       f"Content-Length: {len(self.body)}\r\nContent-Type: application/json\r\n"
                       f"Authorization: Bearer {lab.tokens['a1']}\r\n"
                       "Expect: 100-continue\r\nConnection: close\r\n\r\n").encode()
            self.socket.sendall(headers)
            status = self.reader.readline(8192)
            check(status == b"HTTP/1.1 100 Continue\r\n", "未获得占槽后的100 Continue")
            check(self.reader.readline(8192) == b"\r\n", "100 Continue头不符")
            self.socket.sendall(self.body[:-1])
            self.admitted_ns = time.monotonic_ns()
        except BaseException:
            self.close()
            raise

    def evidence(self):
        return {"client_port": self.port, "interim_status": 100,
                "request_sha256": hashlib.sha256(self.body).hexdigest(),
                "body_bytes": len(self.body), "withheld_bytes": 1,
                "started_ns": self.started_ns, "admitted_ns": self.admitted_ns}

    def complete(self):
        self.socket.sendall(self.body[-1:])

    def response(self):
        response = http.client.HTTPResponse(self.socket)
        try:
            response.begin()
            return response.status, json.loads(response.read(2 * 1024 * 1024))
        finally:
            response.close()
            self.close()

    def truncate(self):
        self.socket.shutdown(socket.SHUT_WR)

    def reset(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        self.close()

    def assert_eof(self):
        check(self.socket.recv(1) == b"", "超时后原连接仍未结束")
        self.close()

    def close(self):
        if not self.closed:
            self.closed = True
            self.reader.close()
            self.socket.close()


def occupy(lab, operation, requests):
    held = []
    try:
        for fields in requests:
            held.append(HeldRequest(lab, operation, fields))
        ports = [request.port for request in held]
        check(len(held) == len(set(ports)) == 8, "必须是8条不同连接")
        since = held[0].started_ns
        entered = wait_events(lab, ports, "body_read_entered", since_ns=since)
        check(not any(e["stage"] == "worker_finished" and e["client_port"] in ports
                      and e["monotonic_ns"] >= since for e in events(lab)),
              "第9请求前已有占槽线程结束")
        record(lab, "eight_connections_admitted", connections=[h.evidence() for h in held], entered=entered)
        return held
    except BaseException:
        for request in held:
            request.close()
        raise


def reject_ninth(lab, packet, held, before):
    rejected = lab.submit(packet, expected=503)
    check(rejected["code"] == "resource_exhausted" and rejected["outcome"] == "not_recorded"
          and rejected["retry_after_ms"] == "1000", "第9请求背压契约不符")
    after = relay_records(lab)
    check(after == before, "背压请求或未完整正文产生了部分消息写入")
    check(not any(e["stage"] == "worker_finished" and e["client_port"] in [h.port for h in held]
                  and e["monotonic_ns"] >= held[0].started_ns
                  for e in events(lab)), "拒绝窗口没有保持8条在途请求")
    record(lab, "ninth_rejected", error=rejected, before=before, after=after)


def readmission(lab, packet):
    """恢复后再占8条只读请求，确认完整容量且未超释放；不重启进程。"""
    fields = {"service_id": lab.service, "conversation_id": "G1",
              "logical_message_id": "capacity_unknown", "attempt_id": "P1"}
    before = relay_records(lab)
    held = occupy(lab, "get_attempt", [fields] * 8)
    try:
        reject_ninth(lab, packet, held, before)
        for request in held:
            request.complete()
        replies = [request.response() for request in held]
        check(all(status == 200 and body["result"]["outcome"] == "not_found" for status, body in replies),
              "重新占满的8条原HTTP请求没有全部恢复")
        finished = wait_events(lab, [h.port for h in held], "worker_finished", since_ns=held[0].started_ns)
        check(relay_records(lab) == before, "只读恢复请求改变消息投影")
        record(lab, "full_capacity_recovered", finished=finished, response_count=len(replies),
               ninth_still_rejected=True, message_projection_unchanged=True)
    finally:
        for request in held:
            request.close()
