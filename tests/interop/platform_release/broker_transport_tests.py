"""以真实TCP验证本机控制通道的关闭通知，避免固定长度POST复用已关闭连接。"""
import json
from pathlib import Path
import socket
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from platform_release.broker import Broker


class BrokerTransportTests(unittest.TestCase):
    def test_keep_alive_client_receives_close_and_cannot_pipeline_second_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            broker = Broker("transport-test", ["browser"], directory)
            try:
                body = json.dumps(dict(run_id="transport-test", endpoint_id="browser",
                                       sdk_version="0.1.0-stage0.1", platform="browser")).encode()
                request = (b"POST /interop/transport-test/browser/ready HTTP/1.1\r\n"
                           b"Host: 127.0.0.1\r\nConnection: keep-alive\r\n"
                           b"Content-Type: application/json\r\nContent-Length: "
                           + str(len(body)).encode() + b"\r\n\r\n" + body)
                with socket.create_connection(("127.0.0.1", broker.server.server_port), timeout=3) as client:
                    client.sendall(request + request)
                    chunks = []
                    while chunk := client.recv(4096):
                        chunks.append(chunk)
                wire = b"".join(chunks)
                headers, response = wire.split(b"\r\n\r\n", 1)
                self.assertTrue(headers.startswith(b"HTTP/1.0 200 "))
                self.assertIn(b"\r\nConnection: close", headers)
                self.assertEqual(json.loads(response), {"ok": True})
                self.assertEqual(wire.count(b"HTTP/1.0"), 1)
                self.assertEqual(list(broker.http_errors), [])
                events = [json.loads(line) for line in (Path(directory) / "control-events.jsonl").read_text().splitlines()]
                self.assertEqual(sum(e["event"] == "post_received" for e in events), 1)
                self.assertEqual(sum(e["event"] == "ack_written" for e in events), 1)
            finally:
                broker.close()


if __name__ == "__main__":
    unittest.main()
