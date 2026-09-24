"""M02 探针解析与子进程装置回归；替身结果不作为实际加密调用证据。"""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from .retry_fixture import RetryLab


def probe(calls="0", **changes):
    return json.dumps({"probe": "wire_send_create_message", "version": 1,
                       "calls": calls, **changes}) + "\n"


class FakeProcess:
    def __init__(self, stderr="", *, returncode=0, stdout=None, pid=7311, timeout=False):
        self.stderr = stderr
        self.stdout = stdout if stdout is not None else json.dumps({"ok": True, "result": {"saved": True}})
        self.pid, self.returncode = pid, returncode
        self.timeout, self.killed, self.closed = timeout, False, False
        self.communications, self.waits = [], 0

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.closed = True
        self.wait()

    def communicate(self, data=None, timeout=None):
        self.communications.append((data, timeout))
        if self.timeout and not self.killed:
            raise subprocess.TimeoutExpired("synthetic-cli", timeout)
        return self.stdout, self.stderr

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self):
        self.waits += 1
        return self.returncode


class RetryFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rim-retry-fixture-")
        self.directory = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def lab(self, enabled=True):
        return RetryLab("unused-rust", self.directory / "lab", probe_enabled=enabled)

    def invoke(self, lab, process, operation="wire_send", **options):
        with patch("network_poc.retry_fixture.subprocess.Popen", return_value=process) as launch:
            result = lab.rust("a1", operation, **options)
        return result, launch

    def assert_invalid_probe(self, stderr):
        lab, process = self.lab(), FakeProcess(stderr)
        with self.assertRaises(AssertionError):
            self.invoke(lab, process)
        self.assertEqual(lab.process_count, 1)
        self.assertEqual(lab.encryption_observations[0]["calls"], None)
        self.assertEqual(lab.encryption_observations[0]["measurement"], "NOT_INSTRUMENTED")
        self.assertTrue(process.closed)

    def test_measured_calls_capture_pid_and_only_safe_metadata(self):
        lab, process = self.lab(), FakeProcess(probe("1"), pid=9012)
        result, launch = self.invoke(lab, process, payload="synthetic-secret")
        self.assertEqual(result, {"saved": True})
        self.assertEqual(lab.encryption_observations, [{"device": "a1", "operation": "wire_send",
                         "pid": 9012, "exit_code": 0, "measurement": "measured", "calls": "1"}])
        self.assertNotIn("synthetic-secret", json.dumps(lab.encryption_observations))
        self.assertEqual(lab.process_count, 1)
        self.assertEqual(launch.call_args.args, (["unused-rust"],))
        self.assertEqual(launch.call_args.kwargs, {"stdin": subprocess.PIPE, "stdout": subprocess.PIPE,
                                                 "stderr": subprocess.PIPE, "text": True})
        request, timeout = process.communications[0]
        self.assertEqual(timeout, 30)
        self.assertEqual(json.loads(request), {"directory": str(lab.directory / "a1"),
                         "service": lab.service, "account": "alice", "device": "a1",
                         "operation": "wire_send", "payload": "synthetic-secret"})
        self.assertTrue(process.closed)

    def test_each_call_launches_new_process_and_keeps_its_pid(self):
        lab = self.lab()
        for pid, calls in ((7312, "1"), (7313, "0")):
            self.invoke(lab, FakeProcess(probe(calls), pid=pid))
        self.assertEqual(lab.process_count, 2)
        self.assertEqual([item["pid"] for item in lab.encryption_observations], [7312, 7313])
        self.assertEqual([item["calls"] for item in lab.encryption_observations], ["1", "0"])

    def test_disabled_probe_is_explicitly_unmeasured(self):
        lab = self.lab(False)
        self.invoke(lab, FakeProcess(), operation="wire_inspect")
        self.assertEqual(lab.encryption_observations[0]["measurement"], "NOT_INSTRUMENTED")
        self.assertIsNone(lab.encryption_observations[0]["calls"])

    def test_disabled_probe_rejects_any_stderr(self):
        for stderr in (probe(), " ", "\n", "unexpected diagnostic"):
            with self.subTest(stderr=stderr), self.assertRaises(AssertionError):
                self.invoke(self.lab(False), FakeProcess(stderr))

    def test_missing_probe_never_becomes_zero(self):
        for stderr in ("", "\n", " "):
            with self.subTest(stderr=stderr):
                self.assert_invalid_probe(stderr)

    def test_malformed_json_and_nonobject_are_rejected(self):
        for stderr in ("{", "null", "[]", "true", "1", '"record"'):
            with self.subTest(stderr=stderr):
                self.assert_invalid_probe(stderr)

    def test_repeated_keys_are_rejected_even_when_values_match(self):
        for key, value in (("probe", '"wire_send_create_message"'), ("version", "1"), ("calls", '"0"')):
            with self.subTest(key=key):
                self.assert_invalid_probe(probe().rstrip()[:-1] + f',"{key}":{value}' + "}\n")

    def test_missing_and_extra_fields_are_rejected(self):
        for key in ("probe", "version", "calls"):
            record = json.loads(probe())
            record.pop(key)
            with self.subTest(key=key):
                self.assert_invalid_probe(json.dumps(record))
        self.assert_invalid_probe(probe(extra="unexpected"))

    def test_wrong_probe_name_or_version_is_rejected(self):
        self.assert_invalid_probe(probe(probe="different_probe"))
        for version in (0, 2, "1", True, 1.0, None):
            with self.subTest(version=version):
                self.assert_invalid_probe(probe(version=version))

    def test_multiline_output_is_rejected(self):
        for stderr in (probe() + probe(), "\n" + probe(), probe() + "\n", probe() + "diagnostic\n"):
            with self.subTest(stderr=stderr):
                self.assert_invalid_probe(stderr)

    def test_calls_are_canonical_ascii_u64_strings(self):
        for calls in ("", "-1", "+1", "00", "01", "1.0", "1e0", " 1", "1 ", "١", "１",
                      "1\n", 0, 1, 1.0, True, None, "18446744073709551616", "9" * 21):
            with self.subTest(calls=calls):
                self.assert_invalid_probe(probe(calls))
        for calls in ("0", "1", "18446744073709551615"):
            with self.subTest(calls=calls):
                lab = self.lab()
                self.invoke(lab, FakeProcess(probe(calls)))
                self.assertEqual(lab.encryption_observations[0]["calls"], calls)

    def test_non_send_operation_must_measure_zero(self):
        lab = self.lab()
        self.invoke(lab, FakeProcess(probe()), operation="wire_inspect")
        self.assertEqual(lab.encryption_observations[-1]["calls"], "0")
        with self.assertRaises(AssertionError):
            self.invoke(lab, FakeProcess(probe("1")), operation="wire_inspect")

    def test_business_error_preserves_error_result_and_observation(self):
        error = {"code": "attempt_missing", "message": "synthetic error"}
        process = FakeProcess(probe(), returncode=1, stdout=json.dumps({"ok": False, "error": error}))
        lab = self.lab()
        result, _ = self.invoke(lab, process, expected_exit=1)
        self.assertEqual(result, error)
        self.assertEqual(lab.encryption_observations[0]["exit_code"], 1)
        self.assertEqual(lab.encryption_observations[0]["calls"], "0")

    def test_unexpected_exit_fails_without_dumping_stdout(self):
        lab = self.lab()
        process = FakeProcess(probe(), returncode=1, stdout="synthetic-secret-response")
        with self.assertRaises(AssertionError) as failure:
            self.invoke(lab, process)
        self.assertNotIn(process.stdout, str(failure.exception))
        self.assertEqual(lab.encryption_observations[0]["exit_code"], 1)

    def test_invalid_response_or_success_status_cannot_pass(self):
        for stdout in ("synthetic-secret-response", "null", "[]", '{}', '{"ok":1,"result":{}}',
                       '{"ok":false,"error":{}}', '{"ok":true}'):
            with self.subTest(stdout=stdout), self.assertRaises(AssertionError) as failure:
                self.invoke(self.lab(), FakeProcess(probe(), stdout=stdout))
            self.assertNotIn("synthetic-secret-response", str(failure.exception))

    def test_unsupported_expected_exit_is_rejected_before_launch(self):
        lab = self.lab()
        for expected in (83, 84, 85, -9, 2, True, "0"):
            with self.subTest(expected=expected), patch("network_poc.retry_fixture.subprocess.Popen") as launch:
                with self.assertRaises(AssertionError):
                    lab.rust("a1", "wire_send", expected_exit=expected)
                launch.assert_not_called()
        self.assertEqual(lab.process_count, 0)
        self.assertEqual(lab.encryption_observations, [])

    def test_timeout_kills_reaps_and_never_fabricates_measurement(self):
        lab, process = self.lab(), FakeProcess(probe("1"), timeout=True)
        with self.assertRaises(TimeoutError) as failure:
            self.invoke(lab, process, payload="synthetic-secret")
        self.assertNotIn("synthetic-secret", str(failure.exception))
        self.assertTrue(process.killed and process.closed)
        self.assertEqual(process.waits, 1)
        self.assertEqual(len(process.communications), 2)
        self.assertEqual(process.communications[1], (None, None))
        self.assertEqual(lab.encryption_observations, [{"device": "a1", "operation": "wire_send",
                         "pid": 7311, "exit_code": -9, "measurement": "NOT_INSTRUMENTED", "calls": None}])


if __name__ == "__main__":
    unittest.main()
