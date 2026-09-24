"""M11.c 启动装置回归；替身只验证参数与隔离，不作为联合到期证据。"""

from contextlib import redirect_stderr
from io import StringIO
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import expiration_relay as relay

sys.path.insert(0, str(relay.ROOT / "tests/interop"))
from network_poc.fixture import NetworkLab


class ExpirationHarnessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rim-expiration-harness-")
        self.directory = Path(self.temporary.name).resolve()
        self.clock_path = self.directory / "clock-ms.txt"
        self.write_clock(b"1800000000000\n")
        self.original = (sys.argv, relay.messages.RETENTION_MS, relay.messages.now_ms,
                         relay.synchronization.now_ms, relay.storage.now_ms, relay.storage.RETENTION_MS)

    def tearDown(self):
        self.assertEqual((sys.argv, relay.messages.RETENTION_MS, relay.messages.now_ms,
                          relay.synchronization.now_ms, relay.storage.now_ms, relay.storage.RETENTION_MS),
                         self.original)
        self.temporary.cleanup()

    def write_clock(self, raw):
        self.clock_path.write_bytes(raw)
        self.clock_path.chmod(0o600)

    def arguments(self, *options):
        return ["--test-retention-ms", "2000", "--enable-test-controls",
                "--database", str(self.directory / "relay.sqlite"),
                "--fixture", str(self.directory / "fixture.json"), *options]

    def clock_arguments(self):
        return self.arguments("--test-clock-file", str(self.clock_path))

    def assert_rejected(self, arguments):
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as failure:
            relay.prepare(arguments)
        self.assertEqual(failure.exception.code, 2)

    def test_requires_explicit_test_controls_and_retention(self):
        self.assert_rejected(["--test-retention-ms", "2000"])
        self.assert_rejected(["--test-retention-ms", "2000", "--enable-test-control"])
        self.assert_rejected(["--enable-test-controls"])

    def test_retention_is_canonical_positive_and_bounded(self):
        for value in ("0", "-1", "+1", "01", "1.0", " 1", "1 ", "١", "1e3",
                      str(relay.MAX_RETENTION_MS + 1), "9" * 100):
            with self.subTest(value=value):
                self.assert_rejected(["--test-retention-ms", value, "--enable-test-controls"])
        for value in (1, relay.MAX_RETENTION_MS):
            with self.subTest(value=value):
                config = relay.prepare(["--test-retention-ms=" + str(value), "--enable-test-controls"])
                self.assertEqual(config.retention_ms, value)

    def test_repeated_test_flags_are_rejected(self):
        self.assert_rejected(self.arguments("--test-retention-ms=3000"))
        self.assert_rejected(self.clock_arguments() + ["--test-clock-file=" + str(self.clock_path)])

    def test_prepare_only_removes_its_flags_and_does_not_mutate_globals(self):
        arguments = self.clock_arguments() + ["--unknown-original-option", "value"]
        config = relay.prepare(arguments)
        self.assertEqual(config.arguments, tuple(self.arguments()[2:] + ["--unknown-original-option", "value"]))
        self.assertEqual(config.clock(), 1800000000000)
        self.assertEqual(relay.messages.RETENTION_MS, self.original[1])
        self.assertIs(relay.messages.now_ms, self.original[2])
        self.assertIs(relay.synchronization.now_ms, self.original[3])

    def test_default_clock_remains_original_and_original_parser_receives_arguments(self):
        def original_main():
            self.assertEqual(relay.messages.RETENTION_MS, 2000)
            self.assertEqual(relay.storage.RETENTION_MS, self.original[5])
            self.assertIs(relay.messages.now_ms, self.original[2])
            self.assertIs(relay.synchronization.now_ms, self.original[3])
            self.assertIs(relay.storage.now_ms, self.original[4])
            self.assertEqual(sys.argv[1:], self.arguments()[2:])
            return "original-server-result"

        with patch.object(relay.server, "main", side_effect=original_main) as main:
            self.assertEqual(relay.main(self.arguments()), "original-server-result")
        main.assert_called_once_with()

    def test_one_file_clock_injects_both_modules_and_reads_updated_value(self):
        def original_main():
            self.assertIs(relay.messages.now_ms, relay.synchronization.now_ms)
            self.assertIs(relay.storage.now_ms, self.original[4])
            self.assertEqual(relay.messages.now_ms(), 1800000000000)
            replacement = self.directory / "next-clock.txt"
            replacement.write_text("1800000002000")
            replacement.chmod(0o600)
            replacement.replace(self.clock_path)
            self.assertEqual(relay.messages.now_ms(), 1800000002000)
            self.assertEqual(relay.synchronization.now_ms(), 1800000002000)

        with patch.object(relay.server, "main", side_effect=original_main):
            relay.main(self.clock_arguments())

    def test_startup_failure_restores_original_globals(self):
        with patch.object(relay.server, "main", side_effect=RuntimeError("synthetic startup failure")):
            with self.assertRaisesRegex(RuntimeError, "synthetic startup failure"):
                relay.main(self.clock_arguments())

    def test_clock_accepts_u64_bounds_and_single_final_newline(self):
        clock = relay.FileClock(self.clock_path)
        for value in (0, relay.MAX_CLOCK_MS):
            for ending in (b"", b"\n"):
                with self.subTest(value=value, ending=ending):
                    self.write_clock(str(value).encode() + ending)
                    self.assertEqual(clock(), value)

    def test_clock_rejects_malformed_or_large_content(self):
        invalid = (b"", b" 1", b"1 ", b"01", b"+1", b"-1", b"1.0", b"1\n\n", b"1\r\n",
                   b"1\x00", "١".encode(), str(relay.MAX_CLOCK_MS + 1).encode(), b"1" * 100)
        for raw in invalid:
            with self.subTest(raw=raw):
                self.write_clock(raw)
                self.assert_rejected(self.clock_arguments())

    def test_clock_rejects_relative_missing_directory_and_traversal_paths(self):
        paths = ("clock-ms.txt", self.directory / "missing", self.directory,
                 str(self.directory / ".." / self.directory.name / "clock-ms.txt"))
        for path in paths:
            with self.subTest(path=path):
                self.assert_rejected(self.arguments("--test-clock-file", str(path)))

    def test_clock_rejects_symbolic_links_and_hard_links(self):
        symlink = self.directory / "linked-clock"
        symlink.symlink_to(self.clock_path)
        linked_directory = self.directory / "linked-directory"
        linked_directory.symlink_to(self.directory, target_is_directory=True)
        for path in (symlink, linked_directory / self.clock_path.name):
            with self.subTest(path=path):
                self.assert_rejected(self.arguments("--test-clock-file", str(path)))
        hardlink = self.directory / "hard-clock"
        os.link(self.clock_path, hardlink)
        self.assert_rejected(self.clock_arguments())

    def test_clock_rejects_shared_write_and_other_owner(self):
        for mode in (0o620, 0o602):
            with self.subTest(mode=mode):
                self.clock_path.chmod(mode)
                self.assert_rejected(self.clock_arguments())
        self.clock_path.chmod(0o600)
        with patch.object(relay.os, "getuid", return_value=os.getuid() + 1):
            self.assert_rejected(self.clock_arguments())

    def test_clock_revalidates_file_after_configuration(self):
        config = relay.prepare(self.clock_arguments())
        self.write_clock(b"bad")
        with self.assertRaises(ValueError):
            config.clock()
        self.clock_path.unlink()
        self.clock_path.symlink_to(self.directory / "missing")
        with self.assertRaises(OSError):
            config.clock()

    def test_network_lab_default_and_custom_launch_arguments_survive_restart(self):
        for options in ({}, {"relay_entrypoint": Path(relay.__file__).resolve(),
                             "relay_args": ["--test-retention-ms", "2000"]}):
            with self.subTest(options=options):
                lab = NetworkLab("unused-rust", self.directory / "lab", **options)
                lab.fixture_path = lab.directory / "fixture.json"
                with patch("network_poc.fixture.subprocess.Popen") as process, patch(
                        "network_poc.fixture.selectors.DefaultSelector") as selector:
                    process.return_value.stdout.readline.return_value = '{"status":"ready","url":"http://127.0.0.1:1"}\n'
                    process.return_value.poll.return_value = 0
                    selector.return_value.__enter__.return_value.select.return_value = [True]
                    try:
                        lab.start()
                        lab.restart()
                    finally:
                        lab.stop()
                    commands = [call.args[0] for call in process.call_args_list]
                self.assertEqual(commands[0], commands[1])
                expected_entrypoint = options.get("relay_entrypoint", relay.ROOT / "poc/network-relay/server.py")
                self.assertEqual(commands[0][2], str(expected_entrypoint))
                self.assertEqual(commands[0][3:10], ["--database", str(lab.directory / "relay.sqlite"),
                                  "--fixture", str(lab.fixture_path), "--port", "0", "--enable-test-controls"])
                self.assertEqual(commands[0][10:], options.get("relay_args", []))


if __name__ == "__main__":
    unittest.main()
