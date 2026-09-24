"""测试控制端诊断仅保留当前进程的固定元数据，不泄漏任意日志正文。"""
import unittest

from android_runtime import AndroidRuntimes


class AndroidDiagnosticsTests(unittest.TestCase):
    def test_known_transport_and_outer_failure_are_preserved(self):
        output = ("1790000001.125 4254 4287 E RocketInterop: transport_failed: GET next response_status "
                  "unexpected_eof IOException EOFException cmd000279\n"
                  "1790000001.126 4254 4287 E RocketInterop: harness_failed: IOException\n")
        events, discarded = AndroidRuntimes._harness_events(output, "4254", 1790000000)
        self.assertEqual(discarded, 0)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["phase"], "response_status")
        self.assertEqual(events[0]["last_command_id"], "cmd000279")
        self.assertEqual(events[0]["cause_type"], "EOFException")
        self.assertEqual(events[1]["event"], "harness_failed")

    def test_other_process_old_event_and_unknown_text_are_discarded(self):
        output = ("1790000001.125 9999 4287 E RocketInterop: harness_failed: IOException\n"
                  "1789999999.125 4254 4287 E RocketInterop: harness_failed: IOException\n"
                  "1790000001.125 4254 4287 E RocketInterop: secret payload\n"
                  "1790000001.125 4254 4287 E RocketInterop: harness_failed: UntrustedException\n")
        self.assertEqual(AndroidRuntimes._harness_events(output, "4254", 1790000000), ([], 4))

    def test_extra_text_invalid_action_and_cause_are_not_logged(self):
        prefix = "1790000001.125 4254 4287 E RocketInterop: transport_failed: "
        output = (prefix + "GET next read_body eof IOException none cmd000279 private-message\n"
                  + prefix + "GET private-path read_body eof IOException none cmd000279\n"
                  + prefix + "GET next read_body eof IOException PrivateException cmd000279\n")
        self.assertEqual(AndroidRuntimes._harness_events(output, "4254", 1790000000), ([], 3))


if __name__ == "__main__":
    unittest.main()
