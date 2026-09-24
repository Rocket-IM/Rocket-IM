"""真实Worker验证互通装置总预算；不加载SDK或修改单请求超时。"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools/platform_release"))
from node_pack import node_binary


class NodeTimeoutTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        shutil.copy2(ROOT / "tests/consumers/node-interop/interop.mjs", self.work)
        (self.work / "package.json").write_text('{"type":"module"}')
        (self.work / "dist").mkdir()

    def run_worker(self, budget, body):
        (self.work / "dist/interop.js").write_text("export async function runInterop() { " + body + " }")
        environment = {k: v for k, v in os.environ.items()
                       if k not in {"NODE_OPTIONS", "NODE_PATH", "ROCKET_INTEROP_TIMEOUT_SECONDS"}}
        if budget is not None:
            environment["ROCKET_INTEROP_TIMEOUT_SECONDS"] = budget
        result = subprocess.run([node_binary(), self.work / "interop.mjs"], cwd=self.work,
                                env=environment, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.stderr, "")
        return result.returncode, json.loads(result.stdout)

    def test_default_and_explicit_budget_allow_normal_worker_shutdown(self):
        for budget in (None, "10", "1800"):
            code, result = self.run_worker(budget, "return { shutdown: true };")
            self.assertEqual((code, result["status"]), (0, "PASS"))
            self.assertEqual(result["worker"]["exitCode"], 0)
            self.assertTrue(result["worker"]["shutdown"])

    def test_invalid_budgets_fail_before_starting_worker_without_echoing_input(self):
        for budget in ("9", "3601", "10.5", "NaN", "", "secret-not-logged"):
            code, result = self.run_worker(budget, "return { shutdown: true };")
            self.assertEqual((code, result["status"]), (1, "FAIL"))
            self.assertNotIn("worker", result)
            self.assertEqual(result["error"], "runtime_or_worker_start_failed")
            self.assertNotIn("secret-not-logged", json.dumps(result))

    def test_explicit_budget_terminates_a_stalled_worker(self):
        code, result = self.run_worker("10", "await new Promise(resolve => setTimeout(resolve, 60000)); return { shutdown: true };")
        self.assertEqual((code, result["status"], result["error"]), (1, "FAIL", "worker_timeout"))
        self.assertFalse(result["worker"]["shutdown"])
        self.assertNotEqual(result["worker"]["exitCode"], 0)

    def test_cli_rejects_out_of_range_budget_before_build_or_runtime(self):
        for budget in ("9", "3601", "10.5"):
            result = subprocess.run([sys.executable, "-B", ROOT / "tools/platform_release/interop_node.py",
                                     "--node-timeout-seconds", budget], cwd=ROOT,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertIn("--node-timeout-seconds", result.stderr)


if __name__ == "__main__":
    unittest.main()
