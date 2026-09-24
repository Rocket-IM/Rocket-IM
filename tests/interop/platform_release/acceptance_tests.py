"""显式互通验收清单仍须绑定实际通过的报告和不可变发布包。"""

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools/platform_release"))
import interop_apple_web as acceptance


class AcceptanceManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        output = self.root / "dist/current"
        output.mkdir(parents=True)
        self.manifest = output / "accepted.json"
        self.entries = []
        keys = {"swift": "archive_sha256", "browser": "archive_sha256",
                "kotlin": "aar_sha256", "flutter": "package_sha256"}
        for platform, key in keys.items():
            artifact = output / (platform + ".artifact")
            artifact.write_bytes((platform + " verified bytes").encode())
            report = output / (platform + ".json")
            result = {"status": "PASS", "run_id": platform, key: acceptance.sha(artifact)}
            report.write_text(json.dumps(result))
            self.entries.append({"platform": platform, "run_id": platform,
                                 "artifact": str(artifact.relative_to(self.root)),
                                 "sha256": acceptance.sha(artifact),
                                 "report": str(report.relative_to(self.root)),
                                 "report_sha256": acceptance.sha(report)})
        self.write_manifest()
        patches = patch.multiple(acceptance, ROOT=self.root, ACCEPTED=self.manifest, OUTPUT=output)
        patches.start()
        self.addCleanup(patches.stop)

    def write_manifest(self):
        self.manifest.write_text(json.dumps(self.entries))

    def rejects(self, code):
        with self.assertRaisesRegex(RuntimeError, "^" + code + "$"):
            acceptance.accepted_entries()

    def test_current_manifest_accepts_all_four_verified_packages(self):
        self.assertEqual(acceptance.accepted_entries(), self.entries)

    def test_changed_archive_is_rejected(self):
        (self.root / self.entries[0]["artifact"]).write_bytes(b"tampered")
        self.rejects("accepted_package_changed")

    def test_changed_report_is_rejected(self):
        (self.root / self.entries[0]["report"]).write_text("{}")
        self.rejects("accepted_report_changed")

    def test_failed_report_cannot_be_accepted_by_repinning_its_hash(self):
        entry = self.entries[0]
        report = self.root / entry["report"]
        result = json.loads(report.read_text())
        result["status"] = "FAIL"
        report.write_text(json.dumps(result))
        entry["report_sha256"] = acceptance.sha(report)
        self.write_manifest()
        self.rejects("accepted_package_not_verified")

    def test_explicit_manifest_requires_report_hash(self):
        self.entries[0].pop("report_sha256")
        self.write_manifest()
        self.rejects("explicit_acceptance_report_digest_required")

    def test_duplicate_platform_is_rejected(self):
        self.entries[0] = self.entries[1]
        self.write_manifest()
        self.rejects("invalid_accepted_package_set")

    def test_archive_outside_dist_is_rejected(self):
        artifact = self.root / "outside.artifact"
        artifact.write_bytes(b"outside")
        self.entries[0].update(artifact="outside.artifact", sha256=acceptance.sha(artifact))
        self.write_manifest()
        self.rejects("accepted_package_changed")

    def test_mobile_selection_does_not_require_unrelated_archives_or_reports(self):
        for entry in self.entries[:2]:
            (self.root / entry["artifact"]).unlink()
            (self.root / entry["report"]).unlink()
        self.assertEqual(acceptance.accepted_entries({"kotlin", "flutter"}), self.entries[2:])
        with self.assertRaises(FileNotFoundError):
            acceptance.accepted_entries()

    def test_only_mobile_manifest_is_accepted_for_mobile_scope(self):
        self.entries = self.entries[2:]
        self.write_manifest()
        self.assertEqual(acceptance.accepted_entries({"kotlin", "flutter"}), self.entries)
        self.rejects("invalid_accepted_package_set")

    def test_single_swift_manifest_is_accepted_by_actual_package_selector(self):
        self.entries = self.entries[:1]
        self.write_manifest()
        archive, entry = acceptance.accepted("swift")
        self.assertEqual(entry, self.entries[0])
        self.assertEqual(archive, self.root / entry["artifact"])
        self.rejects("invalid_accepted_package_set")

    def test_missing_required_mobile_platform_is_rejected(self):
        self.entries = self.entries[2:3]
        self.write_manifest()
        with self.assertRaisesRegex(RuntimeError, "invalid_accepted_package_set"):
            acceptance.accepted_entries({"kotlin", "flutter"})

    def test_duplicate_required_mobile_platform_is_rejected(self):
        self.entries.append(self.entries[2])
        self.write_manifest()
        with self.assertRaisesRegex(RuntimeError, "invalid_accepted_package_set"):
            acceptance.accepted_entries({"kotlin", "flutter"})

    def test_selected_archive_and_report_tampering_are_rejected(self):
        artifact = self.root / self.entries[2]["artifact"]
        original = artifact.read_bytes()
        artifact.write_bytes(b"tampered")
        with self.assertRaisesRegex(RuntimeError, "accepted_package_changed"):
            acceptance.accepted_entries({"kotlin", "flutter"})
        artifact.write_bytes(original)
        (self.root / self.entries[2]["report"]).write_text("{}")
        with self.assertRaisesRegex(RuntimeError, "accepted_report_changed"):
            acceptance.accepted_entries({"kotlin", "flutter"})

    def test_selected_failed_report_cannot_be_repinned(self):
        entry = self.entries[2]
        report = self.root / entry["report"]
        result = json.loads(report.read_text())
        result["status"] = "FAIL"
        report.write_text(json.dumps(result))
        entry["report_sha256"] = acceptance.sha(report)
        self.write_manifest()
        with self.assertRaisesRegex(RuntimeError, "accepted_package_not_verified"):
            acceptance.accepted_entries({"kotlin", "flutter"})

    def test_selected_report_digest_remains_required(self):
        self.entries[2].pop("report_sha256")
        self.write_manifest()
        with self.assertRaisesRegex(RuntimeError, "explicit_acceptance_report_digest_required"):
            acceptance.accepted_entries({"kotlin", "flutter"})

    def test_empty_or_unknown_selection_cannot_skip_validation(self):
        for selection in (set(), {"unknown"}):
            with self.assertRaisesRegex(ValueError, "invalid_accepted_platform_selection"):
                acceptance.accepted_entries(selection)


if __name__ == "__main__":
    unittest.main()
