"""Behavioral probes for missing coverage and unsafe dependency reports."""

import copy
import importlib.util
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


MODULE = Path(__file__).parents[1] / "scripts/ci/check-dependencies.py"
spec = importlib.util.spec_from_file_location("dependency_gate", MODULE)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class DependencyGateTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 2, 18, tzinfo=timezone.utc)
        self.lock = {"packages": [], "packages-dev": [{"name": "vendor/test", "version": "v1.2.3"}]}
        self.report = {
            "SchemaVersion": 2,
            "ArtifactName": "composer.lock",
            "ArtifactType": "filesystem",
            "Results": [{
                "Target": "composer.lock", "Type": "composer", "Class": "lang-pkgs",
                "Packages": [{"Name": "vendor/test", "Version": "v1.2.3"}],
                "Vulnerabilities": [],
            }],
        }
        self.metadata = {
            "Version": 2,
            "UpdatedAt": self.now.isoformat(),
            "DownloadedAt": self.now.isoformat(),
        }

    def check(self):
        return gate.check(self.report, self.lock, self.metadata, self.now)

    def test_clean_complete_scan_is_accepted(self):
        self.assertEqual(self.check(), 1)

    def test_development_dependencies_cannot_be_silently_excluded(self):
        self.report["Results"] = []
        with self.assertRaises(gate.GateError):
            self.check()

    def test_missing_package_is_rejected(self):
        self.report["Results"][0]["Packages"] = []
        with self.assertRaises(gate.GateError):
            self.check()

    def test_wrong_version_is_rejected(self):
        self.report["Results"][0]["Packages"][0]["Version"] = "v1.2.4"
        with self.assertRaises(gate.GateError):
            self.check()

    def test_wrong_target_or_schema_is_rejected(self):
        for field, value in (("ArtifactName", "other.lock"), ("SchemaVersion", 3)):
            with self.subTest(field=field):
                report = copy.deepcopy(self.report)
                report[field] = value
                with self.assertRaises(gate.GateError):
                    gate.check(report, self.lock, self.metadata, self.now)

    def test_high_and_critical_findings_block_even_without_a_fix(self):
        for severity in ("HIGH", "CRITICAL"):
            for fix in ("", "v1.2.4"):
                with self.subTest(severity=severity, fix=fix):
                    self.report["Results"][0]["Vulnerabilities"] = [{
                        "VulnerabilityID": "CVE-2026-0000", "Severity": severity,
                        "FixedVersion": fix,
                    }]
                    with self.assertRaises(gate.GateError):
                        self.check()

    def test_low_findings_do_not_block(self):
        self.report["Results"][0]["Vulnerabilities"] = [{"Severity": "LOW"}]
        self.assertEqual(self.check(), 1)

    def test_unknown_severity_or_malformed_findings_require_triage(self):
        for findings in ([{"Severity": "UNKNOWN"}], None, "invalid", [None]):
            with self.subTest(findings=findings):
                self.report["Results"][0]["Vulnerabilities"] = findings
                with self.assertRaises(gate.GateError):
                    self.check()

    def test_old_database_and_future_timestamps_are_rejected(self):
        for field, delta in (("UpdatedAt", -49), ("DownloadedAt", -25), ("UpdatedAt", 1)):
            with self.subTest(field=field, delta=delta):
                metadata = copy.deepcopy(self.metadata)
                metadata[field] = (self.now + timedelta(hours=delta)).isoformat()
                with self.assertRaises(gate.GateError):
                    gate.check(self.report, self.lock, metadata, self.now)

    def test_missing_database_metadata_is_rejected(self):
        with self.assertRaises(gate.GateError):
            gate.check(self.report, self.lock, {}, self.now)

    def test_empty_lockfile_and_duplicate_target_are_rejected(self):
        with self.assertRaises(gate.GateError):
            gate.check(self.report, {"packages": [], "packages-dev": []}, self.metadata, self.now)
        self.report["Results"].append(copy.deepcopy(self.report["Results"][0]))
        with self.assertRaises(gate.GateError):
            self.check()


if __name__ == "__main__":
    unittest.main()
