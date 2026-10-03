"""Reject substituted artifacts, incomplete inventories and unsafe release evidence."""

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "release_gate", Path(__file__).parents[1] / "scripts/ci/release-artifact.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ReleaseGateTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 3, 8, tzinfo=timezone.utc)
        self.sha = "a" * 40
        self.config = "sha256:" + "b" * 64
        self.raw = json.dumps({"schemaVersion": 2, "mediaType": gate.MANIFEST_TYPES[0],
                               "config": {"digest": self.config}, "layers": [{"digest": "sha256:" + "c" * 64}]}).encode()
        self.digest = "sha256:" + hashlib.sha256(self.raw).hexdigest()
        self.ref = gate.IMAGE + "@" + self.digest
        labels = {"org.opencontainers.image.source": gate.SOURCE,
                  "org.opencontainers.image.revision": self.sha,
                  "io.omnestack.limesurvey.upstream-revision": gate.UPSTREAM,
                  "org.opencontainers.image.version": gate.VERSION}
        self.inspect = [{"Id": self.config, "Os": "linux", "Architecture": "arm64",
                         "RepoDigests": [self.ref], "Config": {"Labels": labels}}]
        self.inventory = {"os": [["libc6", "1:2.36-9"]], "composer": {
            "var/www/html/vendor/composer/installed.json": [["vendor/runtime", "v1.2.3"]],
            gate.PLUGIN_TARGET: [["robthree/twofactorauth", "1.6.5"]]}}
        self.report = {"SchemaVersion": 2, "ArtifactName": self.ref, "ArtifactType": "container_image",
                       "Trivy": {"Version": "0.75.0"},
                       "Metadata": {"ImageID": self.config, "RepoDigests": [self.ref],
                                    "OS": {"Family": "debian", "Name": "12.15"},
                                    "ImageConfig": {"architecture": "arm64", "os": "linux"}},
                       "Results": [{"Target": "image (debian 12)", "Class": "os-pkgs", "Type": "debian",
                                    "Packages": [{"Name": "libc6", "Version": "2.36", "Release": "9", "Epoch": 1,
                                                  "Identifier": {"PURL": "pkg:deb/debian/libc6@1%3A2.36-9?arch=arm64"}}]}]}
        for target, pairs in self.inventory["composer"].items():
            self.report["Results"].append({"Target": target, "Class": "lang-pkgs", "Type": "composer-vendor",
                                          "Packages": [{"Name": name, "Version": version.removeprefix("v"),
                                                        "Identifier": {"PURL": "pkg:composer/" + name + "@" + version.removeprefix("v")}}
                                                       for name, version in pairs]})
        self.db = {"Version": 2, "UpdatedAt": self.now.isoformat(), "DownloadedAt": self.now.isoformat()}
        self.sbom = {"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
                     "metadata": {"component": {"type": "container", "name": self.ref,
                                                "properties": [{"name": "aquasecurity:trivy:ImageID", "value": self.config}]}},
                     "components": [{"name": item["Name"], "version": item["Version"], "purl": item["Identifier"]["PURL"]}
                                    for result in self.report["Results"] for item in result["Packages"]]}

    def check(self):
        return gate.validate_image(self.raw, self.digest, self.inspect, self.report,
                                   self.inventory, self.db, self.sbom, self.sha, self.now)

    def test_complete_artifact_passes(self):
        self.assertEqual(self.check(), {"os_packages": 1, "composer_packages": 2})

    def test_digest_config_platform_or_source_substitution_blocks(self):
        for mutate in (
            lambda: setattr(self, "digest", "sha256:" + "0" * 64),
            lambda: self.inspect[0].update(Id="sha256:" + "0" * 64),
            lambda: self.inspect[0].update(Architecture="amd64"),
            lambda: self.inspect[0]["Config"]["Labels"].update({"org.opencontainers.image.revision": "d" * 40}),
            lambda: self.report["Metadata"].update(ImageID="sha256:" + "e" * 64),
            lambda: self.report.update(ArtifactName=gate.IMAGE + ":latest"),
        ):
            with self.subTest(mutation=mutate):
                self.setUp()
                mutate()
                with self.assertRaises(gate.GateError):
                    self.check()

    def test_multi_platform_index_is_not_the_tested_single_manifest(self):
        self.raw = json.dumps({"schemaVersion": 2, "manifests": []}).encode()
        self.digest = "sha256:" + hashlib.sha256(self.raw).hexdigest()
        with self.assertRaises(gate.GateError):
            self.check()

    def test_missing_os_root_or_plugin_coverage_blocks(self):
        for index in range(3):
            with self.subTest(index=index):
                self.setUp()
                self.report["Results"].pop(index)
                with self.assertRaises(gate.GateError):
                    self.check()

    def test_missing_or_substituted_package_version_blocks(self):
        for packages in ([], [{"Name": "vendor/runtime", "Version": "1.2.4"}]):
            self.report["Results"][1]["Packages"] = packages
            with self.assertRaises(gate.GateError):
                self.check()

    def test_high_critical_unknown_in_any_result_block_even_without_fix(self):
        for index in range(3):
            for severity in ("HIGH", "CRITICAL", "UNKNOWN"):
                with self.subTest(index=index, severity=severity):
                    self.setUp()
                    self.report["Results"][index]["Vulnerabilities"] = [{"Severity": severity, "FixedVersion": ""}]
                    with self.assertRaises(gate.GateError):
                        self.check()

    def test_low_medium_do_not_block(self):
        self.report["Results"][0]["Vulnerabilities"] = [{"Severity": "LOW"}, {"Severity": "MEDIUM"}]
        self.check()

    def test_debian_epoch_release_and_sbom_ecosystem_are_bound(self):
        self.report["Results"][0]["Packages"][0]["Epoch"] = 0
        with self.assertRaises(gate.GateError):
            self.check()
        self.setUp()
        self.sbom["components"][0]["purl"] = "pkg:composer/libc6@1%3A2.36-9"
        with self.assertRaises(gate.GateError):
            self.check()

    def test_stale_future_missing_db_or_eol_blocks(self):
        for field, delta in (("UpdatedAt", -49), ("DownloadedAt", -25), ("UpdatedAt", 1)):
            self.setUp()
            self.db[field] = (self.now + timedelta(hours=delta)).isoformat()
            with self.assertRaises(gate.GateError):
                self.check()
        self.setUp()
        self.report["Metadata"]["OS"]["Eosl"] = True
        with self.assertRaises(gate.GateError):
            self.check()

    def test_sbom_substitution_or_missing_package_blocks(self):
        for mutate in (lambda: self.sbom["metadata"]["component"].update(name="wrong"),
                       lambda: self.sbom["components"].pop(),
                       lambda: self.sbom["metadata"]["component"]["properties"][0].update(value="wrong")):
            self.setUp()
            mutate()
            with self.assertRaises(gate.GateError):
                self.check()

    def test_malformed_inventory_report_or_findings_blocks(self):
        for field, value in (("SchemaVersion", 3), ("Results", []), ("Metadata", None)):
            self.setUp()
            self.report[field] = value
            with self.assertRaises((gate.GateError, TypeError, AttributeError)):
                self.check()
        self.setUp()
        self.report["Results"][0]["Vulnerabilities"] = None
        with self.assertRaises(gate.GateError):
            self.check()

    def test_preflight_requires_main_current_sha_and_latest_successful_push(self):
        branch = {"commit": {"sha": self.sha}, "protected": True}
        run = {"id": 10, "run_attempt": 1, "head_sha": self.sha, "head_branch": "main",
               "event": "push", "status": "completed", "conclusion": "success",
               "path": ".github/workflows/release-gate.yml", "repository": {"full_name": gate.REPOSITORY}}
        runs = {"workflow_runs": [run]}
        self.assertEqual(gate.preflight(branch, runs, self.sha, "refs/heads/main")["id"], 10)
        for ref in ("refs/heads/feature", "refs/pull/1/merge"):
            with self.assertRaises(gate.GateError):
                gate.preflight(branch, runs, self.sha, ref)
        failed = copy.deepcopy(run)
        failed.update(id=11, conclusion="failure")
        with self.assertRaises(gate.GateError):
            gate.preflight(branch, {"workflow_runs": [run, failed]}, self.sha, "refs/heads/main")
        branch["commit"]["sha"] = "f" * 40
        with self.assertRaises(gate.GateError):
            gate.preflight(branch, runs, self.sha, "refs/heads/main")

    def invoke_manifest(self, directory):
        self.db.update(UpdatedAt=datetime.now(timezone.utc).isoformat(),
                       DownloadedAt=datetime.now(timezone.utc).isoformat())
        for name, document in (("image.json", self.inspect), ("scan.json", self.report),
                               ("inventory.json", self.inventory), ("db.json", self.db),
                               ("sbom.cdx.json", self.sbom),
                               ("ci.json", {"id": 10, "run_attempt": 1, "head_sha": self.sha,
                                            "event": "push", "path": ".github/workflows/release-gate.yml"})):
            (directory / name).write_text(json.dumps(document))
        (directory / "registry-manifest.json").write_bytes(self.raw)
        return subprocess.run([sys.executable, str(spec.origin), "manifest", str(directory),
                               self.digest, self.sha, "20", "1"], capture_output=True, text=True, timeout=10)

    def test_unsafe_scan_never_creates_eligible_manifest(self):
        self.report["Results"][0]["Vulnerabilities"] = [{"Severity": "HIGH"}]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            result = self.invoke_manifest(directory)
            self.assertEqual(result.returncode, 1)
            self.assertIn("HIGH/CRITICAL", result.stderr)
            self.assertFalse((directory / "release.json").exists())

    def test_verified_manifest_keeps_staging_pending_and_production_hold(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            result = self.invoke_manifest(directory)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((directory / "release.json").read_text())
            self.assertEqual(manifest["image"], self.ref)
            self.assertEqual(manifest["staging"]["status"], "PENDING")
            self.assertEqual(manifest["production"]["status"], "HOLD")
            self.assertEqual(manifest["migrations"]["status"], "REVIEW_REQUIRED")
            self.assertIn("sbom.cdx.json", manifest["evidence_sha256"])


if __name__ == "__main__":
    unittest.main()
