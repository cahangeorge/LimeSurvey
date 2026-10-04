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
from unittest.mock import patch

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
        self.inventory = {"os_family": "debian", "os_version": "12",
                          "os": [["libc6", "1:2.36-9"]], "composer": {
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

    def test_independent_os_identity_is_required(self):
        for field in ("os_family", "os_version"):
            with self.subTest(field=field):
                self.setUp()
                del self.inventory[field]
                with self.assertRaises((gate.GateError, KeyError)):
                    self.check()

    def test_mixed_or_duplicate_os_results_block(self):
        for family in ("debian", "alpine", "ubuntu"):
            with self.subTest(family=family):
                self.setUp()
                extra = copy.deepcopy(self.report["Results"][0])
                extra["Type"] = family
                self.report["Results"].append(extra)
                with self.assertRaises(gate.GateError):
                    self.check()

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

    def test_os_epoch_and_sbom_ecosystem_are_bound(self):
        self.report["Results"][0]["Packages"][0]["Epoch"] = 1 if self.inventory["os_family"] == "alpine" else 0
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


class AlpineReleaseGateTests(ReleaseGateTests):
    """Run every existing identity/coverage/severity/CLI gate against Alpine too."""

    def setUp(self):
        super().setUp()
        self.inventory.update(os_family="alpine", os_version="3.24.2", os=[["musl", "1.2.6-r2"]])
        self.report["Metadata"]["OS"] = {"Family": "alpine", "Name": "3.24.2"}
        package = {"Name": "musl", "Version": "1.2.6-r2",
                   "Identifier": {"PURL": "pkg:apk/alpine/musl@1.2.6-r2?arch=aarch64&distro=3.24.2"}}
        self.report["Results"][0].update(Target="image (alpine 3.24.2)", Type="alpine", Packages=[package])
        self.sbom["components"][0] = {"name": "musl", "version": "1.2.6-r2", "purl": package["Identifier"]["PURL"]}

    def test_os_family_version_and_support_mismatches_block(self):
        for document, field, value in (
            ("inventory", "os_family", "debian"), ("inventory", "os_version", "3.23.4"),
            ("scan", "Family", "debian"), ("scan", "Name", "3.23.4"),
            ("scan", "Name", "3.24.1"), ("scan", "Name", "3.240.2"),
            ("scan", "Eosl", True), ("scan", "Name", "edge"),
        ):
            with self.subTest(document=document, field=field, value=value):
                self.setUp()
                target = self.inventory if document == "inventory" else self.report["Metadata"]["OS"]
                target[field] = value
                with self.assertRaises(gate.GateError):
                    self.check()

    def test_apk_release_revision_is_exact_and_not_debian_reconstructed(self):
        for replacement in ({"Version": "1.2.6-r1"}, {"Version": "1.2.6", "Release": "r2"},
                            {"Epoch": 1}, {"Release": "r2"}):
            with self.subTest(replacement=replacement):
                self.setUp()
                self.report["Results"][0]["Packages"][0].update(replacement)
                with self.assertRaises(gate.GateError):
                    self.check()


class InstalledInventoryTests(unittest.TestCase):
    def test_apk_records_preserve_revisions_and_virtual_packages(self):
        raw = "P:musl\nV:1.2.6-r2\nF:lib\nR:libc.so\nR:ld.so\n\nP:.extension-rundeps\nV:20261003.103515\nD:so:libc.so\n"
        self.assertEqual(gate.parse_apk_inventory(raw), [["musl", "1.2.6-r2"], [".extension-rundeps", "20261003.103515"]])

    def test_missing_malformed_or_duplicate_apk_records_fail_closed(self):
        for raw in ("", "P:musl\n", "V:1.2-r1\n", "P:musl\nV:\n", "P:musl\nV:1 2\n", "P:musl\nV:1-r0 ",
                    "P:musl\nP:other\nV:1-r0\n", "P:musl\nV:1-r0\nV:2-r0\n",
                    "P:musl\nV:1-r0\n\nP:musl\nV:1-r0\n", "P:musl\nV:1-r0\n\nP:bad\n"):
            with self.subTest(raw=raw), self.assertRaises(gate.GateError):
                gate.parse_apk_inventory(raw)

    def test_os_release_is_parsed_as_data_not_executed(self):
        self.assertEqual(gate.parse_os_release('NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.24.2\n'), ("alpine", "3.24.2"))
        self.assertEqual(gate.parse_os_release("ID='debian'\nVERSION_ID=\"12\"\n"), ("debian", "12"))
        for raw in ("ID=alpine\n", "VERSION_ID=3.24.2\n", "ID=alpine\nID=debian\nVERSION_ID=3.24.2\n",
                    'ID=alpine\nVERSION_ID="$(touch /tmp/invalid)"\n', 'ID=alpine\nVERSION_ID="3.24.2\n'):
            with self.subTest(raw=raw), self.assertRaises(gate.GateError):
                gate.parse_os_release(raw)

    def test_only_explicit_supported_runtime_releases_are_allowed(self):
        for family, version in (("alpine", "edge"), ("alpine", "3.23.4"), ("alpine", "3.240"),
                                ("debian", "13"), ("ubuntu", "24.04")):
            with self.subTest(family=family, version=version), self.assertRaises(gate.GateError):
                gate.supported_os(family, version)

    def test_extraction_uses_tested_image_and_fails_without_os_fallback(self):
        image = "sha256:" + "b" * 64
        for family, version, database in (("alpine", "3.24.2", "P:musl\nV:1.2.6-r2\n"),
                                         ("debian", "12", "ii \tlibc6\t1:2.36-9\n")):
            def read(command, **kwargs):
                self.assertIn("--network", command)
                self.assertIn("none", command)
                self.assertEqual(command[command.index("--entrypoint") + 2], image)
                if command[-1] == "/etc/os-release": return f'ID={family}\nVERSION_ID="{version}"\n'
                if command[-1] == "/lib/apk/db/installed" or "dpkg-query" in command: return database
                if command[-1] == "echo PHP_VERSION;": return "8.3.35"
                return json.dumps({gate.ROOT_TARGET: [["vendor/runtime", "1.2.3"]]})
            with self.subTest(family=family), patch.object(gate.subprocess, "check_output", side_effect=read):
                result = gate.extract_inventory(image)
                self.assertEqual((result["os_family"], result["os_version"]), (family, version))
                self.assertEqual(len(result["os"]), 1)
        with patch.object(gate.subprocess, "check_output", side_effect=subprocess.CalledProcessError(1, "cat")) as reader:
            with self.assertRaises(subprocess.CalledProcessError): gate.extract_inventory(image)
            self.assertEqual(reader.call_count, 1)


if __name__ == "__main__":
    unittest.main()
