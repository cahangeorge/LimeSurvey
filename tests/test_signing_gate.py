"""Reject release substitutions before and after the Cosign verification boundary."""

import base64
import copy
import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "signing_gate", Path(__file__).parents[1] / "scripts/ci/sign-release.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class SigningGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sha = "a" * 40
        self.run = 123
        self.attempt = 1
        self.raw = b'{"schemaVersion":2,"config":{"digest":"sha256:bbbb"}}'
        self.digest = "sha256:" + hashlib.sha256(self.raw).hexdigest()
        self.image = "ghcr.io/cahangeorge/limesurvey@" + self.digest
        self.sbom = {"bomFormat": "CycloneDX", "specVersion": "1.7", "components": [],
                     "metadata": {"component": {"type": "container", "name": self.image}}}
        self.files = {"registry-manifest.json": self.raw, "image.json": b'[]',
                      "inventory.json": b'{}', "scan.json": b'{}', "db.json": b'{}',
                      "sbom.cdx.json": json.dumps(self.sbom).encode(), "ci.json": b'{}'}
        for name, data in self.files.items():
            (self.root / name).write_bytes(data)
        self.release = {"schema_version": 1, "status": "ARTIFACT_VERIFIED",
                        "repository": "cahangeorge/LimeSurvey", "source_commit": self.sha,
                        "image": self.image, "digest": self.digest, "platform": "linux/arm64",
                        "scan": {"status": "PASS"}, "release_run": {"id": self.run, "attempt": 1},
                        "ci": {"head_sha": self.sha, "event": "push", "path": ".github/workflows/release-gate.yml"},
                        "evidence_sha256": {n: hashlib.sha256(d).hexdigest() for n, d in self.files.items()}}
        self.write_release()

    def write_release(self):
        (self.root / "release.json").write_text(json.dumps(self.release))

    def context(self):
        return gate.context(self.root, "php", self.sha, self.run, self.attempt)

    def envelope(self, predicate_type, predicate, digest=None):
        statement = {"_type": "https://in-toto.io/Statement/v0.1",
                     "subject": [{"name": self.image.split("@")[0],
                                  "digest": {"sha256": (digest or self.digest).split(":")[1]}}],
                     "predicateType": predicate_type, "predicate": predicate}
        return json.dumps({"payloadType": "application/vnd.in-toto+json",
                           "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
                           "signatures": [{"sig": "synthetic-verifier-output"}]})

    def outputs(self):
        c = self.context()
        signature = json.dumps([{"critical": {"image": {"docker-manifest-digest": self.digest},
                                              "identity": {"docker-reference": self.image},
                                              "type": "https://sigstore.dev/cosign/sign/v1"}}])
        return [signature, self.envelope(gate.PROVENANCE_TYPE, c["provenance"]),
                self.envelope(gate.SBOM_TYPE, self.sbom)]

    def verify(self):
        return gate.verify(self.root, "php", self.sha, self.run, self.attempt)

    def test_complete_evidence_binds_source_run_and_every_file(self):
        c = self.context()
        self.assertEqual(c["image"], self.image)
        self.assertEqual(c["identity"], "https://github.com/cahangeorge/LimeSurvey/.github/workflows/release.yml@refs/heads/main")
        dependencies = c["provenance"]["buildDefinition"]["resolvedDependencies"]
        self.assertEqual(dependencies[0]["digest"], {"gitCommit": self.sha})
        self.assertEqual(len(dependencies), len(self.files) + 2)
        self.assertTrue(c["provenance"]["runDetails"]["metadata"]["invocationId"].endswith("/123/attempts/1"))

    def test_changed_or_missing_evidence_blocks(self):
        for name in self.files:
            with self.subTest(file=name):
                (self.root / name).write_bytes(b'changed')
                with self.assertRaises(gate.GateError):
                    self.context()
                (self.root / name).write_bytes(self.files[name])
        (self.root / "scan.json").unlink()
        with self.assertRaises(OSError):
            self.context()

    def test_wrong_source_run_platform_scan_and_status_block(self):
        for key, value in [("source_commit", "b" * 40), ("release_run", {"id": 124, "attempt": 1}),
                           ("platform", "linux/amd64"), ("scan", {"status": "FAIL"}),
                           ("status", "ARTIFACT_UNVERIFIED"), ("repository", "another/repo"),
                           ("image", self.image.split("@")[0] + ":latest")]:
            with self.subTest(key=key):
                original = copy.deepcopy(self.release)
                self.release[key] = value
                self.write_release()
                with self.assertRaises(gate.GateError):
                    self.context()
                self.release = original

    def test_missing_required_hash_or_path_traversal_blocks(self):
        del self.release["evidence_sha256"]["scan.json"]
        self.write_release()
        with self.assertRaises(gate.GateError):
            self.context()
        self.release["evidence_sha256"]["scan.json"] = hashlib.sha256(b'{}').hexdigest()
        self.release["evidence_sha256"]["../outside.json"] = "b" * 64
        self.write_release()
        with self.assertRaises(gate.GateError):
            self.context()

    def test_successful_verification_uses_exact_identity_issuer_and_source(self):
        with patch.object(gate, "cosign", side_effect=self.outputs()) as cli:
            result = self.verify()
        self.assertEqual(result["status"], "SIGNATURES_VERIFIED")
        for call in cli.call_args_list:
            argv = call.args[0]
            self.assertIn("--certificate-identity=" + result["identity"], argv)
            self.assertIn("--certificate-oidc-issuer=https://token.actions.githubusercontent.com", argv)
            self.assertIn("--certificate-github-workflow-sha=" + self.sha, argv)
            self.assertEqual(argv[-1], self.image)
        self.assertEqual(json.loads((self.root / "signing.json").read_text()), result)

    def test_verifier_failure_erases_previous_success(self):
        (self.root / "signing.json").write_text('{"status":"SIGNATURES_VERIFIED"}')
        with patch.object(gate, "cosign", side_effect=subprocess.CalledProcessError(1, "cosign")):
            with self.assertRaises(subprocess.SubprocessError):
                self.verify()
        self.assertFalse((self.root / "signing.json").exists())

    def test_substituted_signature_digest_blocks(self):
        outputs = self.outputs()
        outputs[0] = json.dumps([{"critical": {"image": {"docker-manifest-digest": "sha256:" + "b" * 64}}}])
        with patch.object(gate, "cosign", side_effect=outputs):
            with self.assertRaises(gate.GateError):
                self.verify()

    def test_substituted_signature_repository_blocks(self):
        outputs = self.outputs()
        claim = json.loads(outputs[0])
        claim[0]["critical"]["identity"]["docker-reference"] = "ghcr.io/another/repository"
        outputs[0] = json.dumps(claim)
        with patch.object(gate, "cosign", side_effect=outputs):
            with self.assertRaises(gate.GateError):
                self.verify()

    def test_attestation_claims_are_not_image_signatures(self):
        for kind in (gate.PROVENANCE_TYPE, gate.SBOM_TYPE, "unknown", None):
            with self.subTest(kind=kind):
                outputs = self.outputs()
                claim = json.loads(outputs[0])
                claim[0]["critical"]["type"] = kind
                outputs[0] = json.dumps(claim)
                with patch.object(gate, "cosign", side_effect=outputs):
                    with self.assertRaises(gate.GateError):
                        self.verify()
                self.assertFalse((self.root / "signing.json").exists())

    def test_signature_reference_must_include_exact_digest(self):
        for reference in (self.image.split("@")[0], self.image.split("@")[0] + ":latest",
                          self.image.split("@")[0] + "@sha256:" + "b" * 64):
            with self.subTest(reference=reference):
                outputs = self.outputs()
                claim = json.loads(outputs[0])
                claim[0]["critical"]["identity"]["docker-reference"] = reference
                outputs[0] = json.dumps(claim)
                with patch.object(gate, "cosign", side_effect=outputs):
                    with self.assertRaises(gate.GateError):
                        self.verify()

    def test_evidence_changed_while_verifier_runs_blocks(self):
        outputs = iter(self.outputs())
        def verifier(_arguments):
            output = next(outputs)
            if "cyclonedx" in _arguments[1]:
                (self.root / "scan.json").write_bytes(b'changed during network operation')
            return output
        with patch.object(gate, "cosign", side_effect=verifier):
            with self.assertRaises(gate.GateError):
                self.verify()
        self.assertFalse((self.root / "signing.json").exists())

    def test_ndjson_verified_attestations_allow_current_run_after_older_run(self):
        outputs = self.outputs()
        previous = copy.deepcopy(self.context()["provenance"])
        previous["runDetails"]["metadata"]["invocationId"] += "0"
        outputs[1] = self.envelope(gate.PROVENANCE_TYPE, previous) + "\n" + outputs[1]
        with patch.object(gate, "cosign", side_effect=outputs):
            self.assertEqual(self.verify()["status"], "SIGNATURES_VERIFIED")

    def test_wrong_attestation_subject_type_source_run_or_sbom_blocks(self):
        c = self.context()
        wrong_provenance = copy.deepcopy(c["provenance"])
        wrong_provenance["buildDefinition"]["externalParameters"]["source_commit"] = "b" * 40
        wrong_run = copy.deepcopy(c["provenance"])
        wrong_run["runDetails"]["metadata"]["invocationId"] += "0"
        wrong_sbom = copy.deepcopy(self.sbom)
        wrong_sbom["components"] = [{"name": "substituted"}]
        mutations = [(1, self.envelope(gate.PROVENANCE_TYPE, c["provenance"], "sha256:" + "b" * 64)),
                     (1, self.envelope("https://example.invalid/predicate", c["provenance"])),
                     (1, self.envelope(gate.PROVENANCE_TYPE, wrong_provenance)),
                     (1, self.envelope(gate.PROVENANCE_TYPE, wrong_run)),
                     (2, self.envelope(gate.SBOM_TYPE, wrong_sbom))]
        for index, changed in mutations:
            with self.subTest(index=index, changed=changed):
                outputs = self.outputs()
                outputs[index] = changed
                with patch.object(gate, "cosign", side_effect=outputs):
                    with self.assertRaises(gate.GateError):
                        self.verify()
                self.assertFalse((self.root / "signing.json").exists())

    def test_empty_or_malformed_verifier_output_blocks(self):
        for malformed in ["", "[]", "null", "{}", "garbage"]:
            outputs = self.outputs()
            outputs[1] = malformed
            with self.subTest(output=malformed), patch.object(gate, "cosign", side_effect=outputs):
                with self.assertRaises((gate.GateError, ValueError, KeyError, TypeError)):
                    self.verify()

    def test_signing_requires_matching_main_workflow_context(self):
        with patch.dict("os.environ", {}, clear=True), patch.object(gate, "cosign") as cli:
            with self.assertRaises(gate.GateError):
                gate.sign(self.root, "php", self.sha, self.run, self.attempt)
        cli.assert_not_called()

    def test_sign_then_verify_binds_all_components(self):
        for component, base, workflow, status, digest_key in [
            ("mariadb", "ghcr.io/cahangeorge/limesurvey-mariadb", "mariadb-release.yml", "DATABASE_ARTIFACT_VERIFIED", "digest"),
            ("php", "ghcr.io/cahangeorge/limesurvey", "release.yml", "ARTIFACT_VERIFIED", "digest"),
            ("nginx", "ghcr.io/cahangeorge/limesurvey-nginx", "nginx-release.yml", "COMPANION_ARTIFACT_VERIFIED", "registry_manifest_digest"),
        ]:
            with self.subTest(component=component):
                if component == "mariadb":
                    for name in ("buildinfo.json", "parent-image.json", "parent-binary.json", "regression.json",
                                 "final-inventory.json", "candidate-image.json", "candidate-scan.json",
                                 "candidate-db.json", "tested.json", "branch.json", "runs.json"):
                        (self.root / name).write_bytes(b'{}')
                        self.release["evidence_sha256"][name] = hashlib.sha256(b'{}').hexdigest()
                self.image = base + "@" + self.digest
                self.sbom["metadata"]["component"]["name"] = self.image
                sbom_bytes = json.dumps(self.sbom).encode()
                (self.root / "sbom.cdx.json").write_bytes(sbom_bytes)
                self.release.update(status=status, image=self.image)
                self.release[digest_key] = self.digest
                self.release["evidence_sha256"]["sbom.cdx.json"] = hashlib.sha256(sbom_bytes).hexdigest()
                self.write_release()
                ctx = gate.context(self.root, component, self.sha, self.run, self.attempt)
                signature = json.dumps([{"critical": {"image": {"docker-manifest-digest": self.digest},
                                                       "identity": {"docker-reference": self.image},
                                                       "type": "https://sigstore.dev/cosign/sign/v1"}}])
                outputs = ["", "", "", signature, self.envelope(gate.PROVENANCE_TYPE, ctx["provenance"]),
                           self.envelope(gate.SBOM_TYPE, self.sbom)]
                env = {"GITHUB_REPOSITORY": "cahangeorge/LimeSurvey", "GITHUB_REF": "refs/heads/main",
                       "GITHUB_SHA": self.sha, "GITHUB_RUN_ID": str(self.run), "GITHUB_RUN_ATTEMPT": "1",
                       "GITHUB_EVENT_NAME": "workflow_dispatch",
                       "GITHUB_WORKFLOW_REF": "cahangeorge/LimeSurvey/.github/workflows/" + workflow + "@refs/heads/main"}
                with patch.dict("os.environ", env, clear=True), patch.object(gate, "cosign", side_effect=outputs) as cli:
                    result = gate.sign(self.root, component, self.sha, self.run, self.attempt)
                self.assertEqual(result["status"], "SIGNATURES_VERIFIED")
                self.assertEqual(cli.call_args_list[0].args[0], ["sign", "--yes", self.image])
                self.assertEqual(cli.call_count, 6)
                self.assertEqual(json.loads((self.root / "provenance.json").read_text()), ctx["provenance"])

    def test_database_additional_evidence_cannot_be_omitted(self):
        self.image = "ghcr.io/cahangeorge/limesurvey-mariadb@" + self.digest
        self.release.update(image=self.image, status="DATABASE_ARTIFACT_VERIFIED")
        self.sbom["metadata"]["component"]["name"] = self.image
        raw = json.dumps(self.sbom).encode(); (self.root / "sbom.cdx.json").write_bytes(raw)
        self.release["evidence_sha256"]["sbom.cdx.json"] = hashlib.sha256(raw).hexdigest()
        self.write_release()
        with self.assertRaises(gate.GateError): gate.context(self.root, "mariadb", self.sha, self.run, self.attempt)

    def test_cosign_process_is_bounded_and_failure_is_propagated(self):
        with patch.object(gate.subprocess, "run", side_effect=subprocess.TimeoutExpired("cosign", 180)) as run:
            with self.assertRaises(subprocess.TimeoutExpired):
                gate.cosign(["verify", self.image])
        self.assertTrue(run.call_args.kwargs["check"])
        self.assertEqual(run.call_args.kwargs["timeout"], 180)


if __name__ == "__main__":
    unittest.main()
