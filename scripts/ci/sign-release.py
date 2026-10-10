#!/usr/bin/env python3
"""Sign and verify eligible GHCR digests; never authorize deployment."""

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SOURCE = "https://github.com/cahangeorge/LimeSurvey"
ISSUER = "https://token.actions.githubusercontent.com"
PROVENANCE_TYPE = "https://slsa.dev/provenance/v1"
SBOM_TYPE = "https://cyclonedx.org/bom"
COMPONENTS = {
    "php": ("ghcr.io/cahangeorge/limesurvey", "release.yml", "ARTIFACT_VERIFIED", "digest"),
    "nginx": ("ghcr.io/cahangeorge/limesurvey-nginx", "nginx-release.yml", "COMPANION_ARTIFACT_VERIFIED", "registry_manifest_digest"),
}
REQUIRED_EVIDENCE = {"registry-manifest.json", "image.json", "inventory.json", "scan.json",
                     "db.json", "sbom.cdx.json", "ci.json"}


class GateError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise GateError(message)


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def context(root, component, sha, run_id, attempt):
    require(component in COMPONENTS and re.fullmatch(r"[0-9a-f]{40}", sha), "invalid component or source")
    require(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0,
            "invalid release run identity")
    image, workflow, status, digest_key = COMPONENTS[component]
    release = json.loads((root / "release.json").read_text())
    require(release.get("schema_version") == 1 and release.get("status") == status
            and release.get("repository") == "cahangeorge/LimeSurvey"
            and release.get("source_commit") == sha and release.get("platform") == "linux/arm64"
            and release.get("scan", {}).get("status") == "PASS", "release is not an eligible exact-source artifact")
    digest = release[digest_key]
    require(isinstance(digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", digest), "invalid image digest")
    ref = image + "@" + digest
    require(release.get("image") == ref and release["release_run"].get("id") == run_id
            and release["release_run"].get("attempt") == attempt, "image or publisher run mismatch")
    ci = release["ci"]
    require(ci.get("head_sha") == sha and ci.get("event") == "push"
            and ci.get("path") == ".github/workflows/release-gate.yml", "required CI source mismatch")
    hashes = release["evidence_sha256"]
    require(isinstance(hashes, dict) and REQUIRED_EVIDENCE <= hashes.keys(), "missing required evidence hashes")
    for name, expected in hashes.items():
        require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name)
                and isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected), "unsafe evidence name or hash")
        require(file_hash(root / name) == expected, "evidence bytes changed: " + name)
    require("sha256:" + file_hash(root / "registry-manifest.json") == digest, "registry digest mismatch")
    sbom = json.loads((root / "sbom.cdx.json").read_text())
    require(sbom.get("bomFormat") == "CycloneDX" and sbom.get("metadata", {}).get("component", {}).get("name") == ref,
            "SBOM image mismatch")
    identity = SOURCE + "/.github/workflows/" + workflow + "@refs/heads/main"
    invocation = SOURCE + f"/actions/runs/{run_id}/attempts/{attempt}"
    dependencies = [{"uri": SOURCE + "@" + sha, "digest": {"gitCommit": sha}}]
    dependencies += [{"uri": "urn:limesurvey:evidence:" + name, "digest": {"sha256": value}}
                     for name, value in sorted({**hashes, "release.json": file_hash(root / "release.json")}.items())]
    provenance = {
        "buildDefinition": {
            "buildType": SOURCE + "/blob/main/docs/delivery/artifact-signing.md#build-definition-v1",
            "externalParameters": {"source_commit": sha, "source_ref": "refs/heads/main", "component": component},
            "internalParameters": {"platform": "linux/arm64"},
            "resolvedDependencies": dependencies,
        },
        "runDetails": {"builder": {"id": identity}, "metadata": {"invocationId": invocation}},
    }
    return {"image": ref, "repository": image, "digest": digest, "identity": identity,
            "invocation": invocation, "provenance": provenance, "sbom": sbom, "workflow": workflow}


def cosign(arguments):
    # Never echo OIDC/registry credentials or external stderr into artifact evidence.
    return subprocess.run(["cosign", *arguments], check=True, capture_output=True,
                          text=True, timeout=180).stdout


def json_values(output):
    decoder = json.JSONDecoder()
    values = []
    remaining = output.strip()
    while remaining:
        value, offset = decoder.raw_decode(remaining)
        values.extend(value if isinstance(value, list) else [value])
        remaining = remaining[offset:].strip()
    require(values and all(isinstance(value, dict) for value in values), "empty or malformed verifier output")
    return values


def verified_predicate(output, expected, predicate_type, ctx):
    # These envelopes are consumed only after Cosign has verified certificate,
    # signature, OIDC identity/source, transparency log and digest.
    for envelope in json_values(output):
        require(envelope.get("payloadType") == "application/vnd.in-toto+json", "unsupported DSSE payload")
        statement = json.loads(base64.b64decode(envelope["payload"], validate=True))
        require(statement.get("_type") == "https://in-toto.io/Statement/v0.1"
                and statement.get("predicateType") == predicate_type, "wrong statement or predicate type")
        require(statement.get("subject") == [{"name": ctx["repository"], "digest": {"sha256": ctx["digest"][7:]}}],
                "attestation subject mismatch")
        if statement.get("predicate") == expected:
            return
    raise GateError("no verified attestation matches the expected source, run and evidence")


def verify(root, component, sha, run_id, attempt):
    receipt = root / "signing.json"
    receipt.unlink(missing_ok=True)
    ctx = context(root, component, sha, run_id, attempt)
    policy = ["--certificate-identity=" + ctx["identity"], "--certificate-oidc-issuer=" + ISSUER,
              "--certificate-github-workflow-sha=" + sha]
    outputs = {}
    signatures = cosign(["verify", *policy, ctx["image"]])
    claims = json_values(signatures)
    require(any(value.get("critical", {}).get("image", {}).get("docker-manifest-digest") == ctx["digest"]
                and value.get("critical", {}).get("identity", {}).get("docker-reference") == ctx["image"]
                and value.get("critical", {}).get("type") == "https://sigstore.dev/cosign/sign/v1"
                for value in claims), "signature digest mismatch")
    outputs["cosign-signature.json"] = signatures
    for kind, expected, cli_type, predicate_type in (
        ("provenance", ctx["provenance"], "slsaprovenance1", PROVENANCE_TYPE),
        ("sbom", ctx["sbom"], "cyclonedx", SBOM_TYPE),
    ):
        output = cosign(["verify-attestation", "--type=" + cli_type, *policy, ctx["image"]])
        verified_predicate(output, expected, predicate_type, ctx)
        outputs["cosign-" + kind + ".json"] = output
    require(context(root, component, sha, run_id, attempt) == ctx, "evidence changed during verification")
    for name, output in outputs.items():
        (root / name).write_text(output)
    result = {"schema_version": 1, "status": "SIGNATURES_VERIFIED", "image": ctx["image"],
              "source_commit": sha, "identity": ctx["identity"], "issuer": ISSUER,
              "release_run": {"id": run_id, "attempt": attempt},
              "release_sha256": file_hash(root / "release.json"),
              "verification_sha256": {name: file_hash(root / name) for name in outputs},
              "staging": "PENDING", "production": "HOLD"}
    receipt.write_text(json.dumps(result, indent=2) + "\n")
    return result


def sign(root, component, sha, run_id, attempt):
    (root / "signing.json").unlink(missing_ok=True)
    ctx = context(root, component, sha, run_id, attempt)
    expected_env = {"GITHUB_REPOSITORY": "cahangeorge/LimeSurvey", "GITHUB_REF": "refs/heads/main",
                    "GITHUB_SHA": sha, "GITHUB_RUN_ID": str(run_id), "GITHUB_RUN_ATTEMPT": str(attempt),
                    "GITHUB_EVENT_NAME": "workflow_dispatch",
                    "GITHUB_WORKFLOW_REF": "cahangeorge/LimeSurvey/.github/workflows/" + ctx["workflow"] + "@refs/heads/main"}
    require(all(os.environ.get(key) == value for key, value in expected_env.items()),
            "signing requires the matching main publisher context")
    predicate = root / "provenance.json"
    predicate.write_text(json.dumps(ctx["provenance"], indent=2) + "\n")
    cosign(["sign", "--yes", ctx["image"]])
    for kind, path in (("slsaprovenance1", predicate), ("cyclonedx", root / "sbom.cdx.json")):
        cosign(["attest", "--yes", "--type=" + kind, "--predicate=" + str(path), ctx["image"]])
    return verify(root, component, sha, run_id, attempt)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("sign", "verify"))
    parser.add_argument("directory", type=Path)
    parser.add_argument("component", choices=COMPONENTS)
    parser.add_argument("sha")
    parser.add_argument("run_id", type=int)
    parser.add_argument("attempt", type=int)
    args = parser.parse_args()
    try:
        result = (sign if args.command == "sign" else verify)(args.directory, args.component, args.sha, args.run_id, args.attempt)
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError):
        print("release_signing=HOLD: missing, changed or failed signing evidence", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
